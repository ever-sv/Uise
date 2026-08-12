"""
Durable storage for a Uise node - SQLite via the standard library.

SQLite is chosen deliberately for the reference node: it is ACID, needs no server,
and ships with Python, so a node runs anywhere with no operational setup. The
schema is intentionally narrow, so replacing it with PostgreSQL for a multi-region
deployment means reimplementing this one class.

The log table is append-only by construction: this module exposes no update or
delete path for it. That is not politeness - a log that can be rewritten proves
nothing.

Money is stored as text and summed with `Decimal`. SQLite has no exact decimal
type, and binary floating point for money is a conformance defect. Daily rollups
are computed at write time so the dashboard never has to re-add every row.
"""

import json
import os
import sqlite3
import time
from decimal import Decimal

SCHEMA = """
CREATE TABLE IF NOT EXISTS log_entries (
    idx        INTEGER PRIMARY KEY,
    rid        TEXT    NOT NULL UNIQUE,
    leaf_hash  BLOB    NOT NULL,
    entry      BLOB    NOT NULL,
    receipt    TEXT    NOT NULL,
    payer      TEXT    NOT NULL,
    payee      TEXT    NOT NULL,
    capability TEXT    NOT NULL,
    amount     TEXT    NOT NULL,
    unit       TEXT    NOT NULL,
    fee_amount TEXT    NOT NULL,
    fee_unit   TEXT    NOT NULL,
    billed_to  TEXT    NOT NULL,
    issued_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS log_entries_by_billed_to ON log_entries (billed_to);
CREATE INDEX IF NOT EXISTS log_entries_by_issued_at ON log_entries (issued_at);

CREATE TABLE IF NOT EXISTS usage_daily (
    day        TEXT NOT NULL,
    unit       TEXT NOT NULL,
    receipts   INTEGER NOT NULL,
    fee_total  TEXT NOT NULL,
    volume_total TEXT NOT NULL,
    PRIMARY KEY (day, unit)
);

CREATE TABLE IF NOT EXISTS accounts (
    did          TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    rail         TEXT NOT NULL,
    rail_ref     TEXT,
    -- NULL means "inherit the node's policy". Recording someone's billing
    -- details must never, by itself, change whether they are served.
    credit_limit TEXT,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credit_ledger (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    did        TEXT NOT NULL,
    unit       TEXT NOT NULL,
    delta      TEXT NOT NULL,
    kind       TEXT NOT NULL,
    reference  TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS credit_ledger_by_account ON credit_ledger (did, unit, seq);

CREATE TABLE IF NOT EXISTS balances (
    did        TEXT NOT NULL,
    unit       TEXT NOT NULL,
    amount     TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (did, unit)
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id       TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    environment  TEXT NOT NULL,
    -- Only the digest. A dump of this table yields nothing usable.
    digest       BLOB NOT NULL,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    -- Revoked keys are kept, never deleted: an audit trail with holes is not one.
    revoked_at   INTEGER
);

CREATE TABLE IF NOT EXISTS descriptors (
    did        TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL,
    descriptor TEXT    NOT NULL,
    envelope   TEXT    NOT NULL,
    expires    INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS capabilities (
    did           TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    PRIMARY KEY (did, capability_id)
);

CREATE INDEX IF NOT EXISTS capabilities_by_id ON capabilities (capability_id);
"""


def _day(timestamp_ms):
    return time.strftime("%Y-%m-%d", time.gmtime(timestamp_ms / 1000))


class InsufficientCredit(Exception):
    """
    The account cannot absorb this charge within its credit limit.

    Raised from inside the write transaction, never before it: checking a balance
    and then charging it in a separate step is a race that hands out free service
    under concurrency.
    """

    def __init__(self, did, unit, balance, charge, limit):
        super(InsufficientCredit, self).__init__(
            "%s has %s %s and a limit of %s; cannot absorb %s"
            % (did, balance, unit, limit, charge)
        )
        self.did = did
        self.unit = unit
        self.balance = balance
        self.charge = charge
        self.limit = limit


class Storage(object):
    """Node persistence. Not thread-safe by itself; the node serializes writes."""

    def __init__(self, path=":memory:"):
        self.path = path
        if path != ":memory:":
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(SCHEMA)
        self._db.commit()

    def close(self):
        self._db.close()

    # -- transparency log ---------------------------------------------------- #

    def log_size(self):
        return self._db.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]

    def leaf_hashes(self):
        rows = self._db.execute("SELECT leaf_hash FROM log_entries ORDER BY idx")
        return [row["leaf_hash"] for row in rows]

    def append_entry(self, index, leaf, entry, receipt, fee_amount, fee_unit,
                     billed_to, credit_limit=None):
        """
        Append one receipt, charge its fee and roll up usage - all in one
        transaction. Either the receipt is logged and paid for, or neither.

        Raises sqlite3.IntegrityError on a duplicate rid, which keeps one
        obligation from appearing twice in the log, and InsufficientCredit when the
        charge would take the account past its limit.

        `credit_limit` of None means the fee is metered but not enforced - the
        launch phase, where usage is free and the balance simply accrues.
        """
        day = _day(receipt["issued_at"])
        with self._db:
            # Negative: a fee draws the balance down. The sign lives here, once,
            # so no caller can get the direction of money wrong.
            self._charge(billed_to, fee_unit, -Decimal(fee_amount), "issuance",
                         receipt["rid"], receipt["issued_at"], credit_limit)
            self._db.execute(
                "INSERT INTO log_entries"
                " (idx, rid, leaf_hash, entry, receipt, payer, payee, capability,"
                "  amount, unit, fee_amount, fee_unit, billed_to, issued_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (index, receipt["rid"], leaf, entry,
                 json.dumps(receipt, ensure_ascii=False),
                 receipt["payer"], receipt["payee"], receipt["capability"],
                 receipt["amount"], receipt["unit"],
                 str(fee_amount), fee_unit, billed_to, receipt["issued_at"]),
            )
            existing = self._db.execute(
                "SELECT receipts, fee_total, volume_total FROM usage_daily"
                " WHERE day = ? AND unit = ?", (day, receipt["unit"]),
            ).fetchone()
            if existing is None:
                self._db.execute(
                    "INSERT INTO usage_daily (day, unit, receipts, fee_total, volume_total)"
                    " VALUES (?, ?, 1, ?, ?)",
                    (day, receipt["unit"], str(fee_amount), receipt["amount"]),
                )
            else:
                self._db.execute(
                    "UPDATE usage_daily SET receipts = ?, fee_total = ?, volume_total = ?"
                    " WHERE day = ? AND unit = ?",
                    (existing["receipts"] + 1,
                     str(Decimal(existing["fee_total"]) + Decimal(fee_amount)),
                     str(Decimal(existing["volume_total"]) + Decimal(receipt["amount"])),
                     day, receipt["unit"]),
                )

    def entry_by_rid(self, rid):
        row = self._db.execute(
            "SELECT idx, rid, receipt FROM log_entries WHERE rid = ?", (rid,)
        ).fetchone()
        if row is None:
            return None
        return {"index": row["idx"], "rid": row["rid"], "receipt": json.loads(row["receipt"])}

    def entries(self, start, end):
        rows = self._db.execute(
            "SELECT idx, rid, receipt FROM log_entries"
            " WHERE idx >= ? AND idx < ? ORDER BY idx",
            (start, end),
        )
        return [{"index": r["idx"], "rid": r["rid"], "receipt": json.loads(r["receipt"])}
                for r in rows]

    # -- credits ------------------------------------------------------------- #
    #
    # The ledger is append-only and the balance is derived from it. The balance is
    # also materialized so a dashboard never has to re-add every row, but
    # `recompute_balance` exists to prove the two agree: a stored total that can
    # silently drift from its ledger is how money bugs survive for years.

    def _charge(self, did, unit, delta, kind, reference, now_ms, credit_limit=None):
        """
        Apply a signed movement inside the caller's transaction.

        `delta` is negative for a charge and positive for a deposit. The limit is
        checked here, atomically, so two concurrent issuances cannot both pass a
        balance check and then both charge.
        """
        row = self._db.execute(
            "SELECT amount FROM balances WHERE did = ? AND unit = ?", (did, unit)
        ).fetchone()
        current = Decimal(row["amount"]) if row else Decimal(0)
        updated = current + delta

        if credit_limit is not None and updated < -Decimal(credit_limit):
            raise InsufficientCredit(did, unit, current, -delta, credit_limit)

        self._db.execute(
            "INSERT INTO credit_ledger (did, unit, delta, kind, reference, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (did, unit, str(delta), kind, reference, now_ms),
        )
        self._db.execute(
            "INSERT INTO balances (did, unit, amount, updated_at) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(did, unit) DO UPDATE SET"
            " amount=excluded.amount, updated_at=excluded.updated_at",
            (did, unit, str(updated), now_ms),
        )
        return updated

    def apply_credit(self, did, unit, delta, kind, reference, now_ms, credit_limit=None):
        """Standalone movement - a deposit, a refund, or a manual adjustment."""
        with self._db:
            return self._charge(did, unit, delta, kind, reference, now_ms, credit_limit)

    def balance(self, did, unit):
        row = self._db.execute(
            "SELECT amount FROM balances WHERE did = ? AND unit = ?", (did, unit)
        ).fetchone()
        return Decimal(row["amount"]) if row else Decimal(0)

    def recompute_balance(self, did, unit):
        """Re-add the ledger from scratch. Used to audit the materialized total."""
        rows = self._db.execute(
            "SELECT delta FROM credit_ledger WHERE did = ? AND unit = ?", (did, unit)
        ).fetchall()
        return sum((Decimal(row["delta"]) for row in rows), Decimal(0))

    def ledger(self, did, unit, limit=100):
        rows = self._db.execute(
            "SELECT seq, delta, kind, reference, created_at FROM credit_ledger"
            " WHERE did = ? AND unit = ? ORDER BY seq DESC LIMIT ?",
            (did, unit, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def balances(self):
        rows = self._db.execute(
            "SELECT b.did, b.unit, b.amount, b.updated_at, a.label, a.credit_limit"
            " FROM balances b LEFT JOIN accounts a ON a.did = b.did"
            " ORDER BY b.updated_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def float_held(self):
        """
        Prepaid money that has been received but not yet earned.

        It is a liability, not revenue, and showing it as anything else would be
        lying to yourself about how much of the bank balance is actually yours.
        """
        rows = self._db.execute("SELECT unit, amount FROM balances").fetchall()
        totals = {}
        for row in rows:
            amount = Decimal(row["amount"])
            if amount > 0:
                totals[row["unit"]] = totals.get(row["unit"], Decimal(0)) + amount
        return {unit: str(total) for unit, total in totals.items()}

    def outstanding(self):
        """Service consumed beyond what was funded - what customers owe."""
        rows = self._db.execute("SELECT unit, amount FROM balances").fetchall()
        totals = {}
        for row in rows:
            amount = Decimal(row["amount"])
            if amount < 0:
                totals[row["unit"]] = totals.get(row["unit"], Decimal(0)) - amount
        return {unit: str(total) for unit, total in totals.items()}

    # -- metering ------------------------------------------------------------ #

    def revenue(self):
        """Total fees charged, as exact decimals grouped by unit."""
        rows = self._db.execute(
            "SELECT unit, fee_total FROM usage_daily"
        ).fetchall()
        totals = {}
        for row in rows:
            totals[row["unit"]] = totals.get(row["unit"], Decimal(0)) + Decimal(row["fee_total"])
        return {unit: str(total) for unit, total in totals.items()}

    def transacted_volume(self):
        """
        Total value that changed hands between agents. Uise never touches this
        money - it is the number the fee is a fraction of.
        """
        rows = self._db.execute("SELECT unit, volume_total FROM usage_daily").fetchall()
        totals = {}
        for row in rows:
            totals[row["unit"]] = totals.get(row["unit"], Decimal(0)) + Decimal(row["volume_total"])
        return {unit: str(total) for unit, total in totals.items()}

    def daily_usage(self, days=30):
        rows = self._db.execute(
            "SELECT day, unit, receipts, fee_total, volume_total FROM usage_daily"
            " ORDER BY day DESC LIMIT ?", (days * 4,),
        ).fetchall()
        return [{"day": r["day"], "unit": r["unit"], "receipts": r["receipts"],
                 "fee_total": r["fee_total"], "volume_total": r["volume_total"]}
                for r in reversed(rows)]

    def usage_for(self, billed_to, since_ms=None, until_ms=None):
        """Every billable line for one account in a period. The basis of an invoice."""
        clauses = ["billed_to = ?"]
        values = [billed_to]
        if since_ms is not None:
            clauses.append("issued_at >= ?")
            values.append(since_ms)
        if until_ms is not None:
            clauses.append("issued_at < ?")
            values.append(until_ms)
        rows = self._db.execute(
            "SELECT rid, capability, fee_amount, fee_unit, issued_at FROM log_entries"
            " WHERE " + " AND ".join(clauses) + " ORDER BY issued_at",
            values,
        ).fetchall()
        return [{"rid": r["rid"], "capability": r["capability"],
                 "fee_amount": r["fee_amount"], "fee_unit": r["fee_unit"],
                 "issued_at": r["issued_at"]} for r in rows]

    def active_agents(self):
        """Distinct agents that have appeared as a payer, payee or issuer."""
        row = self._db.execute(
            "SELECT COUNT(*) AS total FROM ("
            "  SELECT payer AS did FROM log_entries"
            "  UNION SELECT payee FROM log_entries"
            ")"
        ).fetchone()
        return row["total"]

    def agent_graph(self, limit=60):
        """
        Who works with whom, weighted by receipts.

        The edges are the network: a pair only appears here because one agent paid
        the other for real work, verified by three signatures.
        """
        rows = self._db.execute(
            "SELECT payer, payee, COUNT(*) AS receipts, unit,"
            " GROUP_CONCAT(amount) AS amounts FROM log_entries"
            " GROUP BY payer, payee, unit ORDER BY receipts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        edges = []
        for row in rows:
            volume = sum((Decimal(value) for value in row["amounts"].split(",")),
                         Decimal(0))
            edges.append({"payer": row["payer"], "payee": row["payee"],
                          "receipts": row["receipts"], "unit": row["unit"],
                          "volume": str(volume)})
        return edges

    def top_capabilities(self, limit=10):
        rows = self._db.execute(
            "SELECT capability, COUNT(*) AS receipts FROM log_entries"
            " GROUP BY capability ORDER BY receipts DESC LIMIT ?", (limit,),
        ).fetchall()
        return [{"capability": r["capability"], "receipts": r["receipts"]} for r in rows]

    # -- accounts ------------------------------------------------------------ #

    def upsert_account(self, did, label, rail, rail_ref, created_at, credit_limit=None):
        with self._db:
            self._db.execute(
                "INSERT INTO accounts (did, label, rail, rail_ref, credit_limit, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(did) DO UPDATE SET"
                " label=excluded.label, rail=excluded.rail, rail_ref=excluded.rail_ref,"
                " credit_limit=excluded.credit_limit",
                (did, label, rail, rail_ref,
                 None if credit_limit is None else str(credit_limit), created_at),
            )

    def account(self, did):
        row = self._db.execute("SELECT * FROM accounts WHERE did = ?", (did,)).fetchone()
        return dict(row) if row else None

    def accounts(self):
        rows = self._db.execute("SELECT * FROM accounts ORDER BY created_at")
        return [dict(row) for row in rows]

    # -- api credentials ----------------------------------------------------- #

    def insert_api_key(self, key_id, label, environment, key_digest, scopes, created_at):
        with self._db:
            self._db.execute(
                "INSERT INTO api_keys"
                " (key_id, label, environment, digest, scopes, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, label, environment, key_digest, ",".join(scopes), created_at),
            )

    def api_key(self, key_id):
        row = self._db.execute(
            "SELECT * FROM api_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        return dict(row) if row else None

    def api_keys(self):
        """Every key on file, without digests: nothing here can authenticate."""
        rows = self._db.execute(
            "SELECT key_id, label, environment, scopes, created_at, last_used_at,"
            " revoked_at FROM api_keys ORDER BY created_at"
        )
        return [dict(row) for row in rows]

    def has_active_api_key(self):
        """Cheap check on the request path: a count, not a table of objects."""
        return self._db.execute(
            "SELECT EXISTS(SELECT 1 FROM api_keys WHERE revoked_at IS NULL)"
        ).fetchone()[0] == 1

    def touch_api_key(self, key_id, now_ms):
        with self._db:
            self._db.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (now_ms, key_id)
            )

    def revoke_api_key(self, key_id, now_ms):
        with self._db:
            self._db.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                (now_ms, key_id),
            )

    # -- discovery ----------------------------------------------------------- #

    def upsert_descriptor(self, did, descriptor, envelope, updated_at):
        capability_ids = [c["id"] for c in descriptor.get("capabilities", [])]
        with self._db:
            self._db.execute(
                "INSERT INTO descriptors (did, name, descriptor, envelope, expires, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(did) DO UPDATE SET"
                " name=excluded.name, descriptor=excluded.descriptor,"
                " envelope=excluded.envelope, expires=excluded.expires,"
                " updated_at=excluded.updated_at",
                (did, descriptor.get("name", ""),
                 json.dumps(descriptor, ensure_ascii=False),
                 json.dumps(envelope, ensure_ascii=False),
                 descriptor.get("expires"), updated_at),
            )
            self._db.execute("DELETE FROM capabilities WHERE did = ?", (did,))
            self._db.executemany(
                "INSERT INTO capabilities (did, capability_id) VALUES (?, ?)",
                [(did, capability_id) for capability_id in capability_ids],
            )

    def descriptor(self, did):
        row = self._db.execute(
            "SELECT descriptor FROM descriptors WHERE did = ?", (did,)
        ).fetchone()
        return json.loads(row["descriptor"]) if row else None

    def registered_agents(self):
        return self._db.execute("SELECT COUNT(*) FROM descriptors").fetchone()[0]

    def registered_capabilities(self):
        return self._db.execute(
            "SELECT COUNT(DISTINCT capability_id) FROM capabilities"
        ).fetchone()[0]

    def find_by_capability(self, capability_id, now_ms, limit=50):
        rows = self._db.execute(
            "SELECT d.descriptor FROM descriptors d"
            " JOIN capabilities c ON c.did = d.did"
            " WHERE c.capability_id = ? AND (d.expires IS NULL OR d.expires > ?)"
            " ORDER BY d.updated_at DESC LIMIT ?",
            (capability_id, now_ms, limit),
        )
        return [json.loads(row["descriptor"]) for row in rows]
