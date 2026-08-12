"""
The Uise node - discovery, receipt issuance and the public transparency log.

This is the value plane, and the only part of the system that charges. It is
deliberately absent from the conversation plane: agents talk to each other
directly, and a node never sees that traffic. Putting a node on that path would
make it the bottleneck of its own network.

A node does three things:

  * **Discovery.** Accepts signed `announce` envelopes and answers capability
    queries. Read-only, free, and replaceable - anyone may run one.
  * **Issuance.** Verifies what two parties agreed, adds the third signature, and
    charges a fee for that one act. This is the business.
  * **Transparency.** Publishes every issued receipt into an append-only Merkle
    log with a signed tree head, so nobody has to trust the node to believe it.

The fee is charged for *issuing the proof*, never for moving money: the node
never holds or transfers funds, which keeps it a data service rather than a
regulated money transmitter.
"""

import json
import os
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from sqlite3 import IntegrityError
from threading import Lock
from urllib.parse import parse_qs, urlparse

from uip import codec, did as did_module, envelope

from . import api, dashboard, events as events_module, log, suites, transport
from .credits import UNLIMITED, Credits, InsufficientCredit
from .events import EventBus
from .identity import Identity
from .keys import ENVIRONMENT_LIVE, ApiKeys
from .ratelimit import Limiters
from .storage import Storage

DOMAIN_SIGNED_TREE_HEAD = b"uip/1.sth\n"

RECEIPT_CONTENT_TYPE = "application/uip-receipt+json"
DESCRIPTOR_CONTENT_TYPE = "application/uip-descriptor+json"
ERROR_CONTENT_TYPE = "application/uip-error+json"
JSON_CONTENT_TYPE = "application/json"

DEFAULT_FEE = "0.0001"
ISSUANCE_SKEW_MS = 300_000
MAX_DISCOVERY_RESULTS = 50

PATH_DISCOVER = "/uip/v1/discover"
PATH_STH = "/uip/v1/log/sth"
PATH_PROOF = "/uip/v1/log/proof"
PATH_CONSISTENCY = "/uip/v1/log/consistency"
PATH_ENTRIES = "/uip/v1/log/entries"


def _now_ms():
    return int(time.time() * 1000)


class Node(object):
    """An issuer: identity, durable storage, and an append-only log over both."""

    def __init__(self, identity=None, storage=None, log_url="https://log.example.com",
                 fee=DEFAULT_FEE, fee_unit="USD", name="uise-node",
                 default_credit_limit=UNLIMITED, environment=ENVIRONMENT_LIVE,
                 rate_limits=None):
        # An issuer signs permanent evidence, so it defaults to the composite
        # post-quantum suite. Anything less is refused outright rather than
        # merely discouraged.
        self.identity = identity or Identity.generate(suites.ISSUER_DEFAULT)
        if not self.identity.suite.long_term_evidence:
            raise ValueError(
                "an issuer must use a long-term-evidence suite; %s is not one"
                % self.identity.suite.name
            )
        if not isinstance(fee, str):
            raise TypeError("fee must be a decimal string, never a float")

        self.name = name
        self.log_url = log_url.rstrip("/")
        self.fee = Decimal(fee)
        self.fee_unit = fee_unit
        self.storage = storage or Storage()
        self.tree = log.MerkleLog(self.storage.leaf_hashes())
        # UNLIMITED meters every issuance without refusing any: the launch phase,
        # where usage is free and simply accrues. Setting a limit of "0" makes the
        # node strictly prepaid the day pricing turns on, with no retrofit.
        self.credits = Credits(self.storage, default_credit_limit, fee_unit)
        # The product API stays closed until a credential exists. The protocol
        # endpoints under /uip/v1 remain open, as a protocol must be.
        self.keys = ApiKeys(self.storage, environment)
        self.limiters = Limiters(rate_limits)
        self.events = EventBus()
        # An account is warned once it can no longer cover this many issuances,
        # so it can top up before service stops rather than after.
        self.low_balance_receipts = 100
        self.replay = envelope.ReplayStore()
        self._lock = Lock()

    @property
    def did(self):
        return self.identity.did

    def close(self):
        self.events.close()
        self.storage.close()

    # -- money in ------------------------------------------------------------ #

    def deposit(self, did, amount, unit=None, reference=None):
        """
        Record funds that arrived elsewhere, and announce it.

        Event publication lives here rather than in `Credits` so that every path
        which moves a balance emits exactly one event, and the ledger stays a
        module with no opinion about who is watching.
        """
        balance = self.credits.deposit(did, amount, unit, reference)
        self.events.publish(events_module.CREDIT_DEPOSITED, {
            "account": did,
            "amount": str(amount),
            "unit": unit or self.fee_unit,
            "balance": str(balance),
        })
        return balance

    # -- transparency log ---------------------------------------------------- #

    def signed_tree_head(self):
        """
        A signed commitment to the whole log at a point in time.

        Auditors pin this. Two tree heads plus a consistency proof are enough to
        prove the node never rewrote history - without trusting the node at all.
        """
        head = {
            "v": envelope.VERSION,
            "log": self.log_url,
            "issuer": self.did,
            "tree_size": len(self.tree),
            "root": log.tag(self.tree.root(), self.tree.algorithm),
            "timestamp": _now_ms(),
        }
        signature = self.identity.sign(DOMAIN_SIGNED_TREE_HEAD + codec.canonicalize(head))
        head["sig"] = codec.b64u_encode(signature)
        return head

    def anchor_for(self, index, tree_size=None):
        size = len(self.tree) if tree_size is None else tree_size
        proof = self.tree.inclusion_proof(index, size)
        return {
            "log": self.log_url,
            "index": index,
            "tree_size": size,
            "root": log.tag(self.tree.root(size), self.tree.algorithm),
            "inclusion_proof": [log.tag(node, self.tree.algorithm) for node in proof],
        }

    def consistency_proof(self, first_size, second_size):
        proof = self.tree.consistency_proof(first_size, second_size)
        return {
            "first_size": first_size,
            "second_size": second_size,
            "first_root": log.tag(self.tree.root(first_size), self.tree.algorithm),
            "second_root": log.tag(self.tree.root(second_size), self.tree.algorithm),
            "proof": [log.tag(node, self.tree.algorithm) for node in proof],
        }

    # -- issuance ------------------------------------------------------------ #

    def issue(self, receipt, billed_to=None):
        """
        Verify what the parties agreed, add the issuer signature, and log it.

        Idempotent by `rid`: re-submitting an already issued receipt returns the
        logged one rather than creating a second entry. A log that can contain the
        same obligation twice is not evidence.

        `billed_to` names who owes Uise the issuance fee. It defaults to the payee,
        which mirrors card networks: the party being paid carries the cost of the
        proof, because it is the party the proof protects.
        """
        envelope.check_receipt_structure(receipt)
        if receipt.get("issuer") != self.did:
            raise envelope.UipError("UIP_DID_INVALID", "receipt names a different issuer")
        if receipt.get("anchor") is not None:
            raise envelope.UipError("UIP_HEADER_MALFORMED",
                                    "anchor must be null at submission")

        issued_at = receipt.get("issued_at")
        if not isinstance(issued_at, int) or isinstance(issued_at, bool):
            raise envelope.UipError("UIP_HEADER_MALFORMED", "issued_at must be an integer")
        if abs(issued_at - _now_ms()) > ISSUANCE_SKEW_MS:
            raise envelope.UipError("UIP_CLOCK_SKEW", "issued_at is outside the window")

        rid = receipt.get("rid")
        if not codec.ulid_is_valid(rid):
            raise envelope.UipError("UIP_HEADER_MALFORMED", "rid is not a valid ULID")

        account = billed_to or receipt["payee"]
        if account not in (receipt["payer"], receipt["payee"]):
            raise envelope.UipError("UIP_DID_INVALID",
                                    "the fee can only be billed to a party of the receipt")

        # Both parties must already have agreed before the issuer certifies.
        envelope.verify_receipt_signatures(receipt, ("payer", "payee"))

        with self._lock:
            existing = self.storage.entry_by_rid(rid)
            if existing is not None:
                logged = existing["receipt"]
                return dict(logged, anchor=self.anchor_for(existing["index"]))

            signed = self.identity.sign_receipt_as(receipt, "issuer")
            envelope.verify_receipt(signed, require_long_term_issuer=True)

            entry = log.receipt_entry(signed)
            index = len(self.tree)
            leaf = log.leaf_hash(entry, self.tree.algorithm)
            try:
                self.storage.append_entry(
                    index, leaf, entry, signed, self.fee, self.fee_unit, account,
                    credit_limit=self.credits.limit_for(account),
                )
            except InsufficientCredit as error:
                raise envelope.UipError("UIP_PAYMENT_REQUIRED", str(error))
            except IntegrityError:
                raise envelope.UipError("UIP_REPLAY", "receipt %s is already logged" % rid)

            # The durable write is the source of truth. The in-memory tree only
            # advances once it has committed, so a failed charge can never leave a
            # tree that disagrees with the evidence it is meant to prove.
            self.tree.append_leaf(leaf)
            issued = dict(signed, anchor=self.anchor_for(index))

        # Published outside the lock: a subscriber must never be able to hold up
        # the next issuance.
        self.events.publish(events_module.RECEIPT_ISSUED, {
            "rid": rid,
            "index": index,
            "payer": receipt["payer"],
            "payee": receipt["payee"],
            "capability": receipt["capability"],
            "amount": receipt["amount"],
            "unit": receipt["unit"],
            "billed_to": account,
        })
        self._warn_if_low(account)
        return issued

    def _warn_if_low(self, account):
        """Warn before service stops, not after."""
        limit = self.credits.limit_for(account)
        if limit is None:
            return                              # unmetered: it cannot run out
        headroom = self.credits.balance(account) + limit
        if headroom < self.fee * self.low_balance_receipts:
            self.events.publish(events_module.CREDIT_LOW, {
                "account": account,
                "balance": str(self.credits.balance(account)),
                "unit": self.fee_unit,
                "remaining_issuances": int(headroom / self.fee) if self.fee else None,
            })

    def revenue(self):
        """What the node has charged, as exact decimals. The business, measured."""
        return self.storage.revenue()

    # -- discovery ----------------------------------------------------------- #

    def register(self, header, body):
        """Record a signed descriptor so other agents can find its capabilities."""
        descriptor = json.loads(body.decode("utf-8"))
        if descriptor.get("agent") != header["from"]:
            raise envelope.UipError("UIP_DID_INVALID",
                                    "descriptor does not match the signer")
        if not descriptor.get("capabilities"):
            raise envelope.UipError("UIP_SCHEMA_INVALID", "descriptor declares no capabilities")
        self.storage.upsert_descriptor(header["from"], descriptor,
                                       dict(header), _now_ms())
        self.events.publish(events_module.AGENT_ANNOUNCED, {
            "agent": header["from"],
            "name": descriptor.get("name"),
            "capabilities": [c["id"] for c in descriptor["capabilities"]],
        })
        return descriptor

    def discover(self, capability_id, limit=MAX_DISCOVERY_RESULTS):
        return self.storage.find_by_capability(
            capability_id, _now_ms(), min(limit, MAX_DISCOVERY_RESULTS)
        )

    def descriptor(self):
        """The node publishes its own price list in the same format as any agent."""
        return {
            "v": envelope.VERSION,
            "agent": self.did,
            "name": self.name,
            "capabilities": [{
                "id": "uise.receipt.issue",
                "description": "Verifies an agreed receipt, signs it as issuer, and "
                               "anchors it in the public transparency log.",
                "input_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema",
                                 "type": "object"},
                "output_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema",
                                  "type": "object"},
                "price": {"amount": str(self.fee), "unit": self.fee_unit, "per": "call"},
            }],
            "endpoints": [{"transport": "https", "url": self.log_url + "/uip/v1"}],
        }

    # -- envelope intake ----------------------------------------------------- #

    def _sign(self, message_type, to, body, content_type, corr=None):
        header = {
            "v": envelope.VERSION,
            "id": codec.ulid_new(_now_ms(), os.urandom(10)),
            "from": self.did,
            "type": message_type,
            "ts": _now_ms(),
            "ttl": 30_000,
            "content_type": content_type,
            "body_hash": envelope.body_hash(body),
        }
        if to is not None:
            header["to"] = to
        if corr is not None:
            header["corr"] = corr
        return self.identity.sign_envelope(header)

    def _error(self, code, message, to=None, corr=None):
        body = codec.canonicalize({"code": code, "message": message})
        return self._sign("error", to, body, ERROR_CONTENT_TYPE, corr=corr), body

    def handle(self, frame, peer=None):
        """Process one wire frame. Returns (http_status, response_frame)."""
        if peer is not None and not self.limiters.peer.check(peer).allowed:
            return 429, transport.encode_wire(
                *self._error("UIP_RATE_LIMITED", "too many requests from this address")
            )

        try:
            header, body = transport.decode_wire(frame)
        except ValueError as error:
            return 400, transport.encode_wire(*self._error("UIP_HEADER_MALFORMED", str(error)))

        sender = header.get("from") if isinstance(header, dict) else None
        correlation = header.get("id") if isinstance(header, dict) else None

        try:
            envelope.verify_envelope(header, body, now_ms=_now_ms(), seen_ids=self.replay)

            # Keyed on the sender only now that its signature has been verified.
            # Keying on an unverified claim would let anyone exhaust somebody
            # else's allowance simply by naming them.
            if not self.limiters.agent.check(header["from"]).allowed:
                raise envelope.UipError("UIP_RATE_LIMITED", "quota exhausted for this agent")

            if header["type"] == "announce":
                descriptor = self.register(header, body)
                payload = {"registered": descriptor["agent"],
                           "capabilities": len(descriptor["capabilities"])}
            elif header["type"] == "receipt":
                payload = self.issue(json.loads(body.decode("utf-8")))
            else:
                raise envelope.UipError(
                    "UIP_HEADER_MALFORMED",
                    "a node accepts `announce` and `receipt` envelopes",
                )
        except envelope.UipError as error:
            return 400, transport.encode_wire(
                *self._error(error.code, str(error), to=sender, corr=correlation)
            )
        except (ValueError, KeyError, TypeError) as error:
            return 400, transport.encode_wire(
                *self._error("UIP_SCHEMA_INVALID", str(error), to=sender, corr=correlation)
            )

        response_body = codec.canonicalize(payload)
        content_type = (RECEIPT_CONTENT_TYPE if header["type"] == "receipt"
                        else JSON_CONTENT_TYPE)
        response = self._sign("response", sender, response_body, content_type,
                              corr=header["id"])
        return 200, transport.encode_wire(response, response_body)

    def serve(self, host="127.0.0.1", port=8443):
        server = ThreadingHTTPServer((host, port), make_handler(self))
        try:
            server.serve_forever()
        finally:
            server.server_close()


def make_handler(node):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _respond(self, status, payload, headers=None):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", transport.CONTENT_TYPE)
            self.send_header("Content-Length", str(len(data)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def do_DELETE(self):
            if not self.path.startswith(api.PREFIX):
                self.send_error(404)
                return
            self._serve_api("DELETE")

        def do_POST(self):
            if self.path.startswith(api.PREFIX):
                self._serve_api("POST")
                return
            if self.path != transport.PATH_ENVELOPE:
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > envelope.MAX_BODY_BYTES:
                self.send_error(413)
                return
            try:
                frame = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self.send_error(400)
                return
            self._respond(*node.handle(frame, peer=self.client_address[0]))

        def _respond_html(self, status, markup):
            data = markup.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            # The console loads nothing from anywhere and may talk only to the
            # node that served it. Declared so a browser enforces it even if a
            # future edit forgets.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self'",
            )
            self.end_headers()
            self.wfile.write(data)

        def _api_request(self, method, parsed, query, body=None):
            return api.Request(
                method, parsed.path, query,
                {name.lower(): value for name, value in self.headers.items()},
                self.client_address[0], body,
            )

        def _read_json_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > envelope.MAX_BODY_BYTES:
                raise ValueError("body too large")
            raw = self.rfile.read(length) if length else b""
            return json.loads(raw) if raw else None

        def _serve_api(self, method):
            parsed = urlparse(self.path)
            try:
                body = self._read_json_body() if method in ("POST", "PUT") else None
            except ValueError:
                self._respond(400, {"error": {"code": api.ERROR_BAD_REQUEST,
                                              "message": "malformed JSON body"}})
                return
            request = self._api_request(method, parsed, parse_qs(parsed.query), body)
            status, payload, headers = api.dispatch(node, request)
            if isinstance(payload, api.Stream):
                self._stream(status, payload, headers)
            else:
                self._respond(status, payload, headers)

        def _stream(self, status, stream, headers):
            """
            Write an open-ended response.

            No Content-Length and no keep-alive: the body has no end, so the
            connection belongs to this stream until one side closes it.
            """
            self.send_response(status)
            self.send_header("Content-Type", stream.content_type)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.close_connection = True
            try:
                for chunk in stream.chunks:
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass                            # the reader left; entirely normal
            finally:
                stream.close()

        def _dashboard_allowed(self, request):
            """
            The console shows revenue, so it is never open to the network.

            Loopback is allowed without a token because the check is against the
            real TCP peer address, which a remote client cannot forge, and because
            an operator on the machine already has the database. Browser login for
            remote access arrives with full credential management.
            """
            return request.is_local or node.keys.verify(request.bearer) is not None

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)

            if parsed.path.startswith(api.PREFIX):
                self._serve_api("GET")
                return

            if parsed.path == dashboard.PATH_DASHBOARD:
                request = self._api_request("GET", parsed, query)
                if not self._dashboard_allowed(request):
                    self._respond(401, {"error": {
                        "code": api.ERROR_UNAUTHORIZED,
                        "message": "the console is available on loopback, or with a bearer token",
                    }})
                    return
                # A fresh short-lived read-only credential, so the page can read
                # the same public API as any other client rather than being given
                # a private back door - or the caller's own long-lived key.
                self._respond_html(
                    200,
                    dashboard.render(dashboard.stats(node),
                                     node.keys.create_session()),
                )
                return

            try:
                payload = self._route(parsed.path, query)
            except (ValueError, KeyError, IndexError) as error:
                self._respond(400, {"code": "UIP_SCHEMA_INVALID", "message": str(error)})
                return
            if payload is None:
                self.send_error(404)
                return
            self._respond(200, payload)

        def _route(self, path, query):
            if path == transport.PATH_DESCRIPTOR:
                header, body = self._announcement()
                return transport.encode_wire(header, body)
            if path == PATH_STH:
                return node.signed_tree_head()
            if path == PATH_DISCOVER:
                capability_id = query["capability"][0]
                return {"capability": capability_id, "agents": node.discover(capability_id)}
            if path == PATH_PROOF:
                entry = node.storage.entry_by_rid(query["rid"][0])
                if entry is None:
                    return None
                return {"rid": entry["rid"], "receipt": entry["receipt"],
                        "anchor": node.anchor_for(entry["index"])}
            if path == PATH_CONSISTENCY:
                return node.consistency_proof(int(query["first"][0]), int(query["second"][0]))
            if path == PATH_ENTRIES:
                start = int(query.get("start", ["0"])[0])
                end = int(query.get("end", [str(start + 50)])[0])
                return {"entries": node.storage.entries(start, min(end, start + 50))}
            return None

        def _announcement(self):
            descriptor = node.descriptor()
            body = codec.canonicalize(descriptor)
            return node._sign("announce", None, body, DESCRIPTOR_CONTENT_TYPE), body

        def log_message(self, fmt, *args):
            pass                                # silence per-request stderr noise

    return Handler


def verify_signed_tree_head(head):
    """
    Check a tree head with no access to the node. An auditor runs this, then
    fetches a consistency proof against a head it saw earlier.
    """
    unsigned = {key: value for key, value in head.items() if key != "sig"}
    suite, public_key = did_module.decode(head["issuer"])
    signature = codec.b64u_decode(head["sig"])
    payload = DOMAIN_SIGNED_TREE_HEAD + codec.canonicalize(unsigned)
    return suite.verify(signature, payload, public_key)
