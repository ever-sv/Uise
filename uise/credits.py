"""
Prepaid credit - how a node gets paid by counterparties it cannot invoice.

An agent is a `did:key`. It has no country, no legal entity, no tax number and no
card. **You cannot send an invoice to a public key.** Post-paid billing therefore
only works for organizations under contract; for agents themselves it does not
work at all.

So a node meters every issuance against an account balance:

  * **Agents** fund a balance in advance. The node debits it per receipt and
    refuses to issue when the balance would go past its limit. No collection risk,
    no chargebacks, and it works for a counterparty with no legal identity.
  * **Organizations** are the same mechanism with a credit limit above zero: they
    are allowed to go negative, and the negative balance is the invoice.
  * **The launch phase** is the same mechanism with no limit at all: usage is
    metered from day one and simply accrues, so the day pricing turns on there is
    already a year of honest usage data.

One mechanism, three business models, and metering that never has to be retrofitted.

**A deposit records that money arrived; it never receives money.** The node has no
payment credentials and no way to move funds. The operator confirms a bank
transfer, an on-chain payment or a Stripe charge in the provider's own console,
and then records it here with that provider's reference.
"""

import time
from decimal import Decimal

from .storage import InsufficientCredit

KIND_DEPOSIT = "deposit"
KIND_ISSUANCE = "issuance"
KIND_REFUND = "refund"
KIND_ADJUSTMENT = "adjustment"

UNLIMITED = None


def _now_ms():
    return int(time.time() * 1000)


def _decimal(value, field):
    """Accept only exact decimal input. A float here is a rounding bug waiting."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, str):
        return Decimal(value)
    raise TypeError("%s must be a decimal string, never a float" % field)


class Credits(object):
    """
    Account balances for one node.

    `default_credit_limit` applies to accounts with no record of their own.
    `None` means metered but unenforced - the launch phase. `"0"` means strictly
    prepaid: no balance, no service.
    """

    def __init__(self, storage, default_credit_limit=UNLIMITED, unit="USD"):
        self.storage = storage
        self.unit = unit
        self.default_credit_limit = (
            None if default_credit_limit is UNLIMITED
            else _decimal(default_credit_limit, "default_credit_limit")
        )

    # -- policy -------------------------------------------------------------- #

    def limit_for(self, did):
        """
        How far below zero this account may go. None means unenforced.

        An account with no limit of its own inherits the node's policy. Recording
        somebody's billing details is administrative, and must never by itself
        decide whether they get served.
        """
        account = self.storage.account(did)
        if account is None or account["credit_limit"] is None:
            return self.default_credit_limit
        return _decimal(account["credit_limit"], "credit_limit")

    def set_limit(self, did, limit):
        """
        Grant an account post-paid terms. A limit above zero means the node keeps
        serving into a negative balance, and that negative balance is the invoice.
        """
        account = self.storage.account(did)
        if account is None:
            raise ValueError("no account on file for %s; register it first" % did)
        self.storage.upsert_account(
            did, account["label"], account["rail"], account["rail_ref"],
            account["created_at"], str(_decimal(limit, "limit")),
        )
        return self.limit_for(did)

    # -- movements ----------------------------------------------------------- #

    def deposit(self, did, amount, unit=None, reference=None):
        """
        Record funds that have already arrived elsewhere.

        `reference` is required and identifies the real-world payment - a bank
        transfer id, a transaction hash, a Stripe payment intent. Crediting an
        account without saying which payment it came from is how balances become
        unauditable.
        """
        value = _decimal(amount, "amount")
        if value <= 0:
            raise ValueError("a deposit must be positive")
        if not reference:
            raise ValueError("a deposit must reference the payment it came from")
        return self.storage.apply_credit(
            did, unit or self.unit, value, KIND_DEPOSIT, reference, _now_ms()
        )

    def refund(self, did, amount, unit=None, reference=None):
        """Record money returned to the customer, reducing their balance."""
        value = _decimal(amount, "amount")
        if value <= 0:
            raise ValueError("a refund must be positive")
        if not reference:
            raise ValueError("a refund must reference the payment it reverses")
        return self.storage.apply_credit(
            did, unit or self.unit, -value, KIND_REFUND, reference, _now_ms()
        )

    def adjust(self, did, delta, unit=None, reference=None):
        """
        A deliberate correction, in either direction.

        Corrections are ledger entries like any other, never edits: the record of
        what went wrong is part of the record.
        """
        value = _decimal(delta, "delta")
        if value == 0:
            raise ValueError("an adjustment must move something")
        if not reference:
            raise ValueError("an adjustment must say why")
        return self.storage.apply_credit(
            did, unit or self.unit, value, KIND_ADJUSTMENT, reference, _now_ms()
        )

    # -- reading ------------------------------------------------------------- #

    def balance(self, did, unit=None):
        return self.storage.balance(did, unit or self.unit)

    def statement(self, did, unit=None, limit=100):
        unit = unit or self.unit
        return {
            "account": did,
            "unit": unit,
            "balance": str(self.balance(did, unit)),
            "limit": (None if self.limit_for(did) is None else str(self.limit_for(did))),
            "entries": self.storage.ledger(did, unit, limit),
        }

    def audit(self):
        """
        Recompute every balance from its ledger and report any disagreement.

        The materialized balance exists for speed; this proves it still equals the
        ledger it came from. A stored total that can drift from its ledger is how
        money bugs survive for years.
        """
        discrepancies = []
        for row in self.storage.balances():
            stored = Decimal(row["amount"])
            recomputed = self.storage.recompute_balance(row["did"], row["unit"])
            if stored != recomputed:
                discrepancies.append({
                    "account": row["did"],
                    "unit": row["unit"],
                    "stored": str(stored),
                    "recomputed": str(recomputed),
                })
        return discrepancies


__all__ = ["Credits", "InsufficientCredit", "UNLIMITED",
           "KIND_DEPOSIT", "KIND_ISSUANCE", "KIND_REFUND", "KIND_ADJUSTMENT"]
