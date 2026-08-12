"""
Billing - how Uise collects its own fee.

There are two entirely different flows of money in this system, and confusing them
is the mistake that turns a protocol company into an unlicensed bank:

  1. **What Uise charges.** A fee for issuing a receipt. Uise billing its own
     customer for its own service. Ordinary software revenue, no licensing.
  2. **What agents owe each other.** The amount inside the receipt. Uise records
     that obligation and never touches the money. The parties settle on whatever
     rail they already use.

This module implements the first and deliberately has no mechanism for the second.
The moment a node holds funds belonging to someone else, it stops being a data
service and becomes a money transmitter.

**Rails prepare charges; they never execute them.** Every adapter here returns the
request a payment provider expects and stops. Credentials, network calls and
payouts stay entirely on the operator's side, in the provider's own console. No
key, card number or bank detail is ever handled by this library.
"""

import time
from decimal import Decimal

RAIL_STRIPE = "stripe"
RAIL_STABLECOIN = "stablecoin"
RAIL_MANUAL = "manual"


class Invoice(object):
    """Immutable statement of what one account owes for one period."""

    __slots__ = ("account", "label", "rail", "rail_ref", "since_ms", "until_ms",
                 "lines", "unit", "total")

    def __init__(self, account, label, rail, rail_ref, since_ms, until_ms, lines, unit, total):
        self.account = account
        self.label = label
        self.rail = rail
        self.rail_ref = rail_ref
        self.since_ms = since_ms
        self.until_ms = until_ms
        self.lines = lines
        self.unit = unit
        self.total = total

    def as_dict(self):
        return {
            "account": self.account,
            "label": self.label,
            "rail": self.rail,
            "since_ms": self.since_ms,
            "until_ms": self.until_ms,
            "receipts": len(self.lines),
            "unit": self.unit,
            "total": str(self.total),
        }

    def __repr__(self):
        return "<Invoice %s %s %s>" % (self.label, self.total, self.unit)


def build_invoice(storage, account_did, since_ms=None, until_ms=None):
    """
    Total one account's issuance fees for a period.

    Amounts are summed with `Decimal`, never floating point: a rounding error in
    billing is a defect, not a rounding error.
    """
    usage = storage.usage_for(account_did, since_ms, until_ms)
    units = {line["fee_unit"] for line in usage}
    if len(units) > 1:
        raise ValueError("cannot invoice mixed units: %s" % sorted(units))

    total = sum((Decimal(line["fee_amount"]) for line in usage), Decimal(0))
    record = storage.account(account_did) or {}
    return Invoice(
        account=account_did,
        label=record.get("label") or account_did,
        rail=record.get("rail") or RAIL_MANUAL,
        rail_ref=record.get("rail_ref"),
        since_ms=since_ms,
        until_ms=until_ms,
        lines=usage,
        unit=units.pop() if units else "USD",
        total=total,
    )


# --------------------------------------------------------------------------- #
# Rails
# --------------------------------------------------------------------------- #

class Rail(object):
    """
    Base rail. A rail formats a charge request and returns it. It never sends it.

    That boundary is deliberate: executing the charge requires the operator's
    credentials, and those belong in the operator's environment, not in a library
    they did not write.
    """

    name = None

    def prepare(self, invoice):
        raise NotImplementedError

    def _require_reference(self, invoice):
        if not invoice.rail_ref:
            raise ValueError("account %s has no %s reference on file"
                             % (invoice.account, self.name))
        return invoice.rail_ref


class ManualRail(Rail):
    """
    No provider at all: produce a statement and collect it however you like.

    This is the honest default. It works on day one, needs no integration, and
    keeps the node useful for operators who invoice by hand or by bank transfer.
    """

    name = RAIL_MANUAL

    def prepare(self, invoice):
        return {
            "rail": self.name,
            "reference": invoice.rail_ref,
            "statement": invoice.as_dict(),
            "lines": [
                {"rid": line["rid"], "capability": line["capability"],
                 "amount": line["fee_amount"], "unit": line["fee_unit"],
                 "issued_at": line["issued_at"]}
                for line in invoice.lines
            ],
        }


class StripeRail(Rail):
    """
    Card, debit and bank transfer via Stripe. Money lands in the operator's own
    bank account through Stripe's payouts.

    `prepare` returns the parameters for a Stripe invoice item. The operator's own
    code performs the API call with the operator's own secret key:

        params = StripeRail().prepare(invoice)
        stripe.InvoiceItem.create(**params["invoice_item"])   # operator's key

    Stripe expects integer minor units, so the decimal total is scaled here and
    checked for exactness. A fee that cannot be expressed in whole cents is
    accumulated rather than rounded - silently rounding somebody's bill is a bug
    that compounds.
    """

    name = RAIL_STRIPE

    MINOR_UNITS = {"USD": 2, "EUR": 2, "GBP": 2, "JPY": 0}

    def prepare(self, invoice):
        customer = self._require_reference(invoice)
        exponent = self.MINOR_UNITS.get(invoice.unit)
        if exponent is None:
            raise ValueError("unknown minor-unit scale for %s" % invoice.unit)

        scaled = invoice.total * (10 ** exponent)
        if scaled != scaled.to_integral_value():
            raise ValueError(
                "%s %s cannot be billed exactly in %s minor units; accumulate it "
                "into the next period instead of rounding"
                % (invoice.total, invoice.unit, invoice.unit)
            )
        return {
            "rail": self.name,
            "invoice_item": {
                "customer": customer,
                "amount": int(scaled),
                "currency": invoice.unit.lower(),
                "description": "Uise receipt issuance: %d receipts" % len(invoice.lines),
            },
            "statement": invoice.as_dict(),
        }


class StablecoinRail(Rail):
    """
    Stablecoin settlement for crypto-native operators and sub-cent amounts.

    `prepare` returns a payment request: where to pay, how much, and a memo that
    binds the payment to this exact invoice. It performs no transfer and holds no
    key. The operator watches the address and reconciles.
    """

    name = RAIL_STABLECOIN

    def __init__(self, address, chain="base", token="USDC", decimals=6):
        self.address = address
        self.chain = chain
        self.token = token
        self.decimals = decimals

    def prepare(self, invoice):
        scaled = invoice.total * (10 ** self.decimals)
        if scaled != scaled.to_integral_value():
            raise ValueError("%s exceeds the %d decimals of %s"
                             % (invoice.total, self.decimals, self.token))
        return {
            "rail": self.name,
            "payment_request": {
                "chain": self.chain,
                "token": self.token,
                "to": self.address,
                "amount": str(invoice.total),
                "amount_base_units": int(scaled),
                "memo": "uise:%s:%s" % (invoice.account, invoice.until_ms or "open"),
            },
            "statement": invoice.as_dict(),
        }


RAILS = {
    RAIL_MANUAL: ManualRail,
    RAIL_STRIPE: StripeRail,
    RAIL_STABLECOIN: StablecoinRail,
}


def register_account(storage, did, label, rail=RAIL_MANUAL, rail_ref=None,
                     credit_limit=None):
    """
    Record who a paying account is and how they settle with Uise.

    `credit_limit` is how far below zero the balance may go. `None` inherits the
    node's policy - registering billing details is administrative and must not by
    itself decide whether an account is served. `"0"` is strictly prepaid, the only
    model that works for an agent with no legal identity to invoice. A limit above
    zero grants post-paid terms, and the negative balance becomes the invoice.
    """
    if rail not in RAILS:
        raise ValueError("unknown rail %r; known rails are %s" % (rail, sorted(RAILS)))
    if credit_limit is not None and not isinstance(credit_limit, str):
        raise TypeError("credit_limit must be a decimal string, never a float")
    storage.upsert_account(did, label, rail, rail_ref, int(time.time() * 1000),
                           credit_limit)
    return storage.account(did)
