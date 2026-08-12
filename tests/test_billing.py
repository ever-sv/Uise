"""
Billing and dashboard tests.

The load-bearing assertions here are about what the software refuses to do. Money
arithmetic must be exact or not happen at all, and no code path may hold, move or
transmit funds - that boundary is what keeps a node a data service rather than an
unlicensed money transmitter.
"""

import json
import os
import time
from decimal import Decimal

import pytest

from uip import codec, envelope
from uise import Agent, Node, billing, dashboard
from uise.node import make_handler  # noqa: F401  (imported to keep the route surface honest)

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


@pytest.fixture
def node():
    instance = Node(log_url="https://log.uise.test", fee="0.0001")
    yield instance
    instance.close()


@pytest.fixture
def parties():
    return Agent.generate(name="payer"), Agent.generate(name="payee")


def issue(node, payer, payee, amount="0.0004", billed_to=None):
    base = {
        "v": "uip/1",
        "rid": codec.ulid_new(_now_ms(), os.urandom(10)),
        "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
        "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
        "payer": payer.did,
        "payee": payee.did,
        "capability": "translate.text",
        "amount": amount,
        "unit": "USD",
        "terms_hash": envelope.terms_hash(CAPABILITY),
        "issued_at": _now_ms(),
        "issuer": node.did,
        "settlement": None,
        "anchor": None,
    }
    signed = payer.identity.sign_receipt_as(base, "payer")
    signed = payee.identity.sign_receipt_as(signed, "payee")
    return node.issue(signed, billed_to=billed_to)


# --------------------------------------------------------------------------- #
# Metering
# --------------------------------------------------------------------------- #

class TestMetering:
    def test_the_payee_is_billed_by_default(self):
        """
        Card networks charge the party being paid. The proof protects the payee,
        so the payee carries its cost.
        """
        node = Node(fee="0.0001")
        payer, payee = Agent.generate(), Agent.generate()
        try:
            issue(node, payer, payee)
            assert len(node.storage.usage_for(payee.did)) == 1
            assert node.storage.usage_for(payer.did) == []
        finally:
            node.close()

    def test_the_fee_can_be_billed_to_the_payer_instead(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee, billed_to=payer.did)
        assert len(node.storage.usage_for(payer.did)) == 1

    def test_the_fee_cannot_be_billed_to_a_stranger(self, node, parties):
        payer, payee = parties
        with pytest.raises(envelope.UipError) as error:
            issue(node, payer, payee, billed_to=Agent.generate().did)
        assert error.value.code == "UIP_DID_INVALID"

    def test_revenue_and_volume_are_tracked_separately(self, node, parties):
        """
        Two different flows of money. Conflating them is how a protocol company
        turns into an unlicensed bank.
        """
        payer, payee = parties
        for _ in range(5):
            issue(node, payer, payee, amount="1.50")
        assert node.storage.revenue() == {"USD": "0.0005"}
        assert node.storage.transacted_volume() == {"USD": "7.50"}

    def test_sub_cent_amounts_keep_full_precision(self, node, parties):
        payer, payee = parties
        for _ in range(3):
            issue(node, payer, payee, amount="0.000001")
        assert node.storage.transacted_volume() == {"USD": "0.000003"}

    def test_counts_distinguish_transacting_from_registered_agents(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee)
        assert node.storage.active_agents() == 2
        assert node.storage.registered_agents() == 0      # neither announced

    def test_daily_rollups_accumulate(self, node, parties):
        payer, payee = parties
        for _ in range(4):
            issue(node, payer, payee)
        daily = node.storage.daily_usage()
        assert len(daily) == 1
        assert daily[0]["receipts"] == 4
        assert daily[0]["fee_total"] == "0.0004"


# --------------------------------------------------------------------------- #
# Invoicing
# --------------------------------------------------------------------------- #

class TestInvoicing:
    def test_invoice_totals_are_exact_decimals(self, node, parties):
        payer, payee = parties
        for _ in range(7):
            issue(node, payer, payee)
        invoice = billing.build_invoice(node.storage, payee.did)
        assert invoice.total == Decimal("0.0007")
        assert len(invoice.lines) == 7
        assert invoice.unit == "USD"

    def test_invoice_respects_the_period(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee)
        future = billing.build_invoice(node.storage, payee.did, since_ms=_now_ms() + 60_000)
        assert future.total == Decimal(0)
        assert future.lines == []

    def test_manual_rail_is_the_default_and_needs_no_provider(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee)
        invoice = billing.build_invoice(node.storage, payee.did)
        prepared = billing.ManualRail().prepare(invoice)
        assert prepared["rail"] == "manual"
        assert prepared["statement"]["receipts"] == 1

    def test_stripe_rail_scales_to_exact_minor_units(self, node, parties):
        payer, payee = parties
        billing.register_account(node.storage, payee.did, "Acme", "stripe", "cus_123")
        for _ in range(100):                              # 100 x 0.0001 = 0.01 USD
            issue(node, payer, payee)
        invoice = billing.build_invoice(node.storage, payee.did)
        prepared = billing.StripeRail().prepare(invoice)
        assert prepared["invoice_item"] == {
            "customer": "cus_123",
            "amount": 1,                                  # one cent, exactly
            "currency": "usd",
            "description": "Uise receipt issuance: 100 receipts",
        }

    def test_stripe_rail_refuses_to_round_a_fraction_of_a_cent(self, node, parties):
        """Silently rounding somebody's bill is a defect that compounds."""
        payer, payee = parties
        billing.register_account(node.storage, payee.did, "Acme", "stripe", "cus_123")
        issue(node, payer, payee)                         # 0.0001 USD
        invoice = billing.build_invoice(node.storage, payee.did)
        with pytest.raises(ValueError) as error:
            billing.StripeRail().prepare(invoice)
        assert "accumulate" in str(error.value)

    def test_a_rail_without_a_reference_is_refused(self, node, parties):
        payer, payee = parties
        billing.register_account(node.storage, payee.did, "Acme", "stripe", None)
        issue(node, payer, payee)
        with pytest.raises(ValueError):
            billing.StripeRail().prepare(billing.build_invoice(node.storage, payee.did))

    def test_stablecoin_rail_produces_a_payment_request_not_a_transfer(self, node, parties):
        payer, payee = parties
        billing.register_account(node.storage, payee.did, "Acme", "stablecoin", None)
        issue(node, payer, payee)
        invoice = billing.build_invoice(node.storage, payee.did)
        prepared = billing.StablecoinRail("0xabc", chain="base").prepare(invoice)
        request = prepared["payment_request"]
        assert request["to"] == "0xabc"
        assert request["amount"] == "0.0001"
        assert request["amount_base_units"] == 100        # USDC has 6 decimals
        assert request["memo"].startswith("uise:")

    def test_no_rail_can_execute_anything(self):
        """
        Rails format requests and stop. Nothing here sends, transfers, or touches a
        credential - executing a charge is the operator's own code, with the
        operator's own keys.
        """
        for rail in (billing.ManualRail, billing.StripeRail, billing.StablecoinRail):
            methods = {name for name in dir(rail) if not name.startswith("_")}
            assert methods <= {"name", "prepare", "MINOR_UNITS"}

    def test_unknown_rail_is_refused_at_registration(self, node):
        with pytest.raises(ValueError):
            billing.register_account(node.storage, "did:key:z6Mk", "X", "paypal", None)


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

class TestDashboard:
    def test_stats_are_json_serializable(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee)
        data = dashboard.stats(node)
        json.dumps(data)                                  # must not raise
        assert data["totals"]["receipts"] == 1
        assert data["totals"]["revenue"] == {"USD": "0.0001"}
        assert data["issuer"]["long_term_evidence"] is True

    def test_page_renders_with_no_data(self, node):
        markup = dashboard.render(dashboard.stats(node))
        assert "<!doctype html>" in markup
        assert "No receipts issued yet." in markup

    def test_page_shows_revenue_volume_and_take_rate(self, node, parties):
        payer, payee = parties
        for _ in range(10):
            issue(node, payer, payee, amount="1.00")
        markup = dashboard.render(dashboard.stats(node))
        assert "0.0010 USD" in markup                     # revenue
        assert "10.00 USD" in markup                      # volume
        assert "0.010%" in markup                         # take rate

    def test_page_loads_nothing_from_outside(self):
        """A dashboard that phones home leaks who runs a node and what it earns."""
        node = Node(fee="0.0001")
        try:
            markup = dashboard.render(dashboard.stats(node))
        finally:
            node.close()
        for forbidden in ("http://", "src=", "<script", "@import", "cdn"):
            assert forbidden not in markup

    def test_page_offers_no_way_to_move_money(self, node, parties):
        """
        Deliberate. A withdrawal flow means custodying funds, which is the one
        thing the architecture exists to avoid.
        """
        payer, payee = parties
        issue(node, payer, payee)
        markup = dashboard.render(dashboard.stats(node)).lower()
        assert "<form" not in markup
        assert "withdraw" not in markup
        assert "never holds anyone else's money" in markup

    def test_hostile_names_cannot_inject_markup(self, node, parties):
        payer, payee = parties
        billing.register_account(node.storage, payee.did,
                                 "<script>alert(1)</script>", "manual", None)
        issue(node, payer, payee)
        markup = dashboard.render(dashboard.stats(node))
        assert "<script>alert(1)</script>" not in markup
        assert "&lt;script&gt;" in markup
