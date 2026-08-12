"""
Credit tests - the mechanism that makes the network chargeable.

Two properties carry the most weight here. First, a charge and its log entry are
one transaction: a receipt is never issued without being paid for, and never
charged without being issued. Second, the materialized balance always equals the
ledger it derives from - a stored total that can silently drift is how money bugs
survive for years.
"""

import os
import time
from decimal import Decimal

import pytest

from uip import codec, envelope
from uise import Agent, Node, billing, credits, dashboard
from uise.credits import UNLIMITED

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


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


@pytest.fixture
def parties():
    return Agent.generate(name="payer"), Agent.generate(name="payee")


def prepaid_node(**kwargs):
    return Node(log_url="https://log.uise.test", fee="0.0001",
                default_credit_limit="0", **kwargs)


# --------------------------------------------------------------------------- #
# The three business models, one mechanism
# --------------------------------------------------------------------------- #

class TestCreditPolicy:
    def test_launch_phase_meters_without_refusing(self, parties):
        """
        Usage is free but recorded from day one, so the day pricing turns on there
        is already real usage data and no retrofit.
        """
        payer, payee = parties
        node = Node(fee="0.0001", default_credit_limit=UNLIMITED)
        try:
            for _ in range(5):
                issue(node, payer, payee)
            assert node.storage.log_size() == 5
            assert node.credits.balance(payee.did) == Decimal("-0.0005")
        finally:
            node.close()

    def test_prepaid_agent_is_refused_without_funds(self, parties):
        """
        An agent is a public key. There is nobody to invoice, so it pays first or
        it does not get served.
        """
        payer, payee = parties
        node = prepaid_node()
        try:
            with pytest.raises(envelope.UipError) as error:
                issue(node, payer, payee)
            assert error.value.code == "UIP_PAYMENT_REQUIRED"
            assert node.storage.log_size() == 0
        finally:
            node.close()

    def test_prepaid_agent_is_served_after_funding(self, parties):
        payer, payee = parties
        node = prepaid_node()
        try:
            node.credits.deposit(payee.did, "0.0010", reference="bank:TRX-88123")
            for _ in range(10):
                issue(node, payer, payee)
            assert node.storage.log_size() == 10
            assert node.credits.balance(payee.did) == Decimal(0)

            with pytest.raises(envelope.UipError) as error:
                issue(node, payer, payee)                 # balance exhausted
            assert error.value.code == "UIP_PAYMENT_REQUIRED"
        finally:
            node.close()

    def test_organization_runs_on_a_credit_limit(self, parties):
        """A post-paid customer is the same mechanism with room to go negative."""
        payer, payee = parties
        node = prepaid_node()
        try:
            billing.register_account(node.storage, payee.did, "Acme Robotics",
                                     "stripe", "cus_123", credit_limit="0.0005")
            for _ in range(5):
                issue(node, payer, payee)
            assert node.credits.balance(payee.did) == Decimal("-0.0005")

            with pytest.raises(envelope.UipError) as error:
                issue(node, payer, payee)                 # limit reached
            assert error.value.code == "UIP_PAYMENT_REQUIRED"
        finally:
            node.close()

    def test_limit_can_be_granted_after_registration(self, parties):
        payer, payee = parties
        node = prepaid_node()
        try:
            billing.register_account(node.storage, payee.did, "Acme", "manual")
            node.credits.set_limit(payee.did, "1.00")
            issue(node, payer, payee)
            assert node.credits.balance(payee.did) == Decimal("-0.0001")
        finally:
            node.close()

    def test_registering_billing_details_does_not_change_service(self, parties):
        """
        Recording who somebody is and how they pay is administrative. If it also
        silently switched them to prepaid, adding a customer's invoicing details
        would cut off the customer.
        """
        payer, payee = parties
        node = Node(fee="0.0001", default_credit_limit=UNLIMITED)
        try:
            issue(node, payer, payee)
            billing.register_account(node.storage, payee.did, "Acme", "stripe", "cus_1")
            issue(node, payer, payee)                     # must still be served
            assert node.storage.log_size() == 2
            assert node.credits.limit_for(payee.did) is None
        finally:
            node.close()

    def test_limit_cannot_be_set_for_an_unknown_account(self):
        node = prepaid_node()
        try:
            with pytest.raises(ValueError):
                node.credits.set_limit("did:key:z6MkNobody", "1.00")
        finally:
            node.close()


# --------------------------------------------------------------------------- #
# Atomicity
# --------------------------------------------------------------------------- #

class TestAtomicity:
    def test_a_refused_charge_leaves_nothing_behind(self, parties):
        """
        No log entry, no ledger movement, no rollup, and no advance of the Merkle
        tree. A tree that runs ahead of the database disagrees with the evidence it
        exists to prove.
        """
        payer, payee = parties
        node = prepaid_node()
        try:
            root_before = node.signed_tree_head()["root"]
            with pytest.raises(envelope.UipError):
                issue(node, payer, payee)
            assert node.storage.log_size() == 0
            assert len(node.tree) == 0
            assert node.storage.ledger(payee.did, "USD") == []
            assert node.storage.daily_usage() == []
            assert node.signed_tree_head()["root"] == root_before
        finally:
            node.close()

    def test_tree_and_database_stay_in_step(self, parties):
        payer, payee = parties
        node = prepaid_node()
        try:
            node.credits.deposit(payee.did, "0.0003", reference="bank:1")
            for _ in range(3):
                issue(node, payer, payee)
            with pytest.raises(envelope.UipError):
                issue(node, payer, payee)
            assert len(node.tree) == node.storage.log_size() == 3
        finally:
            node.close()

    def test_a_paid_issuance_is_charged_exactly_once(self, parties):
        """Re-submitting an issued receipt returns the logged one and bills nothing."""
        payer, payee = parties
        node = prepaid_node()
        try:
            node.credits.deposit(payee.did, "1.00", reference="bank:1")
            base_rid = codec.ulid_new(_now_ms(), os.urandom(10))

            def submit():
                receipt = {
                    "v": "uip/1", "rid": base_rid,
                    "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
                    "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
                    "payer": payer.did, "payee": payee.did,
                    "capability": "translate.text", "amount": "0.0004", "unit": "USD",
                    "terms_hash": envelope.terms_hash(CAPABILITY),
                    "issued_at": _now_ms(), "issuer": node.did,
                    "settlement": None, "anchor": None,
                }
                signed = payer.identity.sign_receipt_as(receipt, "payer")
                signed = payee.identity.sign_receipt_as(signed, "payee")
                return node.issue(signed)

            submit()
            after_first = node.credits.balance(payee.did)
            submit()
            assert node.credits.balance(payee.did) == after_first
            assert node.storage.log_size() == 1
        finally:
            node.close()


# --------------------------------------------------------------------------- #
# The ledger
# --------------------------------------------------------------------------- #

class TestLedger:
    def test_balance_always_equals_its_ledger(self, parties):
        payer, payee = parties
        node = Node(fee="0.0001")
        try:
            node.credits.deposit(payee.did, "5.00", reference="bank:1")
            for _ in range(20):
                issue(node, payer, payee)
            node.credits.refund(payee.did, "1.00", reference="bank:1-reversal")
            node.credits.adjust(payee.did, "0.25", reference="goodwill credit")

            assert node.credits.audit() == []
            assert node.credits.balance(payee.did) == node.storage.recompute_balance(
                payee.did, "USD"
            )
            assert node.credits.balance(payee.did) == Decimal("4.2480")
        finally:
            node.close()

    def test_every_movement_names_its_cause(self):
        """An unreferenced credit is an unauditable balance."""
        node = Node()
        try:
            for call in (node.credits.deposit, node.credits.refund):
                with pytest.raises(ValueError):
                    call("did:key:z6Mk", "1.00")
            with pytest.raises(ValueError):
                node.credits.adjust("did:key:z6Mk", "1.00")
        finally:
            node.close()

    def test_floats_are_refused_everywhere(self):
        node = Node()
        try:
            with pytest.raises(TypeError):
                node.credits.deposit("did:key:z6Mk", 1.0, reference="x")
            with pytest.raises(TypeError):
                billing.register_account(node.storage, "did:key:z6Mk", "X",
                                         credit_limit=0.0)
        finally:
            node.close()

    def test_non_positive_movements_are_refused(self):
        node = Node()
        try:
            with pytest.raises(ValueError):
                node.credits.deposit("did:key:z6Mk", "0", reference="x")
            with pytest.raises(ValueError):
                node.credits.refund("did:key:z6Mk", "-1", reference="x")
            with pytest.raises(ValueError):
                node.credits.adjust("did:key:z6Mk", "0", reference="x")
        finally:
            node.close()

    def test_statement_reads_back_the_history(self, parties):
        payer, payee = parties
        node = Node()
        try:
            node.credits.deposit(payee.did, "1.00", reference="bank:9")
            issue(node, payer, payee)
            statement = node.credits.statement(payee.did)
            kinds = [entry["kind"] for entry in statement["entries"]]
            assert kinds == [credits.KIND_ISSUANCE, credits.KIND_DEPOSIT]
            assert statement["balance"] == "0.9999"
        finally:
            node.close()

    def test_audit_detects_a_tampered_balance(self, parties):
        """The whole point of keeping the ledger as well as the total."""
        payer, payee = parties
        node = Node()
        try:
            node.credits.deposit(payee.did, "1.00", reference="bank:1")
            node.storage._db.execute(
                "UPDATE balances SET amount = '999.00' WHERE account_id = ?",
                (payee.did,)
            )
            node.storage._db.commit()
            discrepancies = node.credits.audit()
            assert len(discrepancies) == 1
            assert discrepancies[0]["stored"] == "999.00"
            assert discrepancies[0]["recomputed"] == "1.00"
        finally:
            node.close()


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

class TestReporting:
    def test_prepaid_float_is_reported_as_a_liability(self, parties):
        payer, payee = parties
        node = Node()
        try:
            node.credits.deposit(payee.did, "10.00", reference="bank:1")
            issue(node, payer, payee)
            data = dashboard.stats(node)
            assert data["credits"]["float_held"] == {"USD": "9.9999"}
            assert data["credits"]["outstanding"] == {}
            assert data["totals"]["revenue"] == {"USD": "0.0001"}
        finally:
            node.close()

    def test_unfunded_usage_is_reported_as_outstanding(self, parties):
        payer, payee = parties
        node = Node()
        try:
            for _ in range(3):
                issue(node, payer, payee)
            data = dashboard.stats(node)
            assert data["credits"]["outstanding"] == {"USD": "0.0003"}
            assert data["credits"]["float_held"] == {}
        finally:
            node.close()

    def test_dashboard_renders_balances(self, parties):
        payer, payee = parties
        node = Node()
        try:
            billing.register_account(node.storage, payee.did, "Acme Robotics", "manual")
            node.credits.deposit(payee.did, "25.00", reference="bank:1")
            issue(node, payer, payee)
            markup = dashboard.render(dashboard.stats(node))
            assert "Prepaid held" in markup
            assert "24.9999 USD" in markup
            assert "Acme Robotics" in markup
            assert "funded" in markup
        finally:
            node.close()
