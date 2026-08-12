"""
Organization tests - one balance, many agents.

The properties that carry weight are about consent and about money never moving
on its own. Neither side may enrol the other unilaterally, a stale attestation
must not resurrect a membership somebody ended, and leaving must never quietly
spend or discard a balance.
"""

import os
import time
from decimal import Decimal

import pytest

from uip import codec, envelope
from uise import Agent, Node, api, billing, organizations
from uise.keys import SCOPE_ADMIN, SCOPE_READ, SCOPE_WRITE
from uise.organizations import MembershipRefused

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


@pytest.fixture
def node():
    instance = Node(fee="0.0001", environment="test", default_credit_limit="0")
    instance.token = instance.keys.create("tests", [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN])[1]
    yield instance
    instance.close()


@pytest.fixture
def parties():
    return Agent.generate(name="payer"), Agent.generate(name="payee")


def issue(node, payer, payee):
    base = {
        "v": "uip/1", "rid": codec.ulid_new(_now_ms(), os.urandom(10)),
        "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
        "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
        "payer": payer.did, "payee": payee.did, "capability": "translate.text",
        "amount": "0.0004", "unit": "USD",
        "terms_hash": envelope.terms_hash(CAPABILITY),
        "issued_at": _now_ms(), "issuer": node.did,
        "settlement": None, "anchor": None,
    }
    signed = payer.identity.sign_receipt_as(base, "payer")
    signed = payee.identity.sign_receipt_as(signed, "payee")
    return node.issue(signed)


def call(node, path, method="GET", body=None, token=...):
    if token is ...:
        token = node.token
    headers = {"authorization": "Bearer " + token} if token else {}
    status, payload, _ = api.dispatch(
        node, api.Request(method, path, {}, headers, "203.0.113.9", body)
    )
    return status, payload


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #

class TestOrganizationAccounts:
    def test_an_agent_with_no_organization_bills_to_itself(self, node, parties):
        """A solo agent is an organization of one; the code path is identical."""
        _, payee = parties
        assert node.organizations.billing_account(payee.did) == payee.did

    def test_creating_one_gives_it_a_distinguishable_id(self, node):
        record = node.organizations.create("Acme Robotics")
        assert record["account_id"].startswith("org_")
        assert record["kind"] == "organization"
        assert organizations.is_organization(record["account_id"])
        assert not organizations.is_organization("did:key:z6Mk")

    def test_it_starts_empty(self, node):
        record = node.organizations.create("Acme")
        assert node.organizations.members(record["account_id"]) == []
        assert node.credits.balance(record["account_id"]) == Decimal(0)

    def test_a_label_is_required(self, node):
        with pytest.raises(ValueError):
            node.organizations.create("")

    def test_float_credit_limits_are_refused(self, node):
        with pytest.raises(TypeError):
            node.organizations.create("Acme", credit_limit=100.0)

    def test_an_agent_account_is_not_an_organization(self, node, parties):
        _, payee = parties
        billing.register_account(node.storage, payee.did, "Solo", "manual")
        assert node.organizations.get(payee.did) is None


# --------------------------------------------------------------------------- #
# Consent
# --------------------------------------------------------------------------- #

class TestMembershipConsent:
    def test_an_agent_must_sign_to_join(self, node, parties):
        _, payee = parties
        account = node.organizations.create("Acme")["account_id"]
        membership = node.organizations.add_member(account, payee.identity.join(account))
        assert membership["account_id"] == account
        assert node.organizations.billing_account(payee.did) == account

    def test_an_organization_cannot_enrol_an_agent_by_assertion(self, node, parties):
        """
        Otherwise anyone could attach somebody else's agent - and, with a limit of
        zero, cut off its service.
        """
        _, payee = parties
        account = node.organizations.create("Acme")["account_id"]
        with pytest.raises(MembershipRefused):
            node.organizations.add_member(account, {
                "agent": payee.did, "account": account,
                "ts": _now_ms(), "sig": "A" * 86,
            })
        assert node.organizations.billing_account(payee.did) == payee.did

    def test_an_attestation_for_one_organization_cannot_be_used_for_another(self, node,
                                                                            parties):
        _, payee = parties
        first = node.organizations.create("Acme")["account_id"]
        second = node.organizations.create("Other")["account_id"]
        attestation = payee.identity.join(first)
        with pytest.raises(MembershipRefused):
            node.organizations.add_member(second, attestation)

    def test_another_agents_signature_does_not_count(self, node, parties):
        payer, payee = parties
        account = node.organizations.create("Acme")["account_id"]
        forged = payer.identity.join(account)
        forged["agent"] = payee.did              # claim, without the signature
        with pytest.raises(MembershipRefused):
            node.organizations.add_member(account, forged)

    def test_a_stale_attestation_cannot_re_enrol_a_departed_agent(self, node, parties):
        """An attestation is a statement about now, not a standing permission."""
        _, payee = parties
        account = node.organizations.create("Acme")["account_id"]
        old = payee.identity.join(account)
        old["ts"] = _now_ms() - 3_600_000
        old["sig"] = codec.b64u_encode(payee.identity.sign(
            organizations.attestation_input(account, payee.did, old["ts"])
        ))
        with pytest.raises(MembershipRefused):
            node.organizations.add_member(account, old)

    def test_a_malformed_attestation_is_refused(self, node):
        account = node.organizations.create("Acme")["account_id"]
        for bad in (None, {}, {"agent": "x"}, {"agent": "did:key:zBad", "account": account,
                                               "ts": _now_ms(), "sig": "!!"}):
            with pytest.raises(MembershipRefused):
                node.organizations.add_member(account, bad)

    def test_joining_an_unknown_organization_fails(self, node, parties):
        _, payee = parties
        with pytest.raises(ValueError):
            node.organizations.add_member("org_deadbeef0000",
                                          payee.identity.join("org_deadbeef0000"))


# --------------------------------------------------------------------------- #
# Billing through an organization
# --------------------------------------------------------------------------- #

class TestSharedBilling:
    def test_many_agents_draw_on_one_balance(self, node):
        """The whole point: fund once, not once per agent."""
        payer = Agent.generate()
        account = node.organizations.create("Acme", credit_limit="0")["account_id"]
        fleet = [Agent.generate() for _ in range(5)]
        for agent in fleet:
            node.organizations.add_member(account, agent.identity.join(account))

        node.credits.deposit(account, "0.0010", reference="bank:1")
        for agent in fleet:
            issue(node, payer, agent)

        assert node.credits.balance(account) == Decimal("0.0005")
        for agent in fleet:
            assert node.credits.balance(agent.did) == Decimal(0)

    def test_the_organization_limit_governs_every_member(self, node):
        payer = Agent.generate()
        account = node.organizations.create("Acme", credit_limit="0")["account_id"]
        first, second = Agent.generate(), Agent.generate()
        for agent in (first, second):
            node.organizations.add_member(account, agent.identity.join(account))

        node.credits.deposit(account, "0.0001", reference="bank:1")
        issue(node, payer, first)                # spends the last of it
        with pytest.raises(envelope.UipError) as error:
            issue(node, payer, second)           # a different agent, same wall
        assert error.value.code == "UIP_PAYMENT_REQUIRED"

    def test_a_deposit_for_a_member_reaches_the_organization(self, node, parties):
        """
        Otherwise money sent on behalf of an agent lands in a dormant balance
        nobody spends.
        """
        _, payee = parties
        account = node.organizations.create("Acme")["account_id"]
        node.organizations.add_member(account, payee.identity.join(account))

        node.deposit(payee.did, "10.00", reference="bank:1")
        assert node.credits.balance(account) == Decimal("10.00")
        assert node.credits.balance(payee.did) == Decimal(0)

    def test_one_ledger_and_one_invoice_for_the_whole_fleet(self, node):
        payer = Agent.generate()
        account = node.organizations.create("Acme", credit_limit="1.00")["account_id"]
        fleet = [Agent.generate() for _ in range(3)]
        for agent in fleet:
            node.organizations.add_member(account, agent.identity.join(account))
        for agent in fleet:
            issue(node, payer, agent)

        invoice = billing.build_invoice(node.storage, account)
        assert invoice.total == Decimal("0.0003")
        assert len(invoice.lines) == 3

    def test_leaving_restores_the_agents_own_balance_untouched(self, node, parties):
        """Money is never moved implicitly, in either direction."""
        payer, payee = parties
        node.credits.deposit(payee.did, "0.0005", reference="own funds")
        account = node.organizations.create("Acme")["account_id"]
        node.organizations.add_member(account, payee.identity.join(account))
        node.credits.deposit(account, "0.0002", reference="bank:1")

        issue(node, payer, payee)                # drawn from the organization
        assert node.credits.balance(account) == Decimal("0.0001")
        assert node.credits.balance(payee.did) == Decimal("0.0005")

        assert node.organizations.remove_member(payee.did)
        assert node.organizations.billing_account(payee.did) == payee.did
        issue(node, payer, payee)                # now drawn from its own funds
        assert node.credits.balance(payee.did) == Decimal("0.0004")
        assert node.credits.balance(account) == Decimal("0.0001")

    def test_removing_an_agent_that_never_joined_reports_it(self, node, parties):
        _, payee = parties
        assert node.organizations.remove_member(payee.did) is False

    def test_setting_a_limit_does_not_turn_an_organization_into_an_agent(self, node):
        account = node.organizations.create("Acme")["account_id"]
        node.credits.set_limit(account, "50.00")
        assert node.organizations.get(account) is not None
        assert node.storage.account(account)["kind"] == "organization"


# --------------------------------------------------------------------------- #
# Over the API
# --------------------------------------------------------------------------- #

class TestOrganizationEndpoints:
    def test_the_full_flow(self, node, parties):
        payer, payee = parties

        status, created = call(node, api.PREFIX + "/organizations", "POST",
                               {"label": "Acme Robotics", "rail": "stripe",
                                "rail_ref": "cus_1", "credit_limit": "50.00"})
        assert status == 201
        account = created["account_id"]

        status, membership = call(
            node, api.PREFIX + "/organizations/%s/members" % account, "POST",
            payee.identity.join(account),
        )
        assert status == 201 and membership["account_id"] == account

        status, listed = call(node, api.PREFIX + "/organizations/%s/members" % account)
        assert [m["did"] for m in listed["members"]] == [payee.did]

        issue(node, payer, payee)

        # Asking about the agent returns the account that governs it.
        status, balance = call(node, api.PREFIX + "/accounts/%s/balance" % payee.did)
        assert balance["account"] == account
        assert balance["balance"] == "-0.0001"

        status, removed = call(
            node, api.PREFIX + "/organizations/members/%s" % payee.did, "DELETE")
        assert status == 200 and removed["removed"] is True

    def test_an_unsigned_membership_is_refused_over_the_api(self, node, parties):
        _, payee = parties
        _, created = call(node, api.PREFIX + "/organizations", "POST", {"label": "Acme"})
        status, payload = call(
            node, api.PREFIX + "/organizations/%s/members" % created["account_id"],
            "POST", {"agent": payee.did, "account": created["account_id"],
                     "ts": _now_ms(), "sig": "A" * 86},
        )
        assert status == 400
        assert payload["error"]["code"] == api.ERROR_BAD_REQUEST

    def test_creating_one_needs_the_write_scope(self, node):
        _, read_only = node.keys.create("reader", [SCOPE_READ])
        status, _ = call(node, api.PREFIX + "/organizations", "POST",
                         {"label": "Acme"}, token=read_only)
        assert status == 403

    def test_unknown_organizations_are_404(self, node):
        assert call(node, api.PREFIX + "/organizations/org_000000000000")[0] == 404
        assert call(node, api.PREFIX + "/organizations/org_000000000000/members")[0] == 404

    def test_an_agent_account_is_not_reachable_as_an_organization(self, node, parties):
        _, payee = parties
        billing.register_account(node.storage, payee.did, "Solo", "manual")
        assert call(node, api.PREFIX + "/organizations/" + payee.did)[0] == 404
