"""
Product API tests - `/api/v1`.

Three properties carry the weight. The product surface must stay separate from the
protocol surface, because a standard cannot change once others depend on it and a
product must. The product surface must be closed by default, because it exposes
what the operator earns. And a credential must never do more than it was granted.
"""

import json
import os
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from uip import codec, envelope
from uise import Agent, Node, api, billing
from uise.keys import SCOPE_ADMIN, SCOPE_READ, SCOPE_WRITE
from uise.node import PATH_STH, make_handler
from uise.transport import PATH_DESCRIPTOR, PATH_ENVELOPE

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


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


@pytest.fixture
def node():
    instance = Node(log_url="https://log.uise.test", fee="0.0001", environment="test")
    instance.token = instance.keys.create("tests", [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN])[1]
    yield instance
    instance.close()


@pytest.fixture
def parties():
    return Agent.generate(name="payer"), Agent.generate(name="payee")


def raw(node, path, method="GET", body=None, token=..., peer="203.0.113.9", **query):
    """Returns (status, payload, headers)."""
    if token is ...:
        token = node.token
    headers = {"authorization": "Bearer " + token} if token else {}
    request = api.Request(method, path, {k: [str(v)] for k, v in query.items()},
                          headers, peer, body)
    return api.dispatch(node, request)


def call(node, *args, **kwargs):
    """Returns (status, payload); quota headers are exercised in test_ratelimit."""
    status, payload, _ = raw(node, *args, **kwargs)
    return status, payload


# --------------------------------------------------------------------------- #
# Separation of surfaces
# --------------------------------------------------------------------------- #

class TestSurfaceSeparation:
    def test_business_data_is_not_in_the_protocol_namespace(self):
        """
        A standard cannot change once others implement it. Commercial endpoints
        placed inside /uip/v1 would freeze along with it.
        """
        for path in (PATH_ENVELOPE, PATH_DESCRIPTOR, PATH_STH):
            assert path.startswith("/uip/v1")
        for path in (api.PREFIX + "/stats", api.PREFIX + "/accounts",
                     api.PREFIX + "/keys"):
            assert path.startswith("/api/v1")

    def test_protocol_paths_are_unknown_to_the_product_api(self, node):
        status, payload = call(node, "/uip/v1/stats")
        assert status == 404
        assert payload["error"]["code"] == api.ERROR_NOT_FOUND

    def test_the_console_points_at_the_product_api(self):
        from uise import dashboard
        assert dashboard.PATH_STATS == "/api/v1/stats"


# --------------------------------------------------------------------------- #
# Authentication and scopes
# --------------------------------------------------------------------------- #

class TestAuthentication:
    def test_a_node_with_no_credentials_refuses_to_serve_the_api(self):
        """
        Closed by default. An accidentally public business API is not a smaller
        problem than a deliberately public one.
        """
        bare = Node(fee="0.0001", environment="test")
        try:
            status, payload = call(bare, api.PREFIX + "/stats", token=None)
            assert status == 503
            assert payload["error"]["code"] == api.ERROR_API_DISABLED
        finally:
            bare.close()

    def test_a_missing_or_wrong_token_is_rejected(self, node):
        for token in (None, "", "not-a-token",
                      "uise_test_000000000000_wrongsecretvalue"):
            status, payload = call(node, api.PREFIX + "/stats", token=token)
            assert status == 401
            assert payload["error"]["code"] == api.ERROR_UNAUTHORIZED

    def test_authentication_precedes_routing(self, node):
        """
        Otherwise an anonymous caller maps the whole surface by noting which paths
        answer 404 and which answer 401.
        """
        status, _ = call(node, api.PREFIX + "/no-such-endpoint", token=None)
        assert status == 401

    def test_health_is_open_and_reveals_nothing(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee)
        status, payload = call(node, api.PREFIX + "/health", token=None)
        assert status == 200
        assert payload == {"status": "ok", "protocol": "uip/1", "api": "v1"}

    def test_scopes_do_not_imply_one_another(self, node):
        """
        Implicit inheritance is how a credential quietly acquires powers nobody
        meant to give it.
        """
        _, read_only = node.keys.create("reader", [SCOPE_READ])
        _, admin_only = node.keys.create("keymaster", [SCOPE_ADMIN])

        assert call(node, api.PREFIX + "/stats", token=read_only)[0] == 200
        assert call(node, api.PREFIX + "/keys", token=read_only)[0] == 403
        assert call(node, api.PREFIX + "/keys", token=admin_only)[0] == 200
        assert call(node, api.PREFIX + "/stats", token=admin_only)[0] == 403

    def test_a_write_needs_the_write_scope(self, node):
        _, read_only = node.keys.create("reader", [SCOPE_READ])
        status, payload = call(node, api.PREFIX + "/accounts", method="POST",
                               body={"did": "did:key:z6Mk", "label": "X"},
                               token=read_only)
        assert status == 403
        assert payload["error"]["code"] == api.ERROR_FORBIDDEN

    def test_a_test_key_cannot_authenticate_against_a_live_node(self, node):
        """An environment mix-up must fail closed, not quietly work."""
        live = Node(fee="0.0001", environment="live")
        try:
            live.keys.create("live key", [SCOPE_READ])
            assert call(live, api.PREFIX + "/stats", token=node.token)[0] == 401
        finally:
            live.close()


# --------------------------------------------------------------------------- #
# Credential management
# --------------------------------------------------------------------------- #

class TestCredentialEndpoints:
    def test_create_returns_the_secret_exactly_once(self, node):
        status, payload = call(node, api.PREFIX + "/keys", method="POST",
                               body={"label": "ci", "scopes": [SCOPE_READ]})
        assert status == 201
        token = payload["token"]
        assert token.startswith("uise_test_")
        assert call(node, api.PREFIX + "/stats", token=token)[0] == 200

        # It is nowhere in any subsequent listing.
        _, listed = call(node, api.PREFIX + "/keys")
        assert token not in json.dumps(listed)
        assert all("token" not in key for key in listed["keys"])

    def test_listing_never_exposes_a_secret(self, node):
        call(node, api.PREFIX + "/keys", method="POST", body={"label": "one"})
        _, payload = call(node, api.PREFIX + "/keys")
        assert "digest" not in json.dumps(payload)
        assert {"key_id", "label", "environment", "scopes"} <= set(payload["keys"][0])

    def test_revocation_takes_effect_immediately(self, node):
        _, created = call(node, api.PREFIX + "/keys", method="POST",
                          body={"label": "temporary", "scopes": [SCOPE_READ]})
        token = created["token"]
        assert call(node, api.PREFIX + "/stats", token=token)[0] == 200

        status, revoked = call(node, api.PREFIX + "/keys/" + created["key_id"],
                               method="DELETE")
        assert status == 200 and revoked["revoked_at"] is not None
        assert call(node, api.PREFIX + "/stats", token=token)[0] == 401

    def test_revoking_an_unknown_key_is_a_404(self, node):
        assert call(node, api.PREFIX + "/keys/deadbeef0000", method="DELETE")[0] == 404

    def test_unknown_scopes_are_refused(self, node):
        status, payload = call(node, api.PREFIX + "/keys", method="POST",
                               body={"label": "bad", "scopes": ["superuser"]})
        assert status == 400
        assert payload["error"]["code"] == api.ERROR_BAD_REQUEST


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #

class TestReadEndpoints:
    def test_stats(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee)
        status, payload = call(node, api.PREFIX + "/stats")
        assert status == 200
        assert payload["totals"]["receipts"] == 1
        assert payload["totals"]["revenue"] == {"USD": "0.0001"}

    def test_accounts(self, node, parties):
        payer, payee = parties
        billing.register_account(node.storage, payee.did, "Acme", "stripe", "cus_1")
        _, payload = call(node, api.PREFIX + "/accounts")
        assert [a["label"] for a in payload["accounts"]] == ["Acme"]

        status, payload = call(node, api.PREFIX + "/accounts/" + payee.did)
        assert status == 200 and payload["label"] == "Acme"
        assert call(node, api.PREFIX + "/accounts/did:key:z6MkNobody")[0] == 404

    def test_balance_and_ledger(self, node, parties):
        payer, payee = parties
        node.credits.deposit(payee.did, "5.00", reference="bank:1")
        issue(node, payer, payee)

        _, payload = call(node, api.PREFIX + "/accounts/%s/balance" % payee.did)
        assert payload["balance"] == "4.9999"
        assert payload["credit_limit"] is None      # inherits node policy

        _, payload = call(node, api.PREFIX + "/accounts/%s/ledger" % payee.did)
        assert [e["kind"] for e in payload["entries"]] == ["issuance", "deposit"]

    def test_receipts_use_cursor_pagination(self, node, parties):
        """
        Page numbers point at different rows every time the log grows. A cursor is
        a position in the log and stays correct.
        """
        payer, payee = parties
        for _ in range(7):
            issue(node, payer, payee)

        _, first = call(node, api.PREFIX + "/receipts", limit=3)
        assert len(first["receipts"]) == 3 and first["next_cursor"] == 3

        _, second = call(node, api.PREFIX + "/receipts", after=3, limit=3)
        assert [r["index"] for r in second["receipts"]] == [3, 4, 5]

        _, last = call(node, api.PREFIX + "/receipts", after=6, limit=3)
        assert len(last["receipts"]) == 1 and last["next_cursor"] is None

    def test_page_size_is_capped_and_validated(self, node):
        assert call(node, api.PREFIX + "/receipts", limit=100000)[0] == 200
        assert call(node, api.PREFIX + "/receipts", limit=0)[0] == 400
        assert call(node, api.PREFIX + "/receipts", after="banana")[0] == 400

    def test_single_receipt_carries_its_proof(self, node, parties):
        payer, payee = parties
        issued = issue(node, payer, payee)
        status, payload = call(node, api.PREFIX + "/receipts/" + issued["rid"])
        assert status == 200 and payload["anchor"]["index"] == 0
        assert call(node, api.PREFIX + "/receipts/01K2R7Y3B8QW5ZM1P4K7DXCVGN")[0] == 404

    def test_unknown_method_is_reported_as_such(self, node):
        assert call(node, api.PREFIX + "/stats", method="DELETE")[0] == 405


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #

class TestWriteEndpoints:
    def test_create_account_and_record_a_deposit(self, node, parties):
        _, payee = parties
        status, _ = call(node, api.PREFIX + "/accounts", method="POST",
                         body={"did": payee.did, "label": "Acme",
                               "rail": "stripe", "rail_ref": "cus_1"})
        assert status == 201

        status, payload = call(node, api.PREFIX + "/accounts/%s/deposits" % payee.did,
                               method="POST",
                               body={"amount": "25.00", "reference": "bank:TRX-1"})
        assert status == 201 and payload["balance"] == "25.00"

    def test_a_deposit_must_reference_its_payment(self, node, parties):
        _, payee = parties
        status, payload = call(node, api.PREFIX + "/accounts/%s/deposits" % payee.did,
                               method="POST", body={"amount": "25.00"})
        assert status == 400
        assert payload["error"]["code"] == api.ERROR_BAD_REQUEST

    def test_float_amounts_are_refused_over_the_wire(self, node, parties):
        _, payee = parties
        status, _ = call(node, api.PREFIX + "/accounts/%s/deposits" % payee.did,
                         method="POST",
                         body={"amount": 25.0, "reference": "bank:1"})
        assert status == 400

    def test_setting_a_credit_limit(self, node, parties):
        _, payee = parties
        call(node, api.PREFIX + "/accounts", method="POST",
             body={"did": payee.did, "label": "Acme"})
        status, payload = call(node, api.PREFIX + "/accounts/%s/limit" % payee.did,
                               method="POST", body={"credit_limit": "100.00"})
        assert status == 200 and payload["credit_limit"] == "100.00"

    def test_a_missing_body_is_a_bad_request(self, node):
        assert call(node, api.PREFIX + "/accounts", method="POST")[0] == 400


# --------------------------------------------------------------------------- #
# The console over real HTTP
# --------------------------------------------------------------------------- #

def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestConsoleAccess:
    def test_console_and_api_over_real_http(self, node, parties):
        import urllib.error
        import urllib.request

        payer, payee = parties
        issue(node, payer, payee)
        port = _free_port()
        httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(node))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.02)
        try:
            base = "http://127.0.0.1:%d" % port

            # Loopback reaches the console without a token: the check is against
            # the real TCP peer, which a remote client cannot forge.
            with urllib.request.urlopen(base + "/dashboard", timeout=5) as response:
                assert response.status == 200
                assert b"<!doctype html>" in response.read()[:40]

            # The product API always requires one, even on loopback.
            try:
                urllib.request.urlopen(base + "/api/v1/stats", timeout=5)
                raise AssertionError("the API answered without a token")
            except urllib.error.HTTPError as error:
                assert error.code == 401

            request = urllib.request.Request(
                base + "/api/v1/stats",
                headers={"Authorization": "Bearer " + node.token},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                assert json.loads(response.read())["totals"]["receipts"] == 1

            # A write over real HTTP, with a JSON body.
            request = urllib.request.Request(
                base + "/api/v1/accounts",
                data=json.dumps({"did": payee.did, "label": "Acme"}).encode("utf-8"),
                headers={"Authorization": "Bearer " + node.token,
                         "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 201

            # Protocol endpoints stay open, as a protocol must be.
            with urllib.request.urlopen(base + PATH_STH, timeout=5) as response:
                assert json.loads(response.read())["tree_size"] == 1
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def test_console_refuses_a_non_local_caller_without_a_token(self, node):
        request = api.Request("GET", "/dashboard", {}, {}, "203.0.113.9")
        assert not request.is_local
        assert node.keys.verify(request.bearer) is None
