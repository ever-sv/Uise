"""
Operator console tests.

The console is built as a client of the public API, not on a private back door.
That is worth enforcing: if the console needs something the API cannot provide,
the API is incomplete, and every customer building their own view will hit the
same wall.

The other properties here are about what the page must not do - reach outside the
node, expose a long-lived credential, or show nothing when scripting fails.
"""

import json
import os
import re
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from uip import codec, envelope
from uise import Agent, Node, api, billing, dashboard
from uise.keys import SCOPE_READ, SESSION_TTL_SECONDS
from uise.node import make_handler

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


@pytest.fixture
def node():
    instance = Node(name="test-node", fee="0.0001", environment="test")
    yield instance
    instance.close()


@pytest.fixture
def parties():
    return Agent.generate(name="payer"), Agent.generate(name="payee")


def issue(node, payer, payee, capability="translate.text"):
    base = {
        "v": "uip/1", "rid": codec.ulid_new(_now_ms(), os.urandom(10)),
        "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
        "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
        "payer": payer.did, "payee": payee.did, "capability": capability,
        "amount": "0.0004", "unit": "USD",
        "terms_hash": envelope.terms_hash(CAPABILITY),
        "issued_at": _now_ms(), "issuer": node.did,
        "settlement": None, "anchor": None,
    }
    signed = payer.identity.sign_receipt_as(base, "payer")
    signed = payee.identity.sign_receipt_as(signed, "payee")
    return node.issue(signed)


# --------------------------------------------------------------------------- #
# Console credentials
# --------------------------------------------------------------------------- #

class TestSessionCredentials:
    def test_a_session_reads_but_cannot_write(self, node):
        token = node.keys.create_session()
        key = node.keys.verify(token)
        assert key.scopes == {SCOPE_READ}
        assert not key.allows("write")
        assert not key.allows("admin")

    def test_a_session_is_never_written_down(self, node):
        """It exists for minutes; a restart should end it."""
        node.keys.create_session()
        assert node.storage.api_keys() == []

    def test_a_session_expires(self, node):
        token = node.keys.create_session(ttl_seconds=0)
        assert node.keys.verify(token) is None

    def test_the_default_lifetime_is_short(self):
        """Long enough to watch a dashboard, short enough that a forgotten tab
        is not a standing credential."""
        assert SESSION_TTL_SECONDS <= 3600

    def test_a_session_from_another_environment_is_refused(self, node):
        token = node.keys.create_session()
        live = Node(fee="0.0001", environment="live")
        try:
            assert live.keys.verify(token) is None
        finally:
            live.close()

    def test_a_session_alone_is_enough_to_open_the_api(self, node):
        """
        Otherwise a node with no permanent keys would serve a console that cannot
        load its own data.
        """
        assert not node.keys.any_active
        token = node.keys.create_session()
        assert node.keys.any_active
        status, _, _ = api.dispatch(node, api.Request(
            "GET", api.PREFIX + "/stats", {},
            {"authorization": "Bearer " + token}, "203.0.113.9"))
        assert status == 200


# --------------------------------------------------------------------------- #
# The page
# --------------------------------------------------------------------------- #

class TestPage:
    def test_values_are_correct_before_any_script_runs(self, node, parties):
        """
        Server-rendered first, live second. A console that shows nothing until
        JavaScript succeeds shows nothing when it matters most.
        """
        payer, payee = parties
        for _ in range(3):
            issue(node, payer, payee)
        markup = dashboard.render(dashboard.stats(node))
        assert "0.0003 USD" in markup                 # revenue
        assert 'id="count-receipts"' in markup
        assert ">3<" in markup

    def test_a_page_without_a_session_falls_back_to_refreshing(self, node):
        markup = dashboard.render(dashboard.stats(node))
        assert "http-equiv=\"refresh\"" in markup
        assert "<script" not in markup
        assert "snapshot" in markup

    def test_a_page_with_a_session_streams_instead_of_reloading(self, node):
        markup = dashboard.render(dashboard.stats(node), node.keys.create_session())
        assert "http-equiv=\"refresh\"" not in markup   # reloading would drop the stream
        assert "/api/v1/events" in markup
        assert 'id="uise-seed"' in markup

    def test_bootstrap_data_is_inert_json_not_generated_code(self, node, parties):
        """
        Values embedded into a script body become executable if they escape their
        quotes. A JSON block cannot execute at all.
        """
        payer, payee = parties
        issue(node, payer, payee)
        markup = dashboard.render(dashboard.stats(node), node.keys.create_session())
        block = re.search(
            r'<script type="application/json" id="uise-seed">(.*?)</script>',
            markup, re.S,
        )
        assert block
        seed = json.loads(block.group(1).replace("\\u003c", "<"))
        assert seed["stream"] == "/api/v1/events"
        assert seed["graph"][0]["payer"] == payer.did

    def test_the_seed_cannot_close_its_own_block(self, node):
        node.storage.upsert_descriptor(
            "did:key:z6MkTest", {"name": "</script><script>alert(1)</script>",
                                 "capabilities": [{"id": "x.y"}]}, {}, _now_ms())
        markup = dashboard.render(dashboard.stats(node), node.keys.create_session())
        assert "</script><script>alert(1)" not in markup

    def test_the_page_loads_nothing_from_outside(self, node):
        """A console that phones home leaks who runs a node and what it earns."""
        markup = dashboard.render(dashboard.stats(node), node.keys.create_session())
        for forbidden in ("http://", "https://cdn", "@import", "src=\"http"):
            assert forbidden not in markup

    def test_the_page_still_offers_no_way_to_move_money(self, node, parties):
        payer, payee = parties
        issue(node, payer, payee)
        markup = dashboard.render(dashboard.stats(node),
                                  node.keys.create_session()).lower()
        assert "<form" not in markup
        assert "withdraw" not in markup

    def test_hostile_labels_cannot_inject_markup(self, node, parties):
        payer, payee = parties
        billing.register_account(node.storage, payee.did,
                                 "<script>alert(1)</script>", "manual", None)
        issue(node, payer, payee)
        markup = dashboard.render(dashboard.stats(node))
        assert "<script>alert(1)</script>" not in markup
        assert "&lt;script&gt;" in markup


# --------------------------------------------------------------------------- #
# The ecosystem graph
# --------------------------------------------------------------------------- #

class TestEcosystemGraph:
    def test_edges_come_only_from_real_signed_work(self, node, parties):
        payer, payee = parties
        for _ in range(4):
            issue(node, payer, payee)
        graph = dashboard.stats(node)["graph"]
        assert len(graph) == 1
        assert graph[0] == {"payer": payer.did, "payee": payee.did,
                            "receipts": 4, "unit": "USD", "volume": "0.0016"}

    def test_pairs_accumulate_separately(self, node):
        payer = Agent.generate()
        first, second = Agent.generate(), Agent.generate()
        issue(node, payer, first)
        for _ in range(3):
            issue(node, payer, second)
        graph = {(e["payer"], e["payee"]): e["receipts"]
                 for e in dashboard.stats(node)["graph"]}
        assert graph[(payer.did, first.did)] == 1
        assert graph[(payer.did, second.did)] == 3

    def test_an_empty_network_renders_without_error(self, node):
        markup = dashboard.render(dashboard.stats(node))
        assert "No agent pairs yet." in markup

    def test_the_graph_is_also_a_table(self, node, parties):
        """
        The picture shows shape; the table shows exact numbers, and it works with
        no scripting at all.
        """
        payer, payee = parties
        issue(node, payer, payee)
        markup = dashboard.render(dashboard.stats(node))
        assert payee.did[:26] in markup
        assert "0.0004 USD" in markup


# --------------------------------------------------------------------------- #
# Over real HTTP
# --------------------------------------------------------------------------- #

def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestServedConsole:
    def test_the_console_works_end_to_end_on_the_public_api(self, node, parties):
        """
        The page is served, reads its own token, and that token reaches the same
        endpoints any customer would use. If this fails, the API is incomplete.
        """
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
            with urllib.request.urlopen(base + "/dashboard", timeout=5) as response:
                assert response.status == 200
                policy = response.headers["Content-Security-Policy"]
                markup = response.read().decode("utf-8")

            # The page may talk only to the node that served it, and load nothing.
            assert "default-src 'none'" in policy
            assert "connect-src 'self'" in policy

            seed = json.loads(re.search(
                r'id="uise-seed">(.*?)</script>', markup, re.S
            ).group(1).replace("\\u003c", "<"))

            request = urllib.request.Request(
                base + seed["stream"].replace("/events", "/stats"),
                headers={"Authorization": "Bearer " + seed["token"]},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                assert json.loads(response.read())["totals"]["receipts"] == 1
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def test_the_console_token_cannot_write(self, node):
        """A read-only console cannot be turned into a write tool by inspection."""
        import urllib.error
        import urllib.request

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
            with urllib.request.urlopen(base + "/dashboard", timeout=5) as response:
                markup = response.read().decode("utf-8")
            token = json.loads(re.search(
                r'id="uise-seed">(.*?)</script>', markup, re.S
            ).group(1).replace("\\u003c", "<"))["token"]

            request = urllib.request.Request(
                base + "/api/v1/accounts",
                data=json.dumps({"did": "did:key:z6Mk", "label": "X"}).encode("utf-8"),
                headers={"Authorization": "Bearer " + token,
                         "Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                raise AssertionError("a console session performed a write")
            except urllib.error.HTTPError as error:
                assert error.code == 403
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)
