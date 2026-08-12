"""
Live stream tests.

The governing property is that watching must never affect what is being watched.
Everything else here follows from it: bounded queues, dropping the oldest rather
than blocking, and telling the reader how many events it missed instead of quietly
showing an incomplete view as though it were complete.
"""

import json
import os
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from uip import codec, envelope
from uise import Agent, Node, api, events
from uise.credits import UNLIMITED
from uise.keys import SCOPE_READ, SCOPE_WRITE
from uise.node import make_handler
from uise.transport import encode_wire

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


@pytest.fixture
def node():
    instance = Node(fee="0.0001", environment="test")
    instance.token = instance.keys.create("tests", [SCOPE_READ, SCOPE_WRITE])[1]
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


def drain(subscription, expected, timeout=3.0):
    """Collect `expected` events, ignoring keepalives, or fail on timeout."""
    collected = []
    deadline = time.time() + timeout
    for chunk in subscription:
        if chunk.startswith(b":"):
            continue
        for frame in chunk.decode("utf-8").strip().split("\n\n"):
            payload = [line for line in frame.split("\n") if line.startswith("data: ")]
            if payload:
                collected.append(json.loads(payload[0][len("data: "):]))
        if len(collected) >= expected or time.time() > deadline:
            break
    return collected


# --------------------------------------------------------------------------- #
# The bus
# --------------------------------------------------------------------------- #

class TestEventBus:
    def test_a_subscriber_receives_what_is_published(self):
        bus = events.EventBus()
        subscription = bus.subscribe()
        try:
            bus.publish(events.RECEIPT_ISSUED, {"rid": "abc"})
            received = drain(subscription, 1)
            assert received[0]["type"] == events.RECEIPT_ISSUED
            assert received[0]["data"] == {"rid": "abc"}
        finally:
            subscription.close()

    def test_events_are_sequenced(self):
        bus = events.EventBus()
        first = bus.publish("a", {})
        second = bus.publish("b", {})
        assert second.seq == first.seq + 1

    def test_publishing_never_blocks_on_a_slow_reader(self):
        """
        The property everything else follows from: issuing a receipt must not wait
        on a browser tab.
        """
        bus = events.EventBus()
        subscription = bus.subscribe(queue_size=4)
        try:
            started = time.time()
            for index in range(1000):
                bus.publish("noise", {"index": index})
            assert time.time() - started < 1.0
        finally:
            subscription.close()

    def test_an_overflowing_reader_loses_the_oldest_and_is_told(self):
        """
        A reader that silently loses events shows stale numbers as though they
        were complete. Being told means it can reload.
        """
        bus = events.EventBus()
        subscription = bus.subscribe(queue_size=4)
        try:
            for index in range(10):
                bus.publish("noise", {"index": index})
            assert subscription.dropped == 6

            chunks = []
            for chunk in subscription:
                chunks.append(chunk)
                if len(chunks) >= 5:
                    break
            assert any(b"events dropped" in chunk for chunk in chunks)

            delivered = [json.loads(chunk.decode("utf-8").split("data: ")[1])
                         for chunk in chunks if b"data: " in chunk]
            assert [event["data"]["index"] for event in delivered] == [6, 7, 8, 9]
        finally:
            subscription.close()

    def test_subscribers_are_independent(self):
        bus = events.EventBus()
        first, second = bus.subscribe(), bus.subscribe()
        try:
            bus.publish("a", {})
            assert len(drain(first, 1)) == 1
            assert len(drain(second, 1)) == 1
        finally:
            first.close()
            second.close()

    def test_the_number_of_streams_is_bounded(self):
        """Each open stream holds a thread and a socket."""
        bus = events.EventBus(max_subscribers=2)
        held = [bus.subscribe(), bus.subscribe()]
        try:
            with pytest.raises(events.TooManySubscribers):
                bus.subscribe()
        finally:
            for subscription in held:
                subscription.close()

    def test_closing_frees_the_slot(self):
        bus = events.EventBus(max_subscribers=1)
        first = bus.subscribe()
        first.close()
        second = bus.subscribe()
        second.close()
        assert bus.subscriber_count == 0

    def test_resuming_replays_what_is_still_retained(self):
        bus = events.EventBus()
        first = bus.publish("a", {"n": 1})
        bus.publish("b", {"n": 2})
        subscription = bus.subscribe(last_event_id=first.seq)
        try:
            received = drain(subscription, 1)
            assert [event["data"]["n"] for event in received] == [2]
        finally:
            subscription.close()

    def test_resuming_beyond_the_history_reports_a_gap(self):
        """Best effort, and honest about it: a gap is announced, never skipped."""
        bus = events.EventBus(history=3)
        for index in range(10):
            bus.publish("noise", {"index": index})
        subscription = bus.subscribe(last_event_id=1)
        try:
            received = drain(subscription, 1)
            assert received[0]["type"] == events.STREAM_GAP
        finally:
            subscription.close()

    def test_a_quiet_stream_sends_keepalives(self):
        """Proxies close idle connections; a comment line is not application data."""
        bus = events.EventBus()
        subscription = bus.subscribe()
        try:
            events.HEARTBEAT_SECONDS, original = 0.05, events.HEARTBEAT_SECONDS
            chunk = next(iter(subscription))
            assert chunk == b": keepalive\n\n"
        finally:
            events.HEARTBEAT_SECONDS = original
            subscription.close()


# --------------------------------------------------------------------------- #
# What the node publishes
# --------------------------------------------------------------------------- #

class TestNodeEvents:
    def test_issuing_a_receipt_announces_it(self, node, parties):
        payer, payee = parties
        subscription = node.events.subscribe()
        try:
            issued = issue(node, payer, payee)
            received = drain(subscription, 1)
            assert received[0]["type"] == events.RECEIPT_ISSUED
            assert received[0]["data"]["rid"] == issued["rid"]
            assert received[0]["data"]["billed_to"] == payee.did
        finally:
            subscription.close()

    def test_an_agent_joining_announces_itself(self, node):
        agent = Agent.generate(name="translator")

        @agent.capability("translate.text", price="0.0004")
        def translate(payload):
            return payload

        subscription = node.events.subscribe()
        try:
            header, body = agent.announcement()
            node.handle(encode_wire(header, body))
            received = drain(subscription, 1)
            assert received[0]["type"] == events.AGENT_ANNOUNCED
            assert received[0]["data"]["agent"] == agent.did
            assert received[0]["data"]["capabilities"] == ["translate.text"]
        finally:
            subscription.close()

    def test_a_deposit_announces_the_new_balance(self, node, parties):
        _, payee = parties
        subscription = node.events.subscribe()
        try:
            node.deposit(payee.did, "10.00", reference="bank:1")
            received = drain(subscription, 1)
            assert received[0]["type"] == events.CREDIT_DEPOSITED
            assert received[0]["data"]["balance"] == "10.00"
        finally:
            subscription.close()

    def test_an_account_is_warned_before_service_stops(self, parties):
        """Warning after the balance runs out would be a receipt too late."""
        payer, payee = parties
        prepaid = Node(fee="0.0001", environment="test", default_credit_limit="0")
        try:
            prepaid.low_balance_receipts = 3
            prepaid.deposit(payee.did, "0.0005", reference="bank:1")
            subscription = prepaid.events.subscribe()
            try:
                # Funded for five issuances. The warning fires when fewer than
                # three remain, so the first two are silent.
                for _ in range(2):
                    issue(prepaid, payer, payee)
                assert not any(e["type"] == events.CREDIT_LOW
                               for e in drain(subscription, 2, timeout=0.3))

                issue(prepaid, payer, payee)                # two left: warn
                warnings = [e for e in drain(subscription, 2, timeout=1.0)
                            if e["type"] == events.CREDIT_LOW]
                assert warnings
                assert warnings[0]["data"]["remaining_issuances"] == 2
            finally:
                subscription.close()
        finally:
            prepaid.close()

    def test_an_unmetered_account_is_never_warned(self, node, parties):
        """It cannot run out, so a warning would be noise."""
        payer, payee = parties
        assert node.credits.limit_for(payee.did) is UNLIMITED
        subscription = node.events.subscribe()
        try:
            issue(node, payer, payee)
            assert not any(e["type"] == events.CREDIT_LOW
                           for e in drain(subscription, 1, timeout=0.5))
        finally:
            subscription.close()


# --------------------------------------------------------------------------- #
# Over HTTP
# --------------------------------------------------------------------------- #

def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestStreamEndpoint:
    def test_the_stream_requires_a_credential(self, node):
        status, payload, _ = api.dispatch(node, api.Request(
            "GET", api.PREFIX + "/events", {}, {}, "203.0.113.9"))
        assert status == 401

    def test_it_returns_a_stream_rather_than_a_payload(self, node):
        status, payload, _ = api.dispatch(node, api.Request(
            "GET", api.PREFIX + "/events", {},
            {"authorization": "Bearer " + node.token}, "203.0.113.9"))
        try:
            assert status == 200
            assert isinstance(payload, api.Stream)
            assert payload.content_type == "text/event-stream"
        finally:
            payload.close()

    def test_a_full_node_refuses_politely(self, node):
        node.events.max_subscribers = 1
        first = node.events.subscribe()
        try:
            status, payload, _ = api.dispatch(node, api.Request(
                "GET", api.PREFIX + "/events", {},
                {"authorization": "Bearer " + node.token}, "203.0.113.9"))
            assert status == 503
            assert payload["error"]["code"] == api.ERROR_STREAM_FULL
        finally:
            first.close()

    def test_last_event_id_header_takes_precedence(self, node):
        first = node.events.publish("a", {"n": 1})
        node.events.publish("b", {"n": 2})
        status, payload, _ = api.dispatch(node, api.Request(
            "GET", api.PREFIX + "/events", {"last_event_id": ["0"]},
            {"authorization": "Bearer " + node.token,
             "last-event-id": str(first.seq)}, "203.0.113.9"))
        try:
            received = drain(payload.subscription, 1)
            assert [event["data"]["n"] for event in received] == [2]
        finally:
            payload.close()

    def test_live_events_over_real_http(self, node, parties):
        import urllib.request

        payer, payee = parties
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
            request = urllib.request.Request(
                "http://127.0.0.1:%d/api/v1/events" % port,
                headers={"Authorization": "Bearer " + node.token},
            )
            response = urllib.request.urlopen(request, timeout=5)
            assert response.headers["Content-Type"] == "text/event-stream"

            issued = {}

            def emit():
                time.sleep(0.2)
                issued["receipt"] = issue(node, payer, payee)

            threading.Thread(target=emit, daemon=True).start()

            frame = b""
            deadline = time.time() + 5
            while time.time() < deadline and b"receipt.issued" not in frame:
                frame += response.readline()
            response.close()

            assert b"receipt.issued" in frame
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)
