"""
Rate limiting tests.

The properties that matter are about what a limiter must not allow: a caller must
not get twice its quota by straddling a window boundary, must not exhaust somebody
else's allowance by claiming their identity, and must not grow the limiter's memory
without bound by rotating identifiers.
"""

import json
import os
import time

import pytest

from uip import codec, envelope
from uise import Agent, Node, api
from uise.keys import SCOPE_ADMIN, SCOPE_READ, SCOPE_WRITE
from uise.ratelimit import Limiters, Limits, RateLimiter
from uise.transport import decode_wire, encode_wire

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


# --------------------------------------------------------------------------- #
# The bucket
# --------------------------------------------------------------------------- #

class TestTokenBucket:
    def test_allows_up_to_the_limit_then_refuses(self):
        limiter = RateLimiter(limit=5, window_seconds=60)
        decisions = [limiter.check("caller") for _ in range(6)]
        assert [d.allowed for d in decisions] == [True] * 5 + [False]
        assert decisions[0].remaining == 4
        assert decisions[-1].remaining == 0

    def test_keys_are_independent(self):
        limiter = RateLimiter(limit=2, window_seconds=60)
        for _ in range(2):
            assert limiter.check("a").allowed
        assert not limiter.check("a").allowed
        assert limiter.check("b").allowed

    def test_refills_continuously_rather_than_in_steps(self):
        """
        A fixed window lets a caller spend its whole quota at the end of one window
        and again at the start of the next, so the real burst is twice the limit.
        """
        limiter = RateLimiter(limit=10, window_seconds=1)     # 10 per second
        for _ in range(10):
            assert limiter.check("caller").allowed
        assert not limiter.check("caller").allowed

        time.sleep(0.25)                                       # ~2.5 tokens back
        allowed = sum(1 for _ in range(4) if limiter.check("caller").allowed)
        assert 1 <= allowed <= 3

    def test_a_refused_call_says_when_to_retry(self):
        limiter = RateLimiter(limit=1, window_seconds=60)
        limiter.check("caller")
        decision = limiter.check("caller")
        assert not decision.allowed
        assert decision.retry_after >= 1
        assert decision.headers()["Retry-After"] == str(decision.retry_after)

    def test_headers_carry_the_quota(self):
        limiter = RateLimiter(limit=100, window_seconds=60)
        headers = limiter.check("caller").headers()
        assert headers["RateLimit-Limit"] == "100"
        assert headers["RateLimit-Remaining"] == "99"
        assert int(headers["RateLimit-Reset"]) >= 1
        assert "Retry-After" not in headers        # only present when refused

    def test_memory_cannot_grow_without_bound(self):
        """A caller rotating identifiers must not be able to exhaust memory."""
        limiter = RateLimiter(limit=100, window_seconds=60, max_tracked=50)
        for index in range(500):
            limiter.check("caller-%d" % index)
        assert len(limiter) <= 50

    def test_eviction_cannot_hand_out_a_fresh_allowance(self):
        """
        Only full buckets are evicted, and a full bucket is indistinguishable from
        one that never existed - so forgetting it changes no decision.
        """
        limiter = RateLimiter(limit=3, window_seconds=3600, max_tracked=2)
        for _ in range(3):
            limiter.check("heavy")
        for index in range(20):
            limiter.check("light-%d" % index)      # forces eviction sweeps
        assert not limiter.check("heavy").allowed  # still exhausted

    def test_a_limit_must_permit_something(self):
        for bad in ((0, 60), (5, 0), (-1, 60)):
            with pytest.raises(ValueError):
                RateLimiter(*bad)


# --------------------------------------------------------------------------- #
# The product API
# --------------------------------------------------------------------------- #

@pytest.fixture
def node():
    instance = Node(fee="0.0001", environment="test",
                    rate_limits=Limits(peer=1000, api=5, agent=1000))
    instance.token = instance.keys.create("tests", [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN])[1]
    yield instance
    instance.close()


def request(node, path, token=..., peer="203.0.113.9"):
    if token is ...:
        token = node.token
    headers = {"authorization": "Bearer " + token} if token else {}
    return api.dispatch(node, api.Request("GET", path, {}, headers, peer))


class TestApiQuota:
    def test_quota_is_per_credential(self, node):
        for _ in range(5):
            assert request(node, api.PREFIX + "/stats")[0] == 200
        status, payload, headers = request(node, api.PREFIX + "/stats")
        assert status == 429
        assert payload["error"]["code"] == api.ERROR_RATE_LIMITED
        assert headers["Retry-After"]

        # A different credential has its own allowance.
        _, other = node.keys.create("second", [SCOPE_READ])
        assert request(node, api.PREFIX + "/stats", token=other)[0] == 200

    def test_successful_responses_carry_the_quota(self, node):
        _, _, headers = request(node, api.PREFIX + "/stats")
        assert headers["RateLimit-Limit"] == "5"
        assert headers["RateLimit-Remaining"] == "4"

    def test_the_flood_guard_protects_the_authentication_path(self):
        """
        Without it, an anonymous caller can hammer token verification - a database
        lookup and a hash - for free.
        """
        guarded = Node(fee="0.0001", environment="test",
                       rate_limits=Limits(peer=3, api=1000, agent=1000))
        guarded.keys.create("tests", [SCOPE_READ])
        try:
            statuses = [request(guarded, api.PREFIX + "/stats", token="bogus")[0]
                        for _ in range(5)]
            assert statuses[:3] == [401, 401, 401]
            assert statuses[3:] == [429, 429]
        finally:
            guarded.close()

    def test_the_flood_guard_is_per_address(self):
        guarded = Node(fee="0.0001", environment="test",
                       rate_limits=Limits(peer=2, api=1000, agent=1000))
        token = guarded.keys.create("tests", [SCOPE_READ])[1]
        try:
            for _ in range(2):
                assert request(guarded, api.PREFIX + "/stats", token=token)[0] == 200
            assert request(guarded, api.PREFIX + "/stats", token=token)[0] == 429
            assert request(guarded, api.PREFIX + "/stats", token=token,
                           peer="198.51.100.7")[0] == 200
        finally:
            guarded.close()

    def test_health_is_still_guarded_against_flooding(self):
        """Open does not mean unlimited."""
        guarded = Node(fee="0.0001", environment="test",
                       rate_limits=Limits(peer=2, api=1000, agent=1000))
        try:
            assert request(guarded, api.PREFIX + "/health", token=None)[0] == 200
            assert request(guarded, api.PREFIX + "/health", token=None)[0] == 200
            assert request(guarded, api.PREFIX + "/health", token=None)[0] == 429
        finally:
            guarded.close()


# --------------------------------------------------------------------------- #
# The protocol plane
# --------------------------------------------------------------------------- #

def announcement_frame(agent):
    header, body = agent.announcement()
    return encode_wire(header, body)


def signed_receipt(node, payer, payee):
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
    return payee.identity.sign_receipt_as(signed, "payee")


class TestProtocolPlaneQuota:
    def test_an_agent_quota_applies_to_submitted_frames(self):
        limited = Node(fee="0.0001", environment="test",
                       rate_limits=Limits(peer=1000, api=1000, agent=2))
        try:
            payer, payee = Agent.generate(), Agent.generate()

            def submit():
                body = codec.canonicalize(signed_receipt(limited, payer, payee))
                return limited.handle(encode_wire(
                    payee._sign("receipt", limited.did, body,
                                "application/uip-receipt+json"),
                    body,
                ))

            assert submit()[0] == 200
            assert submit()[0] == 200
            status, response = submit()
            assert status == 400
            _, error_body = decode_wire(response)
            assert json.loads(error_body)["code"] == "UIP_RATE_LIMITED"
        finally:
            limited.close()

    def test_an_unverified_claim_cannot_exhaust_another_agents_quota(self):
        """
        Keying on the DID before checking its signature would let anyone deny
        service to a chosen agent simply by naming it.
        """
        limited = Node(fee="0.0001", environment="test",
                       rate_limits=Limits(peer=1000, api=1000, agent=2))
        try:
            victim = Agent.generate(name="victim")

            @victim.capability("x.y")
            def handler(payload):
                return {}

            impostor = Agent.generate(name="impostor")
            header, body = victim.announcement()

            # Signed by the impostor, but claiming to come from the victim.
            forged = impostor.identity.sign_envelope(
                dict(header, **{"from": impostor.did})
            )
            forged["from"] = victim.did
            for _ in range(10):
                status, response = limited.handle(encode_wire(forged, body))
                assert status == 400
                _, error_body = decode_wire(response)
                assert json.loads(error_body)["code"] == "UIP_SIG_INVALID"

            # The victim's own allowance was never touched.
            assert limited.handle(announcement_frame(victim))[0] == 200
        finally:
            limited.close()

    def test_the_address_guard_precedes_parsing(self):
        limited = Node(fee="0.0001", environment="test",
                       rate_limits=Limits(peer=2, api=1000, agent=1000))
        try:
            agent = Agent.generate()

            @agent.capability("x.y")
            def handler(payload):
                return {}

            for _ in range(2):
                limited.handle(announcement_frame(agent), peer="203.0.113.9")
            status, response = limited.handle(b'{"garbage": true}',
                                              peer="203.0.113.9")
            assert status == 429                     # refused before parsing
            _, body = decode_wire(response)
            assert json.loads(body)["code"] == "UIP_RATE_LIMITED"
        finally:
            limited.close()

    def test_agents_enforce_a_quota_too(self):
        """The specification says every receiver should, not only nodes."""
        server = Agent.generate(name="server")

        @server.capability("echo")
        def echo(payload):
            return payload or {}

        server.limiters = Limiters(Limits(peer=1000, api=1000, agent=2))
        client = Agent.generate()

        def send():
            body = codec.canonicalize({"capability": "echo", "input": {}})
            return server.handle(encode_wire(
                client._sign("request", server.did, body, "application/json"), body
            ))

        assert send()[0] == 200
        assert send()[0] == 200
        status, frame = send()
        assert status == 400
        _, body = decode_wire(frame)
        assert json.loads(body)["code"] == "UIP_RATE_LIMITED"
