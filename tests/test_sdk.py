"""
SDK tests - post-quantum suites, identity, envelopes, receipts and live HTTP.

These complement `conformance/`, they do not replace it. The conformance suite
defines the protocol and runs with zero dependencies; this file checks that the
production implementation of that protocol behaves correctly, including the
cryptography the zero-dependency build cannot perform.
"""

import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from uip import codec, did, envelope, suites as registry
from uise import Agent, Identity, UipError, suites
from uise.agent import _make_handler
from uise.transport import decode_wire, encode_wire

ALL_SUITES = (suites.ED25519, suites.ML_DSA_65, suites.COMPOSITE_ED25519_ML_DSA_65)


# --------------------------------------------------------------------------- #
# Cryptographic suites - spec section 4
# --------------------------------------------------------------------------- #

class TestSuites:
    def test_declared_sizes_match_the_library(self):
        """A silent upstream size change would corrupt every DID we produce."""
        for suite in ALL_SUITES:
            seed = bytes(range(suites.SEED_SIZE))
            assert len(suite.derive_public_key(seed)) == suite.public_key_size
            assert len(suite.sign(b"probe", seed)) == suite.signature_size

    def test_composite_sizes_follow_the_spec(self):
        composite = suites.COMPOSITE_ED25519_ML_DSA_65
        assert composite.public_key_size == 32 + 1952 == 1984
        assert composite.signature_size == 64 + 3309 == 3373

    def test_composite_requires_both_halves(self):
        """Either component failing invalidates the whole signature."""
        composite = suites.COMPOSITE_ED25519_ML_DSA_65
        seed = bytes(range(suites.SEED_SIZE))
        public = composite.derive_public_key(seed)
        message = b"uip/1.receipt permanent evidence"
        signature = bytearray(composite.sign(message, seed))
        assert composite.verify(bytes(signature), message, public)

        classical_broken = bytearray(signature)
        classical_broken[0] ^= 1                       # Ed25519 half
        assert not composite.verify(bytes(classical_broken), message, public)

        quantum_broken = bytearray(signature)
        quantum_broken[100] ^= 1                       # ML-DSA half
        assert not composite.verify(bytes(quantum_broken), message, public)

    def test_only_post_quantum_suites_carry_long_term_evidence(self):
        assert not suites.ED25519.long_term_evidence
        assert suites.ML_DSA_65.long_term_evidence
        assert suites.COMPOSITE_ED25519_ML_DSA_65.long_term_evidence

    def test_unassigned_codepoints_are_flagged_provisional(self):
        """
        Codepoints for ML-DSA are not assigned yet. Suites using placeholders must
        say so, so nobody treats them as interoperable across organizations.
        """
        assert not suites.ED25519.provisional
        assert suites.ML_DSA_65.provisional
        assert suites.COMPOSITE_ED25519_ML_DSA_65.provisional

    def test_registry_refuses_to_rebind_a_codepoint(self):
        impostor = registry.Suite(
            name="Not-Ed25519", multicodec=registry.MULTICODEC_ED25519_PUB,
            public_key_size=32, signature_size=64, long_term_evidence=False,
            derive_public_key=lambda seed: b"", sign=lambda m, s: b"",
            verify=lambda s, m, p: True,
        )
        with pytest.raises(registry.SuiteConflict):
            registry.register(impostor, replace=True)

    def test_installation_is_idempotent(self):
        before = {s.name for s in registry.registered()}
        suites.install()
        assert {s.name for s in registry.registered()} == before

    def test_composite_components_are_independent(self):
        """Domain-separated derivation: neither half reveals the other's key."""
        seed = bytes(range(suites.SEED_SIZE))
        composite = suites.COMPOSITE_ED25519_ML_DSA_65.derive_public_key(seed)
        assert composite[:32] != suites.ED25519.derive_public_key(seed)


# --------------------------------------------------------------------------- #
# Identity - spec section 3
# --------------------------------------------------------------------------- #

class TestIdentity:
    def test_did_round_trip_for_every_suite(self):
        for suite in ALL_SUITES:
            identity = Identity.from_seed_hex("11" * 32, suite)
            resolved_suite, public_key = did.decode(identity.did)
            assert resolved_suite.name == suite.name
            assert public_key == identity.public_key

    def test_generate_uses_fresh_entropy(self):
        assert Identity.generate().did != Identity.generate().did

    def test_seed_is_not_exposed_by_repr(self):
        identity = Identity.from_seed_hex("22" * 32)
        assert "22" * 32 not in repr(identity)
        assert identity.secret_seed_hex() == "22" * 32

    def test_refuses_to_sign_for_another_identity(self):
        identity = Identity.generate()
        with pytest.raises(ValueError):
            identity.sign_envelope({"from": "did:key:zSomebodyElse"})


# --------------------------------------------------------------------------- #
# Envelopes and receipts under post-quantum suites
# --------------------------------------------------------------------------- #

class TestPostQuantumEnvelope:
    def _envelope(self, identity, body=b"payload"):
        header = {
            "v": envelope.VERSION,
            "id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
            "from": identity.did,
            "to": identity.did,
            "type": "event",
            "ts": 1754745600123,
            "ttl": 30000,
            "content_type": "application/octet-stream",
            "body_hash": envelope.body_hash(body),
        }
        return identity.sign_envelope(header), body

    def test_composite_envelope_verifies(self):
        identity = Identity.generate(suites.COMPOSITE_ED25519_ML_DSA_65)
        header, body = self._envelope(identity)
        envelope.verify_envelope(header, body, now_ms=1754745600123, seen_ids=set())

    def test_composite_signature_is_kilobytes_not_bytes(self):
        """A verifier hardcoding 64 bytes cannot talk to a post-quantum agent."""
        identity = Identity.generate(suites.COMPOSITE_ED25519_ML_DSA_65)
        header, _ = self._envelope(identity)
        assert len(header["sig"]) > 4000

    def test_tampering_still_fails_under_a_post_quantum_suite(self):
        identity = Identity.generate(suites.COMPOSITE_ED25519_ML_DSA_65)
        header, body = self._envelope(identity)
        with pytest.raises(UipError) as error:
            envelope.verify_envelope(dict(header, ttl=60000), body,
                                     now_ms=1754745600123, seen_ids=set())
        assert error.value.code == "UIP_SIG_INVALID"


class TestReceiptIssuerPolicy:
    def _receipt(self, issuer_identity):
        payer = Identity.from_seed_hex("33" * 32)
        payee = Identity.from_seed_hex("44" * 32)
        capability = {"id": "translate.text", "price": {"amount": "0.0004",
                                                        "unit": "USD", "per": "call"}}
        base = {
            "v": envelope.VERSION,
            "rid": "01K2R7Y3B8QW5ZM1P4K7DXCVGN",
            "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
            "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
            "payer": payer.did,
            "payee": payee.did,
            "capability": "translate.text",
            "amount": "0.0004",
            "unit": "USD",
            "terms_hash": envelope.terms_hash(capability),
            "issued_at": 1754745601987,
            "issuer": issuer_identity.did,
            "settlement": None,
            "anchor": None,
        }
        signed = payer.sign_receipt_as(base, "payer")
        signed = payee.sign_receipt_as(signed, "payee")
        return issuer_identity.sign_receipt_as(signed, "issuer")

    def test_post_quantum_issuer_satisfies_network_policy(self):
        issuer = Identity.generate(suites.ISSUER_DEFAULT)
        receipt = self._receipt(issuer)
        envelope.verify_receipt(receipt, require_long_term_issuer=True)

    def test_classical_issuer_is_rejected_by_network_policy(self):
        """
        A receipt is evidence for decades. An algorithm broken in 2040 would
        retroactively forge every receipt ever signed under it.
        """
        receipt = self._receipt(Identity.generate(suites.ED25519))
        envelope.verify_receipt(receipt)                       # protocol: valid
        with pytest.raises(UipError) as error:
            envelope.verify_receipt(receipt, require_long_term_issuer=True)
        assert error.value.code == "UIP_ISSUER_NOT_ELIGIBLE"

    def test_anchoring_leaves_signatures_untouched(self):
        issuer = Identity.generate(suites.ISSUER_DEFAULT)
        receipt = self._receipt(issuer)
        anchored = dict(receipt, anchor={
            "log": "https://log.example.com/2026",
            "index": 7,
            "tree_size": 8,
            "root": codec.multihash(b"root", "sha384"),
            "inclusion_proof": [codec.multihash(b"sibling", "sha384")],
        })
        assert anchored["sigs"] == receipt["sigs"]
        envelope.verify_receipt(anchored, require_long_term_issuer=True)


# --------------------------------------------------------------------------- #
# Transport framing - spec section 11.1
# --------------------------------------------------------------------------- #

class TestTransportFraming:
    def test_round_trip_preserves_exact_bytes(self):
        header = {"v": "uip/1", "id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD"}
        body = b'{"text":"\xc3\xb1"}'
        recovered_header, recovered_body = decode_wire(encode_wire(header, body))
        assert recovered_header == header
        assert recovered_body == body

    def test_ambiguous_framing_is_rejected(self):
        """
        Two body encodings at once would leave two implementations disagreeing on
        which bytes were signed.
        """
        with pytest.raises(ValueError):
            decode_wire({"v": "uip/1", "body": {}, "body_b64": ""})
        with pytest.raises(ValueError):
            decode_wire({"v": "uip/1"})


# --------------------------------------------------------------------------- #
# The developer-facing agent
# --------------------------------------------------------------------------- #

def build_translator(suite=None):
    agent = Agent.generate(name="translator", suite=suite)

    @agent.capability("translate.text", price="0.0004", description="Uppercases text.")
    def translate(payload):
        return {"text": payload["text"].upper()}

    return agent


class TestAgent:
    def test_descriptor_declares_price_as_a_string(self):
        descriptor = build_translator().descriptor()
        capability = descriptor["capabilities"][0]
        assert capability["price"] == {"amount": "0.0004", "unit": "USD", "per": "call"}
        assert isinstance(capability["price"]["amount"], str)

    def test_float_prices_are_refused_at_declaration_time(self):
        agent = Agent.generate()
        with pytest.raises(TypeError):
            agent.capability("x.y", price=0.0004)(lambda payload: {})

    def test_announcement_is_a_signed_broadcast(self):
        agent = build_translator()
        header, body = agent.announcement()
        assert header["type"] == "announce"
        assert "to" not in header
        envelope.verify_envelope(header, body, now_ms=header["ts"], seen_ids=set())

    def test_unknown_capability_returns_a_signed_error(self):
        server = build_translator()
        client = Agent.generate()
        body = codec.canonicalize({"capability": "nope", "input": {}})
        request = client._sign("request", server.did, body, "application/json")
        status, frame = server.handle(encode_wire(request, body))
        assert status == 400
        header, error_body = decode_wire(frame)
        envelope.verify_envelope(header, error_body, now_ms=header["ts"], seen_ids=set())
        assert json.loads(error_body)["code"] == "UIP_CAPABILITY_UNKNOWN"

    def test_replayed_request_is_rejected(self):
        server = build_translator()
        client = Agent.generate()
        body = codec.canonicalize(
            {"capability": "translate.text", "input": {"text": "hola"}}
        )
        request = client._sign("request", server.did, body, "application/json")
        frame = encode_wire(request, body)
        assert server.handle(frame)[0] == 200
        status, replayed = server.handle(frame)
        assert status == 400
        _, error_body = decode_wire(replayed)
        assert json.loads(error_body)["code"] == "UIP_REPLAY"

    def test_handler_exceptions_do_not_leak_internals(self):
        agent = Agent.generate()

        @agent.capability("boom")
        def explode(payload):
            raise RuntimeError("secret internal detail")

        client = Agent.generate()
        body = codec.canonicalize({"capability": "boom", "input": {}})
        request = client._sign("request", agent.did, body, "application/json")
        status, frame = agent.handle(encode_wire(request, body))
        assert status == 500
        _, error_body = decode_wire(frame)
        assert "secret internal detail" not in error_body.decode("utf-8")


# --------------------------------------------------------------------------- #
# End to end over real HTTP
# --------------------------------------------------------------------------- #

def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestLiveTransaction:
    def test_two_agents_transact_over_http(self):
        server_agent = build_translator()
        port = _free_port()
        server_agent.endpoint = "http://127.0.0.1:%d/uip/v1" % port
        httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(server_agent))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.02)

            client = Agent.generate(name="caller")
            result = client.call(
                "http://127.0.0.1:%d" % port,
                server_agent.did,
                "translate.text",
                {"text": "hola mundo"},
            )
            assert result == {"text": "HOLA MUNDO"}
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)
