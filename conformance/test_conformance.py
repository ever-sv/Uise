#!/usr/bin/env python3
"""
UIP-1 conformance suite.

This suite, not the prose of the specification, is the operative definition of the
protocol. Prose is interpreted differently by every organization; expected bytes
are not.

Runs with nothing installed:

    python3 -m unittest discover -s conformance -v

or directly:

    python3 conformance/test_conformance.py
"""

import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from uip import codec, did, ed25519, envelope, suites  # noqa: E402

VECTORS_DIR = os.path.join(HERE, "vectors")
SCHEMAS_DIR = os.path.join(os.path.dirname(HERE), "spec", "schemas")


def load(name):
    with open(os.path.join(VECTORS_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


class TestEd25519AgainstRfc8032(unittest.TestCase):
    """
    The reference implementation is checked against the official RFC 8032 vectors,
    not only against itself. Self-consistent but wrong cryptography would make Uise
    unable to interoperate with any other implementation on earth.
    """

    VECTORS = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a3"
         "3bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15"
         "996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16"
         "f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    def test_matches_official_vectors(self):
        for seed_hex, public_hex, message_hex, signature_hex in self.VECTORS:
            with self.subTest(seed_hex[:16]):
                seed = bytes.fromhex(seed_hex)
                message = bytes.fromhex(message_hex)
                self.assertEqual(ed25519.public_key(seed).hex(), public_hex)
                self.assertEqual(ed25519.sign(message, seed).hex(), signature_hex)

    def test_rejects_tampered_signatures(self):
        for seed_hex, _, message_hex, signature_hex in self.VECTORS:
            with self.subTest(seed_hex[:16]):
                seed = bytes.fromhex(seed_hex)
                message = bytes.fromhex(message_hex)
                public = ed25519.public_key(seed)
                signature = bytearray(bytes.fromhex(signature_hex))
                self.assertTrue(ed25519.verify(bytes(signature), message, public))
                signature[0] ^= 1
                self.assertFalse(ed25519.verify(bytes(signature), message, public))


class TestSuites(unittest.TestCase):
    """Spec section 4 - the mechanism that lets the protocol outlive its cryptography."""

    def setUp(self):
        self.vectors = load("suites.json")

    def test_registry_matches_vectors(self):
        implemented = {entry["name"]: entry for entry in self.vectors["implemented"]}
        self.assertEqual(set(implemented), {suite.name for suite in suites.registered()})
        for suite in suites.registered():
            with self.subTest(suite.name):
                entry = implemented[suite.name]
                self.assertEqual(entry["multicodec"], "0x%x" % suite.multicodec)
                self.assertEqual(entry["public_key_size"], suite.public_key_size)
                self.assertEqual(entry["signature_size"], suite.signature_size)
                self.assertEqual(entry["long_term_evidence"], suite.long_term_evidence)

    def test_unknown_suite_is_rejected_not_approximated(self):
        with self.assertRaises(suites.SuiteUnsupported):
            did.decode(self.vectors["unknown_suite_did"])

    def test_ed25519_is_not_valid_for_long_term_evidence(self):
        # A classical signature cannot carry decades-long evidence: the day it
        # falls, every receipt ever signed with it becomes forgeable in hindsight.
        self.assertFalse(suites.ED25519.long_term_evidence)

    def test_no_invented_multicodec_values(self):
        # Only officially assigned codepoints may ship. Guessing one would
        # permanently fragment the namespace.
        self.assertEqual(
            {suite.multicodec for suite in suites.registered()},
            {suites.MULTICODEC_ED25519_PUB},
        )


class TestIdentity(unittest.TestCase):
    """Spec section 3 - identity derives from the key, with no network or registry."""

    def setUp(self):
        self.vectors = load("did_key.json")

    def test_public_key_derivation(self):
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                seed = bytes.fromhex(case["seed_hex"])
                self.assertEqual(ed25519.public_key(seed).hex(), case["public_key_hex"])

    def test_did_carries_the_key_and_the_suite(self):
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                public = bytes.fromhex(case["public_key_hex"])
                self.assertEqual(did.encode(suites.ED25519, public), case["did"])
                suite, recovered = did.decode(case["did"])
                self.assertEqual(suite.name, case["suite"])
                self.assertEqual(recovered, public)

    def test_rejects_malformed_dids(self):
        for bad in ["", "did:web:example.com", "did:key:nomultibase",
                    "did:key:z2DeadBeef", "did:key:z6Mk" + "1" * 44]:
            with self.subTest(bad):
                self.assertFalse(did.is_well_formed(bad))

    def test_varint_roundtrip(self):
        # Post-quantum codepoints exceed a single byte, so the prefix reader must
        # be a real varint decoder rather than a fixed two-byte match.
        for value in (0, 1, 0x7F, 0x80, 0xED, 0x1234, 0x3FFFFF):
            with self.subTest(hex(value)):
                encoded = codec.varint_encode(value)
                self.assertEqual(codec.varint_decode(encoded + b"tail"),
                                 (value, len(encoded)))


class TestCanonicalization(unittest.TestCase):
    """Spec section 5 - if this diverges, signatures silently stop validating."""

    def setUp(self):
        self.vectors = load("jcs.json")

    def test_canonical_bytes(self):
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                produced = codec.canonicalize(case["input"])
                self.assertEqual(produced.hex(), case["canonical_hex"])
                self.assertEqual(produced.decode("utf-8"), case["canonical"])
                self.assertEqual(codec.multihash(produced), case["sha256"])

    def test_rejects_floating_point(self):
        with self.assertRaises(ValueError):
            codec.canonicalize({"amount": 0.0004})

    def test_rejects_unsafe_integers(self):
        with self.assertRaises(ValueError):
            codec.canonicalize({"n": 2 ** 53})

    def test_orders_by_utf16_code_units(self):
        # Outside the Basic Multilingual Plane, code point order and UTF-16 order
        # disagree. RFC 8785 mandates UTF-16 order.
        canonical = codec.canonicalize({"\U0001f600": 1, "￿": 2}).decode("utf-8")
        self.assertLess(canonical.index("\U0001f600"), canonical.index("￿"))


class TestHashAgility(unittest.TestCase):
    """Spec section 4.5 - registered digests only, never a silent fallback."""

    def test_registered_algorithms(self):
        for algorithm, length in (("sha256", 43), ("sha384", 64), ("sha512", 86)):
            with self.subTest(algorithm):
                tag = codec.multihash(b"payload", algorithm)
                self.assertTrue(tag.startswith(algorithm + ":"))
                self.assertEqual(len(tag.split(":", 1)[1]), length)
                self.assertTrue(codec.multihash_matches(b"payload", tag))

    def test_rejects_unregistered_algorithm(self):
        with self.assertRaises(ValueError):
            codec.multihash(b"payload", "blake3")
        with self.assertRaises(ValueError):
            codec.multihash_matches(b"payload", "blake3:" + codec.b64u_encode(bytes(32)))


class TestEnvelope(unittest.TestCase):
    """Spec section 7 - the frozen format."""

    def setUp(self):
        self.vectors = load("envelope.json")

    def test_exact_signed_bytes(self):
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                produced = envelope.signing_input(case["header"])
                self.assertEqual(produced.hex(), case["signing_input_hex"])
                self.assertEqual(hashlib.sha256(produced).hexdigest(),
                                 case["signing_input_sha256"])

    def test_valid_envelopes_are_accepted(self):
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                envelope.verify_envelope(
                    case["header"],
                    body=case["body_utf8"].encode("utf-8"),
                    now_ms=case["now_ms"],
                    seen_ids=set(),
                )

    def test_domain_separator_is_present(self):
        # Prevents a UIP signature being replayed into another protocol.
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                raw = bytes.fromhex(case["signing_input_hex"])
                self.assertTrue(raw.startswith(envelope.DOMAIN_ENVELOPE))

    def test_root_is_closed(self):
        # Adding a root field after launch is how protocols are ruined.
        header = dict(self.vectors["cases"][0]["header"], new_field="x")
        with self.assertRaises(envelope.UipError) as context:
            envelope.verify_envelope(header)
        self.assertEqual(context.exception.code, "UIP_HEADER_MALFORMED")

    def test_extension_object_is_signed(self):
        case = next(c for c in self.vectors["cases"] if c["name"] == "event with extension")
        tampered = dict(case["header"], x={"com.example.tracing": "other-value"})
        with self.assertRaises(envelope.UipError) as context:
            envelope.verify_envelope(tampered, now_ms=case["now_ms"])
        self.assertEqual(context.exception.code, "UIP_SIG_INVALID")

    def test_signature_length_is_not_assumed(self):
        # A verifier hardcoding 64 bytes cannot interoperate with a post-quantum
        # agent, so the schema and the code must both accept variable lengths.
        with open(os.path.join(SCHEMAS_DIR, "envelope.schema.json"), encoding="utf-8") as handle:
            schema = json.load(handle)
        pattern = schema["$defs"]["signature"]["pattern"]
        self.assertIn("86,", pattern)
        self.assertNotIn("{86}", pattern)


class TestRejections(unittest.TestCase):
    """Spec sections 7.4 and 12 - what every implementation MUST reject."""

    def setUp(self):
        self.vectors = load("invalid.json")

    def test_every_invalid_vector_is_rejected_with_its_code(self):
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                body = case.get("body_utf8", self.vectors["reference_body_utf8"])
                with self.assertRaises(envelope.UipError) as context:
                    envelope.verify_envelope(
                        case["header"],
                        body=body.encode("utf-8"),
                        now_ms=case.get("now_ms"),
                        seen_ids=set(case.get("seen_ids", [])),
                    )
                self.assertEqual(context.exception.code, case["code"], case["description"])

    def test_no_mutation_survives_the_signature(self):
        """No header field can be edited in transit."""
        case = load("envelope.json")["cases"][0]
        header = case["header"]
        for field in header:
            if field == "sig":
                continue
            tampered = dict(header)
            tampered[field] = 999999 if isinstance(header[field], int) else "tampered"
            with self.subTest(field):
                with self.assertRaises(envelope.UipError):
                    envelope.verify_envelope(tampered, now_ms=case["now_ms"])


class TestReceipt(unittest.TestCase):
    """Spec section 10 - the value primitive."""

    def setUp(self):
        self.vectors = load("receipt.json")

    def test_vector_cases(self):
        for case in self.vectors["cases"]:
            with self.subTest(case["name"]):
                if case["valid"]:
                    envelope.verify_receipt(case["receipt"])
                else:
                    with self.assertRaises(envelope.UipError) as context:
                        envelope.verify_receipt(case["receipt"])
                    self.assertEqual(context.exception.code, case["code"])

    def _case(self, name):
        return next(c for c in self.vectors["cases"] if c["name"] == name)["receipt"]

    def test_requires_all_three_signatures(self):
        complete = self._case("complete receipt")
        for role in envelope.RECEIPT_SIGNERS:
            partial = dict(
                complete,
                sigs={k: v for k, v in complete["sigs"].items() if k != role},
            )
            with self.subTest(role):
                with self.assertRaises(envelope.UipError) as context:
                    envelope.verify_receipt(partial)
                self.assertEqual(context.exception.code, "UIP_RECEIPT_INCOMPLETE")

    def test_price_cannot_be_renegotiated(self):
        """terms_hash anchors the price to the descriptor in force at request time."""
        complete = self._case("complete receipt")
        capability = self.vectors["capability"]
        self.assertEqual(envelope.terms_hash(capability), complete["terms_hash"])

        other_price = json.loads(json.dumps(capability))
        other_price["price"]["amount"] = "0.9999"
        self.assertNotEqual(envelope.terms_hash(other_price), complete["terms_hash"])

    def test_tampering_with_the_amount_invalidates_signatures(self):
        with self.assertRaises(envelope.UipError) as context:
            envelope.verify_receipt(dict(self._case("complete receipt"), amount="9.9999"))
        self.assertEqual(context.exception.code, "UIP_SIG_INVALID")

    def test_anchoring_does_not_alter_the_agreement(self):
        # Signatures are computed with anchor forced to null, so the transparency
        # log can prove existence without touching what the parties agreed to.
        complete = self._case("complete receipt")
        anchored = self._case("anchored receipt")
        self.assertEqual(anchored["sigs"], complete["sigs"])
        self.assertIsNotNone(anchored["anchor"])
        envelope.verify_receipt(anchored)

    def test_anchor_field_is_mandatory_even_when_null(self):
        complete = self._case("complete receipt")
        without_anchor = {k: v for k, v in complete.items() if k != "anchor"}
        with self.assertRaises(envelope.UipError) as context:
            envelope.verify_receipt(without_anchor)
        self.assertEqual(context.exception.code, "UIP_HEADER_MALFORMED")

    def test_issuer_must_be_eligible_for_long_term_evidence(self):
        policy = self.vectors["issuer_policy"]
        receipt = policy["receipt"]
        envelope.verify_receipt(receipt)                      # protocol level: valid
        with self.assertRaises(envelope.UipError) as context: # network policy: not eligible
            envelope.verify_receipt(receipt, require_long_term_issuer=True)
        self.assertEqual(context.exception.code, policy["code"])

    def test_receipt_domain_differs_from_envelope_domain(self):
        raw = bytes.fromhex(self.vectors["signing_input_hex"])
        self.assertTrue(raw.startswith(envelope.DOMAIN_RECEIPT))
        self.assertFalse(raw.startswith(envelope.DOMAIN_ENVELOPE))


class TestSchemas(unittest.TestCase):
    """The published schemas and the implementation must not drift apart."""

    def _schema(self, name):
        with open(os.path.join(SCHEMAS_DIR, "%s.schema.json" % name), encoding="utf-8") as handle:
            return json.load(handle)

    def test_schemas_are_valid_json_schema_2020_12(self):
        for name in ("envelope", "descriptor", "receipt"):
            with self.subTest(name):
                self.assertEqual(self._schema(name)["$schema"],
                                 "https://json-schema.org/draft/2020-12/schema")

    def test_envelope_root_matches_the_implementation(self):
        schema = self._schema("envelope")
        self.assertEqual(set(schema["properties"]), set(envelope.ALLOWED_FIELDS))
        self.assertEqual(set(schema["required"]), set(envelope.REQUIRED_FIELDS))
        self.assertFalse(schema["additionalProperties"])

    def test_receipt_requires_anchor_and_three_signatures(self):
        schema = self._schema("receipt")
        self.assertIn("anchor", schema["required"])
        self.assertEqual(set(schema["properties"]["sigs"]["required"]),
                         set(envelope.RECEIPT_SIGNERS))

    def test_did_pattern_admits_post_quantum_key_sizes(self):
        # An Ed25519-only pattern would lock the protocol out of every
        # post-quantum suite, which is exactly the failure section 4 prevents.
        for name in ("envelope", "receipt", "descriptor"):
            with self.subTest(name):
                pattern = self._schema(name)["$defs"]["did"]["pattern"]
                self.assertNotIn("z6Mk", pattern)
                self.assertIn("4096", pattern)


if __name__ == "__main__":
    unittest.main(verbosity=2)
