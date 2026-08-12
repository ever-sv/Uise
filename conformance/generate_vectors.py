#!/usr/bin/env python3
"""
Generate the normative UIP-1 vectors into `conformance/vectors/`.

Everything here is deterministic: same seeds, same ULIDs, same timestamps. Running
it twice produces byte-identical files. If a code change produces different
vectors, that change breaks the protocol - and the diff makes it visible before it
is ever published.

Usage:  python3 conformance/generate_vectors.py
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uip import codec, did, ed25519, envelope, suites  # noqa: E402

VECTORS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")

# --------------------------------------------------------------------------- #
# Fixed inputs. Do not change: they are part of the standard.
# --------------------------------------------------------------------------- #

SEEDS = {
    "alice": bytes(range(0, 32)),
    "bob": bytes(range(32, 64)),
    "issuer": bytes(range(64, 96)),
}

TS = 1754745600123                    # 2025-08-09T12:00:00.123Z
TTL = 30_000

IDS = {
    "request": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
    "response": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
    "announce": "01K2R7XB1D3EFGHJ0K5M7N9PQR",
    "event": "01K2R7Y5C9RXPZQ2T6V8WXYZAB",
    "sha384": "01K2R7XD2E4FGHJK1M6N8P0QRS",
    "rid": "01K2R7Y3B8QW5ZM1P4K7DXCVGN",
}

CAPABILITY = {
    "id": "translate.text",
    "description": "Translates a text between two languages.",
    "input_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
    "output_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
    "price": {"amount": "0.0004", "unit": "USD", "per": "call"},
}

# A multicodec codepoint that is deliberately unassigned. It exists only to prove
# that an unknown suite is rejected rather than approximated. Inventing a
# plausible-looking codepoint for a real algorithm would permanently fragment the
# namespace, so no such value appears anywhere in this repository.
UNASSIGNED_MULTICODEC = 0x3FFFFF

DIDS = {
    name: did.encode(suites.ED25519, ed25519.public_key(seed))
    for name, seed in SEEDS.items()
}


def write(name, payload):
    path = os.path.join(VECTORS_DIR, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=False)
        handle.write("\n")
    print("  wrote  vectors/%s" % name)


def unknown_suite_did():
    """A syntactically valid did:key naming a suite no implementation knows."""
    payload = codec.varint_encode(UNASSIGNED_MULTICODEC) + bytes(32)
    return "did:key:z" + codec.b58_encode(payload)


# --------------------------------------------------------------------------- #
# 1. Cryptographic suites
# --------------------------------------------------------------------------- #

def vectors_suites():
    return {
        "spec": "UIP-1 section 4 - Cryptographic suites and agility",
        "note": "The envelope never names an algorithm. The multicodec prefix inside "
                "the sender DID does. Adding a post-quantum algorithm therefore adds a "
                "registry entry and a new DID, never a new protocol version.",
        "implemented": [
            {
                "name": suite.name,
                "multicodec": "0x%x" % suite.multicodec,
                "public_key_size": suite.public_key_size,
                "signature_size": suite.signature_size,
                "long_term_evidence": suite.long_term_evidence,
            }
            for suite in suites.registered()
        ],
        "unknown_suite_did": unknown_suite_did(),
        "unknown_suite_note": "MUST be rejected with UIP_SUITE_UNSUPPORTED. An "
                              "implementation MUST NOT fall back to another algorithm: "
                              "a fallback is a downgrade attack.",
    }


# --------------------------------------------------------------------------- #
# 2. did:key
# --------------------------------------------------------------------------- #

def vectors_did():
    cases = []
    for name, seed in SEEDS.items():
        public = ed25519.public_key(seed)
        cases.append({
            "name": name,
            "suite": suites.ED25519.name,
            "seed_hex": seed.hex(),
            "public_key_hex": public.hex(),
            "did": did.encode(suites.ED25519, public),
        })
    return {
        "spec": "UIP-1 section 3 - Identity",
        "note": "The public key derives from the seed; the DID contains the key and the "
                "multicodec that names its suite. Verifying an identity requires no "
                "network and no registry.",
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 3. JCS canonicalization
# --------------------------------------------------------------------------- #

def vectors_jcs():
    inputs = [
        ("key ordering", {"b": 1, "a": 2, "C": 3}),
        ("nesting", {"z": {"b": [1, 2, 3], "a": None}, "a": True}),
        ("mandatory escapes", {"s": "line1\nline2\t\"quotes\"\\backslash"}),
        ("non printable controls", {"s": "\u0000\u001f end"}),
        ("literal non ascii", {"ñ": "año", "a": "€"}),
        ("utf-16 ordering", {"\U0001f600": 1, "￿": 2}),
        ("integer boundary", {"n": 9007199254740991}),
        ("empty array and object", {"a": [], "o": {}}),
    ]
    cases = []
    for name, value in inputs:
        canonical = codec.canonicalize(value)
        cases.append({
            "name": name,
            "input": value,
            "canonical": canonical.decode("utf-8"),
            "canonical_hex": canonical.hex(),
            "sha256": codec.multihash(canonical),
        })
    return {
        "spec": "UIP-1 section 5 - Canonical encoding (JCS, RFC 8785)",
        "note": "If two implementations canonicalize differently their signatures stop "
                "validating against each other and the failure is silent. These bytes "
                "are normative.",
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 4. Valid envelopes
# --------------------------------------------------------------------------- #

def _request_envelope():
    body = json.dumps({"text": "Hola mundo", "from": "es", "to": "en"},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    header = {
        "v": envelope.VERSION,
        "id": IDS["request"],
        "from": DIDS["alice"],
        "to": DIDS["bob"],
        "type": "request",
        "ts": TS,
        "ttl": TTL,
        "content_type": "application/json",
        "body_hash": envelope.body_hash(body),
    }
    return envelope.sign_envelope(header, SEEDS["alice"]), body


def _response_envelope():
    body = json.dumps({"text": "Hello world"}, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    header = {
        "v": envelope.VERSION,
        "id": IDS["response"],
        "from": DIDS["bob"],
        "to": DIDS["alice"],
        "type": "response",
        "ts": TS + 412,
        "ttl": TTL,
        "content_type": "application/json",
        "body_hash": envelope.body_hash(body),
        "corr": IDS["request"],
    }
    return envelope.sign_envelope(header, SEEDS["bob"]), body


def _announce_envelope():
    descriptor = {
        "v": envelope.VERSION,
        "agent": DIDS["bob"],
        "name": "text-translator",
        "capabilities": [CAPABILITY],
        "endpoints": [{"transport": "https", "url": "https://bob.example.com/uip/v1"}],
    }
    body = codec.canonicalize(descriptor)
    header = {
        "v": envelope.VERSION,
        "id": IDS["announce"],
        "from": DIDS["bob"],
        "type": "announce",                       # the only type without a recipient
        "ts": TS - 5_000,
        "ttl": 3_600_000,
        "content_type": "application/uip-descriptor+json",
        "body_hash": envelope.body_hash(body),
    }
    return envelope.sign_envelope(header, SEEDS["bob"]), body


def _extension_envelope():
    """Shows that `x` is the only growth point and that it is signed."""
    body = b""
    header = {
        "v": envelope.VERSION,
        "id": IDS["event"],
        "from": DIDS["alice"],
        "to": DIDS["bob"],
        "type": "event",
        "ts": TS,
        "ttl": TTL,
        "content_type": "application/octet-stream",
        "body_hash": envelope.body_hash(body),
        "x": {"com.example.tracing": "abc-123"},
    }
    return envelope.sign_envelope(header, SEEDS["alice"]), body


def _sha384_envelope():
    """Hash agility: a stronger digest changes nothing structurally."""
    body = b"stronger digest"
    header = {
        "v": envelope.VERSION,
        "id": IDS["sha384"],
        "from": DIDS["alice"],
        "to": DIDS["bob"],
        "type": "event",
        "ts": TS,
        "ttl": TTL,
        "content_type": "application/octet-stream",
        "body_hash": envelope.body_hash(body, "sha384"),
    }
    return envelope.sign_envelope(header, SEEDS["alice"]), body


def vectors_envelopes():
    builders = [
        ("request", "Work request with a JSON body.", _request_envelope),
        ("response", "Response correlated with the request.", _response_envelope),
        ("announce", "Descriptor publication; the only type without `to`.", _announce_envelope),
        ("event with extension", "The `x` object is covered by the signature.", _extension_envelope),
        ("sha384 body hash", "Hash agility, same header shape.", _sha384_envelope),
    ]
    cases = []
    for name, description, build in builders:
        header, body = build()
        cases.append({
            "name": name,
            "description": description,
            "header": header,
            "body_utf8": body.decode("utf-8") if body else "",
            "body_hash": header["body_hash"],
            "signing_input_hex": envelope.signing_input(header).hex(),
            "signing_input_sha256": hashlib.sha256(envelope.signing_input(header)).hexdigest(),
            "now_ms": TS,
        })
    return {
        "spec": "UIP-1 section 7 - The envelope",
        "note": "`signing_input_hex` is exactly what gets signed: the domain separator "
                "followed by JCS(header without sig). An implementation producing any "
                "other bytes is not Uise.",
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 5. Envelopes that MUST be rejected
# --------------------------------------------------------------------------- #

class _Remove(object):
    def __repr__(self):
        return "<remove>"


REMOVE = _Remove()


def vectors_invalid():
    valid, body = _request_envelope()
    response, _ = _response_envelope()

    def mutate(**changes):
        out = dict(valid)
        for key, value in changes.items():
            if value is REMOVE:
                out.pop(key, None)
            else:
                out[key] = value
        return out

    unknown_hash = envelope.sign_envelope(
        dict(valid, body_hash="blake3:" + codec.b64u_encode(bytes(32))),
        SEEDS["alice"],
    )

    cases = [
        {
            "name": "unsupported version",
            "description": "A receiver must be able to reject without parsing the rest.",
            "code": "UIP_VERSION_UNSUPPORTED",
            "header": mutate(v="uip/2"),
        },
        {
            "name": "unknown root field",
            "description": "The root is closed; extensions belong in `x`.",
            "code": "UIP_HEADER_MALFORMED",
            "header": mutate(priority="high"),
        },
        {
            "name": "missing recipient",
            "description": "Only `announce` may omit `to`.",
            "code": "UIP_HEADER_MALFORMED",
            "header": mutate(to=REMOVE),
        },
        {
            "name": "response without correlation",
            "description": "`response` and `stream` must reference the request.",
            "code": "UIP_HEADER_MALFORMED",
            "header": {k: v for k, v in response.items() if k != "corr"},
        },
        {
            "name": "id is not a ulid",
            "description": "The identifier must be a time-ordered ULID.",
            "code": "UIP_HEADER_MALFORMED",
            "header": mutate(id="not-a-valid-ulid-xxxx"),
        },
        {
            "name": "ttl out of range",
            "description": "24 h maximum; it bounds the replay store.",
            "code": "UIP_HEADER_MALFORMED",
            "header": mutate(ttl=envelope.MAX_TTL_MS + 1),
        },
        {
            "name": "malformed sender did",
            "description": "`from` must parse as a did:key.",
            "code": "UIP_DID_INVALID",
            "header": mutate(**{"from": "did:key:zNotAValidKey"}),
        },
        {
            "name": "unsupported signature suite",
            "description": "Well formed DID, unknown algorithm. Never fall back to another.",
            "code": "UIP_SUITE_UNSUPPORTED",
            "header": mutate(**{"from": unknown_suite_did()}),
        },
        {
            "name": "unregistered hash algorithm",
            "description": "Signature is valid; the digest algorithm is not registered.",
            "code": "UIP_HASH_UNSUPPORTED",
            "header": unknown_hash,
        },
        {
            "name": "tampered signature",
            "description": "A single differing bit invalidates the signature.",
            "code": "UIP_SIG_INVALID",
            "header": mutate(sig="A" + valid["sig"][1:]),
        },
        {
            "name": "tampered body hash",
            "description": "Mutating any field breaks the signature: no field is editable.",
            "code": "UIP_SIG_INVALID",
            "header": mutate(body_hash=envelope.body_hash(b"different content")),
        },
        {
            "name": "expired envelope",
            "description": "now > ts + ttl.",
            "code": "UIP_EXPIRED",
            "header": dict(valid),
            "now_ms": TS + TTL + 1,
        },
        {
            "name": "clock skew",
            "description": "ts outside the plus/minus 300 s window.",
            "code": "UIP_CLOCK_SKEW",
            "header": dict(valid),
            "now_ms": TS + envelope.CLOCK_SKEW_MS + 1,
        },
        {
            "name": "replay",
            "description": "The same id was already received inside the window.",
            "code": "UIP_REPLAY",
            "header": dict(valid),
            "now_ms": TS,
            "seen_ids": [IDS["request"]],
        },
        {
            "name": "body does not match",
            "description": "Signature is valid but the delivered body is not the signed one.",
            "code": "UIP_BODY_HASH_MISMATCH",
            "header": dict(valid),
            "now_ms": TS,
            "body_utf8": "substituted content",
        },
    ]
    return {
        "spec": "UIP-1 sections 7.4 and 12 - Verification and errors",
        "note": "These are the most important vectors in the standard: they define what "
                "every implementation MUST reject. Accepting any of them is a "
                "conformance failure.",
        "reference_body_utf8": body.decode("utf-8"),
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 6. Receipts
# --------------------------------------------------------------------------- #

def vectors_receipt():
    base = {
        "v": envelope.VERSION,
        "rid": IDS["rid"],
        "request_id": IDS["request"],
        "response_id": IDS["response"],
        "payer": DIDS["alice"],
        "payee": DIDS["bob"],
        "capability": "translate.text",
        "amount": "0.0004",
        "unit": "USD",
        "terms_hash": envelope.terms_hash(CAPABILITY),
        "issued_at": TS + 1_864,
        "issuer": DIDS["issuer"],
        "settlement": None,
        "anchor": None,
    }
    all_keys = {"payer": SEEDS["alice"], "payee": SEEDS["bob"], "issuer": SEEDS["issuer"]}

    complete = envelope.sign_receipt(base, all_keys)
    partial = dict(complete, sigs={k: v for k, v in complete["sigs"].items() if k != "issuer"})
    settled = envelope.sign_receipt(
        dict(base, settlement={"at": TS + 90_000, "ref": "batch-2026-08-09-0001"}),
        all_keys,
    )

    # Anchoring happens after signing, so the signatures stay identical: the log
    # can add proof of existence but can never alter what the parties agreed to.
    anchored = dict(complete, anchor={
        "log": "https://log.example.com/2026",
        "index": 918273645,
        "tree_size": 918273700,
        "root": codec.multihash(b"merkle root placeholder", "sha384"),
        "inclusion_proof": [
            codec.multihash(b"sibling-0", "sha384"),
            codec.multihash(b"sibling-1", "sha384"),
        ],
    })

    return {
        "spec": "UIP-1 section 10 - Receipt",
        "note": "The receipt is the primitive that distinguishes UIP. `terms_hash` anchors "
                "the price to the descriptor in force, making renegotiation after "
                "delivery cryptographically impossible. A receipt with fewer than three "
                "signatures proves intent, not obligation.",
        "capability": CAPABILITY,
        "signing_input_hex": envelope.receipt_signing_input(base).hex(),
        "cases": [
            {"name": "complete receipt", "valid": True, "receipt": complete},
            {"name": "settled receipt", "valid": True, "receipt": settled},
            {
                "name": "anchored receipt",
                "description": "Signatures are byte-identical to the unanchored receipt.",
                "valid": True,
                "receipt": anchored,
            },
            {
                "name": "partial receipt without issuer",
                "valid": False,
                "code": "UIP_RECEIPT_INCOMPLETE",
                "receipt": partial,
            },
            {
                "name": "floating point amount",
                "valid": False,
                "code": "UIP_HEADER_MALFORMED",
                "receipt": dict(complete, amount=0.0004),
            },
        ],
        "issuer_policy": {
            "description": "Public network policy of section 4.4: an issuer must sign with "
                           "a suite sound for long-term evidence, because a receipt is "
                           "permanent evidence and a suite broken in twenty years "
                           "retroactively forges every receipt issued under it.",
            "code": "UIP_ISSUER_NOT_ELIGIBLE",
            "receipt": complete,
            "issuer_suite": suites.ED25519.name,
            "issuer_long_term_evidence": suites.ED25519.long_term_evidence,
        },
    }


def main():
    os.makedirs(VECTORS_DIR, exist_ok=True)
    print("Generating normative UIP-1 vectors...")
    write("suites.json", vectors_suites())
    write("did_key.json", vectors_did())
    write("jcs.json", vectors_jcs())
    write("envelope.json", vectors_envelopes())
    write("invalid.json", vectors_invalid())
    write("receipt.json", vectors_receipt())
    print("Done.")


if __name__ == "__main__":
    main()
