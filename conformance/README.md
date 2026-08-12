# UIP-1 Conformance Suite

**This suite, not the prose of the specification, is the operative definition of the protocol.**

Prose is interpreted differently by every organization, and in two years that yields five
incompatible versions of the same standard. That is how protocols die. Expected bytes cannot be
interpreted: either your implementation produces exactly these bytes, or it is not Uise.

Where `spec/uip-1.md` and `conformance/vectors/` disagree, **the vectors prevail**.

---

## Running the suite

Nothing to install. Python 3 standard library only.

```bash
python3 conformance/test_conformance.py
```

Or through the test discoverer:

```bash
python3 -m unittest discover -s conformance -v
```

### Why zero dependencies

A conformance suite that requires installing libraries is a conformance suite nobody runs, and a
standard nobody verifies stops being a standard. The cryptography in `uipref/` is pure Python and
deliberately slow: it favours being auditable line by line. **It is not for production** — the SDK
and the node use vetted, constant-time libraries.

---

## Layout

| Path | Purpose |
|---|---|
| `vectors/*.json` | **The normative vectors.** The source of truth for the protocol. |
| `test_conformance.py` | The examination. 36 tests across every primitive. |
| `generate_vectors.py` | Regenerates the vectors. Fully deterministic. |
| `uipref/` | Minimal reference implementation, standard library only. |

### The vectors

| File | Spec | Contents |
|---|---|---|
| `suites.json` | §4 | Registered algorithms, and a DID naming an unknown suite that MUST be rejected. |
| `did_key.json` | §3 | Seed → public key → DID. Identity with no network and no registry. |
| `jcs.json` | §5 | Byte-exact canonicalization, including UTF-16 code unit ordering. |
| `envelope.json` | §7 | Valid envelopes with the exact bytes that get signed. |
| `invalid.json` | §7.4, §12 | **What every implementation MUST reject**, with its error code. |
| `receipt.json` | §10 | Tripartite receipts: complete, settled, anchored, partial, and issuer policy. |

`invalid.json` is the most important file in the standard. Accepting any of those envelopes is a
conformance failure.

---

## External validation

The Ed25519 in `uipref/` is checked against the **official RFC 8032 §7.1 test vectors**: public key,
signature bytes, verification, and rejection of a tampered signature. All three cases match.
Self-consistent but incorrect cryptography would make Uise unable to interoperate with any other
implementation on earth, so self-validation alone is not accepted here.

Vectors regenerate byte for byte. If a code change produces different vectors, that change breaks
the protocol — and the diff makes it visible before it is ever published.

---

## Cryptographic agility

The envelope never names an algorithm. The multicodec prefix inside the sender's DID does. Adding a
post-quantum algorithm therefore adds a registry entry and a new DID — **never a new protocol
version**.

Two rules are enforced by tests:

1. **An unknown suite is rejected, never approximated.** There is no fallback path, because a
   fallback is a downgrade attack (`UIP_SUITE_UNSUPPORTED`).
2. **No multicodec codepoint is ever invented.** Only officially assigned values ship. A
   plausible-looking guess would permanently fragment the namespace, which is precisely the failure
   §4 exists to prevent. Suites awaiting assignment are specified normatively but are not
   wire-reachable.

Signature length is likewise never assumed: Ed25519 is 64 bytes, a composite post-quantum signature
is several thousand. A verifier that hardcodes 64 cannot interoperate with a post-quantum agent, so
both the schema and the implementation accept variable lengths.

---

## Conformance levels

| Level | Requires |
|---|---|
| **Core** | §3, §4, §5, §6, §7, §8, §11.1 — identity, suites, envelope, signing, verification, HTTPS. |
| **Discovery** | Core + §9 — Capability Descriptor and `announce`. |
| **Value** | Discovery + §10 — receipts, tripartite signatures, and issuer suite policy (§4.4). |

Only **Value** level may participate in the value plane of the public Uise network.

---

## Certifying another implementation

The vectors are plain JSON with nothing Python-specific about them. Any language can read them.
To certify an implementation in Go, Rust, or TypeScript:

1. Derive the DIDs in `did_key.json` from their seeds. They must match exactly.
2. Canonicalize the inputs in `jcs.json`. Compare against `canonical_hex`.
3. Reconstruct `signing_input_hex` for every envelope in `envelope.json`. **Byte for byte.**
4. Verify every valid envelope, and reject every case in `invalid.json` with its exact code.
5. Verify the receipts in `receipt.json`, reject the partial one, and reject an ineligible issuer
   when enforcing network policy.

If all five pass, the implementation conforms. If not, it does not. There is no grey area.
