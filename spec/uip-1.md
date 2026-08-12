# UIP-1 — Uise Interoperability Protocol, Version 1

**Status:** Normative draft
**Envelope version:** `uip/1`
**Date:** 2026-08-09
**License:** Apache License 2.0 (with patent grant)

---

## 1. Scope

UIP defines how autonomous software agents identify each other, discover each other's
capabilities, exchange cryptographically verifiable messages, and **certify the economic value**
of work performed between them.

UIP separates traffic into two planes with deliberately different properties:

- **Conversation plane.** Messages between agents. They travel **directly from agent to agent**.
  No Uise infrastructure participates. Unbounded volume by design.
- **Value plane.** Receipts certifying delivered work and the resulting obligation. They require
  an **issuer** signature (§10). Volume is orders of magnitude smaller.

This separation is not an implementation detail. It is the property that removes any ceiling on
network size: an extension that places a global component on the critical path of the conversation
plane violates this document.

### 1.1 Out of scope

UIP does not define the semantic content of payloads, agent internals, the final payment mechanism
(bank transfer, stablecoin, credit line), or the reputation system. Those are built *on top of* UIP.

---

## 2. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **SHOULD NOT**, **MAY**
and **OPTIONAL** are to be interpreted as described in RFC 2119 and RFC 8174.

| Term | Definition |
|---|---|
| **Agent** | Autonomous process holding a private signing key. Its identity *is* its public key. |
| **Envelope** | Atomic transmission unit: a signed header plus an optional body. |
| **Header** | The part of the envelope that is signed. Small, canonical, fully specified here. |
| **Body** | Opaque bytes. UIP never interprets them. |
| **Suite** | A named cryptographic algorithm binding (§4). |
| **Issuer** | Agent authorized to sign receipts. On the public Uise network, a settlement node. |
| **Node** | A UIP implementation offering discovery, relay and/or issuance. |

---

## 3. Identity

### 3.1 Method

An agent **MUST** be identified by a `did:key` DID (W3C DID Core), whose multibase-encoded value
carries a multicodec prefix identifying the signature suite, followed by the public key.

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK    (Ed25519)
```

Deliberate properties of this choice:

- **No network.** Verifying an identity requires no server lookup. The public key is contained in
  the identifier itself.
- **No registry.** No authority issues identities. An agent exists by generating a key.
- **No ledger.** No consensus, no gas, no block latency on the critical path.
- **No ceiling.** Identities can be created without bound and without coordination.

An agent **MAY** additionally publish a resolvable DID (`did:web`, `did:webvh`) binding it to an
organization. That binding is an optional trust layer and **MUST NOT** be a precondition for
sending or receiving messages.

### 3.2 The DID determines the algorithm

The multicodec prefix inside the DID **fully determines** the signature suite used by that agent.
There is no algorithm field in the envelope, and there **MUST NOT** be one.

This is the mechanism that makes UIP survive cryptographic change: identity and algorithm are the
same declaration. Migrating to a new algorithm produces a new DID, not a new protocol version.

A verifier **MUST** reject an envelope whose `from` DID uses a suite it does not implement, with
`UIP_SUITE_UNSUPPORTED`. It **MUST NOT** fall back to a different suite under any circumstance.

### 3.3 Key rotation

Rotating a key produces a different agent. UIP-1 defines no identity continuity across keys; that
belongs to the registry layer (out of scope). An agent requiring continuity **SHOULD** use
`did:web` and publish its active `did:key` values.

---

## 4. Cryptographic suites and agility

### 4.1 Threat model for algorithm lifetime

Envelopes and receipts have fundamentally different lifetimes, and therefore different requirements:

| | Envelope | Receipt |
|---|---|---|
| Maximum validity | 24 hours (`ttl`) | Indefinite — it is permanent evidence |
| Consequence if the algorithm breaks in year *N* | None; every envelope has long expired | **Receipts from year 1 become forgeable retroactively** |
| Post-quantum requirement | Migration before cryptographically relevant quantum computers exist | **Required now, for evidence created today** |

A receipt is a legal proof that must remain unforgeable for decades. A signature scheme broken in
2040 does not merely stop working — it retroactively destroys the integrity of every receipt ever
issued under it. This asymmetry drives the policy in §4.4.

### 4.2 Suite registry

| Suite | Multicodec | Public key | Signature | Long-term evidence | Status |
|---|---|---|---|---|---|
| `Ed25519` | `0xed` **(assigned)** | 32 B | 64 B | **No** | **REQUIRED** — every implementation MUST implement it |
| `ML-DSA-65` | `0x1f0065` *(provisional)* | 1952 B | 3309 B | Yes | RECOMMENDED |
| `Ed25519+ML-DSA-65` | `0x1f0165` *(provisional)* | 1984 B | 3373 B | **Yes** | **REQUIRED for issuers** (§4.4) |
| `SLH-DSA-SHA2-128s` | *not allocated* | 32 B | 7856 B | Yes | OPTIONAL — hash-based fallback |

Sizes for ML-DSA follow FIPS 204 and for SLH-DSA follow FIPS 205. An implementation **MUST** verify
these sizes against its cryptographic library at startup: a silent upstream change would corrupt
every DID it produces.

#### Provisional codepoints

Multicodec codepoints for the post-quantum suites are not yet assigned. UIP therefore allocates
placeholders in a self-scoped provisional range beginning at `0x1f0000`, subject to these rules:

- A suite on a provisional codepoint **MUST** be flagged as provisional wherever it is reported, and
  **MUST NOT** be treated as interoperable across organizations.
- Provisional codepoints **MUST** be replaced with assigned values before UIP-1 reaches 1.0.
- An implementation **MUST NOT** present an invented codepoint as an assignment, and **MUST NOT**
  guess a value for a suite it has not implemented. Shipping a plausible-looking identifier as
  though it were registered would permanently fragment the namespace — the exact failure this
  section exists to prevent.

### 4.3 Composite (hybrid) signatures

A composite suite carries two independent signatures over the same input, concatenated in the
order declared by the suite, with fixed component lengths:

```
Ed25519+ML-DSA-65 signature = ed25519_sig (64 B) || mldsa65_sig (3309 B)
Ed25519+ML-DSA-65 public key = ed25519_pk (32 B) || mldsa65_pk (1952 B)
```

Verification **MUST** require **both** component signatures to validate. A composite signature
where either component fails is invalid.

Rationale: a composite protects against two distinct risks at once — a future quantum attack on
the classical component, and an as-yet-undiscovered flaw in the newer lattice construction. This
follows current IETF and NIST transition guidance. Relying on a single post-quantum algorithm
alone trades one single point of failure for another.

### 4.4 Network policy

The protocol is algorithm-agnostic. The **public Uise network** applies the following policy, which
implementations serving that network **MUST** enforce:

| Role | Permitted suites |
|---|---|
| Conversation plane (`from` on any envelope) | Any registered suite, including `Ed25519` |
| **Issuer** (`issuer` field of a receipt, §10) | **Only suites marked "Long-term evidence: Yes"** |
| Payer and payee signatures on a receipt | Any registered suite |

Issuers carry the permanence guarantee, so issuers carry the post-quantum requirement. Ordinary
agents are not forced to adopt large signatures for ephemeral traffic — a 3 KB signature on every
message would tax the conversation plane for no security benefit, given a 24-hour `ttl`.

### 4.5 Hash agility

Hashes are expressed as `<algorithm>:<base64url>`. Registered algorithms:

| Prefix | Algorithm | Digest | Post-quantum margin |
|---|---|---|---|
| `sha256:` | SHA-256 | 32 B | 128-bit against Grover — **sufficient** |
| `sha384:` | SHA-384 | 48 B | 192-bit — RECOMMENDED for receipt anchoring |
| `sha512:` | SHA-512 | 64 B | 256-bit |

Every implementation **MUST** implement `sha256:` and **MUST** reject unregistered prefixes with
`UIP_HASH_UNSUPPORTED`. Grover's algorithm halves the effective security of a hash function; it
does not break it. SHA-256 remains sound for `body_hash`.

---

## 5. Canonical encoding

Signing requires deterministic bytes: two implementations serializing the same structure
differently would produce signatures that fail to validate against each other, and that failure is
silent and permanent.

- The **header** **MUST** be serialized with **JSON Canonicalization Scheme (JCS, RFC 8785)** before
  being signed or verified.
- The **body** is **NOT** canonicalized. It is an opaque byte sequence; the signature covers it
  through its hash (§7.3).

Design consequence: canonicalization applies only to a small structure fully specified in this
document. Payloads may be JSON, binary, compressed or streamed without affecting verification.

> **Design note.** MessagePack was evaluated and rejected for the header: it has no standardized
> canonical form, which would guarantee cross-implementation signature failures. Payload compression
> is a transport concern (§11), not a protocol concern.

---

## 6. Numbers and monetary values

Every monetary amount **MUST** be represented as a **decimal string**, never a JSON number.

```
"amount": "0.0025"
```

- Format: `^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$`
- **MUST NOT** be negative. Direction of value is expressed by `payer` / `payee`.
- Implementations **MUST** use exact decimal arithmetic. Using binary floating point for money is a
  conformance defect.

This permits sub-cent amounts (`"0.000001"`) without precision loss.

---

## 7. The envelope

### 7.1 Structure

```json
{
  "v": "uip/1",
  "id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
  "from": "did:key:z6Mkha...",
  "to": "did:key:z6MkjR...",
  "type": "request",
  "ts": 1754745600123,
  "ttl": 30000,
  "content_type": "application/json",
  "body_hash": "sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  "corr": "01K2R7XQ0A0000000000000000",
  "sig": "3yfs2c9Kx1QmPd7RtLbVwEaHnZjUgYo4Bs6TeXvCiMkA_pW8rNqDfGhJlSzOu2Y0cX5vB1nT9eKdRmQwLpZaHg"
}
```

### 7.2 Header fields

| Field | Type | Req. | Definition |
|---|---|---|---|
| `v` | string | **MUST** | Protocol version. Exactly `"uip/1"` in this specification. |
| `id` | string | **MUST** | ULID in Crockford base32. Unique per envelope, time-ordered. |
| `from` | string | **MUST** | DID of the signer. Determines the signature suite (§3.2). |
| `to` | string | **MAY** | DID of the recipient. Absent means broadcast; valid only for `announce`. |
| `type` | string | **MUST** | One of the types in §8. |
| `ts` | integer | **MUST** | Milliseconds since the UTC epoch at signing time. |
| `ttl` | integer | **MUST** | Validity in milliseconds from `ts`. Maximum 86 400 000 (24 h). |
| `content_type` | string | **MUST** | Media type of the body (RFC 6838), or `application/octet-stream`. |
| `body_hash` | string | **MUST** | Hash of the body (§4.5). An absent body hashes the empty string. |
| `corr` | string | **MAY** | `id` of the envelope this correlates with. Required for `response` and `stream`. |
| `x` | object | **MAY** | Extensions (§14). Covered by the signature. |
| `sig` | string | **MUST** | Signature (§7.3), base64url without padding. **Length varies by suite.** |

A receiver **MUST** reject any envelope carrying unknown root fields. The root is closed; all future
growth enters through `x`.

> **Design note.** An earlier draft carried a `nonce` field. It was removed: `id` is already unique
> per envelope and Ed25519 signatures are deterministic, so `nonce` defended against nothing. A
> redundant field in a frozen format is permanent debt.

### 7.3 Signing

The body is never signed directly; its hash is, inside the header.

```
unsigned  = header with the "sig" field absent
input     = UTF8("uip/1.envelope\n") || JCS(unsigned)
sig       = base64url_unpadded( Sign(suite_of(from), private_key, input) )
```

The `uip/1.envelope\n` prefix is **domain separation**: it prevents a signature produced for UIP
from being replayed into another protocol using the same key, and vice versa.

The length of `sig` is determined by the suite and **MUST NOT** be assumed by implementations. A
verifier that hardcodes a 64-byte signature cannot interoperate with a post-quantum agent.

### 7.4 Verification

A receiver **MUST** perform these checks, in this order, and discard the envelope if any fails:

1. `v` is exactly `"uip/1"`.
2. The header carries no unknown root fields, and all required fields are present and well-typed.
3. `from` is a syntactically valid DID; the suite is resolved from its multicodec and the public key
   extracted. An unimplemented suite fails with `UIP_SUITE_UNSUPPORTED`.
4. `sig` validates against the input of §7.3 under that suite.
5. `|ts − now|` ≤ 300 000 ms (clock skew, §7.5).
6. `now` ≤ `ts + ttl`.
7. `id` has not been seen within the replay window (§7.5).
8. If the body is present: its hash equals `body_hash`.

Order matters: cheap checks precede signature verification, except those that depend on the
signature to be meaningful. Verifying the signature before touching the body ensures unauthenticated
bytes are never processed.

### 7.5 Replay

A receiver **MUST** retain seen `id` values for at least `ttl + 300 000 ms` and reject duplicates.
Since `ttl` is bounded to 24 h, this store is bounded.

The replay store is **local to each receiver by design**. A globally shared replay store would be
precisely the global component on the critical path that §1 forbids.

---

## 8. Message types

| `type` | Direction | Description |
|---|---|---|
| `announce` | broadcast | Publishes the agent's Capability Descriptor (§9). The only type without `to`. |
| `request` | A → B | Request to execute a capability. |
| `response` | B → A | Result. **MUST** carry `corr` referencing the request. |
| `event` | A → B | One-way notification; no response expected. |
| `stream` | A → B | Fragment of a streamed response. **MUST** carry `corr`. |
| `receipt` | issuer → parties | Certification of work and obligation (§10). |
| `error` | either | Failure. Body conforms to §12. **MUST** carry `corr` where applicable. |

---

## 9. Capability Descriptor

How an agent declares what it can do, in a form **another agent** can read without human
involvement. Transmitted as the body of an `announce` envelope with
`content_type: "application/uip-descriptor+json"`.

```json
{
  "v": "uip/1",
  "agent": "did:key:z6Mkha...",
  "name": "text-translator",
  "description": "Translates text between two languages, preserving formatting.",
  "capabilities": [
    {
      "id": "translate.text",
      "description": "Translates a text between two languages.",
      "input_schema":  { "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object" },
      "output_schema": { "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object" },
      "price": { "amount": "0.0004", "unit": "USD", "per": "call" },
      "sla":   { "p95_ms": 800, "availability": "0.999" }
    }
  ],
  "endpoints": [
    { "transport": "https", "url": "https://agent.example.com/uip/v1" }
  ],
  "expires": 1754832000000
}
```

- `input_schema` and `output_schema` **MUST** be JSON Schema draft 2020-12. A receiving agent
  **MUST** be able to validate its requests against them with no prior knowledge.
- `price.per` **MUST** be one of `"call"`, `"token"`, `"second"`, `"byte"`.
- An absent `price` means free. A present `price` is an **offer**, not a contract: the contract is
  formed by the receipt (§10).
- The descriptor travels inside a signed envelope, so its authenticity follows from §7.3. It carries
  no signature of its own.

### 9.1 Interoperability with MCP and A2A

An implementation **SHOULD** offer bidirectional conversion. Thousands of agents already exist in
these formats; a bridge makes them participants without their authors rewriting anything.

**MCP** (`tools/list` tool object):

| MCP | UIP capability |
|---|---|
| `name` | `id`, normalized; original preserved in `x` when normalization changes it |
| `title` | `x` extension — UIP has no separate display name |
| `description` | `description` |
| `inputSchema` | `input_schema` |
| `outputSchema` | `output_schema`; when absent, the MCP result shape (`content`, `isError`) |
| `annotations` | **dropped** — MCP itself calls them untrusted, and UIP trusts only signatures |

**A2A** (AgentCard / AgentSkill):

| A2A | UIP |
|---|---|
| AgentCard `name`, `description` | Descriptor `name`, `description` |
| AgentCard `interfaces[].url` | `endpoints[]` |
| AgentSkill `id` | Capability `id`, normalized; original preserved in `x` |
| AgentSkill `name` | `x` extension |
| AgentSkill `inputSchema` / `outputSchema` | `input_schema` / `output_schema` |
| Descriptor `agent` (a DID) | AgentCard `id` — a DID is already globally unique and self-verifying |

#### Rules

- An identifier that does not survive normalization **MUST** be preserved under the capability's
  `x` extension. A bridge that silently renames a tool is non-conforming: the round trip must
  return the original document, not a plausible approximation.
- A bridge **MUST NOT** invent field names for a format it cannot verify. Omitting a field is
  recoverable; a wrong field name that looks authoritative is not.

#### The declared gap

Conversion is lossy in one direction, and that loss is the point: **neither MCP nor A2A carries
price, SLA, or settlement.** An agent crossing into UIP gains a cryptographic identity, verifiable
messages and receipts. Crossing back, those are dropped, because the destination has nowhere to put
them. If either format could express them, UIP would be a profile of that format rather than a
protocol.

---

## 10. Receipt

The receipt is the primitive that distinguishes UIP. It certifies that work was requested,
delivered, and what obligation it created. Carried as the body of a `receipt` envelope with
`content_type: "application/uip-receipt+json"`.

```json
{
  "v": "uip/1",
  "rid": "01K2R7Y3B8QW5ZM1P4K7DXCVGN",
  "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
  "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
  "payer": "did:key:z6Mkha...",
  "payee": "did:key:z6MkjR...",
  "capability": "translate.text",
  "amount": "0.0004",
  "unit": "USD",
  "terms_hash": "sha256:qZk-NkcGgWq6PiVxeFDCbJz...",
  "issued_at": 1754745601987,
  "issuer": "did:key:z6MkpL...",
  "settlement": null,
  "anchor": null,
  "sigs": {
    "payer":  "2Nf8qLxV...",
    "payee":  "5Kw1TpRb...",
    "issuer": "9Tb4mZcE..."
  }
}
```

### 10.1 Fields

| Field | Req. | Definition |
|---|---|---|
| `rid` | **MUST** | Unique ULID of the receipt. |
| `request_id` / `response_id` | **MUST** | `id` of the envelopes that created the obligation. Bind the receipt to real work. |
| `payer` / `payee` | **MUST** | DIDs. The direction of value. |
| `capability` | **MUST** | `id` of the executed capability. |
| `amount` / `unit` | **MUST** | Decimal-string amount (§6). `unit`: ISO 4217 (`"USD"`) or token symbol (`"USDC"`). |
| `terms_hash` | **MUST** | Hash of the `capabilities[i]` object in force at request time. Anchors the agreed price. |
| `issued_at` | **MUST** | Epoch ms of issuance. |
| `issuer` | **MUST** | DID of the issuer. **MUST** use a long-term-evidence suite (§4.4). |
| `settlement` | **MUST** | `null` while pending; otherwise `{ "at": <epoch_ms>, "ref": "<string>" }`. |
| `anchor` | **MUST** | `null` until logged; otherwise a transparency-log inclusion proof (§10.4). |
| `sigs` | **MUST** | Signatures of all three parties (§10.2). |

### 10.2 Tripartite signature

Each signature covers the receipt **without the `sigs` object**, canonicalized with JCS, under its
own domain separator:

```
input = UTF8("uip/1.receipt\n") || JCS(receipt without "sigs")
```

A receipt is **valid** only with all three signatures: `payer`, `payee` and `issuer`.

- `payer` signs that it requested the work under those terms.
- `payee` signs that it delivered.
- `issuer` signs that it verified both and recorded the obligation.

A receipt with one or two signatures is a **partial receipt**: it proves intent, not obligation.
This is the basis of the dispute flow (out of scope in UIP-1).

Because `anchor` is part of the signed structure and is `null` at signing time, anchoring produces a
second document: the anchored receipt is `sigs` plus the proof, and verification of the signatures
is performed against the receipt with `anchor` set to `null`. This keeps signing and logging
independent, so the log can never alter what the parties agreed to.

### 10.3 Why the receipt is in the core

A protocol can add message types later; it **cannot** add a value primitive later without splitting
the network into agents that understand it and agents that do not. That is why the receipt is in
UIP-1 rather than an extension.

It is also the only part of the protocol with a defensible position: anyone can relay messages, but
a receipt is only worth anything if both parties accept the issuer. Being the accepted issuer is the
business.

### 10.4 Transparency log

An issuer **SHOULD** publish every issued receipt into an append-only Merkle tree log following the
construction of RFC 6962 (Certificate Transparency).

```json
"anchor": {
  "log": "https://log.example.com/2026",
  "index": 918273645,
  "tree_size": 918273700,
  "root": "sha384:...",
  "inclusion_proof": ["sha384:...", "sha384:..."]
}
```

This provides two properties no signature can provide on its own:

1. **Survives cryptographic breakage.** Merkle proofs rest only on hash functions, which remain
   sound against quantum adversaries (§4.5). A receipt whose signature suite is broken in 2040 still
   has a verifiable proof that it existed, unmodified, at a specific point in the log.
2. **Removes the need to trust the issuer.** Anyone can audit that the issuer never issued a
   contradictory receipt and never removed one. Trust is replaced by verification — the same
   mechanism that lets browsers trust the public certificate ecosystem.

Verifiers **MUST** treat `anchor` as advisory for signature validity and authoritative for
existence and ordering.

The tree follows RFC 6962 §2.1 exactly:

```
MTH({})     = HASH()
MTH({d0})   = HASH(0x00 || d0)
MTH(D[n])   = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))    k = largest power of two < n
```

The distinct `0x00` and `0x01` prefixes are **required**: without them an interior node could be
replayed as a leaf, forging an inclusion proof for data that was never logged.

A log entry is `JCS(receipt with anchor set to null)`, signatures included. One entry therefore
proves both what was agreed and who agreed to it. Logs **SHOULD** use `sha384`, since an entry is
meant to outlive every signature suite in use today.

### 10.5 Signed tree head

An issuer **MUST** publish a signed commitment to the whole log:

```json
{
  "v": "uip/1",
  "log": "https://log.example.com/2026",
  "issuer": "did:key:z6MkpL...",
  "tree_size": 918273700,
  "root": "sha384:...",
  "timestamp": 1754745602000,
  "sig": "..."
}
```

```
input = UTF8("uip/1.sth\n") || JCS(head without "sig")
```

An auditor pins one tree head, returns later, and requests a **consistency proof** between the two
sizes. If it verifies, nothing in between was rewritten or removed. This is what replaces trusting
the issuer: misbehaviour becomes detectable by anyone, not merely prohibited.

An issuer **MUST NOT** log the same `rid` twice. A log that can contain one obligation twice is not
evidence.

### 10.6 Log API

| Operation | Endpoint |
|---|---|
| Signed tree head | `GET /uip/v1/log/sth` |
| Inclusion proof for a receipt | `GET /uip/v1/log/proof?rid=<rid>` |
| Consistency proof between sizes | `GET /uip/v1/log/consistency?first=<n>&second=<m>` |
| Entry range, for auditing | `GET /uip/v1/log/entries?start=<n>&end=<m>` |
| Capability discovery | `GET /uip/v1/discover?capability=<id>` |

All are read-only, unauthenticated and free. An issuer that restricts access to its own log has
published nothing: the point of the log is that adversaries can read it.

---

## 11. Transport

UIP is transport-agnostic. The **same envelope** travels over every binding.

### 11.1 HTTPS (normative, mandatory)

Every conforming implementation **MUST** support this binding.

The `/uip/v1` path prefix is reserved for this specification. An implementation
**MUST NOT** place endpoints of its own beneath it — billing, administration,
metrics, or anything else outside this document. The prefix identifies a frozen
standard; anything sharing it inherits that freeze, and an operator's commercial
surface must be free to change.

| Operation | Method and path |
|---|---|
| Send envelope | `POST /uip/v1/envelope` · `Content-Type: application/uip+json` |
| Receive stream | `GET /uip/v1/stream` · `Accept: text/event-stream` |
| Own descriptor | `GET /uip/v1/descriptor` |

- The HTTP body is a JSON object carrying the header at the root and the envelope body in exactly
  one of two fields:
  - `body_b64` — base64url without padding. The decoded bytes **are** the body, verbatim.
  - `body` — a JSON value. The body bytes are **JCS(body)**, so that a parse-and-reserialize round
    trip cannot change what `body_hash` covers.

  A frame carrying both fields, or neither, **MUST** be rejected with `UIP_HEADER_MALFORMED`.
  Without this rule two implementations could disagree on which bytes were signed, which is a
  silent interoperability failure of exactly the kind §5 exists to prevent.
- The server **MUST** answer `202 Accepted` for a valid envelope accepted for asynchronous
  processing, or `200 OK` with a `response` envelope for synchronous processing.
- TLS 1.3 is **REQUIRED**. Implementations **SHOULD** negotiate a hybrid post-quantum key exchange
  (for example `X25519MLKEM768`) where available: recorded traffic is subject to
  harvest-now-decrypt-later, so confidentiality must be post-quantum *today*, unlike signatures.
- Compression is a transport concern: `Content-Encoding: gzip`. It **SHOULD NOT** be applied to
  bodies under 1 KiB, where it adds latency without useful gain.

### 11.2 SSE — streaming

Each SSE event carries one complete signed `stream` envelope whose `corr` equals the request `id`.
End of stream is signalled by a `response` envelope.

```
event: uip
data: {"v":"uip/1","id":"01K...","type":"stream","corr":"01K...", ...}
```

### 11.3 NATS and gRPC (optional)

- **NATS JetStream** — subject `uip.v1.<did without prefix>`. Provides guaranteed delivery,
  ordering and retries without bespoke logic.
- **gRPC** — service `uip.v1.Transport` with `Send(Envelope) → Ack` and
  `Subscribe(Filter) → stream Envelope`.

Both carry the envelope **unmodified**. An implementation that rewrites the header to suit a
transport is non-conforming: it would break the signature.

---

## 12. Errors

Body of an `error` envelope, `content_type: "application/uip-error+json"`:

```json
{ "code": "UIP_SIG_INVALID", "message": "Signature does not validate for the sender DID.", "detail": {} }
```

| Code | Meaning |
|---|---|
| `UIP_VERSION_UNSUPPORTED` | Unknown `v`. |
| `UIP_HEADER_MALFORMED` | Malformed header, or unknown root field. |
| `UIP_SUITE_UNSUPPORTED` | The signature suite named by the DID is not implemented. |
| `UIP_HASH_UNSUPPORTED` | Unregistered hash algorithm prefix. |
| `UIP_SIG_INVALID` | The signature does not validate. |
| `UIP_DID_INVALID` | `from` or `to` is not a valid DID. |
| `UIP_EXPIRED` | `now > ts + ttl`. |
| `UIP_CLOCK_SKEW` | `ts` outside the ±300 s window. |
| `UIP_REPLAY` | `id` already seen. |
| `UIP_BODY_HASH_MISMATCH` | The body does not match `body_hash`. |
| `UIP_SCHEMA_INVALID` | The body fails the declared `input_schema`. |
| `UIP_CAPABILITY_UNKNOWN` | The requested capability does not exist on this agent. |
| `UIP_RATE_LIMITED` | Rate limit exceeded. |
| `UIP_PAYMENT_REQUIRED` | The account cannot absorb the issuance fee within its credit limit. |
| `UIP_RECEIPT_INCOMPLETE` | The receipt lacks required signatures. |
| `UIP_ISSUER_NOT_ELIGIBLE` | The issuer's suite is not valid for long-term evidence (§4.4). |
| `UIP_TERMS_MISMATCH` | `terms_hash` does not match the descriptor in force. |
| `UIP_INTERNAL` | Receiver-side failure. |

An error message **MUST NOT** disclose key material or another agent's content.

---

## 13. Security considerations

1. **Zero trust.** No envelope is processed before its signature is verified. There is no notion of
   a trusted sender by network origin, IP, or session.
2. **Domain separation.** The `uip/1.envelope\n`, `uip/1.receipt\n` and `uip/1.sth\n` prefixes
   prevent a signature from one context being valid in another. The log's `0x00` and `0x01` node
   prefixes serve the same purpose inside the tree.
3. **No body canonicalization.** The body is authenticated by hash, never by re-serialization,
   eliminating an entire class of serialization-ambiguity attacks.
4. **Replay.** Mitigated by unique `id`, a clock window, and a local expiring store (§7.5).
   Deliberately local: a global store would be the global component §1 forbids.
5. **Denial of service.** A receiver **SHOULD** rate-limit **per DID**, and **MUST** enforce a
   maximum body size before hashing it.
6. **Confidentiality.** UIP signs but does not encrypt. Confidentiality is the transport's
   responsibility (§11.1), and it **must** be post-quantum today because recorded ciphertext can be
   decrypted later. Signatures have no such urgency for the conversation plane — but they do for
   receipts (§4.1).
7. **Algorithm downgrade.** A verifier **MUST NOT** accept a suite weaker than the one named in the
   DID, and **MUST NOT** fall back on failure. The DID is the sole authority on the algorithm.
8. **Key compromise.** Without a registry, a compromised `did:key` cannot be revoked within UIP-1.
   An agent requiring revocation **SHOULD** use `did:web` and publish its active keys.

---

## 14. Versioning and evolution

- `v` is exactly `"uip/1"`. An incompatible change produces `"uip/2"`.
- The root header fields are **frozen**. No new root fields will be added to `uip/1`.
- **A new cryptographic algorithm never produces a new protocol version.** It is a new entry in the
  suite registry (§4.2) and a new multicodec inside the DID. This is the single most important
  longevity property of the design.
- Extensions live in the optional header object `x`, keyed by reverse-namespace identifiers:
  `{"x": {"com.example.tracing": "..."}}`. `x` **is** covered by the signature.
- A receiver **MUST** ignore keys within `x` it does not recognize. This is the only exception to
  the unknown-field rejection rule of §7.2.

---

## 15. Conformance

An implementation is **UIP-1 conforming** if and only if it passes the suite in `conformance/`. That
suite, not this prose, is the operative definition of the protocol.

| Level | Requires |
|---|---|
| **Core** | §3, §4, §5, §6, §7, §8, §11.1 — identity, suites, envelope, signing, verification, HTTPS. |
| **Discovery** | Core + §9 — Capability Descriptor and `announce`. |
| **Value** | Discovery + §10 — receipts, tripartite signatures, and issuer suite policy (§4.4). |

Only **Value** level may participate in the value plane of the public Uise network.

---

## Appendix A — Test vectors

Normative vectors (keys, envelopes, signatures and hashes, byte for byte) live in
`conformance/vectors/`. **Where this document and the vectors disagree, the vectors prevail.**
