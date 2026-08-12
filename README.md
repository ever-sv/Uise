# Uise

[![CI](https://github.com/ever-sv/Uise/actions/workflows/ci.yml/badge.svg)](https://github.com/ever-sv/Uise/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Proof of what AI agents did.**

An agent books, buys, negotiates, delivers, spends. Then something goes wrong — the wrong
quantity, a price nobody agreed to, work that one side says was never delivered.

Today there is no evidence. There is a log file that either party can edit.

Uise is the layer that fixes that: a **receipt signed by every party involved**, anchored in an
**append-only log nobody can rewrite**, with cryptography built to hold up for decades.

- **UIP-1** — the protocol. Open, frozen, implementable by anyone.
- **`conformance/`** — the operative definition. Runs anywhere, with zero dependencies.
- **`uise/`** — the SDK and the node. Connect an agent in five lines.

---

## The receipt

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
  "anchor": { "log": "...", "index": 918273645, "inclusion_proof": ["..."] },
  "sigs": { "payer": "...", "payee": "...", "issuer": "..." }
}
```

Four properties, each doing real work:

| | |
|---|---|
| **Three signatures** | The requester signs that it asked, the worker signs that it delivered, the issuer signs that it verified both. One or two signatures prove intent; three prove obligation |
| **`terms_hash`** | The price agreed *before* the work, hashed. Renegotiating afterwards is cryptographically impossible |
| **`request_id` / `response_id`** | Bound to the actual messages. A receipt cannot exist for work that never happened |
| **`anchor`** | A Merkle inclusion proof. Existence and ordering, provable by a stranger |

`amount` may be `"0"`. A receipt with no money is pure evidence: *this was asked for, this was
delivered, both sides signed.*

---

## Quickstart

```bash
pip install -e ".[dev]"
```

Offer something:

```python
from uise import Agent

agent = Agent.generate(name="translator")

@agent.capability("translate.text", price="0.0004")
def translate(payload):
    return {"text": payload["text"].upper()}

agent.serve(port=8080)
```

Call it:

```python
from uise import Agent

client = Agent.generate()
print(client.call("http://localhost:8080", peer_did, "translate.text", {"text": "hola"}))
```

No account, no registration, no API key. Both agents exist because they hold a key.

See it end to end, including six blocked attacks:

```bash
python3 demo.py        # the conversation plane, nothing to install
python  demo_node.py   # issuance, anchoring, audit
```

---

## Nobody has to trust the issuer

Every receipt goes into an append-only Merkle log, following the RFC 6962 construction. The issuer
publishes a signed tree head.

An auditor pins one tree head, comes back later, asks for a **consistency proof**, and can prove
that nothing was rewritten or removed in between — using only a hash function.

**Misbehaviour becomes detectable, not merely prohibited.**

| Endpoint | |
|---|---|
| `GET /uip/v1/log/sth` | Signed tree head |
| `GET /uip/v1/log/proof?rid=` | Inclusion proof for one receipt |
| `GET /uip/v1/log/consistency?first=&second=` | Proof that history was not rewritten |
| `GET /uip/v1/log/entries?start=&end=` | Entry range, for auditing |

Read-only, unauthenticated, free. An issuer that restricts access to its own log has published
nothing.

---

## Built to outlive its own cryptography

Evidence has to hold up long after the algorithm that signed it:

| | Message | **Receipt** |
|---|---|---|
| Lifetime | 24 hours | Indefinite |
| If the algorithm breaks in 2040 | Nothing; it expired long ago | **Every receipt ever issued becomes forgeable in hindsight** |

So **the envelope never names an algorithm.** The signature suite is declared by the multicodec
prefix inside the sender's DID. Adding a post-quantum algorithm adds a registry entry and a new
DID — **never a new protocol version**.

Issuers sign with a composite **Ed25519 + ML-DSA-65** suite: two independent signatures, both
required. That hedges a future quantum attack on the classical half *and* an undiscovered flaw in
the newer lattice construction.

Two rules are enforced by tests, not convention:

1. **An unknown suite is rejected, never approximated.** A fallback is a downgrade attack.
2. **No multicodec codepoint is presented as assigned when it is not.** Post-quantum codepoints are
   still pending, so they live in a self-scoped provisional range and are flagged everywhere.

**No cryptography is hand-rolled here.** Ed25519 and ML-DSA come from `cryptography` (constant
time, NIST FIPS 204). Lattice schemes written by hand fail silently: they pass their own tests and
interoperate with nothing.

---

## The one architectural idea

Uise has two planes with deliberately different properties.

| | **Conversation plane** | **Value plane** |
|---|---|---|
| Carries | Agents negotiating, working, delivering | "This was done. X is owed to Y." |
| Route | **Directly agent to agent.** No Uise infrastructure | Through an issuer |
| Volume | Unbounded by design | A small fraction of messages |
| Cost | Zero | Charged |

**Nothing global sits on the critical path of a conversation.** That is not an optimization — it is
the property that removes any ceiling on how many agents the network can hold. HTTP scales to the
whole web because it has no central server; the conversation plane works the same way.

---

## Bridging agents that already exist

Thousands of agents are already built against MCP and A2A. Wrapping one costs a few lines and
changes nothing inside the agent:

```python
from uise.bridges import mcp

agent = mcp.bridge_agent(
    list_tools=client.list_tools,
    call_tool=client.call_tool,
    name="weather",
    price="0.0002",
)
agent.serve(port=8080)
```

That MCP server now has a cryptographic identity, signed messages, and receipts.

**The translation is lossy in one direction, and that is the point.** Neither MCP nor A2A carries
price, SLA, or settlement — there is nowhere in those formats to put them. If either could express
them, UIP would be a profile of that format rather than a protocol.

Identifiers that cannot survive translation are preserved under a namespaced `x` extension, so a
round trip returns the original document byte for byte. Field mappings were verified against the
published specifications, not recalled; where a field's shape could not be confirmed, the bridge
omits it rather than inventing a name that would look authoritative and be wrong.

---

## Running a node

```python
from uise import Node

node = Node(log_url="https://log.example.com", fee="0.0001")
node.serve(port=8443)
```

A node does three things: answers discovery queries, certifies what two parties already agreed, and
publishes the proof.

Two flows of money are kept strictly separate, because conflating them is what turns a protocol
company into an unlicensed bank:

| | What Uise charges | What agents owe each other |
|---|---|---|
| Who pays whom | A customer pays Uise for issuing a proof | One agent pays another |
| Uise's role | A software vendor billing for its service | **Records the obligation, never touches the money** |

Because a public key cannot be sent an invoice, every issuance is metered against a prepaid balance.
One mechanism covers three models: unmetered (launch phase — free, but recorded from day one),
strictly prepaid (agents), and a credit limit (organizations, where the negative balance *is* the
invoice).

**A company running a thousand agents funds one balance, not a thousand.** An account is either an
agent's own DID or an organization shared by many — a solo agent is an organization of one, so
nothing downstream needs to know which it is looking at.

Membership requires consent from **both** sides, and neither is trusted to assert it alone. The
organization proves consent by holding a `write` credential — it is taking on the cost. The agent
proves consent by **signing**, because joining can harm it too: one with its own funded balance
would start drawing on an account that may have none. An attestation is valid for five minutes: it
is a statement about now, not a standing permission, so a stale copy cannot re-enrol an agent that
has since left.

Leaving restores the agent's own balance, untouched. **Money is never moved implicitly**, in either
direction.

A deposit **records that money arrived; it never receives money.** The node holds no payment
credentials. The charge and its log entry are one transaction: a receipt is never issued without
being paid for, and never charged without being issued.

---

## The product API

| | `/uip/v1/*` | `/api/v1/*` |
|---|---|---|
| What it is | **The protocol.** Open, frozen | **The product.** Authenticated, free to evolve |
| Who implements it | Anyone | Only Uise |

Mixing them would make commercial endpoints part of the standard, and a standard cannot change once
others depend on it. The specification reserves the `/uip/v1` prefix for exactly this reason.

```
GET    /api/v1/health                     open, empty of business data
GET    /api/v1/openapi.json               the machine-readable contract
GET    /api/v1/events                     live stream, Server-Sent Events
GET    /api/v1/stats                      metrics
GET    /api/v1/receipts?after=&limit=     cursor pagination
GET    /api/v1/accounts/{account}/ledger  every movement, with its cause
POST   /api/v1/organizations              one balance, many agents
POST   /api/v1/organizations/{id}/members enrol an agent, with its signed consent
POST   /api/v1/keys                       mint a credential; shown once
DELETE /api/v1/keys/{key_id}              revoke, immediately
```

**Closed by default.** A node with no credential refuses to serve `/api/v1` at all rather than
serving it openly. Tokens are stored as digests, compared in constant time, and authentication is
checked *before* routing, so an anonymous caller cannot map the surface by noting which paths
answer 404 and which answer 401. Scopes never imply one another.

Agents never use tokens. They sign every message, which a stolen log line cannot reproduce.

The OpenAPI document is **generated from the router**, never maintained beside it — a hand-kept
contract drifts within weeks and then misleads the people building against it. Tests assert that
every route appears, that declared scopes match what is enforced, and that a real validator accepts
the result.

The node also serves an operator console at `/dashboard`, built as a client of that same public
API. If the console needs something the API cannot provide, the API is incomplete.

---

## Layout

| Path | What it is | Dependencies |
|---|---|---|
| `spec/uip-1.md` | The normative specification | — |
| `spec/schemas/` | JSON Schema for envelope, descriptor, receipt | — |
| `conformance/` | **The operative definition of the protocol** | **none** |
| `uip/` | Protocol core: canonicalization, DIDs, envelopes, receipts | **none** |
| `uise/` | SDK, node, credits, API, events, console, bridges | `cryptography` |
| `tests/` | 269 tests | `pytest` |
| `demo.py` · `demo_node.py` | Both planes, working | — |

`uip/` and `uise/` are one implementation, not two: the SDK registers stronger cryptography into
the same protocol core the conformance suite verifies.

---

## Conformance

```bash
python3 conformance/test_conformance.py     # zero dependencies, any machine
python  -m pytest tests/                    # SDK, node, bridges, post-quantum
```

**The conformance suite — not the prose — is the operative definition of UIP-1.** Prose is
interpreted differently by every organization, and in two years that yields five incompatible
standards. Expected bytes cannot be interpreted.

`conformance/vectors/invalid.json` is the most important file here: it lists the fifteen envelopes
every implementation is **obliged to reject**, with the exact error code. Where the specification
and the vectors disagree, the vectors win.

The Ed25519 implementation is checked against the **official RFC 8032 test vectors**, and the Merkle
log against the **RFC 6962 construction** — not against themselves. Vectors regenerate byte for
byte, so any change that would break the protocol shows up as a diff before it is published.

To certify an implementation in Go, Rust or TypeScript, the vectors are plain JSON with nothing
Python-specific about them. If all five steps in `conformance/README.md` pass, it conforms. If not,
it does not. There is no grey area.

Every push runs the conformance suite on **Python 3.9 through 3.13, across Linux, macOS and
Windows, with nothing installed** — there is deliberately no `pip install` step in that job, because
the day one appears the claim stops being true. CI also proves the vectors still regenerate byte for
byte, that both demonstrations run, and that the API contract still matches the routes.

Everything CI runs can be run locally with the same command:

```bash
python conformance/test_conformance.py   # zero dependencies
python -m pytest tests/
python tools/check_contract.py           # the OpenAPI document is valid and complete
python tools/quality.py                  # no dead imports, English only
```

---

## Status

UIP-1 is a normative draft. The envelope's root fields are frozen. Provisional post-quantum
codepoints must be replaced with assigned values before 1.0.

305 tests pass: 36 conformance, 269 implementation. The conformance suite runs on Python 3.9 with
nothing installed.

## License

Apache License 2.0, with patent grant. The protocol, the SDK and the conformance suite are open —
a closed protocol does not become a standard.
