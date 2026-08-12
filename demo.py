#!/usr/bin/env python3
"""
Uise demonstration: two agents that have never met complete an entire business
transaction on their own - no humans, no contract, no account anywhere.

    python3 demo.py

Nothing needs to be installed.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uip import codec, did, ed25519, envelope, suites  # noqa: E402

NOW = 1754745600123

SEEDS = {
    "ana": bytes(range(0, 32)),
    "ben": bytes(range(32, 64)),
    "uise": bytes(range(64, 96)),
    "thief": bytes(range(96, 128)),
}


def banner(text):
    print("\n" + "=" * 74)
    print("  " + text)
    print("=" * 74)


def step(number, text):
    print("\n-- STEP %s . %s" % (number, text))


def ok(text):
    print("   [ OK ]      " + text)


def blocked(text, code):
    print("   [BLOCKED]   %-42s  %s" % (text, code))


banner("UISE - two agents do business on their own, in four seconds")

# --------------------------------------------------------------------------- #
step(1, "Two agents come into existence on opposite sides of the planet")

IDENTITIES = {}
for name in ("ana", "ben", "uise"):
    IDENTITIES[name] = did.encode(suites.ED25519, ed25519.public_key(SEEDS[name]))
    print("   %-5s %s" % (name.capitalize(), IDENTITIES[name]))

print("\n   None of them asked permission, registered, or opened an account.")
print("   Their identity IS their key. That is why there is no ceiling.")

# --------------------------------------------------------------------------- #
step(2, "Ben publishes what he can do, and what it costs")

CAPABILITY = {
    "id": "translate.text",
    "description": "Translates a text between two languages.",
    "input_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
    "output_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
    "price": {"amount": "0.0004", "unit": "USD", "per": "call"},
}

descriptor_body = codec.canonicalize({
    "v": "uip/1",
    "agent": IDENTITIES["ben"],
    "name": "text-translator",
    "capabilities": [CAPABILITY],
    "endpoints": [{"transport": "https", "url": "https://ben.example.com/uip/v1"}],
})
envelope.sign_envelope({
    "v": "uip/1",
    "id": "01K2R7XB1D3EFGHJ0K5M7N9PQR",
    "from": IDENTITIES["ben"],
    "type": "announce",
    "ts": NOW - 5000,
    "ttl": 3600000,
    "content_type": "application/uip-descriptor+json",
    "body_hash": envelope.body_hash(descriptor_body),
}, SEEDS["ben"])

ok("Capability: translate.text    Price: $0.0004 per call")
print("   Ana can read this and decide alone. No human negotiates anything.")

# --------------------------------------------------------------------------- #
step(3, "Ana commissions the work")

request_body = b'{"text":"Hola mundo","from":"es","to":"en"}'
request = envelope.sign_envelope({
    "v": "uip/1",
    "id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
    "from": IDENTITIES["ana"],
    "to": IDENTITIES["ben"],
    "type": "request",
    "ts": NOW,
    "ttl": 30000,
    "content_type": "application/json",
    "body_hash": envelope.body_hash(request_body),
}, SEEDS["ana"])

seen = set()
envelope.verify_envelope(request, request_body, now_ms=NOW, seen_ids=seen)
ok('Ben receives "Hola mundo" and proves it really came from Ana')
print("   Ben has never seen Ana before. He does not need to: the signature proves it.")

# --------------------------------------------------------------------------- #
step(4, "Ben delivers")

response_body = b'{"text":"Hello world"}'
response = envelope.sign_envelope({
    "v": "uip/1",
    "id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
    "from": IDENTITIES["ben"],
    "to": IDENTITIES["ana"],
    "type": "response",
    "ts": NOW + 412,
    "ttl": 30000,
    "content_type": "application/json",
    "body_hash": envelope.body_hash(response_body),
    "corr": request["id"],
}, SEEDS["ben"])

envelope.verify_envelope(response, response_body, now_ms=NOW + 412, seen_ids=seen)
ok('Ana receives "Hello world" in 412 milliseconds')
print("   All of that was DIRECT between the two. Uise never took part. Cost: zero.")

# --------------------------------------------------------------------------- #
step(5, "Now Uise steps in: the receipt is issued")

receipt = envelope.sign_receipt({
    "v": "uip/1",
    "rid": "01K2R7Y3B8QW5ZM1P4K7DXCVGN",
    "request_id": request["id"],
    "response_id": response["id"],
    "payer": IDENTITIES["ana"],
    "payee": IDENTITIES["ben"],
    "capability": "translate.text",
    "amount": "0.0004",
    "unit": "USD",
    "terms_hash": envelope.terms_hash(CAPABILITY),
    "issued_at": NOW + 1864,
    "issuer": IDENTITIES["uise"],
    "settlement": None,
    "anchor": None,
}, {"payer": SEEDS["ana"], "payee": SEEDS["ben"], "issuer": SEEDS["uise"]})

envelope.verify_receipt(receipt)
ok("Ana owes Ben $0.0004 for translate.text")
print("   Signed by all three:  Ana [x]   Ben [x]   Uise [x]")
print("   This proof is the product. It is the only thing Uise charges for.")

# --------------------------------------------------------------------------- #
step(6, "The receipt is anchored in the public transparency log")

anchored = dict(receipt, anchor={
    "log": "https://log.example.com/2026",
    "index": 918273645,
    "tree_size": 918273700,
    "root": codec.multihash(b"merkle root", "sha384"),
    "inclusion_proof": [codec.multihash(b"sibling", "sha384")],
})
envelope.verify_receipt(anchored)

ok("Existence proven, signatures untouched")
print("   The parties signed with anchor = null, so the log can prove WHEN a receipt")
print("   existed but can never change WHAT they agreed to.")
print("   Merkle proofs rest only on hashes, so this evidence outlives any signature")
print("   algorithm - including everything a quantum computer eventually breaks.")

# --------------------------------------------------------------------------- #
step(7, "Five attempts to cheat")


def attempt(description, action):
    try:
        action()
        print("   [PROTOCOL FAILURE] %s -- accepted when it must not be" % description)
        return 1
    except envelope.UipError as error:
        blocked(description, error.code)
        return 0


impostor = envelope.sign_envelope({
    "v": "uip/1",
    "id": "01K2R7ZZ0000000000000000AA",
    "from": IDENTITIES["ana"],            # claims to be Ana...
    "to": IDENTITIES["ben"],
    "type": "request",
    "ts": NOW,
    "ttl": 30000,
    "content_type": "application/json",
    "body_hash": envelope.body_hash(request_body),
}, SEEDS["thief"])                        # ...but signs with its own key

unknown_suite = dict(request)
unknown_suite["from"] = "did:key:z" + codec.b58_encode(
    codec.varint_encode(0x3FFFFF) + bytes(32)
)

failures = 0
failures += attempt(
    "Ben raises the price to $9.99 afterwards",
    lambda: envelope.verify_receipt(dict(receipt, amount="9.9900")),
)
failures += attempt(
    "Ana replays the same request to avoid paying twice",
    lambda: envelope.verify_envelope(request, request_body, now_ms=NOW, seen_ids=seen),
)
failures += attempt(
    "An impostor claims to be Ana",
    lambda: envelope.verify_envelope(impostor, request_body, now_ms=NOW, seen_ids=set()),
)
failures += attempt(
    "Someone swaps the delivered text in transit",
    lambda: envelope.verify_envelope(response, b'{"text":"something else"}',
                                     now_ms=NOW + 412, seen_ids=set()),
)
failures += attempt(
    "A forged algorithm is offered to force a downgrade",
    lambda: envelope.verify_envelope(unknown_suite, request_body, now_ms=NOW,
                                     seen_ids=set()),
)

# --------------------------------------------------------------------------- #
step(8, "Post-quantum policy on the public network")

policy_failures = attempt(
    "A classical-only issuer signs permanent evidence",
    lambda: envelope.verify_receipt(receipt, require_long_term_issuer=True),
)
print("   A message lives 24 hours; a receipt is evidence for decades. An algorithm")
print("   broken in 2040 would retroactively forge every receipt signed under it, so")
print("   issuers on the public network must use a post-quantum suite.")

# --------------------------------------------------------------------------- #
banner("RESULT")
print("""
  A full transaction between two strangers: discovery, order, delivery and a
  signed invoice. No humans. No contract. No bank account.

  Steps 3 and 4 - the conversation - travel directly and cost nothing.
  That is the road: no tolls, no ceiling, nobody in the middle.

  Step 5 - the receipt - is the only thing that passes through Uise.

  Every attempt to cheat failed because of mathematics, not because of rules.
""")
print("  Cheating attempts blocked: %d of 5" % (5 - failures))
print("  Ineligible issuer rejected: %s" % ("yes" if policy_failures == 0 else "NO"))
sys.exit(1 if (failures or policy_failures) else 0)
