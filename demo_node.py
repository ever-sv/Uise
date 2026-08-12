#!/usr/bin/env python3
"""
The value plane: a Uise node issues receipts, charges for them, and publishes an
append-only log that anyone can audit without trusting the node.

    python -m pip install -e .
    python demo_node.py

`demo.py` shows the conversation plane and needs nothing installed. This one needs
`cryptography`, because the issuer signs with post-quantum ML-DSA.
"""

import os
import time

from uip import codec, envelope
from uise import Agent, Identity, Node, log, suites, verify_signed_tree_head
from uise.transport import encode_wire


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


def now_ms():
    return int(time.time() * 1000)


CAPABILITY = {
    "id": "translate.text",
    "price": {"amount": "0.0004", "unit": "USD", "per": "call"},
}


def agreed_receipt(node, payer, payee):
    """What the two parties sign before the issuer ever sees it."""
    base = {
        "v": "uip/1",
        "rid": codec.ulid_new(now_ms(), os.urandom(10)),
        "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
        "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
        "payer": payer.did,
        "payee": payee.did,
        "capability": "translate.text",
        "amount": "0.0004",
        "unit": "USD",
        "terms_hash": envelope.terms_hash(CAPABILITY),
        "issued_at": now_ms(),
        "issuer": node.did,
        "settlement": None,
        "anchor": None,
    }
    signed = payer.identity.sign_receipt_as(base, "payer")
    return payee.identity.sign_receipt_as(signed, "payee")


banner("UISE NODE - the value plane, and why nobody has to trust it")

# --------------------------------------------------------------------------- #
step(1, "A node starts up")

node = Node(log_url="https://log.uise.test", fee="0.0001")
ok("Issuer suite: %s" % node.identity.suite.name)
print("   Signature: %d bytes. Ed25519 alone would be 64." % node.identity.suite.signature_size)
print("   A receipt is evidence for decades, so the issuer signs post-quantum.")
print("   Fee: $%s per receipt issued - for the proof, never for moving money." % node.fee)

# --------------------------------------------------------------------------- #
step(2, "An agent announces itself; another one finds it")

translator = Agent.generate(name="text-translator")


@translator.capability("translate.text", price="0.0004")
def translate(payload):
    return {"text": payload["text"].upper()}


header, body = translator.announcement()
node.handle(encode_wire(header, body))
found = node.discover("translate.text")
ok("Discovery returned %d agent offering translate.text" % len(found))
print("   Discovery is free and read-only. Anyone may run a node that does this.")

# --------------------------------------------------------------------------- #
step(3, "Ten transactions settle")

payer, payee = Agent.generate(name="payer"), Agent.generate(name="payee")
issued = [node.issue(agreed_receipt(node, payer, payee)) for _ in range(10)]
early_head = node.signed_tree_head()

ok("%d receipts issued, each signed by three parties" % len(issued))
print("   Revenue: %s" % node.revenue())
print("   Tree size: %d" % early_head["tree_size"])

# --------------------------------------------------------------------------- #
step(4, "An outsider verifies a receipt without asking the node for permission")

target = issued[4]
anchor = target["anchor"]
algorithm, root = log.untag(anchor["root"])
leaf = log.leaf_hash(log.receipt_entry(target), algorithm)
proof = [log.untag(node_hash)[1] for node_hash in anchor["inclusion_proof"]]

envelope.verify_receipt(target, require_long_term_issuer=True)
ok("Three signatures valid, issuer eligible for permanent evidence")

included = log.verify_inclusion(leaf, anchor["index"], anchor["tree_size"],
                                proof, root, algorithm)
ok("Merkle inclusion proof verifies: %s" % included)
print("   That proof is pure hashing. It keeps working after every signature")
print("   algorithm used today has been broken.")

# --------------------------------------------------------------------------- #
step(5, "The node keeps operating; an auditor checks it never rewrote the past")

for _ in range(7):
    node.issue(agreed_receipt(node, payer, payee))
later_head = node.signed_tree_head()

ok("Signed tree head valid: %s" % verify_signed_tree_head(later_head))
consistency = node.consistency_proof(early_head["tree_size"], later_head["tree_size"])
_, first_root = log.untag(consistency["first_root"])
_, second_root = log.untag(consistency["second_root"])
consistent = log.verify_consistency(
    consistency["first_size"], consistency["second_size"],
    [log.untag(node_hash)[1] for node_hash in consistency["proof"]],
    first_root, second_root, algorithm,
)
ok("Consistency %d -> %d verifies: %s"
   % (consistency["first_size"], consistency["second_size"], consistent))
print("   The auditor pinned a head earlier and just proved that everything it saw")
print("   is still there, unchanged and in the same order. No trust required.")

# --------------------------------------------------------------------------- #
step(6, "Four things the node cannot do, even if it wanted to")


def attempt(description, action):
    try:
        action()
        print("   [FAILURE] %s -- allowed when it must not be" % description)
        return 1
    except (envelope.UipError, ValueError, TypeError) as error:
        blocked(description, getattr(error, "code", type(error).__name__))
        return 0


def log_twice(issuer):
    """Submitting the same rid twice must never produce a second log entry."""
    receipt = agreed_receipt(issuer, payer, payee)
    issuer.issue(receipt)
    before = issuer.storage.log_size()
    issuer.issue(receipt)
    if issuer.storage.log_size() != before:
        raise AssertionError("a duplicate entry was written")
    raise envelope.UipError("UIP_REPLAY", "second issuance returned the logged entry")


failures = 0
failures += attempt(
    "Issue a receipt the parties never signed",
    lambda: node.issue(dict(agreed_receipt(node, payer, payee), amount="9.9900")),
)
failures += attempt(
    "Log the same obligation twice",
    lambda: log_twice(node),
)
failures += attempt(
    "Run an issuer with classical-only signatures",
    lambda: Node(identity=Identity.generate(suites.ED25519)),
)
failures += attempt(
    "Quote a fee as a floating point number",
    lambda: Node(fee=0.0001),
)


# --------------------------------------------------------------------------- #
banner("RESULT")
print("""
  The node did exactly three things: it answered discovery queries, it certified
  what two parties had already agreed, and it published the proof.

  It never carried a conversation. It never held anyone's money. It charged for
  one thing only - issuing the proof that both sides accept.

  And nobody has to trust it: every claim it makes is checkable by a stranger
  with a hash function.
""")
print("  Receipts issued : %d" % node.storage.log_size())
print("  Revenue         : %s" % node.revenue())
print("  Abuses blocked  : %d of 4" % (4 - failures))
node.close()
raise SystemExit(1 if failures else 0)
