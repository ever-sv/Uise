"""
The UIP-1 envelope and receipt - spec sections 7 and 10.

This module is the executable translation of the part of the protocol that is
frozen forever. Where it contradicts `spec/uip-1.md`, the spec wins; where the
spec contradicts `conformance/vectors/`, the vectors win.
"""

import time

from . import codec, did, suites

VERSION = "uip/1"

# Domain separation: prevents a signature made for one context from being valid
# in another, including in an unrelated protocol that reuses the same key.
DOMAIN_ENVELOPE = b"uip/1.envelope\n"
DOMAIN_RECEIPT = b"uip/1.receipt\n"

CLOCK_SKEW_MS = 300_000              # plus or minus 5 minutes (spec section 7.4)
MAX_TTL_MS = 86_400_000              # 24 hours, which bounds the replay store
MAX_BODY_BYTES = 16 * 1024 * 1024    # enforced before hashing (spec section 13.5)

MESSAGE_TYPES = ("announce", "request", "response", "event", "stream", "receipt", "error")

# The header root is CLOSED. All future growth enters through `x`.
ALLOWED_FIELDS = frozenset(
    ("v", "id", "from", "to", "type", "ts", "ttl", "content_type", "body_hash", "corr", "x", "sig")
)
REQUIRED_FIELDS = ("v", "id", "from", "type", "ts", "ttl", "content_type", "body_hash", "sig")

RECEIPT_SIGNERS = ("payer", "payee", "issuer")

# Public Uise network policy (spec section 4.4): an issuer carries the permanence
# guarantee, so an issuer must sign with a suite sound for long-term evidence.
# The protocol itself stays algorithm-agnostic; this is policy, not format.
PUBLIC_NETWORK_REQUIRES_LONG_TERM_ISSUER = True


class ReplayStore(object):
    """
    Expiring set of seen envelope identifiers - spec section 7.5.

    Local by design. A globally shared replay store would be exactly the component
    on the conversation plane's critical path that the two-plane architecture
    exists to avoid, and it would cap how large the network can grow.

    Duck-types the `set` interface that `verify_envelope` uses, so the protocol
    code stays unaware that expiry exists at all.
    """

    __slots__ = ("_expiry", "_horizon_ms")

    def __init__(self, horizon_ms=MAX_TTL_MS + CLOCK_SKEW_MS):
        self._expiry = {}
        self._horizon_ms = horizon_ms

    @staticmethod
    def _now_ms():
        return int(time.time() * 1000)

    def __contains__(self, envelope_id):
        expires_at = self._expiry.get(envelope_id)
        return expires_at is not None and expires_at > self._now_ms()

    def add(self, envelope_id):
        now = self._now_ms()
        if len(self._expiry) > 1024:
            self._expiry = {k: v for k, v in self._expiry.items() if v > now}
        self._expiry[envelope_id] = now + self._horizon_ms

    def __len__(self):
        return len(self._expiry)


class UipError(Exception):
    """Conformance failure carrying the normative code from spec section 12."""

    def __init__(self, code, message=""):
        super(UipError, self).__init__("%s: %s" % (code, message) if message else code)
        self.code = code


def _resolve(did_value, role):
    """Resolve a DID to (suite, public_key), mapping failures to normative codes."""
    try:
        return did.decode(did_value)
    except suites.SuiteUnsupported as error:
        raise UipError("UIP_SUITE_UNSUPPORTED", "%s: %s" % (role, error))
    except (ValueError, TypeError) as error:
        raise UipError("UIP_DID_INVALID", "%s: %s" % (role, error))


# --------------------------------------------------------------------------- #
# Envelope
# --------------------------------------------------------------------------- #

def body_hash(body, algorithm=codec.DEFAULT_HASH):
    """An absent body hashes the empty string (spec section 7.2)."""
    return codec.multihash(body or b"", algorithm)


def signing_input(header):
    """The exact bytes that are signed: domain separator + JCS(header without sig)."""
    unsigned = {key: value for key, value in header.items() if key != "sig"}
    return DOMAIN_ENVELOPE + codec.canonicalize(unsigned)


def sign_envelope(header, secret_key):
    """Return a copy of the header with `sig` computed under the sender's suite."""
    unsigned = {key: value for key, value in header.items() if key != "sig"}
    suite, _ = did.decode(unsigned["from"])
    signature = suite.sign(signing_input(unsigned), secret_key)
    unsigned["sig"] = codec.b64u_encode(signature)
    return unsigned


def _check_structure(header):
    if not isinstance(header, dict):
        raise UipError("UIP_HEADER_MALFORMED", "header is not an object")
    if header.get("v") != VERSION:
        raise UipError("UIP_VERSION_UNSUPPORTED", repr(header.get("v")))

    unknown = set(header) - ALLOWED_FIELDS
    if unknown:
        raise UipError("UIP_HEADER_MALFORMED", "unknown root fields: %s" % sorted(unknown))
    for field in REQUIRED_FIELDS:
        if field not in header:
            raise UipError("UIP_HEADER_MALFORMED", "missing field %r" % field)

    if header["type"] not in MESSAGE_TYPES:
        raise UipError("UIP_HEADER_MALFORMED", "unknown type %r" % header["type"])
    if not codec.ulid_is_valid(header["id"]):
        raise UipError("UIP_HEADER_MALFORMED", "id is not a valid ULID")
    if header["type"] != "announce" and "to" not in header:
        raise UipError("UIP_HEADER_MALFORMED", "missing recipient `to`")
    if header["type"] in ("response", "stream") and "corr" not in header:
        raise UipError("UIP_HEADER_MALFORMED", "missing correlation `corr`")
    if "corr" in header and not codec.ulid_is_valid(header["corr"]):
        raise UipError("UIP_HEADER_MALFORMED", "corr is not a valid ULID")
    if "x" in header and not isinstance(header["x"], dict):
        raise UipError("UIP_HEADER_MALFORMED", "x must be an object")

    for field in ("ts", "ttl"):
        value = header[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise UipError("UIP_HEADER_MALFORMED", "%s must be a non-negative integer" % field)
    if not 1 <= header["ttl"] <= MAX_TTL_MS:
        raise UipError("UIP_HEADER_MALFORMED", "ttl out of range")

    if not isinstance(header["content_type"], str) or not header["content_type"]:
        raise UipError("UIP_HEADER_MALFORMED", "content_type must be a non-empty string")


def verify_envelope(header, body=None, now_ms=None, seen_ids=None):
    """
    Run the checks of spec section 7.4 in their normative order. Returns nothing:
    either the envelope is valid, or UipError is raised carrying its code.

    `seen_ids` is a local set of already-seen identifiers. It is local on purpose:
    a globally shared replay store would be the bottleneck the two-plane design
    exists to avoid.
    """
    # 1-2. Structure and version.
    _check_structure(header)

    # 3. Sender identity and suite. An unimplemented suite is reported distinctly
    #    from a malformed DID, and is never approximated by another algorithm.
    suite, public_key = _resolve(header["from"], "from")
    if "to" in header:
        _resolve(header["to"], "to")

    # 4. Signature. Verified BEFORE the body is touched: unauthenticated bytes are
    #    never processed.
    try:
        signature = codec.b64u_decode(header["sig"])
    except (ValueError, TypeError) as error:
        raise UipError("UIP_SIG_INVALID", str(error))
    if not suite.verify(signature, signing_input(header), public_key):
        raise UipError("UIP_SIG_INVALID", "signature does not validate for the sender DID")

    # 5-6. Time window.
    if now_ms is not None:
        if abs(header["ts"] - now_ms) > CLOCK_SKEW_MS:
            raise UipError("UIP_CLOCK_SKEW", "ts outside the plus/minus 300 s window")
        if now_ms > header["ts"] + header["ttl"]:
            raise UipError("UIP_EXPIRED", "envelope has expired")

    # 7. Replay.
    if seen_ids is not None:
        if header["id"] in seen_ids:
            raise UipError("UIP_REPLAY", header["id"])
        seen_ids.add(header["id"])

    # 8. Body integrity, size-bounded before hashing.
    if body is not None:
        if len(body) > MAX_BODY_BYTES:
            raise UipError("UIP_HEADER_MALFORMED", "body exceeds the maximum size")
        try:
            matches = codec.multihash_matches(body, header["body_hash"])
        except ValueError as error:
            raise UipError("UIP_HASH_UNSUPPORTED", str(error))
        if not matches:
            raise UipError("UIP_BODY_HASH_MISMATCH", "body does not match body_hash")


# --------------------------------------------------------------------------- #
# Receipt
# --------------------------------------------------------------------------- #

def receipt_signing_input(receipt):
    """
    Domain separator + JCS(receipt without `sigs`, with `anchor` forced to null).

    Anchoring happens after signing, so the parties must sign a document in which
    `anchor` is null. This keeps signing and logging independent: the transparency
    log can never alter what the parties actually agreed to.
    """
    unsigned = {key: value for key, value in receipt.items() if key != "sigs"}
    unsigned["anchor"] = None
    return DOMAIN_RECEIPT + codec.canonicalize(unsigned)


def sign_receipt(receipt, secret_keys):
    """Add signatures for the given roles. `secret_keys` maps role to secret key."""
    unsigned = {key: value for key, value in receipt.items() if key != "sigs"}
    unsigned.setdefault("anchor", None)
    payload = receipt_signing_input(unsigned)
    signatures = dict(receipt.get("sigs") or {})
    for role, secret_key in secret_keys.items():
        if role not in RECEIPT_SIGNERS:
            raise ValueError("unknown signing role: %r" % role)
        suite, _ = did.decode(unsigned[role])
        signatures[role] = codec.b64u_encode(suite.sign(payload, secret_key))
    unsigned["sigs"] = signatures
    return unsigned


def terms_hash(capability, algorithm=codec.DEFAULT_HASH):
    """
    Anchor the agreed price to the descriptor in force at request time. This is
    what makes renegotiating after delivery cryptographically impossible.
    """
    return codec.multihash(codec.canonicalize(capability), algorithm)


def check_receipt_structure(receipt):
    """Shape checks shared by full and partial receipt verification."""
    if not isinstance(receipt, dict):
        raise UipError("UIP_HEADER_MALFORMED", "receipt is not an object")
    if receipt.get("v") != VERSION:
        raise UipError("UIP_VERSION_UNSUPPORTED", repr(receipt.get("v")))
    if not isinstance(receipt.get("amount"), str):
        # A floating point amount is a conformance defect, not a detail.
        raise UipError("UIP_HEADER_MALFORMED", "amount must be a decimal string")
    if "anchor" not in receipt:
        raise UipError("UIP_HEADER_MALFORMED", "anchor must be present, null when unlogged")
    if not isinstance(receipt.get("sigs"), dict):
        raise UipError("UIP_RECEIPT_INCOMPLETE", "signatures missing")


def verify_receipt_signatures(receipt, roles, require_long_term_issuer=False):
    """
    Verify the signatures of the given roles only.

    An issuer needs this before it has signed anything: it must check what the
    parties agreed before adding the third signature. Verifying a subset is
    exactly what a partial receipt is - proof of intent, not of obligation.
    """
    signatures = receipt["sigs"]
    payload = receipt_signing_input(receipt)
    for role in roles:
        if role not in signatures:
            raise UipError("UIP_RECEIPT_INCOMPLETE", "missing %s signature" % role)
        if role not in receipt:
            raise UipError("UIP_HEADER_MALFORMED", "missing field %r" % role)
        suite, public_key = _resolve(receipt[role], role)
        if role == "issuer" and require_long_term_issuer and not suite.long_term_evidence:
            raise UipError(
                "UIP_ISSUER_NOT_ELIGIBLE",
                "%s is not sound for long-term evidence" % suite.name,
            )
        try:
            signature = codec.b64u_decode(signatures[role])
        except (ValueError, TypeError) as error:
            raise UipError("UIP_SIG_INVALID", "%s: %s" % (role, error))
        if not suite.verify(signature, payload, public_key):
            raise UipError("UIP_SIG_INVALID", "%s signature does not validate" % role)


def verify_receipt(receipt, require_long_term_issuer=False):
    """
    Validate a receipt. A receipt with fewer than three signatures proves intent,
    not obligation.

    `require_long_term_issuer` applies the public network policy of spec section
    4.4: an issuer must sign with a post-quantum suite, because a receipt is
    permanent evidence and a suite broken in twenty years retroactively forges
    every receipt ever issued under it.
    """
    check_receipt_structure(receipt)
    for role in RECEIPT_SIGNERS:
        if role not in receipt["sigs"]:
            raise UipError("UIP_RECEIPT_INCOMPLETE", "missing %s signature" % role)
    verify_receipt_signatures(receipt, RECEIPT_SIGNERS, require_long_term_issuer)
