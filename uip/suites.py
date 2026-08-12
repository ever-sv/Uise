"""
Cryptographic suite registry - spec section 4.

This is the mechanism that lets UIP-1 outlive its own cryptography. The signature
algorithm is never named in the envelope: it is declared by the multicodec prefix
inside the sender's DID. Adding a post-quantum algorithm therefore adds a registry
entry and a new DID, never a new protocol version.

Two rules make this safe, and both are enforced here:

  1. A suite that is not implemented is rejected, never approximated. There is no
     fallback path, because a fallback is a downgrade attack.
  2. A multicodec codepoint that has not been officially assigned is never
     silently used. Suites awaiting assignment carry `provisional=True`, which is
     surfaced everywhere it matters.

The registry is open: `register()` lets a richer build add suites this pure
standard-library core cannot implement. The SDK uses it to add post-quantum
signing and to swap in a constant-time Ed25519 backend.
"""

from . import ed25519

# Officially assigned multicodec codepoint for ed25519-pub. Stable, and the only
# assigned codepoint this protocol currently relies on.
MULTICODEC_ED25519_PUB = 0xED


class Suite(object):
    """An algorithm binding: how to size, sign and verify for one suite."""

    __slots__ = (
        "name",
        "multicodec",
        "public_key_size",
        "signature_size",
        "long_term_evidence",
        "provisional",
        "_derive_public_key",
        "_sign",
        "_verify",
    )

    def __init__(self, name, multicodec, public_key_size, signature_size,
                 long_term_evidence, derive_public_key, sign, verify,
                 provisional=False):
        self.name = name
        self.multicodec = multicodec
        self.public_key_size = public_key_size
        self.signature_size = signature_size
        # True when the suite is sound for evidence that must stay unforgeable for
        # decades. Classical signatures are not: the day Ed25519 falls, every
        # receipt ever signed with it becomes forgeable in hindsight.
        self.long_term_evidence = long_term_evidence
        # True while the multicodec codepoint is not officially assigned. Such a
        # suite must not be used on the public network: the codepoint may change.
        self.provisional = provisional
        self._derive_public_key = derive_public_key
        self._sign = sign
        self._verify = verify

    def derive_public_key(self, secret_seed):
        return self._derive_public_key(secret_seed)

    def sign(self, message, secret_seed):
        return self._sign(message, secret_seed)

    def verify(self, signature, message, public_key):
        if len(signature) != self.signature_size:
            return False
        if len(public_key) != self.public_key_size:
            return False
        return self._verify(signature, message, public_key)

    def __repr__(self):
        return "<Suite %s%s>" % (self.name, " provisional" if self.provisional else "")


ED25519 = Suite(
    name="Ed25519",
    multicodec=MULTICODEC_ED25519_PUB,
    public_key_size=32,
    signature_size=64,
    long_term_evidence=False,
    derive_public_key=ed25519.public_key,
    sign=ed25519.sign,
    verify=ed25519.verify,
)


class SuiteUnsupported(Exception):
    """The suite named by a DID is not implemented. Never fall back."""


class SuiteConflict(Exception):
    """A different suite is already registered under that codepoint or name."""


_BY_MULTICODEC = {}
_BY_NAME = {}


def register(suite, replace=False):
    """
    Add a suite to the registry.

    `replace=True` is for swapping the backend of an already registered algorithm
    - same codepoint, same wire bytes, different implementation. The SDK uses it
    to install a constant-time Ed25519 over this module's auditable but slow one.
    It must never be used to bind a codepoint to a different algorithm.
    """
    if not replace:
        if suite.multicodec in _BY_MULTICODEC:
            raise SuiteConflict("codepoint 0x%x already registered" % suite.multicodec)
        if suite.name in _BY_NAME:
            raise SuiteConflict("suite %r already registered" % suite.name)
    elif suite.multicodec in _BY_MULTICODEC:
        existing = _BY_MULTICODEC[suite.multicodec]
        if (existing.name != suite.name
                or existing.public_key_size != suite.public_key_size
                or existing.signature_size != suite.signature_size):
            raise SuiteConflict(
                "refusing to rebind codepoint 0x%x from %s to %s"
                % (suite.multicodec, existing.name, suite.name)
            )
    _BY_MULTICODEC[suite.multicodec] = suite
    _BY_NAME[suite.name] = suite
    return suite


def by_multicodec(codepoint):
    try:
        return _BY_MULTICODEC[codepoint]
    except KeyError:
        raise SuiteUnsupported("unsupported multicodec 0x%x" % codepoint)


def by_name(name):
    try:
        return _BY_NAME[name]
    except KeyError:
        raise SuiteUnsupported("unsupported suite %r" % name)


def registered():
    """Suites this build can actually verify, in registration order."""
    return tuple(_BY_NAME.values())


register(ED25519)
