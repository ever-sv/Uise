"""
did:key identity - spec section 3.

An agent does not register anywhere: its identifier contains its own public key,
prefixed by the multicodec codepoint that names its signature suite. Verifying who
someone is requires no network, no consensus and no permission. That is the
property that removes any ceiling on the number of agents.

It is also the property that makes the protocol survive cryptographic change:
identity and algorithm are one declaration, so migrating to a post-quantum suite
produces a new DID rather than a new protocol version.
"""

from . import codec, suites

PREFIX = "did:key:"
MULTIBASE_BASE58BTC = "z"


def encode(suite, public_key):
    """Build the DID for a public key under a given suite."""
    if len(public_key) != suite.public_key_size:
        raise ValueError(
            "%s public key must be %d bytes" % (suite.name, suite.public_key_size)
        )
    payload = codec.varint_encode(suite.multicodec) + public_key
    return PREFIX + MULTIBASE_BASE58BTC + codec.b58_encode(payload)


def decode(did):
    """
    Return (suite, public_key) for a DID.

    Raises ValueError when the DID is malformed, and suites.SuiteUnsupported when
    it is well formed but names an algorithm this build cannot verify. The caller
    must keep those cases distinct: one is a bad message, the other is a message
    this node is not equipped to judge.
    """
    if not isinstance(did, str) or not did.startswith(PREFIX):
        raise ValueError("not a did:key")
    body = did[len(PREFIX):]
    if not body.startswith(MULTIBASE_BASE58BTC):
        raise ValueError("did:key: expected base58btc multibase ('z')")

    raw = codec.b58_decode(body[1:])
    codepoint, consumed = codec.varint_decode(raw)
    suite = suites.by_multicodec(codepoint)

    public_key = raw[consumed:]
    if len(public_key) != suite.public_key_size:
        raise ValueError(
            "did:key: %s expects a %d byte key, found %d"
            % (suite.name, suite.public_key_size, len(public_key))
        )
    return suite, public_key


def is_well_formed(did):
    """True when the DID parses and names a suite this build implements."""
    try:
        decode(did)
        return True
    except (ValueError, TypeError, suites.SuiteUnsupported):
        return False
