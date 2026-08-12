"""
Agent identity - spec section 3.

An identity is a secret seed plus the suite that interprets it. Everything public
about an agent, including which algorithm it speaks, derives from that pair.
"""

import os

from uip import did as _did
from uip import envelope as _envelope

from . import suites


class Identity(object):
    """A signing identity. The seed is secret and never leaves this object."""

    __slots__ = ("_seed", "suite", "public_key", "did")

    def __init__(self, seed, suite=None):
        suite = suite or suites.AGENT_DEFAULT
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != suites.SEED_SIZE:
            raise ValueError("seed must be %d bytes" % suites.SEED_SIZE)
        self._seed = bytes(seed)
        self.suite = suite
        self.public_key = suite.derive_public_key(self._seed)
        self.did = _did.encode(suite, self.public_key)

    @classmethod
    def generate(cls, suite=None):
        """A new identity from operating-system entropy."""
        return cls(os.urandom(suites.SEED_SIZE), suite)

    @classmethod
    def from_seed_hex(cls, seed_hex, suite=None):
        return cls(bytes.fromhex(seed_hex), suite)

    def secret_seed_hex(self):
        """
        Export the secret. Named explicitly so it can never be exposed by accident
        through a generic serializer.
        """
        return self._seed.hex()

    def sign(self, message):
        return self.suite.sign(message, self._seed)

    def sign_envelope(self, header):
        """Return a copy of the header with `sig` filled in."""
        if header.get("from") != self.did:
            raise ValueError("header `from` does not match this identity")
        return _envelope.sign_envelope(header, self._seed)

    def sign_receipt_as(self, receipt, role):
        """Add this identity's signature to a receipt under one of the three roles."""
        if role not in _envelope.RECEIPT_SIGNERS:
            raise ValueError("role must be one of %s" % (_envelope.RECEIPT_SIGNERS,))
        if receipt.get(role) != self.did:
            raise ValueError("receipt %r does not match this identity" % role)
        return _envelope.sign_receipt(receipt, {role: self._seed})

    def __repr__(self):
        return "<Identity %s %s>" % (self.suite.name, self.did)
