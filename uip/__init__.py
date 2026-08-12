"""
Minimal UIP-1 reference implementation, standard library only.

It exists for one purpose: to generate and verify the normative vectors in
`conformance/vectors/`. It is not the SDK and is not production grade - its
cryptography is not constant time. The SDK lives in `reference/uise-py/`.
"""

from . import codec, did, ed25519, envelope, suites  # noqa: F401

__all__ = ["codec", "did", "ed25519", "envelope", "suites"]
