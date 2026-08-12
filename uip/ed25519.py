"""
Ed25519 (RFC 8032) in pure Python, standard library only.

Why this exists instead of `cryptography` or PyNaCl: the normative vectors of a
standard must be verifiable on any machine on earth without installing anything.
A conformance suite that requires dependencies is a conformance suite nobody runs.

This implementation is deliberately slow and direct: it favours being auditable
line by line over performance. It is NOT for production - it is not constant time.
The node and the SDK use a vetted, constant-time library. This module only
generates and checks vectors, and is validated against the official RFC 8032
test vectors by the conformance suite.
"""

import hashlib

# edwards25519 parameters (RFC 8032, section 5.1)
P = 2 ** 255 - 19                                                  # field prime
Q = 2 ** 252 + 27742317777372353535851937790883648493              # subgroup order

SEED_SIZE = 32
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64


def _hash_to_int(data):
    """SHA-512 read as a little-endian integer - H() in the RFC."""
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _invert(x):
    return pow(x, P - 2, P)


D = -121665 * _invert(121666) % P
SQRT_MINUS_ONE = pow(2, (P - 1) // 4, P)


def _recover_x(y):
    """Recover the x coordinate from y on the curve."""
    numerator = (y * y - 1) * _invert(D * y * y + 1)
    x = pow(numerator, (P + 3) // 8, P)
    if (x * x - numerator) % P != 0:
        x = (x * SQRT_MINUS_ONE) % P
    if x % 2 != 0:
        x = P - x
    return x


_BASE_Y = 4 * _invert(5) % P
BASE_POINT = (_recover_x(_BASE_Y) % P, _BASE_Y)


def _add(first, second):
    """Point addition in affine coordinates (Edwards addition law)."""
    x1, y1 = first
    x2, y2 = second
    k = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _invert(1 + k)
    y3 = (y1 * y2 + x1 * x2) * _invert(1 - k)
    return (x3 % P, y3 % P)


def _multiply(point, scalar):
    """Scalar multiplication by double-and-add."""
    if scalar == 0:
        return (0, 1)
    half = _multiply(point, scalar // 2)
    half = _add(half, half)
    return _add(half, point) if scalar & 1 else half


def _on_curve(point):
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _encode_point(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(raw):
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    x = _recover_x(y)
    if (x & 1) != (raw[31] >> 7):
        x = P - x
    point = (x, y)
    if not _on_curve(point):
        raise ValueError("point is not on the curve")
    return point


def _clamp(digest):
    """Prune the secret scalar (RFC 8032, section 5.1.5)."""
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def public_key(seed):
    """Derive the 32 byte public key from the 32 byte private seed."""
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be %d bytes" % SEED_SIZE)
    digest = hashlib.sha512(seed).digest()
    return _encode_point(_multiply(BASE_POINT, _clamp(digest)))


def sign(message, seed):
    """64 byte signature. Deterministic: identical input always yields it."""
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be %d bytes" % SEED_SIZE)
    digest = hashlib.sha512(seed).digest()
    scalar = _clamp(digest)
    encoded_public = _encode_point(_multiply(BASE_POINT, scalar))
    nonce = _hash_to_int(digest[32:64] + message) % Q
    commitment = _multiply(BASE_POINT, nonce)
    challenge = _hash_to_int(_encode_point(commitment) + encoded_public + message) % Q
    proof = (nonce + challenge * scalar) % Q
    return _encode_point(commitment) + proof.to_bytes(32, "little")


def verify(signature, message, key):
    """Verify a signature. Returns False for any malformed input."""
    if len(signature) != SIGNATURE_SIZE or len(key) != PUBLIC_KEY_SIZE:
        return False
    try:
        commitment = _decode_point(signature[:32])
        point = _decode_point(key)
    except ValueError:
        return False
    proof = int.from_bytes(signature[32:64], "little")
    if proof >= Q:                                # rejects malleable signatures
        return False
    challenge = _hash_to_int(signature[:32] + key + message) % Q
    return _multiply(BASE_POINT, proof) == _add(commitment, _multiply(point, challenge))
