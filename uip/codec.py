"""
Encodings frozen by UIP-1: JCS (RFC 8785), unpadded base64url, base58btc,
multihash tags, unsigned varint and ULID. Standard library only.

The critical piece here is `canonicalize`. If two implementations canonicalize
differently, their signatures stop validating against each other and the failure
is silent: messages simply "do not work" with no diagnosable cause. This module
therefore fails loudly rather than guessing.
"""

import base64
import hashlib

# --------------------------------------------------------------------------- #
# JCS - JSON Canonicalization Scheme (RFC 8785)
# --------------------------------------------------------------------------- #

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}

# Largest integer representable without loss in the ES6 number format that JCS
# mandates. Beyond it, two implementations could serialize differently, so the
# value is rejected instead of risked.
_MAX_SAFE_INT = 2 ** 53 - 1


def _serialize_string(value):
    out = ['"']
    for character in value:
        code_point = ord(character)
        if code_point in _ESCAPES:
            out.append(_ESCAPES[code_point])
        elif code_point < 0x20:
            out.append("\\u%04x" % code_point)
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _serialize(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, float):
        # Money and timestamps are never floating point in UIP-1 (spec section 6).
        raise ValueError("JCS: floating point numbers are forbidden in UIP-1")
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise ValueError("JCS: integer outside the ES6 safe range")
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 orders keys by their UTF-16 code units. Encoding to UTF-16BE
        # and comparing bytes yields exactly that order; Python's native code
        # point order diverges outside the Basic Multilingual Plane.
        items = sorted(value.items(), key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(
            _serialize_string(key) + ":" + _serialize(item) for key, item in items
        ) + "}"
    raise TypeError("JCS: unserializable type %r" % type(value))


def canonicalize(value):
    """Canonical JCS serialization as UTF-8 bytes. One input, one output."""
    return _serialize(value).encode("utf-8")


# --------------------------------------------------------------------------- #
# base64url without padding
# --------------------------------------------------------------------------- #

def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text):
    if not isinstance(text, str):
        raise ValueError("base64url: expected a string")
    if any(character in text for character in "+/="):
        raise ValueError("base64url: padding or standard-alphabet character present")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Multihash tags - spec section 4.5
# --------------------------------------------------------------------------- #

# Hash agility matters less than signature agility: Grover's algorithm halves the
# effective security of a hash, it does not break it. SHA-256 stays sound for
# body_hash; SHA-384 is available for transparency-log anchoring, where the proof
# must outlive every signature suite in use today.
HASH_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

DEFAULT_HASH = "sha256"


def multihash(raw, algorithm=DEFAULT_HASH):
    """Hash `raw` and return the `<algorithm>:<base64url>` tag form."""
    try:
        constructor = HASH_ALGORITHMS[algorithm]
    except KeyError:
        raise ValueError("unregistered hash algorithm: %r" % algorithm)
    return algorithm + ":" + b64u_encode(constructor(raw).digest())


def multihash_matches(raw, tag):
    """True when `tag` is the hash of `raw`. Raises on an unregistered prefix."""
    if not isinstance(tag, str) or ":" not in tag:
        raise ValueError("malformed multihash tag")
    algorithm = tag.split(":", 1)[0]
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError("unregistered hash algorithm: %r" % algorithm)
    return multihash(raw, algorithm) == tag


# --------------------------------------------------------------------------- #
# Unsigned varint - multicodec prefixes
# --------------------------------------------------------------------------- #

def varint_encode(value):
    if value < 0:
        raise ValueError("varint: negative values are not representable")
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def varint_decode(raw):
    """Return (value, bytes_consumed). Post-quantum codepoints exceed one byte."""
    value = 0
    shift = 0
    for index, byte in enumerate(raw):
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index + 1
        shift += 7
        if shift > 63:
            raise ValueError("varint: value too large")
    raise ValueError("varint: truncated")


# --------------------------------------------------------------------------- #
# base58btc - required by did:key
# --------------------------------------------------------------------------- #

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_encode(raw):
    number = int.from_bytes(raw, "big")
    out = ""
    while number > 0:
        number, remainder = divmod(number, 58)
        out = _B58_ALPHABET[remainder] + out
    for byte in raw:                       # each leading zero byte becomes a '1'
        if byte != 0:
            break
        out = "1" + out
    return out or "1"


def b58_decode(text):
    number = 0
    for character in text:
        index = _B58_ALPHABET.find(character)
        if index < 0:
            raise ValueError("base58: invalid character %r" % character)
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + body


# --------------------------------------------------------------------------- #
# ULID - Crockford base32, 48 bits of time and 80 bits of entropy
# --------------------------------------------------------------------------- #

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"     # excludes I, L, O, U


def ulid_encode(timestamp_ms, randomness):
    if len(randomness) != 10:
        raise ValueError("ULID requires exactly 10 bytes of entropy")
    value = (timestamp_ms << 80) | int.from_bytes(randomness, "big")
    out = ""
    for _ in range(26):
        value, remainder = divmod(value, 32)
        out = _CROCKFORD[remainder] + out
    return out


def ulid_new(timestamp_ms, randomness):
    """
    Build a fresh ULID. Kept here rather than in the SDK because the encoding is
    part of the wire format, and one encoder means one behaviour everywhere.
    """
    return ulid_encode(timestamp_ms & ((1 << 48) - 1), randomness)


def ulid_is_valid(text):
    return (
        isinstance(text, str)
        and len(text) == 26
        and text[0] in "01234567"                    # prevents overflowing 128 bits
        and all(character in _CROCKFORD for character in text)
    )
