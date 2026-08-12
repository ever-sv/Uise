"""
HTTPS transport binding - spec section 11.1.

The envelope crosses the wire unchanged: a transport that rewrites the header
would break the signature. This module only frames it.

Two body encodings exist and both are exact:
  * `body_b64` - the bytes, verbatim. What this SDK always sends.
  * `body`     - a JSON value whose bytes are JCS(body), so a parse-and-reserialize
                 round trip cannot change what was hashed.
"""

import json
import urllib.error
import urllib.request

from uip import codec

CONTENT_TYPE = "application/uip+json"
PATH_ENVELOPE = "/uip/v1/envelope"
PATH_DESCRIPTOR = "/uip/v1/descriptor"

DEFAULT_TIMEOUT_SECONDS = 30


class TransportError(Exception):
    """The peer could not be reached, or answered something unusable."""


def encode_wire(header, body):
    """Frame a signed header and its body for transmission."""
    payload = dict(header)
    payload["body_b64"] = codec.b64u_encode(body or b"")
    return payload


def decode_wire(payload):
    """
    Split a received frame into (header, body_bytes).

    Raises ValueError when the framing is ambiguous. Ambiguity here would mean two
    implementations disagreeing on which bytes were signed.
    """
    if not isinstance(payload, dict):
        raise ValueError("wire frame is not an object")
    has_b64 = "body_b64" in payload
    has_json = "body" in payload
    if has_b64 == has_json:
        raise ValueError("exactly one of `body` or `body_b64` must be present")

    header = {key: value for key, value in payload.items()
              if key not in ("body", "body_b64")}
    if has_b64:
        return header, codec.b64u_decode(payload["body_b64"])
    return header, codec.canonicalize(payload["body"])


def post(url, payload, timeout=DEFAULT_TIMEOUT_SECONDS):
    """POST a wire frame and return (status_code, parsed_response_or_None)."""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url.rstrip("/") + PATH_ENVELOPE,
        data=data,
        headers={"Content-Type": CONTENT_TYPE, "Accept": CONTENT_TYPE},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, (json.loads(raw) if raw else None)
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise TransportError("%s: %s" % (url, error))
