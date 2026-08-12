"""
The agent API - what a developer actually touches.

    from uise import Agent

    agent = Agent.generate(name="translator")

    @agent.capability("translate.text", price="0.0004")
    def translate(payload):
        return {"text": payload["text"].upper()}

    agent.serve(port=8080)

Adoption is decided in the first ten minutes a developer spends with a protocol,
so this surface stays deliberately small. Everything below it is the same
verification path the conformance suite exercises - there is no second
implementation of the protocol hiding in here.
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from uip import codec, envelope

from . import suites, transport
from .identity import Identity
from .ratelimit import Limiters

JSON_CONTENT_TYPE = "application/json"
DESCRIPTOR_CONTENT_TYPE = "application/uip-descriptor+json"
ERROR_CONTENT_TYPE = "application/uip-error+json"

DEFAULT_TTL_MS = 30_000
DESCRIPTOR_TTL_MS = 3_600_000


def _now_ms():
    return int(time.time() * 1000)


def _new_id():
    return codec.ulid_new(_now_ms(), os.urandom(10))


def _json_bytes(value):
    """Deterministic JSON bytes, so what is hashed is exactly what is sent."""
    return codec.canonicalize(value)


class Capability(object):
    __slots__ = ("id", "handler", "description", "price", "input_schema",
                 "output_schema", "extensions")

    def __init__(self, capability_id, handler, description=None, price=None,
                 input_schema=None, output_schema=None, extensions=None):
        self.id = capability_id
        self.handler = handler
        self.description = description
        self.price = price
        self.input_schema = input_schema
        self.output_schema = output_schema
        # Namespaced extras, used by bridges to preserve identifiers that do not
        # survive translation to another agent format.
        self.extensions = extensions

    def declaration(self):
        declared = {
            "id": self.id,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
        }
        if self.description:
            declared["description"] = self.description
        if self.price:
            declared["price"] = self.price
        if self.extensions:
            declared["x"] = self.extensions
        return declared


class Agent(object):
    """An addressable UIP-1 agent: an identity plus the capabilities it offers."""

    ANY_OBJECT = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}

    def __init__(self, identity, name=None, endpoint=None, description=None):
        self.identity = identity
        self.name = name or "uise-agent"
        self.description = description
        self.endpoint = endpoint
        self.capabilities = {}
        self.replay = envelope.ReplayStore()
        self.limiters = Limiters()

    # -- construction -------------------------------------------------------- #

    @classmethod
    def generate(cls, name=None, suite=None, endpoint=None, description=None):
        return cls(Identity.generate(suite), name=name, endpoint=endpoint,
                   description=description)

    @classmethod
    def from_seed_hex(cls, seed_hex, name=None, suite=None, endpoint=None,
                      description=None):
        return cls(Identity.from_seed_hex(seed_hex, suite), name=name,
                   endpoint=endpoint, description=description)

    @property
    def did(self):
        return self.identity.did

    # -- declaring what this agent can do ------------------------------------ #

    def capability(self, capability_id, description=None, price=None, unit="USD",
                   per="call", input_schema=None, output_schema=None):
        """Decorator registering a capability. `price` is a decimal string."""
        declared_price = None
        if price is not None:
            if not isinstance(price, str):
                raise TypeError("price must be a decimal string, never a float")
            declared_price = {"amount": price, "unit": unit, "per": per}

        def decorate(handler):
            declaration = {
                "id": capability_id,
                "input_schema": input_schema or self.ANY_OBJECT,
                "output_schema": output_schema or self.ANY_OBJECT,
            }
            resolved = description or (handler.__doc__ or "").strip() or None
            if resolved:
                declaration["description"] = resolved
            if declared_price:
                declaration["price"] = declared_price
            self.add_capability(declaration, handler)
            return handler

        return decorate

    def add_capability(self, declaration, handler):
        """
        Register a capability from a UIP declaration dictionary.

        Bridges use this to install capabilities translated from another agent
        format, so there is exactly one place where a capability comes into
        existence regardless of where its definition came from.
        """
        capability = Capability(
            declaration["id"],
            handler,
            declaration.get("description"),
            declaration.get("price"),
            declaration["input_schema"],
            declaration["output_schema"],
            declaration.get("x"),
        )
        self.capabilities[capability.id] = capability
        return capability

    def descriptor(self):
        if not self.capabilities:
            raise ValueError("an agent must declare at least one capability")
        descriptor = {
            "v": envelope.VERSION,
            "agent": self.did,
            "name": self.name,
            "capabilities": [c.declaration() for c in self.capabilities.values()],
            "endpoints": [{"transport": "https", "url": self.endpoint or "https://localhost/uip/v1"}],
        }
        if self.description:
            descriptor["description"] = self.description
        return descriptor

    def announcement(self):
        """A signed `announce` envelope carrying this agent's descriptor."""
        body = _json_bytes(self.descriptor())
        return self._sign(
            "announce", None, body, DESCRIPTOR_CONTENT_TYPE, ttl_ms=DESCRIPTOR_TTL_MS
        ), body

    # -- sending ------------------------------------------------------------- #

    def _sign(self, message_type, to, body, content_type, corr=None, ttl_ms=DEFAULT_TTL_MS):
        header = {
            "v": envelope.VERSION,
            "id": _new_id(),
            "from": self.did,
            "type": message_type,
            "ts": _now_ms(),
            "ttl": ttl_ms,
            "content_type": content_type,
            "body_hash": envelope.body_hash(body),
        }
        if to is not None:
            header["to"] = to
        if corr is not None:
            header["corr"] = corr
        return self.identity.sign_envelope(header)

    def call(self, url, peer_did, capability_id, payload, timeout=None):
        """
        Invoke a capability on a remote agent and return its parsed result.

        This is the conversation plane: it goes straight to the peer. No Uise
        infrastructure is involved and nothing is charged.
        """
        body = _json_bytes({"capability": capability_id, "input": payload})
        request = self._sign("request", peer_did, body, JSON_CONTENT_TYPE)
        status, frame = transport.post(
            url, transport.encode_wire(request, body),
            timeout=timeout or transport.DEFAULT_TIMEOUT_SECONDS,
        )
        if frame is None:
            raise transport.TransportError("empty response (HTTP %s)" % status)

        header, response_body = transport.decode_wire(frame)
        envelope.verify_envelope(header, response_body, now_ms=_now_ms(),
                                 seen_ids=self.replay)
        if header["from"] != peer_did:
            raise envelope.UipError("UIP_SIG_INVALID", "response signed by a different agent")
        if header.get("corr") != request["id"]:
            raise envelope.UipError("UIP_HEADER_MALFORMED", "response correlates to another request")

        parsed = json.loads(response_body.decode("utf-8"))
        if header["type"] == "error":
            raise envelope.UipError(parsed.get("code", "UIP_INTERNAL"), parsed.get("message", ""))
        return parsed

    # -- receiving ----------------------------------------------------------- #

    def _error(self, code, message, to=None, corr=None):
        body = _json_bytes({"code": code, "message": message})
        return self._sign("error", to, body, ERROR_CONTENT_TYPE, corr=corr), body

    def handle(self, frame, peer=None):
        """
        Process one received wire frame and return (http_status, response_frame).

        Framework agnostic on purpose: any HTTP server can call this. `serve()` is
        a convenience, not a requirement.
        """
        if peer is not None and not self.limiters.peer.check(peer).allowed:
            return 429, transport.encode_wire(
                *self._error("UIP_RATE_LIMITED", "too many requests from this address")
            )
        try:
            header, body = transport.decode_wire(frame)
        except ValueError as error:
            return 400, transport.encode_wire(*self._error("UIP_HEADER_MALFORMED", str(error)))

        sender = header.get("from") if isinstance(header, dict) else None
        correlation = header.get("id") if isinstance(header, dict) else None

        try:
            envelope.verify_envelope(header, body, now_ms=_now_ms(), seen_ids=self.replay)

            # Keyed on the sender only now that its signature has been verified.
            # Keying on an unverified claim would let anyone exhaust somebody
            # else's allowance simply by naming them.
            if not self.limiters.agent.check(header["from"]).allowed:
                raise envelope.UipError("UIP_RATE_LIMITED", "quota exhausted for this agent")

            if header["type"] != "request":
                raise envelope.UipError("UIP_HEADER_MALFORMED",
                                        "this endpoint accepts `request` envelopes")
            if header["to"] != self.did:
                raise envelope.UipError("UIP_DID_INVALID", "envelope is addressed elsewhere")

            request = json.loads(body.decode("utf-8"))
            capability = self.capabilities.get(request.get("capability"))
            if capability is None:
                raise envelope.UipError("UIP_CAPABILITY_UNKNOWN",
                                        str(request.get("capability")))
            result = capability.handler(request.get("input"))
        except envelope.UipError as error:
            return 400, transport.encode_wire(
                *self._error(error.code, str(error), to=sender, corr=correlation)
            )
        except (ValueError, KeyError, TypeError) as error:
            return 400, transport.encode_wire(
                *self._error("UIP_SCHEMA_INVALID", str(error), to=sender, corr=correlation)
            )
        except Exception:
            # Never leak an internal traceback to a peer (spec section 12).
            return 500, transport.encode_wire(
                *self._error("UIP_INTERNAL", "handler failed", to=sender, corr=correlation)
            )

        response_body = _json_bytes(result)
        response = self._sign("response", sender, response_body, JSON_CONTENT_TYPE,
                              corr=header["id"])
        return 200, transport.encode_wire(response, response_body)

    def serve(self, host="127.0.0.1", port=8080):
        """
        Convenience HTTP server for development and for the reference node.

        Production deployments should call `handle()` from their own server; this
        one exists so the quickstart is five lines, not fifty.
        """
        server = ThreadingHTTPServer((host, port), _make_handler(self))
        self.endpoint = self.endpoint or "http://%s:%d/uip/v1" % (host, port)
        try:
            server.serve_forever()
        finally:
            server.server_close()


def _make_handler(agent):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _respond(self, status, payload):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", transport.CONTENT_TYPE)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != transport.PATH_ENVELOPE:
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > envelope.MAX_BODY_BYTES:
                self.send_error(413)
                return
            try:
                frame = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self.send_error(400)
                return
            status, response = agent.handle(frame, peer=self.client_address[0])
            self._respond(status, response)

        def do_GET(self):
            if self.path != transport.PATH_DESCRIPTOR:
                self.send_error(404)
                return
            header, body = agent.announcement()
            self._respond(200, transport.encode_wire(header, body))

        def log_message(self, fmt, *args):
            pass                                  # silence per-request stderr noise

    return Handler
