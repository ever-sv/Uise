"""
Uise SDK - connect an agent to the UIP-1 network, or run a node.

    from uise import Agent

    agent = Agent.generate(name="translator")

    @agent.capability("translate.text", price="0.0004")
    def translate(payload):
        return {"text": payload["text"].upper()}

    agent.serve(port=8080)

Importing this package registers the production cryptographic suites into the
shared `uip.suites` registry: constant-time Ed25519 for the conversation plane,
and NIST ML-DSA-65 - alone or composed with Ed25519 - for issuers, whose receipts
are permanent evidence and must survive quantum computers.

The protocol logic itself lives in `uip`, which has no dependencies and is the
same code the conformance suite verifies. There is no second implementation here.
"""

from uip.envelope import ReplayStore, UipError

from . import (api, billing, bridges, credits, dashboard, events, keys, log,
               openapi, ratelimit, suites)
from .agent import Agent, Capability
from .credits import Credits, InsufficientCredit
from .identity import Identity
from .node import Node, verify_signed_tree_head
from .storage import Storage
from .transport import TransportError

__version__ = "0.1.0"

__all__ = [
    "Agent",
    "Capability",
    "Credits",
    "Identity",
    "InsufficientCredit",
    "Node",
    "ReplayStore",
    "Storage",
    "TransportError",
    "UipError",
    "api",
    "billing",
    "bridges",
    "credits",
    "dashboard",
    "events",
    "keys",
    "log",
    "openapi",
    "ratelimit",
    "suites",
    "verify_signed_tree_head",
]
