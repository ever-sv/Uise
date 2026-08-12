"""
Bridges to the agent formats that already exist - spec section 9.1.

Thousands of agents are already built against MCP and A2A. A bridge turns them
into Uise participants without their authors rewriting anything, which is the
only cheap path to adoption.

Translation is deliberately lossy in one direction, and that gap is the point:
**neither MCP nor A2A carries price, SLA, or settlement.** An MCP tool crossing
this bridge gains a cryptographic identity, verifiable messages, and receipts it
could not otherwise have. Going back the other way, those things are dropped -
there is nowhere to put them.

Identifiers that do not survive translation are preserved under the capability's
`x` extension, so a round trip returns the original document unchanged rather
than a plausible-looking approximation.
"""

from . import a2a, mcp

__all__ = ["a2a", "mcp"]
