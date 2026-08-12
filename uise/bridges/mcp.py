"""
Bridge to the Model Context Protocol.

Field names follow the MCP specification revision 2025-06-18, verified against the
published document rather than recalled:

  * `tools/list` returns `tools[]`, each with `name` (required), `title`,
    `description`, `inputSchema` (required), `outputSchema`, `annotations`.
  * `tools/call` takes params `{ "name", "arguments" }`.
  * A result carries `content[]`, optional `structuredContent`, optional `isError`.

Two things are deliberately not carried across:

  * `annotations` are dropped. MCP itself instructs clients to treat them as
    untrusted unless the server is trusted, and Uise has no notion of a trusted
    server - every claim must be signed.
  * Price and SLA have nowhere to live in MCP. That absence is the reason the
    bridge is worth building: an MCP tool that crosses it becomes chargeable.
"""

import re

MCP_NAMESPACE = "io.modelcontextprotocol"
EXTENSION_TOOL_NAME = MCP_NAMESPACE + ".tool-name"
EXTENSION_TOOL_TITLE = MCP_NAMESPACE + ".tool-title"

# The shape an MCP tool result always has. Used as the output schema for tools
# that declare none, which is more truthful than an empty object: this is what
# such a tool actually returns.
UNSTRUCTURED_RESULT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "content": {"type": "array", "items": {"type": "object"}},
        "isError": {"type": "boolean"},
    },
    "required": ["content"],
}

_VALID_CAPABILITY_ID = re.compile(r"^[a-z0-9]+([._-][a-z0-9]+)*$")


def normalize_capability_id(name):
    """
    Turn an MCP tool name into a valid UIP capability id.

    MCP allows names UIP does not, so the original is preserved under `x` whenever
    normalization changes it. Without that, a round trip would silently rename
    somebody's tool.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("tool name must be a non-empty string")
    if _VALID_CAPABILITY_ID.match(name):
        return name
    lowered = re.sub(r"[^a-z0-9._-]+", ".", name.lower())
    collapsed = re.sub(r"[._-]{2,}", ".", lowered).strip("._-")
    if not _VALID_CAPABILITY_ID.match(collapsed):
        raise ValueError("cannot derive a capability id from %r" % name)
    return collapsed


# --------------------------------------------------------------------------- #
# MCP -> UIP
# --------------------------------------------------------------------------- #

def capability_from_tool(tool, price=None, unit="USD", per="call", sla=None):
    """Convert one MCP tool definition into a UIP capability declaration."""
    name = tool["name"]
    capability_id = normalize_capability_id(name)
    capability = {
        "id": capability_id,
        "input_schema": dict(tool["inputSchema"]),
        "output_schema": dict(tool.get("outputSchema") or UNSTRUCTURED_RESULT_SCHEMA),
    }
    if tool.get("description"):
        capability["description"] = tool["description"]
    if price is not None:
        if not isinstance(price, str):
            raise TypeError("price must be a decimal string, never a float")
        capability["price"] = {"amount": price, "unit": unit, "per": per}
    if sla is not None:
        capability["sla"] = dict(sla)

    extensions = {}
    if capability_id != name:
        extensions[EXTENSION_TOOL_NAME] = name
    if tool.get("title"):
        extensions[EXTENSION_TOOL_TITLE] = tool["title"]
    if extensions:
        capability["x"] = extensions
    return capability


def descriptor_from_tools(agent_did, name, tools, endpoint, price=None, unit="USD",
                          per="call", description=None):
    """Build a full UIP Capability Descriptor from an MCP `tools/list` result."""
    listed = tools["tools"] if isinstance(tools, dict) else tools
    if not listed:
        raise ValueError("an MCP server with no tools cannot become an agent")
    descriptor = {
        "v": "uip/1",
        "agent": agent_did,
        "name": name,
        "capabilities": [capability_from_tool(tool, price, unit, per) for tool in listed],
        "endpoints": [{"transport": "https", "url": endpoint}],
    }
    if description:
        descriptor["description"] = description
    return descriptor


def result_to_payload(result):
    """
    Convert an MCP `tools/call` result into a UIP response body.

    A structured result is unwrapped, since that is the useful value. Anything
    else is passed through whole, including `isError`: MCP treats tool execution
    errors as data the caller is meant to read, not as transport failures, and
    flattening that distinction would lose information the caller needs.
    """
    if result.get("isError"):
        return {"content": result.get("content", []), "isError": True}
    if "structuredContent" in result:
        return dict(result["structuredContent"])
    return {"content": result.get("content", []), "isError": False}


# --------------------------------------------------------------------------- #
# UIP -> MCP
# --------------------------------------------------------------------------- #

def tool_from_capability(capability):
    """Convert a UIP capability back into an MCP tool definition."""
    extensions = capability.get("x") or {}
    tool = {
        "name": extensions.get(EXTENSION_TOOL_NAME, capability["id"]),
        "inputSchema": dict(capability["input_schema"]),
    }
    if extensions.get(EXTENSION_TOOL_TITLE):
        tool["title"] = extensions[EXTENSION_TOOL_TITLE]
    if capability.get("description"):
        tool["description"] = capability["description"]
    if capability.get("output_schema") != UNSTRUCTURED_RESULT_SCHEMA:
        tool["outputSchema"] = dict(capability["output_schema"])
    return tool


def tools_from_descriptor(descriptor):
    """Render a UIP descriptor as an MCP `tools/list` result. Price and SLA are lost."""
    return {"tools": [tool_from_capability(c) for c in descriptor["capabilities"]]}


def call_params(capability, arguments):
    """Build `tools/call` params for a UIP capability."""
    extensions = capability.get("x") or {}
    return {
        "name": extensions.get(EXTENSION_TOOL_NAME, capability["id"]),
        "arguments": dict(arguments or {}),
    }


# --------------------------------------------------------------------------- #
# Putting an existing MCP server on the network
# --------------------------------------------------------------------------- #

def bridge_agent(list_tools, call_tool, name, price=None, unit="USD", per="call",
                 suite=None, endpoint=None, description=None):
    """
    Wrap a live MCP server as a Uise agent.

        agent = mcp.bridge_agent(
            list_tools=client.list_tools,
            call_tool=client.call_tool,
            name="weather",
            price="0.0002",
        )
        agent.serve(port=8080)

    `list_tools()` must return an MCP `tools/list` result (or the bare list), and
    `call_tool(name, arguments)` must return an MCP `tools/call` result. Nothing
    inside the MCP server changes: it gains an identity, signed messages and
    receipts by being wrapped, not by being rewritten.
    """
    from ..agent import Agent                      # imported here to avoid a cycle

    listed = list_tools()
    tools = listed["tools"] if isinstance(listed, dict) else listed
    if not tools:
        raise ValueError("an MCP server with no tools cannot become an agent")

    agent = Agent.generate(name=name, suite=suite, endpoint=endpoint,
                           description=description)
    for tool in tools:
        declaration = capability_from_tool(tool, price, unit, per)
        tool_name = call_params(declaration, {})["name"]

        def handler(payload, _tool_name=tool_name):
            return result_to_payload(call_tool(_tool_name, payload or {}))

        agent.add_capability(declaration, handler)
    return agent
