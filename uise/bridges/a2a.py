"""
Bridge to the A2A protocol.

Field names follow the A2A specification as published at the time of writing,
verified against the document rather than recalled:

  * AgentCard: `id` and `name` required; `description`, `provider`, `capabilities`,
    `skills`, `interfaces`, `securitySchemes`, `security`, `extensions`,
    `signature` optional.
  * AgentSkill: `id` and `name` required; `description`, `inputSchema`,
    `outputSchema`, `extensions` optional.
  * Agent cards are published at `/.well-known/agent-card.json`.
  * Messages are sent with the JSON-RPC method `sendMessage`.

A2A is a moving specification, so this bridge is **lenient on input and minimal on
output**: it reads whatever endpoint information a card happens to carry, and it
emits only fields whose names were verified. In particular the internal shape of
`AgentInterface` could not be confirmed, so the bridge writes a `url` key and
reads any `url` key it finds, rather than inventing sub-fields that would look
authoritative and be wrong.

As with MCP, price, SLA and settlement have nowhere to live in A2A. That absence
is what a bridged agent gains by crossing over.
"""

A2A_NAMESPACE = "org.a2a"
EXTENSION_SKILL_ID = A2A_NAMESPACE + ".skill-id"
EXTENSION_SKILL_NAME = A2A_NAMESPACE + ".skill-name"

AGENT_CARD_PATH = "/.well-known/agent-card.json"

ANY_OBJECT = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}


def _endpoint_urls(card):
    """Read endpoint URLs leniently: A2A has moved this field before."""
    urls = []
    for interface in card.get("interfaces") or []:
        if isinstance(interface, dict) and interface.get("url"):
            urls.append(interface["url"])
        elif isinstance(interface, str):
            urls.append(interface)
    if not urls and card.get("url"):
        urls.append(card["url"])
    return urls


# --------------------------------------------------------------------------- #
# A2A -> UIP
# --------------------------------------------------------------------------- #

def capability_from_skill(skill, price=None, unit="USD", per="call"):
    """Convert one AgentSkill into a UIP capability declaration."""
    from .mcp import normalize_capability_id

    skill_id = skill["id"]
    capability_id = normalize_capability_id(skill_id)
    capability = {
        "id": capability_id,
        "input_schema": dict(skill.get("inputSchema") or ANY_OBJECT),
        "output_schema": dict(skill.get("outputSchema") or ANY_OBJECT),
    }
    if skill.get("description"):
        capability["description"] = skill["description"]
    if price is not None:
        if not isinstance(price, str):
            raise TypeError("price must be a decimal string, never a float")
        capability["price"] = {"amount": price, "unit": unit, "per": per}

    extensions = {}
    if capability_id != skill_id:
        extensions[EXTENSION_SKILL_ID] = skill_id
    if skill.get("name"):
        extensions[EXTENSION_SKILL_NAME] = skill["name"]
    if extensions:
        capability["x"] = extensions
    return capability


def descriptor_from_agent_card(card, agent_did, endpoint=None, price=None,
                               unit="USD", per="call"):
    """Convert an A2A AgentCard into a UIP Capability Descriptor."""
    skills = card.get("skills") or []
    if not skills:
        raise ValueError("an agent card with no skills cannot become a descriptor")

    url = endpoint or (_endpoint_urls(card) or [None])[0]
    if not url:
        raise ValueError("agent card carries no endpoint URL")

    descriptor = {
        "v": "uip/1",
        "agent": agent_did,
        "name": card["name"],
        "capabilities": [capability_from_skill(skill, price, unit, per)
                         for skill in skills],
        "endpoints": [{"transport": "https", "url": url}],
    }
    if card.get("description"):
        descriptor["description"] = card["description"]
    return descriptor


# --------------------------------------------------------------------------- #
# UIP -> A2A
# --------------------------------------------------------------------------- #

def skill_from_capability(capability):
    """Convert a UIP capability back into an AgentSkill. Price and SLA are lost."""
    extensions = capability.get("x") or {}
    skill = {
        "id": extensions.get(EXTENSION_SKILL_ID, capability["id"]),
        "name": extensions.get(EXTENSION_SKILL_NAME, capability["id"]),
        "inputSchema": dict(capability["input_schema"]),
        "outputSchema": dict(capability["output_schema"]),
    }
    if capability.get("description"):
        skill["description"] = capability["description"]
    return skill


def agent_card_from_descriptor(descriptor, card_id=None):
    """
    Render a UIP descriptor as an A2A AgentCard.

    `id` defaults to the agent's DID: it is already a globally unique identifier
    that carries its own verification key, which is strictly more than A2A asks
    for and costs nothing to provide.
    """
    card = {
        "id": card_id or descriptor["agent"],
        "name": descriptor["name"],
        "skills": [skill_from_capability(c) for c in descriptor["capabilities"]],
        "interfaces": [{"url": endpoint["url"]} for endpoint in descriptor["endpoints"]],
    }
    if descriptor.get("description"):
        card["description"] = descriptor["description"]
    return card


def send_message_params(capability, text, message_id=None, role="user"):
    """
    Build params for the A2A `sendMessage` JSON-RPC method.

    Only `message` is populated; `tenant`, `configuration` and `metadata` are
    omitted rather than guessed, since a wrong value is worse than an absent one.
    """
    extensions = capability.get("x") or {}
    message = {
        "role": role,
        "parts": [{"kind": "text", "text": text}],
        "skillId": extensions.get(EXTENSION_SKILL_ID, capability["id"]),
    }
    if message_id:
        message["messageId"] = message_id
    return {"message": message}


# --------------------------------------------------------------------------- #
# Putting an existing A2A agent on the network
# --------------------------------------------------------------------------- #

def bridge_agent(card, invoke_skill, price=None, unit="USD", per="call",
                 suite=None, endpoint=None):
    """
    Wrap a live A2A agent as a Uise agent.

    `invoke_skill(skill_id, payload)` performs the A2A call however the caller
    prefers. Nothing inside the A2A agent changes: it gains a cryptographic
    identity, signed messages and receipts by being wrapped.
    """
    from ..agent import Agent                      # imported here to avoid a cycle

    skills = card.get("skills") or []
    if not skills:
        raise ValueError("an agent card with no skills cannot become an agent")

    agent = Agent.generate(name=card["name"], suite=suite, endpoint=endpoint,
                           description=card.get("description"))
    for skill in skills:
        declaration = capability_from_skill(skill, price, unit, per)
        skill_id = skill_from_capability(declaration)["id"]

        def handler(payload, _skill_id=skill_id):
            return invoke_skill(_skill_id, payload or {})

        agent.add_capability(declaration, handler)
    return agent
