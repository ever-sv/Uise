"""
Bridge tests - MCP and A2A translation.

The central assertions here are round-trip fidelity and declared loss. A bridge
that quietly renames somebody's tool, or that pretends a price survived a format
which has nowhere to put one, is worse than no bridge: it produces documents that
look right and are not.
"""

import json

import pytest

from uip import codec, envelope
from uise import Agent
from uise.bridges import a2a, mcp
from uise.transport import decode_wire, encode_wire

# Verbatim from the MCP specification, revision 2025-06-18.
WEATHER_TOOL = {
    "name": "get_weather",
    "title": "Weather Information Provider",
    "description": "Get current weather information for a location",
    "inputSchema": {
        "type": "object",
        "properties": {"location": {"type": "string", "description": "City name or zip code"}},
        "required": ["location"],
    },
}

WEATHER_DATA_TOOL = {
    "name": "get_weather_data",
    "title": "Weather Data Retriever",
    "description": "Get current weather data for a location",
    "inputSchema": {
        "type": "object",
        "properties": {"location": {"type": "string"}},
        "required": ["location"],
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "temperature": {"type": "number"},
            "conditions": {"type": "string"},
            "humidity": {"type": "number"},
        },
        "required": ["temperature", "conditions", "humidity"],
    },
}

AGENT_CARD = {
    "id": "urn:example:translator",
    "name": "Translator",
    "description": "Translates text between languages.",
    "skills": [
        {
            "id": "translateText",
            "name": "Translate text",
            "description": "Translates a text between two languages.",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
            "outputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
        }
    ],
    "interfaces": [{"url": "https://translator.example.com/a2a"}],
}

DID = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"


# --------------------------------------------------------------------------- #
# MCP
# --------------------------------------------------------------------------- #

class TestMcpTranslation:
    def test_tool_becomes_a_capability(self):
        capability = mcp.capability_from_tool(WEATHER_TOOL)
        assert capability["id"] == "get_weather"
        assert capability["input_schema"] == WEATHER_TOOL["inputSchema"]
        assert capability["description"] == WEATHER_TOOL["description"]
        assert capability["x"][mcp.EXTENSION_TOOL_TITLE] == WEATHER_TOOL["title"]

    def test_missing_output_schema_becomes_the_real_mcp_result_shape(self):
        """
        A tool without an outputSchema still returns content blocks. Declaring
        that is more truthful than declaring an empty object.
        """
        capability = mcp.capability_from_tool(WEATHER_TOOL)
        assert capability["output_schema"] == mcp.UNSTRUCTURED_RESULT_SCHEMA
        assert "outputSchema" not in mcp.tool_from_capability(capability)

    def test_round_trip_is_exact(self):
        for tool in (WEATHER_TOOL, WEATHER_DATA_TOOL):
            assert mcp.tool_from_capability(mcp.capability_from_tool(tool)) == tool

    def test_names_uip_cannot_express_survive_the_round_trip(self):
        """A bridge that silently renames somebody's tool is a broken bridge."""
        awkward = dict(WEATHER_TOOL, name="getWeatherNOW")
        capability = mcp.capability_from_tool(awkward)
        assert capability["id"] == "getweathernow"
        assert capability["x"][mcp.EXTENSION_TOOL_NAME] == "getWeatherNOW"
        assert mcp.tool_from_capability(capability)["name"] == "getWeatherNOW"

    def test_rejects_a_name_it_cannot_normalize(self):
        with pytest.raises(ValueError):
            mcp.capability_from_tool(dict(WEATHER_TOOL, name="!!!"))

    def test_price_is_added_on_the_way_in_and_lost_on_the_way_out(self):
        """
        The declared gap. MCP has nowhere to record a price, so crossing back
        drops it - which is exactly why crossing in is worth doing.
        """
        capability = mcp.capability_from_tool(WEATHER_TOOL, price="0.0002")
        assert capability["price"] == {"amount": "0.0002", "unit": "USD", "per": "call"}
        assert "price" not in json.dumps(mcp.tool_from_capability(capability))

    def test_float_prices_are_refused(self):
        with pytest.raises(TypeError):
            mcp.capability_from_tool(WEATHER_TOOL, price=0.0002)

    def test_structured_results_are_unwrapped(self):
        result = {
            "content": [{"type": "text", "text": '{"temperature": 22.5}'}],
            "structuredContent": {"temperature": 22.5, "conditions": "Partly cloudy"},
        }
        assert mcp.result_to_payload(result) == result["structuredContent"]

    def test_tool_execution_errors_are_preserved_not_swallowed(self):
        """MCP treats isError as data the caller must read, not a transport fault."""
        result = {"content": [{"type": "text", "text": "rate limit exceeded"}],
                  "isError": True}
        payload = mcp.result_to_payload(result)
        assert payload["isError"] is True
        assert payload["content"] == result["content"]

    def test_descriptor_from_a_tools_list_result(self):
        descriptor = mcp.descriptor_from_tools(
            DID, "weather", {"tools": [WEATHER_TOOL, WEATHER_DATA_TOOL]},
            "https://weather.example.com/uip/v1", price="0.0002",
        )
        assert descriptor["agent"] == DID
        assert [c["id"] for c in descriptor["capabilities"]] == \
               ["get_weather", "get_weather_data"]
        assert mcp.tools_from_descriptor(descriptor)["tools"] == \
               [WEATHER_TOOL, WEATHER_DATA_TOOL]

    def test_call_params_use_the_original_tool_name(self):
        capability = mcp.capability_from_tool(dict(WEATHER_TOOL, name="getWeatherNOW"))
        params = mcp.call_params(capability, {"location": "Madrid"})
        assert params == {"name": "getWeatherNOW", "arguments": {"location": "Madrid"}}


class TestMcpBridgedAgent:
    def _server(self):
        calls = []

        def list_tools():
            return {"tools": [WEATHER_TOOL]}

        def call_tool(name, arguments):
            calls.append((name, arguments))
            return {"content": [{"type": "text", "text": "sunny in " + arguments["location"]}]}

        return list_tools, call_tool, calls

    def test_an_mcp_server_becomes_a_chargeable_agent(self):
        list_tools, call_tool, calls = self._server()
        agent = mcp.bridge_agent(list_tools=list_tools, call_tool=call_tool,
                                 name="weather", price="0.0002")

        descriptor = agent.descriptor()
        capability = descriptor["capabilities"][0]
        assert capability["id"] == "get_weather"
        assert capability["price"]["amount"] == "0.0002"

        client = Agent.generate()
        body = codec.canonicalize({"capability": "get_weather",
                                   "input": {"location": "Madrid"}})
        request = client._sign("request", agent.did, body, "application/json")
        status, frame = agent.handle(encode_wire(request, body))
        assert status == 200

        header, response_body = decode_wire(frame)
        envelope.verify_envelope(header, response_body, now_ms=header["ts"], seen_ids=set())
        assert calls == [("get_weather", {"location": "Madrid"})]
        assert json.loads(response_body)["content"][0]["text"] == "sunny in Madrid"

    def test_the_wrapped_server_gains_a_verifiable_identity(self):
        """The MCP server did not change; it acquired an identity by being wrapped."""
        list_tools, call_tool, _ = self._server()
        agent = mcp.bridge_agent(list_tools=list_tools, call_tool=call_tool, name="weather")
        header, body = agent.announcement()
        envelope.verify_envelope(header, body, now_ms=header["ts"], seen_ids=set())
        assert json.loads(body)["agent"] == agent.did

    def test_an_empty_server_is_refused(self):
        with pytest.raises(ValueError):
            mcp.bridge_agent(list_tools=lambda: {"tools": []},
                             call_tool=lambda name, args: {}, name="empty")


# --------------------------------------------------------------------------- #
# A2A
# --------------------------------------------------------------------------- #

class TestA2aTranslation:
    def test_well_known_path_matches_the_specification(self):
        assert a2a.AGENT_CARD_PATH == "/.well-known/agent-card.json"

    def test_agent_card_becomes_a_descriptor(self):
        descriptor = a2a.descriptor_from_agent_card(AGENT_CARD, DID, price="0.0004")
        assert descriptor["name"] == "Translator"
        assert descriptor["endpoints"][0]["url"] == "https://translator.example.com/a2a"
        capability = descriptor["capabilities"][0]
        assert capability["id"] == "translatetext"
        assert capability["x"][a2a.EXTENSION_SKILL_ID] == "translateText"
        assert capability["price"]["amount"] == "0.0004"

    def test_skill_round_trip_is_exact(self):
        descriptor = a2a.descriptor_from_agent_card(AGENT_CARD, DID)
        card = a2a.agent_card_from_descriptor(descriptor)
        assert card["skills"] == AGENT_CARD["skills"]
        assert card["name"] == AGENT_CARD["name"]
        assert card["interfaces"] == AGENT_CARD["interfaces"]

    def test_card_id_defaults_to_the_did(self):
        """A DID is a globally unique id that carries its own verification key."""
        descriptor = a2a.descriptor_from_agent_card(AGENT_CARD, DID)
        assert a2a.agent_card_from_descriptor(descriptor)["id"] == DID

    def test_endpoint_reading_is_lenient(self):
        """A2A has moved this field before, so the bridge accepts either shape."""
        legacy = {k: v for k, v in AGENT_CARD.items() if k != "interfaces"}
        legacy["url"] = "https://legacy.example.com/a2a"
        descriptor = a2a.descriptor_from_agent_card(legacy, DID)
        assert descriptor["endpoints"][0]["url"] == "https://legacy.example.com/a2a"

    def test_a_card_without_an_endpoint_is_refused(self):
        stripped = {k: v for k, v in AGENT_CARD.items() if k != "interfaces"}
        with pytest.raises(ValueError):
            a2a.descriptor_from_agent_card(stripped, DID)

    def test_price_does_not_survive_the_return_trip(self):
        descriptor = a2a.descriptor_from_agent_card(AGENT_CARD, DID, price="0.0004")
        card = a2a.agent_card_from_descriptor(descriptor)
        assert "0.0004" not in json.dumps(card)

    def test_send_message_params_carry_the_original_skill_id(self):
        descriptor = a2a.descriptor_from_agent_card(AGENT_CARD, DID)
        params = a2a.send_message_params(descriptor["capabilities"][0], "hola")
        assert params["message"]["skillId"] == "translateText"
        assert params["message"]["parts"][0]["text"] == "hola"
        # Fields whose shape was not verifiable are omitted, never guessed.
        assert set(params) == {"message"}


class TestA2aBridgedAgent:
    def test_an_a2a_agent_becomes_a_chargeable_agent(self):
        calls = []

        def invoke_skill(skill_id, payload):
            calls.append((skill_id, payload))
            return {"text": payload["text"].upper()}

        agent = a2a.bridge_agent(AGENT_CARD, invoke_skill, price="0.0004")
        client = Agent.generate()
        body = codec.canonicalize({"capability": "translatetext",
                                   "input": {"text": "hola"}})
        request = client._sign("request", agent.did, body, "application/json")
        status, frame = agent.handle(encode_wire(request, body))

        assert status == 200
        assert calls == [("translateText", {"text": "hola"})]
        _, response_body = decode_wire(frame)
        assert json.loads(response_body) == {"text": "HOLA"}


# --------------------------------------------------------------------------- #
# What the bridges are for
# --------------------------------------------------------------------------- #

class TestDeclaredGap:
    def test_neither_format_can_carry_price_sla_or_settlement(self):
        """
        This is the reason UIP exists rather than being a profile of MCP or A2A.
        If either format could express these, the bridge would be the product.
        """
        capability = mcp.capability_from_tool(
            WEATHER_TOOL, price="0.0002",
        )
        capability["sla"] = {"p95_ms": 800}

        as_mcp = json.dumps(mcp.tool_from_capability(capability))
        as_a2a = json.dumps(a2a.skill_from_capability(capability))
        for rendered in (as_mcp, as_a2a):
            assert "price" not in rendered
            assert "sla" not in rendered
            assert "receipt" not in rendered
