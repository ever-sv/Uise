"""
OpenAPI contract tests.

The document is generated from the router rather than maintained beside it, and
these tests are what keep that promise honest: every route must appear, with the
scope it actually enforces and the errors it can actually return. A contract that
drifts from the code is worse than no contract, because people build against it.
"""

import json

import pytest

from uise import Node, api, openapi
from uise.keys import SCOPE_ADMIN, SCOPE_READ, SCOPE_WRITE

pytest.importorskip("openapi_spec_validator")


@pytest.fixture(scope="module")
def document():
    return openapi.document(api.router, title="Uise API")


@pytest.fixture
def node():
    instance = Node(name="test-node", fee="0.0001", environment="test")
    instance.token = instance.keys.create("tests", [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN])[1]
    yield instance
    instance.close()


class TestValidity:
    def test_the_document_validates_against_the_specification(self, document):
        """Checked by a real validator, not by assertion that it looks right."""
        from openapi_spec_validator import validate

        validate(document)

    def test_it_targets_3_1_and_the_protocol_schema_dialect(self, document):
        """
        One schema language across the system: 3.1 uses JSON Schema 2020-12, the
        same dialect capability descriptors already use.
        """
        assert document["openapi"] == "3.1.0"
        assert document["jsonSchemaDialect"] == \
            "https://json-schema.org/draft/2020-12/schema"

    def test_it_is_json_serializable(self, document):
        json.dumps(document)


class TestFidelity:
    def test_every_route_appears(self, document):
        """The property that makes generation worth doing."""
        registered = {(route.method.lower(), route.template) for route in api.router.routes}
        documented = {(method, path)
                      for path, operations in document["paths"].items()
                      for method in operations}
        assert registered == documented

    def test_operation_ids_are_unique(self, document):
        ids = [operation["operationId"]
               for operations in document["paths"].values()
               for operation in operations.values()]
        assert len(ids) == len(set(ids))

    def test_every_operation_is_summarised(self, document):
        for path, operations in document["paths"].items():
            for method, operation in operations.items():
                assert operation["summary"], "%s %s has no summary" % (method, path)

    def test_declared_scopes_match_what_is_enforced(self, document):
        for route in api.router.routes:
            operation = document["paths"][route.template][route.method.lower()]
            if route.scope is None:
                assert "Requires the" not in operation.get("description", "")
            else:
                assert "`%s` scope" % route.scope in operation["description"]

    def test_path_parameters_are_derived_from_the_template(self, document):
        operation = document["paths"][api.PREFIX + "/accounts/{account}/balance"]["get"]
        path_params = [p for p in operation["parameters"] if p["in"] == "path"]
        assert [p["name"] for p in path_params] == ["account"]
        assert all(p["required"] for p in path_params)

    def test_write_endpoints_declare_a_body(self, document):
        for route in api.router.routes:
            if route.method != "POST":
                continue
            operation = document["paths"][route.template]["post"]
            assert operation["requestBody"]["required"] is True


class TestSecurityDocumentation:
    def test_bearer_authentication_is_the_global_default(self, document):
        assert document["security"] == [{"bearerAuth": []}]
        assert document["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"

    def test_only_declared_public_routes_opt_out(self, document):
        opted_out = {path for path, operations in document["paths"].items()
                     for operation in operations.values()
                     if operation.get("security") == []}
        assert opted_out == set(api.router.public_paths)
        assert opted_out == {api.PREFIX + "/health"}

    def test_authenticated_routes_document_their_failures(self, document):
        operation = document["paths"][api.PREFIX + "/stats"]["get"]
        assert {"401", "403", "429", "503"} <= set(operation["responses"])

    def test_a_public_route_does_not_document_a_401(self, document):
        operation = document["paths"][api.PREFIX + "/health"]["get"]
        assert "401" not in operation["responses"]
        assert "429" in operation["responses"]      # open does not mean unlimited


class TestQuotaDocumentation:
    def test_success_responses_advertise_the_quota(self, document):
        for path, operations in document["paths"].items():
            for method, operation in operations.items():
                success = next(code for code in operation["responses"]
                               if code.startswith("2"))
                headers = operation["responses"][success]["headers"]
                assert {"RateLimit-Limit", "RateLimit-Remaining",
                        "RateLimit-Reset"} <= set(headers), "%s %s" % (method, path)


class TestMoneyIsAlwaysAString:
    def test_no_monetary_field_is_declared_as_a_number(self, document):
        """
        Binary floating point for money is a defect. A contract that permits it
        invites every client to introduce one.
        """
        rendered = json.dumps(document["components"]["schemas"])
        assert '"type": "number"' not in rendered
        for name in ("Balance", "Statement"):
            assert document["components"]["schemas"][name]["properties"]["balance"] \
                == openapi.DECIMAL_STRING

    def test_deposit_amounts_are_decimal_strings(self, document):
        body = document["paths"][api.PREFIX + "/accounts/{account}/deposits"]["post"]
        schema = body["requestBody"]["content"]["application/json"]["schema"]
        assert schema["properties"]["amount"] == openapi.DECIMAL_STRING
        assert "reference" in schema["required"]


class TestServedEndpoint:
    def test_the_node_serves_its_own_contract(self, node):
        status, payload, _ = api.dispatch(node, api.Request(
            "GET", api.PREFIX + "/openapi.json", {},
            {"authorization": "Bearer " + node.token}, "203.0.113.9",
        ))
        assert status == 200
        assert payload["info"]["title"] == "test-node API"
        assert api.PREFIX + "/stats" in payload["paths"]

    def test_the_contract_requires_a_credential(self, node):
        """
        It enumerates the operator's whole surface. The canonical public copy
        belongs in the repository, not on a live node's open port.
        """
        status, _, _ = api.dispatch(node, api.Request(
            "GET", api.PREFIX + "/openapi.json", {}, {}, "203.0.113.9",
        ))
        assert status == 401

    def test_any_scope_can_read_the_contract(self, node):
        _, read_only = node.keys.create("reader", [SCOPE_READ])
        status, _, _ = api.dispatch(node, api.Request(
            "GET", api.PREFIX + "/openapi.json", {},
            {"authorization": "Bearer " + read_only}, "203.0.113.9",
        ))
        assert status == 200
