"""
OpenAPI document, generated from the router.

It is derived from the routes themselves rather than written alongside them. A
hand-maintained contract drifts from the code within weeks and then actively
misleads the people integrating against it - worse than having no document at all.
Generating it means the two cannot disagree, and a test asserts that every
registered route appears here.

The document targets OpenAPI 3.1, whose schema dialect is JSON Schema 2020-12 -
the same dialect the protocol already uses for capability descriptors. One schema
language across the whole system rather than two.
"""

OPENAPI_VERSION = "3.1.0"
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

SECURITY_SCHEME = "bearerAuth"

# Applied to every response, because a client that cannot see its remaining quota
# will discover the limit only by being refused.
RATE_LIMIT_HEADERS = {
    "RateLimit-Limit": {"schema": {"type": "string"},
                        "description": "Requests permitted per window."},
    "RateLimit-Remaining": {"schema": {"type": "string"},
                            "description": "Requests left in the current window."},
    "RateLimit-Reset": {"schema": {"type": "string"},
                        "description": "Seconds until the quota is fully restored."},
}

DECIMAL_STRING = {
    "type": "string",
    "pattern": r"^-?(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$",
    "description": "Exact decimal as a string. Never a JSON number: binary "
                   "floating point for money is a defect, not a rounding detail.",
}

SCHEMAS = {
    "Error": {
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {"type": "string",
                             "description": "Stable machine-readable code."},
                    "message": {"type": "string"},
                },
            }
        },
    },
    "Account": {
        "type": "object",
        "required": ["did", "label", "rail", "created_at"],
        "properties": {
            "did": {"type": "string"},
            "label": {"type": "string"},
            "rail": {"enum": ["manual", "stripe", "stablecoin"]},
            "rail_ref": {"type": ["string", "null"]},
            "credit_limit": {
                "oneOf": [DECIMAL_STRING, {"type": "null"}],
                "description": "How far below zero the balance may go. null "
                               "inherits the node policy.",
            },
            "created_at": {"type": "integer"},
        },
    },
    "Balance": {
        "type": "object",
        "required": ["account", "unit", "balance", "credit_limit"],
        "properties": {
            "account": {"type": "string"},
            "unit": {"type": "string"},
            "balance": DECIMAL_STRING,
            "credit_limit": {"oneOf": [DECIMAL_STRING, {"type": "null"}]},
        },
    },
    "LedgerEntry": {
        "type": "object",
        "required": ["seq", "delta", "kind", "created_at"],
        "properties": {
            "seq": {"type": "integer"},
            "delta": DECIMAL_STRING,
            "kind": {"enum": ["deposit", "issuance", "refund", "adjustment"]},
            "reference": {"type": ["string", "null"],
                          "description": "The real-world payment this movement "
                                         "came from. Required for every deposit."},
            "created_at": {"type": "integer"},
        },
    },
    "Statement": {
        "type": "object",
        "required": ["account", "unit", "balance", "entries"],
        "properties": {
            "account": {"type": "string"},
            "unit": {"type": "string"},
            "balance": DECIMAL_STRING,
            "limit": {"oneOf": [DECIMAL_STRING, {"type": "null"}]},
            "entries": {"type": "array", "items": {"$ref": "#/components/schemas/LedgerEntry"}},
        },
    },
    "ReceiptEntry": {
        "type": "object",
        "required": ["index", "rid", "receipt"],
        "properties": {
            "index": {"type": "integer",
                      "description": "Position in the transparency log."},
            "rid": {"type": "string"},
            "receipt": {"type": "object",
                        "description": "A UIP-1 receipt. See spec section 10."},
            "anchor": {"type": ["object", "null"],
                       "description": "Merkle inclusion proof, present on a single "
                                      "receipt lookup."},
        },
    },
    "ReceiptPage": {
        "type": "object",
        "required": ["receipts", "cursor", "next_cursor", "tree_size"],
        "properties": {
            "receipts": {"type": "array",
                         "items": {"$ref": "#/components/schemas/ReceiptEntry"}},
            "cursor": {"type": "integer"},
            "next_cursor": {"type": ["integer", "null"],
                            "description": "null when the last page has been reached."},
            "tree_size": {"type": "integer"},
        },
    },
    "ApiKey": {
        "type": "object",
        "required": ["key_id", "label", "environment", "scopes", "created_at"],
        "properties": {
            "key_id": {"type": "string",
                       "description": "Public identifier. Safe to display and log."},
            "label": {"type": "string"},
            "environment": {"enum": ["live", "test"]},
            "scopes": {"type": "array", "items": {"enum": ["read", "write", "admin"]}},
            "created_at": {"type": "integer"},
            "last_used_at": {"type": ["integer", "null"]},
            "revoked_at": {"type": ["integer", "null"]},
        },
    },
    "CreatedApiKey": {
        "allOf": [
            {"$ref": "#/components/schemas/ApiKey"},
            {
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "The secret. Returned here and nowhere else, "
                                       "ever. No code path can recover it afterwards.",
                    },
                    "warning": {"type": "string"},
                },
            },
        ]
    },
    "Health": {
        "type": "object",
        "required": ["status", "protocol", "api"],
        "properties": {
            "status": {"const": "ok"},
            "protocol": {"type": "string"},
            "api": {"type": "string"},
        },
    },
    "Stats": {
        "type": "object",
        "required": ["issuer", "log", "totals", "credits", "daily", "generated_at"],
        "properties": {
            "issuer": {"type": "object"},
            "log": {"type": "object"},
            "totals": {
                "type": "object",
                "properties": {
                    "receipts": {"type": "integer"},
                    "revenue": {"type": "object",
                                "description": "Exact decimals keyed by unit. What "
                                               "Uise charged."},
                    "transacted_volume": {"type": "object",
                                          "description": "Value moved between "
                                                         "agents. Uise never holds it."},
                    "transacting_agents": {"type": "integer"},
                    "registered_agents": {"type": "integer"},
                },
            },
            "credits": {"type": "object"},
            "daily": {"type": "array", "items": {"type": "object"}},
            "top_capabilities": {"type": "array", "items": {"type": "object"}},
            "accounts": {"type": "array", "items": {"$ref": "#/components/schemas/Account"}},
            "generated_at": {"type": "integer"},
        },
    },
}

DESCRIPTION = """\
The Uise product API.

This surface is separate from `/uip/v1`, which carries the UIP-1 protocol itself.
The protocol is frozen and open, because a standard cannot change once others
implement it. This one is authenticated and free to evolve.

**Authentication.** Every endpoint except `/health` requires a bearer token. Agents
never use one - they sign each protocol message, which a stolen log line cannot
reproduce. Tokens exist for browsers and scripts, which have nowhere safe to keep a
private key.

**Money is always a decimal string**, never a JSON number.

**Pagination is by cursor**, never by page number: with a log that only grows, page
three points at different rows every time something is appended.
"""


def _error_response(description):
    return {
        "description": description,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
    }


COMMON_RESPONSES = {
    "400": _error_response("The request was malformed."),
    "401": _error_response("No valid credential was presented."),
    "403": _error_response("The credential lacks the scope this endpoint needs."),
    "404": _error_response("No such resource."),
    "429": _error_response("Quota exhausted. The response carries Retry-After."),
    "503": _error_response("The API is unavailable: the node has no credentials, or "
                           "it is already streaming to as many clients as it accepts."),
}


def _path_parameters(template):
    return [
        {
            "name": segment[1:-1],
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
        }
        for segment in template.strip("/").split("/")
        if segment.startswith("{") and segment.endswith("}")
    ]


def _operation(route):
    responses = {
        str(route.status): {
            "description": route.response_description or "Success.",
            "headers": dict(RATE_LIMIT_HEADERS),
            "content": {route.response_content_type:
                        {"schema": route.response_schema or {"type": "object"}}},
        }
    }
    for status in route.error_statuses:
        responses[status] = COMMON_RESPONSES[status]

    operation = {
        "operationId": route.handler.__name__,
        "summary": route.summary,
        "parameters": _path_parameters(route.template) + list(route.parameters),
        "responses": responses,
    }
    if route.scope is not None:
        operation["description"] = "Requires the `%s` scope." % route.scope
    if route.request_schema is not None:
        operation["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": route.request_schema}},
        }
    if route.public:
        operation["security"] = []           # explicitly overrides the global default
    return operation


def document(router, title="Uise API", version="1.0.0"):
    """Build the OpenAPI document for a router. Pure: no node state involved."""
    paths = {}
    for route in router.routes:
        paths.setdefault(route.template, {})[route.method.lower()] = _operation(route)

    return {
        "openapi": OPENAPI_VERSION,
        "jsonSchemaDialect": SCHEMA_DIALECT,
        "info": {
            "title": title,
            "version": version,
            "description": DESCRIPTION,
            "license": {"name": "Apache-2.0",
                        "identifier": "Apache-2.0"},
        },
        "components": {
            "securitySchemes": {
                SECURITY_SCHEME: {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "A token minted by the node operator. Shown once "
                                   "at creation and never recoverable afterwards.",
                }
            },
            "schemas": dict(SCHEMAS),
        },
        "security": [{SECURITY_SCHEME: []}],
        "paths": paths,
    }
