"""
The Uise product API - `/api/v1`.

This is deliberately a different surface from `/uip/v1`:

    /uip/v1   The protocol. UIP-1. Anyone may implement it, and it is frozen.
    /api/v1   Uise's own product. Only Uise implements it, and it may evolve.

Mixing them would make commercial endpoints part of the standard, and a standard
cannot be changed once other people depend on it. Business data - revenue,
balances, accounts - therefore lives here and never in the protocol namespace.

**Authentication is not optional.** These endpoints expose what the operator earns
and who its customers are. A node with no credentials configured refuses to serve
them at all rather than serving them openly: a business API that is accidentally
public is not a smaller problem than one that is deliberately public.

Every route declares the scope it needs, and scopes do not imply one another. An
`admin` key cannot read revenue unless it was also granted `read`. Implicit
inheritance is how a credential quietly acquires powers nobody meant to give it.

Each route also declares its own documentation, so the OpenAPI contract is
generated from these definitions rather than maintained beside them. A contract
kept separately drifts from the code and then misleads the people integrating
against it.
"""

import json

from . import keys as keys_module
from . import openapi as openapi_module

VERSION = "v1"
PREFIX = "/api/" + VERSION

# Product error codes are lowercase and distinct from the protocol's UIP_ codes.
# One namespace is a frozen standard; the other is a product surface that will
# grow. Sharing a code space between them would freeze the product one too.
ERROR_UNAUTHORIZED = "unauthorized"
ERROR_FORBIDDEN = "forbidden"
ERROR_NOT_FOUND = "not_found"
ERROR_BAD_REQUEST = "bad_request"
ERROR_API_DISABLED = "api_disabled"
ERROR_RATE_LIMITED = "rate_limited"
ERROR_STREAM_FULL = "stream_full"

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# Loopback peers, checked against the real TCP source address rather than a
# header, so it cannot be spoofed by a client that is not actually local.
LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")


class ApiError(Exception):
    """A product-API failure with an HTTP status and a stable machine code."""

    def __init__(self, status, code, message, headers=None):
        super(ApiError, self).__init__(message)
        self.status = status
        self.code = code
        self.message = message
        # A 429 must carry its own quota headers: a client that cannot see when
        # to retry will simply retry immediately and make things worse.
        self.headers = headers or {}

    def payload(self):
        return {"error": {"code": self.code, "message": self.message}}


class Request(object):
    __slots__ = ("method", "path", "query", "headers", "peer", "body")

    def __init__(self, method, path, query=None, headers=None, peer=None, body=None):
        self.method = method
        self.path = path
        self.query = query or {}
        self.headers = headers or {}
        self.peer = peer
        self.body = body

    def one(self, name, default=None):
        values = self.query.get(name)
        return values[0] if values else default

    def integer(self, name, default):
        raw = self.one(name)
        if raw is None:
            return default
        try:
            return int(raw)
        except ValueError:
            raise ApiError(400, ERROR_BAD_REQUEST, "%s must be an integer" % name)

    def field(self, name, required=True, default=None):
        if not isinstance(self.body, dict):
            raise ApiError(400, ERROR_BAD_REQUEST, "a JSON object body is required")
        if name not in self.body:
            if required:
                raise ApiError(400, ERROR_BAD_REQUEST, "%s is required" % name)
            return default
        return self.body[name]

    @property
    def bearer(self):
        value = self.headers.get("authorization") or ""
        return value[len("Bearer "):].strip() if value.startswith("Bearer ") else None

    @property
    def is_local(self):
        return self.peer in LOOPBACK


class Stream(object):
    """
    A streaming response body.

    Returned by a handler instead of a payload; the HTTP layer recognises it and
    writes chunks as they arrive rather than buffering a response that never ends.
    """

    __slots__ = ("chunks", "content_type", "subscription")

    def __init__(self, chunks, content_type="text/event-stream", subscription=None):
        self.chunks = chunks
        self.content_type = content_type
        self.subscription = subscription

    def close(self):
        if self.subscription is not None:
            self.subscription.close()


def query(name, description, schema=None, required=False):
    return {"name": name, "in": "query", "required": required,
            "description": description, "schema": schema or {"type": "string"}}


def schema_ref(name):
    return {"$ref": "#/components/schemas/" + name}


class Route(object):
    """One endpoint, with everything the router and the contract both need."""

    __slots__ = ("method", "template", "segments", "scope", "public", "handler",
                 "summary", "parameters", "request_schema", "response_schema",
                 "response_description", "status", "error_statuses",
                 "response_content_type")

    def __init__(self, method, template, scope, public, handler, summary,
                 parameters, request_schema, response_schema,
                 response_description, status, errors,
                 response_content_type="application/json"):
        self.method = method
        self.template = template
        self.segments = template.strip("/").split("/")
        self.scope = scope
        self.public = public
        self.handler = handler
        self.summary = summary
        self.parameters = parameters
        self.request_schema = request_schema
        self.response_schema = response_schema
        self.response_description = response_description
        self.status = status
        self.error_statuses = self._errors(errors)
        self.response_content_type = response_content_type

    def _errors(self, extra):
        if self.public:
            statuses = ["429"]
        else:
            statuses = ["401", "429", "503"]
            if self.scope is not None:
                statuses.append("403")
        return sorted(set(statuses) | set(extra))


class Router(object):
    """Path router with `{name}` segment capture and per-route documentation."""

    def __init__(self):
        self.routes = []

    def _register(self, method, template, scope, public=False, summary="",
                  parameters=(), request_schema=None, response_schema=None,
                  response_description=None, status=200, errors=(),
                  response_content_type="application/json"):
        def register(handler):
            self.routes.append(Route(
                method, template, scope, public, handler, summary, parameters,
                request_schema, response_schema, response_description, status, errors,
                response_content_type,
            ))
            return handler
        return register

    def get(self, template, scope=keys_module.SCOPE_READ, **metadata):
        return self._register("GET", template, scope, **metadata)

    def post(self, template, scope=keys_module.SCOPE_WRITE, **metadata):
        metadata.setdefault("status", 201)      # creation, unless the route says otherwise
        return self._register("POST", template, scope, **metadata)

    def delete(self, template, scope=keys_module.SCOPE_ADMIN, **metadata):
        return self._register("DELETE", template, scope, **metadata)

    def resolve(self, method, path):
        segments = path.strip("/").split("/")
        allowed = set()
        for route in self.routes:
            params = _match(route.segments, segments)
            if params is None:
                continue
            if route.method != method:
                allowed.add(route.method)
                continue
            return route, params
        if allowed:
            raise ApiError(405, ERROR_BAD_REQUEST,
                           "method not allowed; try %s" % ", ".join(sorted(allowed)))
        raise ApiError(404, ERROR_NOT_FOUND, "no such endpoint")

    @property
    def public_paths(self):
        """Derived from the routes, so the two can never disagree."""
        return frozenset(route.template for route in self.routes if route.public)


def _match(template, segments):
    if len(template) != len(segments):
        return None
    params = {}
    for expected, actual in zip(template, segments):
        if expected.startswith("{") and expected.endswith("}"):
            params[expected[1:-1]] = actual
        elif expected != actual:
            return None
    return params


router = Router()

PAGE_PARAMETERS = (
    query("limit", "Items per page. Capped at %d." % MAX_PAGE_SIZE,
          {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE}),
)


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #

@router.get(PREFIX + "/health", scope=None, public=True,
            summary="Liveness check.",
            response_schema=schema_ref("Health"),
            response_description="The node is serving.")
def health(node, request, params, key):
    """
    Open by design, and deliberately empty of business data.

    A health check exists so a load balancer can use it, so it must not require a
    credential - and therefore must not reveal anything worth protecting.
    """
    return 200, {"status": "ok", "protocol": "uip/1", "api": VERSION}


@router.get(PREFIX + "/openapi.json", scope=None,
            summary="The machine-readable contract for this API.",
            response_description="An OpenAPI 3.1 document.")
def openapi(node, request, params, key):
    """
    Authenticated, though it is only a contract.

    The document enumerates the operator's whole surface. The canonical public
    copy belongs in the repository; this one describes a specific running node,
    and anyone integrating already holds a credential.
    """
    return 200, openapi_module.document(router, title="%s API" % node.name)


@router.get(PREFIX + "/events",
            summary="Live stream of node activity, as Server-Sent Events.",
            parameters=(query("last_event_id",
                              "Resume after this sequence number. The "
                              "`Last-Event-ID` header takes precedence.",
                              {"type": "integer", "minimum": 0}),),
            response_content_type="text/event-stream",
            response_schema={"type": "string",
                             "description": "An endless SSE stream. Event types: "
                                            "receipt.issued, agent.announced, "
                                            "credit.deposited, credit.low, "
                                            "stream.gap."},
            response_description="An open stream. It does not end.",
            errors=("503",))
def events(node, request, params, key):
    """
    Authenticated like every other endpoint, which means `EventSource` cannot be
    used directly: it cannot set headers. Browsers should read the stream with
    `fetch()` instead.

    The alternative - accepting the token as a query parameter - would write a
    live credential into every access log and proxy cache along the path. A slight
    inconvenience in the browser is the correct trade.
    """
    from .events import TooManySubscribers               # imported here to avoid a cycle

    header_value = request.headers.get("last-event-id")
    last_event_id = int(header_value) if (header_value or "").isdigit() else None
    if last_event_id is None:
        last_event_id = request.integer("last_event_id", None)

    try:
        subscription = node.events.subscribe(last_event_id)
    except TooManySubscribers as error:
        raise ApiError(503, ERROR_STREAM_FULL, str(error))
    return 200, Stream(iter(subscription), subscription=subscription)


@router.get(PREFIX + "/stats",
            summary="Metrics: receipts, revenue, transacted value, agents.",
            parameters=(query("days", "Days of daily history to include.",
                              {"type": "integer", "minimum": 1}),),
            response_schema=schema_ref("Stats"),
            response_description="Current totals and recent history.")
def stats(node, request, params, key):
    from . import dashboard                        # imported here to avoid a cycle

    return 200, dashboard.stats(node, days=request.integer("days", 30))


@router.get(PREFIX + "/accounts",
            summary="List billing accounts.",
            response_schema={"type": "object", "properties": {
                "accounts": {"type": "array", "items": schema_ref("Account")}}})
def accounts(node, request, params, key):
    return 200, {"accounts": node.storage.accounts()}


@router.get(PREFIX + "/accounts/{account}",
            summary="One billing account.",
            response_schema=schema_ref("Account"), errors=("404",))
def account(node, request, params, key):
    record = node.storage.account(params["account"])
    if record is None:
        raise ApiError(404, ERROR_NOT_FOUND, "no such account")
    return 200, record


@router.get(PREFIX + "/accounts/{account}/balance",
            summary="Current balance and credit limit.",
            parameters=(query("unit", "Currency or token symbol."),),
            response_schema=schema_ref("Balance"))
def balance(node, request, params, key):
    """
    Asking for an agent that joined an organization returns that organization's
    balance, because that is the one which governs whether it gets served. The
    resolved identifier comes back in `account`.
    """
    account = node.organizations.billing_account(params["account"])
    unit = request.one("unit", node.fee_unit)
    limit = node.credits.limit_for(account)
    return 200, {
        "account": account,
        "unit": unit,
        "balance": str(node.credits.balance(account, unit)),
        "credit_limit": None if limit is None else str(limit),
    }


@router.get(PREFIX + "/accounts/{account}/ledger",
            summary="Every movement on an account, with its cause.",
            parameters=(query("unit", "Currency or token symbol."),) + PAGE_PARAMETERS,
            response_schema=schema_ref("Statement"), errors=("400",))
def ledger(node, request, params, key):
    unit = request.one("unit", node.fee_unit)
    account = node.organizations.billing_account(params["account"])
    return 200, node.credits.statement(account, unit, _page_size(request))


@router.get(PREFIX + "/receipts",
            summary="Issued receipts, paginated by cursor.",
            parameters=(query("after", "Log position to read from.",
                              {"type": "integer", "minimum": 0}),) + PAGE_PARAMETERS,
            response_schema=schema_ref("ReceiptPage"), errors=("400",))
def receipts(node, request, params, key):
    """
    Cursor pagination, not page numbers.

    With a log that only grows, a page number points at different rows every time
    something is appended. A cursor is a position in the log and stays correct.
    """
    cursor = request.integer("after", 0)
    size = _page_size(request)
    entries = node.storage.entries(cursor, cursor + size)
    return 200, {
        "receipts": entries,
        "cursor": cursor,
        "next_cursor": cursor + len(entries) if len(entries) == size else None,
        "tree_size": node.storage.log_size(),
    }


@router.get(PREFIX + "/receipts/{rid}",
            summary="One receipt with its transparency-log inclusion proof.",
            response_schema=schema_ref("ReceiptEntry"), errors=("404",))
def receipt(node, request, params, key):
    entry = node.storage.entry_by_rid(params["rid"])
    if entry is None:
        raise ApiError(404, ERROR_NOT_FOUND, "no such receipt")
    return 200, dict(entry, anchor=node.anchor_for(entry["index"]))


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #

@router.post(PREFIX + "/accounts",
             summary="Create or update a billing account.",
             request_schema={
                 "type": "object",
                 "required": ["did", "label"],
                 "properties": {
                     "did": {"type": "string"},
                     "label": {"type": "string"},
                     "rail": {"enum": ["manual", "stripe", "stablecoin"]},
                     "rail_ref": {"type": "string"},
                     "credit_limit": {"type": "string",
                                      "description": "Decimal string. Omit to "
                                                     "inherit the node policy."},
                 },
             },
             response_schema=schema_ref("Account"),
             response_description="The stored account.", errors=("400",))
def create_account(node, request, params, key):
    from . import billing                          # imported here to avoid a cycle

    try:
        record = billing.register_account(
            node.storage,
            request.field("did"),
            request.field("label"),
            request.field("rail", required=False, default=billing.RAIL_MANUAL),
            request.field("rail_ref", required=False),
            request.field("credit_limit", required=False),
        )
    except (ValueError, TypeError) as error:
        raise ApiError(400, ERROR_BAD_REQUEST, str(error))
    return 201, record


@router.post(PREFIX + "/accounts/{account}/deposits",
             summary="Record that money arrived. Never receives money.",
             request_schema={
                 "type": "object",
                 "required": ["amount", "reference"],
                 "properties": {
                     "amount": openapi_module.DECIMAL_STRING,
                     "unit": {"type": "string"},
                     "reference": {"type": "string",
                                   "description": "The real payment this came from: "
                                                  "a transfer id, transaction hash "
                                                  "or payment intent. Required - an "
                                                  "unreferenced credit is an "
                                                  "unauditable balance."},
                 },
             },
             response_schema={"type": "object", "properties": {
                 "account": {"type": "string"},
                 "balance": openapi_module.DECIMAL_STRING}},
             response_description="The balance after the deposit.", errors=("400",))
def record_deposit(node, request, params, key):
    """
    The node holds no payment credentials. The operator confirms the transfer,
    on-chain payment or card charge in the provider's own console, then records it
    here with that provider's reference.
    """
    try:
        balance_after = node.deposit(
            params["account"],
            request.field("amount"),
            request.field("unit", required=False, default=node.fee_unit),
            request.field("reference"),
        )
    except (ValueError, TypeError) as error:
        raise ApiError(400, ERROR_BAD_REQUEST, str(error))
    return 201, {"account": params["account"], "balance": str(balance_after)}


@router.post(PREFIX + "/accounts/{account}/limit", status=200,
             summary="Grant post-paid terms by raising the credit limit.",
             request_schema={
                 "type": "object",
                 "required": ["credit_limit"],
                 "properties": {"credit_limit": openapi_module.DECIMAL_STRING},
             },
             response_schema={"type": "object", "properties": {
                 "account": {"type": "string"},
                 "credit_limit": {"oneOf": [openapi_module.DECIMAL_STRING,
                                            {"type": "null"}]}}},
             errors=("400",))
def set_limit(node, request, params, key):
    try:
        account = node.organizations.billing_account(params["account"])
        limit = node.credits.set_limit(account, request.field("credit_limit"))
    except (ValueError, TypeError) as error:
        raise ApiError(400, ERROR_BAD_REQUEST, str(error))
    return 200, {"account": account,
                 "credit_limit": None if limit is None else str(limit)}


# --------------------------------------------------------------------------- #
# Organizations
# --------------------------------------------------------------------------- #

@router.get(PREFIX + "/organizations",
            summary="List organization accounts.",
            response_schema={"type": "object", "properties": {
                "organizations": {"type": "array", "items": schema_ref("Account")}}})
def organizations(node, request, params, key):
    return 200, {"organizations": node.organizations.list()}


@router.post(PREFIX + "/organizations",
             summary="Open an organization account: one balance, many agents.",
             request_schema={
                 "type": "object",
                 "required": ["label"],
                 "properties": {
                     "label": {"type": "string"},
                     "rail": {"enum": ["manual", "stripe", "stablecoin"]},
                     "rail_ref": {"type": "string"},
                     "credit_limit": {"type": "string",
                                      "description": "Decimal string. Omit to "
                                                     "inherit the node policy."},
                 },
             },
             response_schema=schema_ref("Account"),
             response_description="The new organization. It starts with no members.",
             errors=("400",))
def create_organization(node, request, params, key):
    """
    A company running a thousand agents funds one balance and receives one
    invoice, instead of topping up a thousand.
    """
    try:
        record = node.organizations.create(
            request.field("label"),
            request.field("rail", required=False, default="manual"),
            request.field("rail_ref", required=False),
            request.field("credit_limit", required=False),
        )
    except (ValueError, TypeError) as error:
        raise ApiError(400, ERROR_BAD_REQUEST, str(error))
    return 201, record


@router.get(PREFIX + "/organizations/{account}",
            summary="One organization account.",
            response_schema=schema_ref("Account"), errors=("404",))
def organization(node, request, params, key):
    record = node.organizations.get(params["account"])
    if record is None:
        raise ApiError(404, ERROR_NOT_FOUND, "no such organization")
    return 200, record


@router.get(PREFIX + "/organizations/{account}/members",
            summary="The agents billing to an organization.",
            response_schema={"type": "object", "properties": {
                "members": {"type": "array", "items": schema_ref("Membership")}}},
            errors=("404",))
def organization_members(node, request, params, key):
    if node.organizations.get(params["account"]) is None:
        raise ApiError(404, ERROR_NOT_FOUND, "no such organization")
    return 200, {"members": node.organizations.members(params["account"])}


@router.post(PREFIX + "/organizations/{account}/members",
             summary="Enrol an agent, given proof that the agent agreed.",
             request_schema=schema_ref("MembershipAttestation"),
             response_schema=schema_ref("Membership"),
             response_description="The membership.",
             errors=("400", "404"))
def add_member(node, request, params, key):
    """
    Both sides must consent, and neither is trusted to assert it alone.

    The organization proves consent by holding this credential - it is taking on
    the cost. The agent proves consent by signing, because joining can harm it
    too: one with its own funded balance would start drawing on an account that
    may have none.
    """
    from .organizations import MembershipRefused   # imported here to avoid a cycle

    if not isinstance(request.body, dict):
        raise ApiError(400, ERROR_BAD_REQUEST, "a JSON object body is required")
    try:
        return 201, node.organizations.add_member(params["account"], request.body)
    except MembershipRefused as error:
        raise ApiError(400, ERROR_BAD_REQUEST, str(error))
    except ValueError as error:
        raise ApiError(404, ERROR_NOT_FOUND, str(error))


@router.delete(PREFIX + "/organizations/members/{did}",
               scope=keys_module.SCOPE_WRITE,
               summary="Remove an agent from its organization.",
               response_schema={"type": "object", "properties": {
                   "agent": {"type": "string"}, "removed": {"type": "boolean"}}},
               response_description="The agent bills to itself again. Its own "
                                    "balance, if any, is untouched.",
               errors=("404",))
def remove_member(node, request, params, key):
    if not node.organizations.remove_member(params["did"]):
        raise ApiError(404, ERROR_NOT_FOUND, "that agent is not in an organization")
    return 200, {"agent": params["did"], "removed": True}


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #

@router.get(PREFIX + "/keys", scope=keys_module.SCOPE_ADMIN,
            summary="List credentials. Never their secrets.",
            response_schema={"type": "object", "properties": {
                "keys": {"type": "array", "items": schema_ref("ApiKey")}}})
def list_keys(node, request, params, key):
    return 200, {"keys": [record.as_dict() for record in node.keys.list()]}


@router.post(PREFIX + "/keys", scope=keys_module.SCOPE_ADMIN,
             summary="Mint a credential. The secret is shown once.",
             request_schema={
                 "type": "object",
                 "required": ["label"],
                 "properties": {
                     "label": {"type": "string",
                               "description": "So the key can be recognised later."},
                     "scopes": {"type": "array",
                                "items": {"enum": ["read", "write", "admin"]}},
                 },
             },
             response_schema=schema_ref("CreatedApiKey"),
             response_description="The new credential, including its secret.",
             errors=("400",))
def create_key(node, request, params, key):
    """
    A credential a service can re-read is a credential that a compromise of that
    service hands over, so the secret appears here and in no other response.
    """
    scopes = request.field("scopes", required=False, default=[keys_module.SCOPE_READ])
    if not isinstance(scopes, list):
        raise ApiError(400, ERROR_BAD_REQUEST, "scopes must be a list")
    try:
        record, token = node.keys.create(request.field("label"), scopes)
    except ValueError as error:
        raise ApiError(400, ERROR_BAD_REQUEST, str(error))
    return 201, dict(record.as_dict(), token=token,
                     warning="This token is shown once and cannot be recovered.")


@router.delete(PREFIX + "/keys/{key_id}", scope=keys_module.SCOPE_ADMIN,
               summary="Revoke a credential, immediately.",
               response_schema=schema_ref("ApiKey"),
               response_description="The revoked key. Records are kept, not deleted.",
               errors=("404",))
def revoke_key(node, request, params, key):
    record = node.keys.revoke(params["key_id"])
    if record is None:
        raise ApiError(404, ERROR_NOT_FOUND, "no such key")
    return 200, record.as_dict()


def _page_size(request):
    size = request.integer("limit", DEFAULT_PAGE_SIZE)
    if size < 1:
        raise ApiError(400, ERROR_BAD_REQUEST, "limit must be positive")
    return min(size, MAX_PAGE_SIZE)


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

def dispatch(node, request):
    """
    Route one product-API request. Returns (status, payload, headers).

    The order is deliberate:

      1. Flood guard on the source address - before anything else, so the
         authentication path itself cannot be hammered.
      2. Authentication - before routing, so an unauthenticated caller cannot map
         the surface by noting which paths answer 404 and which answer 401.
      3. Quota for the credential.
      4. Routing, then scope, because only the route knows what it needs.
    """
    headers = {}
    try:
        _guard_peer(node, request)
        key = _authenticate(node, request)

        if key is not None:
            decision = node.limiters.api.check(key.key_id)
            headers = decision.headers()
            if not decision.allowed:
                raise ApiError(429, ERROR_RATE_LIMITED,
                               "quota exhausted for this credential", headers)

        route, params = router.resolve(request.method, request.path)
        if route.scope is not None and not key.allows(route.scope):
            raise ApiError(403, ERROR_FORBIDDEN,
                           "this key lacks the %r scope" % route.scope)
        status, payload = route.handler(node, request, params, key)
        return status, payload, headers
    except ApiError as error:
        return error.status, error.payload(), dict(headers, **error.headers)


def _guard_peer(node, request):
    if request.peer is None:
        return
    decision = node.limiters.peer.check(request.peer)
    if not decision.allowed:
        raise ApiError(429, ERROR_RATE_LIMITED,
                       "too many requests from this address", decision.headers())


def _authenticate(node, request):
    """Returns the key, or None for endpoints that need no credential."""
    if request.path in router.public_paths:
        return None
    if not node.keys.any_active:
        raise ApiError(
            503, ERROR_API_DISABLED,
            "the product API is disabled because no credentials exist; "
            "create one locally with node.keys.create(label, scopes)",
        )
    key = node.keys.verify(request.bearer)
    if key is None:
        raise ApiError(401, ERROR_UNAUTHORIZED, "a valid bearer token is required")
    return key


def serialize(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")
