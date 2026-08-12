"""
API credentials for the human plane.

Agents never hold a credential: they sign every message, and a signature copied
out of a log proves nothing. Tokens exist only for browsers and scripts, which
have nowhere safe to keep a private key.

A token looks like this:

    uise_live_3f9a2c17b4d8_QzR1c2VfdG9rZW5fZXhhbXBsZV9zZWNyZXRfdmFsdWU

    uise_live     environment. A test key cannot authenticate against a live node.
    3f9a2c17b4d8  key id. Public, safe to display and to log.
    Qz...          the secret. Shown once, at creation, and never again.

Four properties, each there for a reason:

  * **The prefix is distinctive.** Secret scanners match on it, so a token pasted
    into a public repository can be found and revoked before it is used.
  * **The id travels with the secret.** Verification is a single lookup rather
    than a comparison against every key on file, and the id can be displayed and
    logged without ever exposing the secret.
  * **Only a digest is stored.** A database or memory dump yields nothing usable.
  * **Revoked keys are kept, not deleted.** The record of what existed and when it
    was withdrawn is part of the audit trail.
"""

import hashlib
import hmac
import secrets
import time

ENVIRONMENT_LIVE = "live"
ENVIRONMENT_TEST = "test"
ENVIRONMENTS = (ENVIRONMENT_LIVE, ENVIRONMENT_TEST)

BRAND = "uise"
KEY_ID_BYTES = 6                       # 12 hex characters
SECRET_BYTES = 32                      # 43 base64url characters

SCOPE_READ = "read"
SCOPE_WRITE = "write"
SCOPE_ADMIN = "admin"
SCOPES = (SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN)

# Writing to the database on every single request would turn a read endpoint into
# a write one. A minute of resolution is plenty to answer "is this key still in
# use?", which is the only question the field exists to answer.
LAST_USED_RESOLUTION_MS = 60_000

# Console sessions are deliberately short: long enough to watch a dashboard,
# short enough that a forgotten browser tab is not a standing credential.
SESSION_TTL_SECONDS = 900


def _now_ms():
    return int(time.time() * 1000)


def digest(secret):
    return hashlib.sha256(secret.encode("utf-8")).digest()


def format_token(environment, key_id, secret):
    return "%s_%s_%s_%s" % (BRAND, environment, key_id, secret)


def parse_token(token):
    """
    Split a token into (environment, key_id, secret), or None if malformed.

    Splitting from the left with a bounded count means the secret may contain the
    separator without ambiguity.
    """
    if not isinstance(token, str):
        return None
    parts = token.split("_", 3)
    if len(parts) != 4:
        return None
    brand, environment, key_id, secret = parts
    if brand != BRAND or environment not in ENVIRONMENTS:
        return None
    if len(key_id) != KEY_ID_BYTES * 2 or not all(c in "0123456789abcdef" for c in key_id):
        return None
    if not secret:
        return None
    return environment, key_id, secret


class ApiKey(object):
    """A credential record. Never carries the secret."""

    __slots__ = ("key_id", "label", "environment", "scopes",
                 "created_at", "last_used_at", "revoked_at")

    def __init__(self, key_id, label, environment, scopes,
                 created_at, last_used_at=None, revoked_at=None):
        self.key_id = key_id
        self.label = label
        self.environment = environment
        self.scopes = frozenset(scopes)
        self.created_at = created_at
        self.last_used_at = last_used_at
        self.revoked_at = revoked_at

    @property
    def revoked(self):
        return self.revoked_at is not None

    def allows(self, scope):
        return scope in self.scopes

    def as_dict(self):
        return {
            "key_id": self.key_id,
            "label": self.label,
            "environment": self.environment,
            "scopes": sorted(self.scopes),
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "revoked_at": self.revoked_at,
        }

    def __repr__(self):
        return "<ApiKey %s %s%s>" % (self.key_id, ",".join(sorted(self.scopes)),
                                     " revoked" if self.revoked else "")


class ApiKeys(object):
    """
    The node's credential store.

    Creation is a local operation on purpose: the first key has to come from
    somewhere, and a bootstrap token baked into configuration is a credential that
    never rotates and often reaches a repository. Run it once on the machine, then
    manage everything else over the API with the admin key it gives you.
    """

    def __init__(self, storage, environment=ENVIRONMENT_LIVE):
        if environment not in ENVIRONMENTS:
            raise ValueError("environment must be one of %s" % (ENVIRONMENTS,))
        self.storage = storage
        self.environment = environment
        # Ephemeral console credentials. Memory only, never written down: they
        # exist for minutes and a restart should end them.
        self._sessions = {}

    def create_session(self, ttl_seconds=SESSION_TTL_SECONDS):
        """
        Mint a short-lived read-only credential for the operator console.

        The console is a browser, so it cannot hold a private key and cannot be
        handed a long-lived token safely. It is only ever served to a caller on
        loopback - somebody who already has the database on disk - so a read-only
        credential that expires in minutes adds no exposure that was not already
        there, and it lets the console run on the same public API as any other
        client rather than on a private back door.
        """
        secret = secrets.token_urlsafe(SECRET_BYTES)
        key_id = "session-" + secrets.token_hex(4)
        expires_at = _now_ms() + ttl_seconds * 1000
        self._sessions[digest(secret)] = (key_id, expires_at)
        self._expire_sessions()
        return format_token(self.environment, secrets.token_hex(KEY_ID_BYTES), secret)

    def _expire_sessions(self):
        now = _now_ms()
        self._sessions = {key: value for key, value in self._sessions.items()
                          if value[1] > now}

    def _session_for(self, secret):
        entry = self._sessions.get(digest(secret))
        if entry is None or entry[1] <= _now_ms():
            return None
        key_id, expires_at = entry
        return ApiKey(key_id, "console session", self.environment, [SCOPE_READ],
                      expires_at - SESSION_TTL_SECONDS * 1000, _now_ms())

    def create(self, label, scopes=(SCOPE_READ,)):
        """
        Mint a key. Returns (ApiKey, token) - the token is shown exactly once.

        There is no path anywhere that can recover it afterwards, which is the
        point: a credential a service can reveal is a credential a compromise of
        that service reveals.
        """
        requested = frozenset(scopes)
        unknown = requested - set(SCOPES)
        if unknown:
            raise ValueError("unknown scopes: %s" % sorted(unknown))
        if not requested:
            raise ValueError("a key with no scopes can do nothing")
        if not label:
            raise ValueError("a key must be labelled, so it can be recognised later")

        key_id = secrets.token_hex(KEY_ID_BYTES)
        secret = secrets.token_urlsafe(SECRET_BYTES)
        created_at = _now_ms()
        self.storage.insert_api_key(key_id, label, self.environment, digest(secret),
                                    sorted(requested), created_at)
        record = ApiKey(key_id, label, self.environment, requested, created_at)
        return record, format_token(self.environment, key_id, secret)

    def verify(self, token):
        """
        Resolve a token to its key, or None.

        Comparison is constant time, and a revoked or wrong-environment key fails
        exactly like an unknown one: a caller must not learn from the response
        whether a key ever existed.
        """
        parsed = parse_token(token)
        if parsed is None:
            return None
        environment, key_id, secret = parsed
        if environment != self.environment:
            return None

        session = self._session_for(secret)
        if session is not None:
            return session

        row = self.storage.api_key(key_id)
        if row is None:
            # Still do the hashing work, so a missing key and a wrong secret take
            # comparable time.
            hmac.compare_digest(digest(secret), digest(secret))
            return None
        if not hmac.compare_digest(digest(secret), row["digest"]):
            return None
        if row["environment"] != environment or environment != self.environment:
            return None
        if row["revoked_at"] is not None:
            return None

        now = _now_ms()
        if row["last_used_at"] is None or now - row["last_used_at"] > LAST_USED_RESOLUTION_MS:
            self.storage.touch_api_key(key_id, now)
        return ApiKey(row["key_id"], row["label"], row["environment"],
                      row["scopes"].split(","), row["created_at"], now, None)

    def list(self):
        return [ApiKey(row["key_id"], row["label"], row["environment"],
                       row["scopes"].split(","), row["created_at"],
                       row["last_used_at"], row["revoked_at"])
                for row in self.storage.api_keys()]

    def revoke(self, key_id):
        """Withdraw a key. The record stays: an audit trail with holes is not one."""
        row = self.storage.api_key(key_id)
        if row is None:
            return None
        if row["revoked_at"] is None:
            self.storage.revoke_api_key(key_id, _now_ms())
        return self.get(key_id)

    def get(self, key_id):
        row = self.storage.api_key(key_id)
        if row is None:
            return None
        return ApiKey(row["key_id"], row["label"], row["environment"],
                      row["scopes"].split(","), row["created_at"],
                      row["last_used_at"], row["revoked_at"])

    @property
    def any_active(self):
        """Checked on every request, so it is a count rather than a listing."""
        self._expire_sessions()
        return bool(self._sessions) or self.storage.has_active_api_key()

    @property
    def active(self):
        return [key for key in self.list() if not key.revoked]
