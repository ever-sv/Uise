"""
Organizations - one balance, many agents.

Billing is keyed by account, and an account is either an agent's own DID or an
organization shared by several. A company running a thousand agents funds one
balance and receives one invoice, instead of topping up a thousand.

A solo agent bills to itself, which is the same code path with a membership of
one. Nothing downstream needs to know which case it is looking at.

**Membership requires consent from both sides**, and neither side is trusted to
assert it alone:

  * The organization proves consent by holding a credential with the `write`
    scope - it is taking on the cost.
  * The agent proves consent by **signing** the membership, because joining can
    also harm it: an agent with its own funded balance would start drawing on an
    organization that may have none.

The attestation is signed under `uise/1.membership`, not `uip/1`. Organizations
are a billing concept belonging to this product, not to the protocol, and the
two namespaces must not blur - the protocol is frozen and this is not.
"""

import secrets
import time

from uip import codec, did as did_module
from uip import suites as suite_registry

VERSION = "uise/1"
DOMAIN_MEMBERSHIP = b"uise/1.membership\n"

ACCOUNT_PREFIX = "org_"
ACCOUNT_ID_BYTES = 6

KIND_AGENT = "agent"
KIND_ORGANIZATION = "organization"

# An attestation is a statement about now, not a standing permission. Reusing an
# old one must not silently re-enrol an agent that has since left.
ATTESTATION_WINDOW_MS = 300_000


def _now_ms():
    return int(time.time() * 1000)


def new_account_id():
    return ACCOUNT_PREFIX + secrets.token_hex(ACCOUNT_ID_BYTES)


def is_organization(account):
    return isinstance(account, str) and account.startswith(ACCOUNT_PREFIX)


def attestation_input(account, agent_did, timestamp_ms):
    """The exact bytes an agent signs to join an organization."""
    statement = {
        "v": VERSION,
        "action": "join",
        "account": account,
        "agent": agent_did,
        "ts": timestamp_ms,
    }
    return DOMAIN_MEMBERSHIP + codec.canonicalize(statement)


def attest(identity, account, timestamp_ms=None):
    """
    Produce a membership attestation. Called by the agent, never by the node.

    Returns the dictionary an organization submits when adding this agent.
    """
    timestamp_ms = _now_ms() if timestamp_ms is None else timestamp_ms
    signature = identity.sign(attestation_input(account, identity.did, timestamp_ms))
    return {
        "agent": identity.did,
        "account": account,
        "ts": timestamp_ms,
        "sig": codec.b64u_encode(signature),
    }


class MembershipRefused(Exception):
    """The attestation does not prove the agent agreed to this membership."""


class Organizations(object):
    """Organization accounts and who belongs to them."""

    def __init__(self, storage):
        self.storage = storage

    # -- accounts ------------------------------------------------------------ #

    def create(self, label, rail="manual", rail_ref=None, credit_limit=None,
               account=None):
        """Open an organization account. It starts with no members and no balance."""
        if not label:
            raise ValueError("an organization must be labelled")
        if credit_limit is not None and not isinstance(credit_limit, str):
            raise TypeError("credit_limit must be a decimal string, never a float")

        account = account or new_account_id()
        if not is_organization(account):
            raise ValueError("an organization id must start with %r" % ACCOUNT_PREFIX)
        self.storage.upsert_account(account, label, rail, rail_ref, _now_ms(),
                                    credit_limit, KIND_ORGANIZATION)
        return self.storage.account(account)

    def get(self, account):
        record = self.storage.account(account)
        if record is None or record["kind"] != KIND_ORGANIZATION:
            return None
        return record

    def list(self):
        return self.storage.accounts(KIND_ORGANIZATION)

    # -- membership ---------------------------------------------------------- #

    def add_member(self, account, attestation):
        """
        Enrol an agent, given proof that the agent agreed.

        The caller has already been authorised as the organization; this verifies
        the other half.
        """
        organization = self.get(account)
        if organization is None:
            raise ValueError("no such organization: %s" % account)
        self._verify(account, attestation)
        self.storage.add_membership(attestation["agent"], account, _now_ms())
        return self.storage.membership(attestation["agent"])

    def _verify(self, account, attestation):
        if not isinstance(attestation, dict):
            raise MembershipRefused("an attestation object is required")
        for field in ("agent", "account", "ts", "sig"):
            if field not in attestation:
                raise MembershipRefused("the attestation is missing %r" % field)
        if attestation["account"] != account:
            raise MembershipRefused("the attestation names a different organization")

        timestamp = attestation["ts"]
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise MembershipRefused("ts must be an integer")
        if abs(timestamp - _now_ms()) > ATTESTATION_WINDOW_MS:
            # An attestation is a statement about now. Accepting an old one would
            # let a stale copy re-enrol an agent that has since left.
            raise MembershipRefused("the attestation is outside the time window")

        try:
            suite, public_key = did_module.decode(attestation["agent"])
            signature = codec.b64u_decode(attestation["sig"])
        except (ValueError, TypeError, suite_registry.SuiteUnsupported) as error:
            raise MembershipRefused(str(error))

        payload = attestation_input(account, attestation["agent"], timestamp)
        if not suite.verify(signature, payload, public_key):
            raise MembershipRefused("the agent did not sign this membership")

    def remove_member(self, agent_did):
        """
        Remove an agent. Its own balance, if it had one, is untouched and
        available again - money is never moved implicitly.
        """
        return self.storage.remove_membership(agent_did)

    def members(self, account):
        return self.storage.members(account)

    def billing_account(self, agent_did):
        """Which account this agent bills to. Itself, unless it joined one."""
        return self.storage.billing_account(agent_did)
