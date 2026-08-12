"""
Rate limiting - token buckets, in memory, per node process.

A token bucket rather than a fixed window: a fixed window lets a caller spend its
whole quota at the end of one window and again at the start of the next, so the
real burst is twice the configured limit. A bucket refills continuously, so a
legitimate burst is absorbed and a sustained flood is not.

Time comes from `time.monotonic()`, never the wall clock. An NTP correction that
steps the clock backwards would hand out free quota; one that steps it forwards
would lock callers out. A monotonic clock cannot do either.

**Scope is one process.** Behind a load balancer with several nodes, the effective
limit is multiplied by the number of nodes. That is a deliberate trade: a shared
limiter would be exactly the global component on the critical path that the
architecture exists to avoid, and a rate limit is a protection mechanism, not an
accounting one - being approximately right is enough. Metering, which must be
exact, lives in the ledger instead.
"""

import time

# Buckets are evicted once this many keys are tracked. A caller rotating
# identifiers must not be able to grow this dictionary without bound.
DEFAULT_MAX_TRACKED = 10_000


class Limits(object):
    """
    The three quotas a node enforces, each keyed differently on purpose.

    `peer` is a flood guard on the source address, checked before anything else so
    that the authentication path itself cannot be hammered. It is deliberately
    higher than `api`: it exists to stop a flood, not to be anyone's quota.

    `api` is the real quota for the product API, keyed by credential.

    `agent` applies to the protocol plane and is keyed by the sender's DID **after
    its signature has been verified**. Keying on an unverified claim would let an
    attacker exhaust somebody else's allowance by naming them.
    """

    __slots__ = ("peer", "api", "agent", "window_seconds")

    def __init__(self, peer=1200, api=600, agent=300, window_seconds=60):
        self.peer = peer
        self.api = api
        self.agent = agent
        self.window_seconds = window_seconds


class Decision(object):
    """The outcome of one rate-limit check, and the numbers a client needs."""

    __slots__ = ("allowed", "limit", "remaining", "reset_seconds", "retry_after")

    def __init__(self, allowed, limit, remaining, reset_seconds, retry_after=0):
        self.allowed = allowed
        self.limit = limit
        self.remaining = remaining
        self.reset_seconds = reset_seconds
        self.retry_after = retry_after

    def headers(self):
        """
        Fields from the IETF RateLimit header specification, plus `Retry-After`,
        which is the one every HTTP client already understands.
        """
        fields = {
            "RateLimit-Limit": str(self.limit),
            "RateLimit-Remaining": str(self.remaining),
            "RateLimit-Reset": str(self.reset_seconds),
        }
        if not self.allowed:
            fields["Retry-After"] = str(max(1, self.retry_after))
        return fields

    def __repr__(self):
        return "<Decision %s %d/%d>" % (
            "allow" if self.allowed else "deny", self.remaining, self.limit
        )


class RateLimiter(object):
    """`limit` requests per `window_seconds`, per key, refilled continuously."""

    __slots__ = ("limit", "window_seconds", "max_tracked", "_rate", "_buckets")

    def __init__(self, limit=600, window_seconds=60, max_tracked=DEFAULT_MAX_TRACKED):
        if limit < 1 or window_seconds <= 0:
            raise ValueError("a rate limit must allow at least one request per window")
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_tracked = max_tracked
        self._rate = float(limit) / window_seconds
        self._buckets = {}

    def check(self, key):
        """Consume one token for `key`. Returns a Decision; never raises."""
        now = time.monotonic()
        tokens, last_seen = self._buckets.get(key, (float(self.limit), now))
        tokens = min(float(self.limit), tokens + (now - last_seen) * self._rate)

        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            return Decision(
                allowed=False,
                limit=self.limit,
                remaining=0,
                reset_seconds=self._seconds_to_full(tokens),
                retry_after=int((1.0 - tokens) / self._rate) + 1,
            )

        tokens -= 1.0
        if len(self._buckets) >= self.max_tracked:
            self._evict(now)
        self._buckets[key] = (tokens, now)
        return Decision(
            allowed=True,
            limit=self.limit,
            remaining=int(tokens),
            reset_seconds=self._seconds_to_full(tokens),
        )

    def _seconds_to_full(self, tokens):
        return int((self.limit - tokens) / self._rate) + 1

    def _evict(self, now):
        """
        Make room without handing anybody a fresh allowance.

        First drop buckets that have refilled completely: a full bucket is
        indistinguishable from one that never existed, so forgetting it changes no
        decision.

        If that is not enough, keep the **most depleted** buckets rather than the
        most recent. Evicting by recency would let a caller flood the limiter with
        new identifiers to displace a throttled victim and reset it. Flooding
        creates buckets that are nearly full, so under this rule the flood evicts
        itself and the throttled state survives.
        """
        survivors = {
            key: state for key, state in self._buckets.items()
            if state[0] + (now - state[1]) * self._rate < self.limit
        }
        if len(survivors) >= self.max_tracked:
            by_depletion = sorted(survivors.items(),
                                  key=lambda item: item[1][0] + (now - item[1][1]) * self._rate)
            survivors = dict(by_depletion[:self.max_tracked - 1])
        self._buckets = survivors

    def forget(self, key):
        self._buckets.pop(key, None)

    def __len__(self):
        return len(self._buckets)


class Limiters(object):
    """The three limiters a node or agent enforces, built from one Limits config."""

    __slots__ = ("peer", "api", "agent")

    def __init__(self, limits=None):
        limits = limits or Limits()
        self.peer = RateLimiter(limits.peer, limits.window_seconds)
        self.api = RateLimiter(limits.api, limits.window_seconds)
        self.agent = RateLimiter(limits.agent, limits.window_seconds)
