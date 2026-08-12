"""
Live event stream - what the node is doing, as it happens.

The governing rule is that **watching must never affect what is being watched**. A
dashboard that falls behind, a laptop that closes its lid, a client on a slow link:
none of them may delay a receipt being issued.

That rules out the obvious designs. Blocking the producer until every subscriber
has caught up makes issuance wait on a browser. An unbounded queue turns one slow
reader into memory exhaustion. So each subscriber gets a **bounded** queue, and
when it overflows the oldest events are dropped and counted.

Dropping is honest rather than silent: the subscriber is told how many events it
missed, so it knows its view has gaps and can reload rather than quietly showing
stale numbers as if they were complete.
"""

import itertools
import json
import threading
import time

RECEIPT_ISSUED = "receipt.issued"
AGENT_ANNOUNCED = "agent.announced"
CREDIT_DEPOSITED = "credit.deposited"
CREDIT_LOW = "credit.low"
STREAM_GAP = "stream.gap"

# Per-subscriber queue. Large enough to absorb a burst, small enough that a
# forgotten browser tab costs kilobytes rather than megabytes.
DEFAULT_QUEUE_SIZE = 256

# Each open stream holds a thread and a socket, so the count is bounded.
DEFAULT_MAX_SUBSCRIBERS = 64

# Recent history, replayed to a client that reconnects with Last-Event-ID.
DEFAULT_HISTORY = 1024

# Proxies and load balancers close idle connections. A comment line keeps the
# connection alive without being delivered to the application.
HEARTBEAT_SECONDS = 15


class Event(object):
    __slots__ = ("seq", "type", "data", "timestamp")

    def __init__(self, seq, event_type, data, timestamp):
        self.seq = seq
        self.type = event_type
        self.data = data
        self.timestamp = timestamp

    def as_dict(self):
        return {"seq": self.seq, "type": self.type,
                "at": self.timestamp, "data": self.data}

    def encode(self):
        """One Server-Sent Events frame."""
        return ("id: %d\nevent: %s\ndata: %s\n\n"
                % (self.seq, self.type,
                   json.dumps(self.as_dict(), ensure_ascii=False))).encode("utf-8")

    def __repr__(self):
        return "<Event %d %s>" % (self.seq, self.type)


class Subscription(object):
    """One reader's view of the stream. Iterating yields encoded SSE frames."""

    def __init__(self, bus, queue_size=DEFAULT_QUEUE_SIZE):
        self._bus = bus
        self._queue = []
        self._queue_size = queue_size
        self._condition = threading.Condition()
        self._closed = False
        self._iterator = None
        self.dropped = 0

    def offer(self, event):
        """Called by the bus. Never blocks, never raises: the producer is sacred."""
        with self._condition:
            if self._closed:
                return
            if len(self._queue) >= self._queue_size:
                # Drop the oldest and say so. A reader that silently loses events
                # shows stale numbers as though they were complete.
                self._queue.pop(0)
                self.dropped += 1
            self._queue.append(event)
            self._condition.notify()

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()
        self._bus.unsubscribe(self)

    def __iter__(self):
        """
        A stream has exactly one consumer, so this returns the same generator
        every time.

        Handing out a second generator would look harmless and would not be: the
        first one gets discarded, and its cleanup closes the subscription out from
        under whoever was still reading it.
        """
        if self._iterator is None:
            self._iterator = self._generate()
        return self._iterator

    def _generate(self):
        try:
            while True:
                with self._condition:
                    if not self._queue and not self._closed:
                        self._condition.wait(HEARTBEAT_SECONDS)
                    if self._closed and not self._queue:
                        return
                    pending, self._queue = self._queue, []
                    dropped, self.dropped = self.dropped, 0

                if dropped:
                    yield (": %d events dropped; this view has gaps\n\n"
                           % dropped).encode("utf-8")
                if not pending:
                    yield b": keepalive\n\n"
                for event in pending:
                    yield event.encode()
        finally:
            self.close()


class EventBus(object):
    """
    In-process publish and subscribe.

    Deliberately in-process: a shared broker would be a global component on the
    path of every issuance, which is what the architecture exists to avoid. Each
    node streams what it did; an aggregate view is assembled by the reader.
    """

    def __init__(self, max_subscribers=DEFAULT_MAX_SUBSCRIBERS, history=DEFAULT_HISTORY):
        self.max_subscribers = max_subscribers
        self._history_size = history
        self._history = []
        self._subscribers = []
        self._sequence = itertools.count(1)
        self._lock = threading.Lock()

    def publish(self, event_type, data):
        """Fan out one event. Returns it. Never blocks on a slow subscriber."""
        event = Event(next(self._sequence), event_type, data, int(time.time() * 1000))
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._history_size:
                del self._history[:-self._history_size]
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            subscriber.offer(event)
        return event

    def subscribe(self, last_event_id=None, queue_size=DEFAULT_QUEUE_SIZE):
        """
        Attach a reader, optionally resuming after `last_event_id`.

        Resumption is best effort and says so: anything older than the retained
        history is reported as a gap rather than silently skipped.
        """
        subscription = Subscription(self, queue_size)
        with self._lock:
            if len(self._subscribers) >= self.max_subscribers:
                raise TooManySubscribers(self.max_subscribers)
            replay, missed = self._since(last_event_id)
            self._subscribers.append(subscription)

        if missed:
            subscription.offer(Event(
                0, STREAM_GAP,
                {"reason": "requested events are older than the retained history"},
                int(time.time() * 1000),
            ))
        for event in replay:
            subscription.offer(event)
        return subscription

    def _since(self, last_event_id):
        if last_event_id is None or not self._history:
            return [], False
        replay = [event for event in self._history if event.seq > last_event_id]
        missed = self._history[0].seq > last_event_id + 1
        return replay, missed

    def unsubscribe(self, subscription):
        with self._lock:
            if subscription in self._subscribers:
                self._subscribers.remove(subscription)

    @property
    def subscriber_count(self):
        with self._lock:
            return len(self._subscribers)

    def close(self):
        for subscriber in list(self._subscribers):
            subscriber.close()


class TooManySubscribers(Exception):
    def __init__(self, limit):
        super(TooManySubscribers, self).__init__(
            "this node is already streaming to %d clients" % limit
        )
        self.limit = limit
