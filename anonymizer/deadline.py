"""One document, one clock, one set of ids that follow it everywhere.

A document that never finishes is a worker held forever, and a service that
holds enough workers is a service that is down. So every document gets a budget
— 300 seconds, end to end — and the budget travels WITH the work rather than
wrapping it: an outer timeout that abandons a call tells the caller the answer
is late while the call carries on spending money.

Two things are carried together because they are always wanted together. The
``Deadline`` is how long there is left; the ``RunContext`` is who is asking.
Correlation ids matter for the same reason the deadline does: several documents
are in flight at once, on several threads, and a log line that cannot say which
one it belongs to cannot be used to reconstruct anything.

WHAT CANNOT BE MADE HARD, stated plainly because it is the honest limit of this
design: a Python thread cannot be killed. When the deadline expires, no NEW
provider call starts and no queued chunk begins, but a call already in flight
runs until its own timeout — which is itself bounded by the remaining budget, so
it ends at the deadline rather than beyond it. CPU-bound stages are not
preemptible either; they are bounded by the resource limits instead, and the
deadline is checked between them.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from anonymizer.errors import DocumentTimeoutError

# Below this, there is no point starting a provider call: the request would be
# cut off before it could answer, and the attempt would cost a round trip to
# learn what the clock already says.
MIN_ATTEMPT_BUDGET_S = 1.0


def new_request_id() -> str:
    """An opaque id for one HTTP request. Never derived from user input."""
    return uuid.uuid4().hex[:16]


def new_document_id() -> str:
    """An opaque id for one document. Deliberately NOT the filename.

    A filename is chosen by whoever sent the document and can contain anything,
    including someone's name. Correlation ids end up in every log line, so they
    are generated rather than borrowed.
    """
    return uuid.uuid4().hex[:12]


class Deadline:
    """How much of a document's budget is left, and whether it has been spent.

    Backed by a monotonic clock, so a system clock adjustment mid-document
    cannot extend or collapse the budget. The clock is injectable because a test
    that really waited five minutes would prove nothing a fake one does not.
    """

    def __init__(
        self,
        expires_at: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._expires_at = expires_at
        self._clock = clock
        self._cancelled = threading.Event()

    @classmethod
    def after(
        cls, seconds: float, *, clock: Callable[[], float] = time.monotonic
    ) -> "Deadline":
        """A budget of ``seconds`` starting now."""
        return cls(clock() + float(seconds), clock=clock)

    def remaining(self) -> float:
        """Seconds left, never negative."""
        return max(0.0, self._expires_at - self._clock())

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def check(self, stage: str) -> None:
        """Raise if the budget is gone. Called at every stage boundary.

        This is the cooperative half of cancellation: it cannot interrupt work
        already running, but it guarantees that no NEW stage begins on a
        document that has run out of time — including the stage that would have
        produced the output.
        """
        if self.expired():
            raise DocumentTimeoutError(stage)

    def budget(self, cap: float, *, stage: str, floor: float = MIN_ATTEMPT_BUDGET_S) -> float:
        """The timeout to give one blocking operation: ``cap``, or less.

        Raises when less than ``floor`` remains, because starting a call that
        cannot finish spends a round trip to discover what the clock already
        knew.
        """
        left = self.remaining()
        if left <= floor:
            raise DocumentTimeoutError(stage)
        return min(float(cap), left)

    def cancel(self) -> None:
        """Tell every worker to stop at its next checkpoint."""
        self._cancelled.set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    @property
    def done(self) -> bool:
        """Either out of time or told to stop. What a worker actually asks."""
        return self._cancelled.is_set() or self.expired()


@dataclass(frozen=True)
class RunContext:
    """Who is asking, and how long they have.

    Threaded explicitly through the pipeline rather than held in a context
    variable. Explicit is worth the parameter here: the work happens on a thread
    pool, where a context variable would have to be copied into every worker,
    and the ids have to appear in the MESSAGE of each log line anyway because
    the formatter is shared with third-party loggers that know nothing about
    them.
    """

    deadline: "Deadline"
    request_id: str = field(default_factory=new_request_id)
    document_id: str = field(default_factory=new_document_id)

    @classmethod
    def start(
        cls,
        seconds: float,
        *,
        request_id: str | None = None,
        document_id: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> "RunContext":
        """Begin a document's budget now, with fresh ids for anything absent."""
        return cls(
            deadline=Deadline.after(seconds, clock=clock),
            request_id=request_id or new_request_id(),
            document_id=document_id or new_document_id(),
        )

    def tag(self) -> str:
        """The correlation fields, ready to append to a log message."""
        return f"request_id={self.request_id} document_id={self.document_id}"

    def chunk_tag(
        self,
        chunk_index: int,
        pass_number: int | None = None,
        attempt: str | None = None,
    ) -> str:
        """The same, plus which chunk and which pass. Chunks count from 1."""
        parts = [self.tag(), f"chunk={chunk_index + 1}"]
        if pass_number is not None:
            parts.append(f"pass={pass_number}")
        if attempt is not None:
            parts.append(f"attempt={attempt}")
        return " ".join(parts)


__all__ = [
    "Deadline",
    "MIN_ATTEMPT_BUDGET_S",
    "RunContext",
    "new_document_id",
    "new_request_id",
]
