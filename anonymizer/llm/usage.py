"""Per-document LLM token accounting for the two-pass detection stage.

One ``UsageRecorder`` is created per document, in ``anonymize_document``, and
threaded down to every provider call that document makes — pass 1, pass-2 first
attempts, and pass-2 retries alike. There is no module-level counter and
nothing is keyed by thread or by document id: the recorder IS the document's
scope, so two documents cannot mix their totals however they are run (several
gunicorn workers, repeated CLI invocations, or a future caller that overlaps
them), and there is no shared state to reset between runs.

Within one document, chunks are processed on a thread pool, so the recorder is
mutated concurrently. Every write is taken under a lock, and the numbers leave
as an immutable ``LlmUsage`` snapshot so nothing downstream can edit a total
after the fact.

Only counts are recorded here. Prompt text, candidate text and completion text
are never read for accounting and never stored — token totals come from what
the provider reported about the call, not from anything this code measures over
the document.

The provider is not required to report usage. When it does not (a duck-typed
client in a test, an endpoint that omits the block), the call is counted in
``calls_missing_usage`` rather than guessed at: an estimate would need to
tokenize the prompt, which means handling the document text for accounting, and
a wrong number is worse than an absent one.
"""

from __future__ import annotations

import logging
import math
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

logger = logging.getLogger(__name__)

# Above this, a reported count is not a count. Providers report thousands;
# a billion is not a number this service will ever legitimately see, and
# accepting an arbitrary integer means accepting one that breaks the sum.
_MAX_REPORTED_TOKENS = 1_000_000_000

# How a chunk's pass 1 turned out. Exactly three states, because exactly three
# things can be done about them: nothing, fix the model's formatting, raise
# ANON_MAX_COMPLETION_TOKENS.
#
# None of them is an error condition for the DOCUMENT. Pass 1 is discovery
# evidence, and a degraded pass 1 FORCES pass 2 to run over the whole chunk
# even when the queue is empty, so a lost pass 1 costs recommendations, not
# coverage — so these are counters, not failures, and they
# exist so that a silent degradation is a NUMBER somebody can see rather than a
# thing nobody knew happened.
PASS1_SUCCESS = "pass1_success"
PASS1_PARSE_FAILURE = "pass1_parse_failure"
PASS1_OUTPUT_TRUNCATED = "pass1_output_truncated"
PASS1_OUTCOMES = (PASS1_SUCCESS, PASS1_PARSE_FAILURE, PASS1_OUTPUT_TRUNCATED)

# How a chunk's pass 2 turned out. Unlike the pass-1 counters above these are
# not degradation counters: they exist because "pass 2 ran" and "pass 2 was
# skipped" are different claims about a document, and a summary that cannot
# tell them apart cannot answer the only question worth asking after an
# incident -- was this chunk read by the pass that makes the decisions?
#
# A chunk is counted exactly once, under exactly one of these.
PASS2_SKIPPED = "pass2_skipped"    # pass 1 succeeded with nothing to adjudicate
PASS2_EXECUTED = "pass2_executed"  # pass 2 ran and produced a usable reading
PASS2_FAILED = "pass2_failed"      # pass 2 ran and the chunk was abandoned
PASS2_OUTCOMES = (PASS2_SKIPPED, PASS2_EXECUTED, PASS2_FAILED)


@dataclass(frozen=True)
class TruncatedCall:
    """A call the provider ended because it hit the output-token ceiling.

    This is the diagnostic that separates "the model made a bad decision" from
    "the model ran out of room to answer". An incomplete pass-2 response with a
    truncation recorded against it is a budget problem —
    ``ANON_MAX_COMPLETION_TOKENS`` is too low for that chunk's queue — while the
    same failure with no truncation is the model genuinely omitting a decision.
    The two need opposite fixes, and the counts alone cannot tell them apart.
    """

    chunk_index: int
    pass_number: int
    # "first" or "retry" — a retry is the smaller request, so a truncation there
    # means the budget is far too low, not marginally.
    attempt: str
    output_tokens: int
    limit: int

    @property
    def chunk_number(self) -> int:
        """The chunk as a person counts it: 1-based.

        ``chunk_index`` stays 0-based for indexing. Reporters use this instead
        of adding one themselves, so a truncation warning always names the same
        chunk the detector's own logs and errors do.
        """
        return self.chunk_index + 1


@dataclass(frozen=True)
class LlmUsage:
    """One document's finished LLM accounting. Immutable by the time it is read."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    # Calls whose provider response carried no usable usage block. Non-zero
    # means the token totals above are incomplete, and it is reported rather
    # than hidden so a total is never silently understated.
    calls_missing_usage: int = 0
    truncated: tuple[TruncatedCall, ...] = ()
    # How this document's chunks fared in pass 1, one count per chunk that ran
    # it. The two failure counters are the observable half of the degradation
    # policy: pass 1 losing its output never fails a document, so without these
    # a run in which every chunk's pass 1 came back unusable would look exactly
    # like a run in which every chunk's pass 1 found nothing.
    pass1_success: int = 0
    pass1_parse_failure: int = 0
    pass1_output_truncated: int = 0
    # How this document's chunks fared in pass 2. ``pass2_skipped`` is only
    # ever a chunk whose pass 1 SUCCEEDED with nothing to adjudicate: a
    # degraded pass 1 forces pass 2 to run, so a skip can never hide a chunk
    # that nobody read.
    pass2_skipped: int = 0
    pass2_executed: int = 0
    pass2_failed: int = 0
    # Chunks that needed their one corrective retry, and the attempt counts
    # behind them. ``pass2_incomplete_attempts`` is the diagnostic that
    # separates "the model answered badly" from "the provider never let it
    # finish": it counts responses that were not a reading at all --
    # truncated, filtered, empty, or unparseable.
    pass2_retried: int = 0
    pass2_attempts: int = 0
    pass2_incomplete_attempts: int = 0

    @property
    def hit_output_limit(self) -> bool:
        """Whether any call for this document ran into its completion cap."""
        return bool(self.truncated)

    @property
    def pass1_degraded(self) -> int:
        """Chunks whose pass 1 contributed nothing because its output was unusable."""
        return self.pass1_parse_failure + self.pass1_output_truncated

    @property
    def pass2_chunks(self) -> int:
        """Chunks accounted for by a pass-2 outcome, whichever one."""
        return self.pass2_skipped + self.pass2_executed + self.pass2_failed


class UsageRecorder:
    """Thread-safe accumulator for one document's provider calls.

    Created per document and never shared between them. ``record`` is safe to
    call from the chunk worker threads; ``snapshot`` is safe to call once they
    have all finished.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls = 0
        self._input = 0
        self._output = 0
        self._total = 0
        self._missing = 0
        self._truncated: list[TruncatedCall] = []
        self._pass1: dict[str, int] = {outcome: 0 for outcome in PASS1_OUTCOMES}
        self._pass2: dict[str, int] = {outcome: 0 for outcome in PASS2_OUTCOMES}
        self._pass2_retried = 0
        self._pass2_attempts = 0
        self._pass2_incomplete = 0

    def record(
        self,
        response: Any,
        *,
        chunk_index: int,
        pass_number: int,
        attempt: str,
        limit: int,
    ) -> str | None:
        """Add one provider response to this document's totals.

        Returns the provider's FINISH REASON — ``stop``, ``length``,
        ``content_filter``, whatever it said — or None when the response
        carried none. The caller needs it to judge what the completion is
        worth: a body the provider cut short at the token ceiling, or refused
        to finish, is a FRAGMENT rather than a short answer, and the finish
        reason is the only thing that says so — the text of a truncated list
        of decisions looks exactly like a complete list of fewer decisions.
        It is parsed here anyway for the truncation ledger, so returning it
        keeps ONE reader of the response shape rather than two that could
        disagree.

        Reads only the response's ``usage`` block and its finish reason; the
        completion text is not touched. Never raises — accounting must not be
        able to fail a document that was otherwise produced correctly, so a
        response shaped unexpectedly is counted as missing usage instead.
        """
        # READ THE FINISH REASON FIRST, AND OUTSIDE THE GUARD BELOW.
        #
        # It is the caller's evidence about whether the completion is an
        # answer or a fragment, and losing it to an arithmetic problem in the
        # token counts would let a truncated pass-2 response be judged as if
        # it had finished. Bookkeeping may fail; the diagnostic may not.
        finish_reason = _finish_reason(response)
        try:
            self._account(
                response,
                finish_reason,
                chunk_index=chunk_index,
                pass_number=pass_number,
                attempt=attempt,
                limit=limit,
            )
        except Exception as exc:  # pragma: no cover - the helpers are total
            # A last-resort net. The readers above are written to be total, so
            # reaching this is a bug rather than a provider quirk — but a bug
            # in COUNTING must not be able to fail a document that was
            # otherwise produced correctly. The type is logged, not swallowed.
            logger.warning(
                "usage_accounting_failed chunk=%d pass=%d error=%s",
                chunk_index + 1, pass_number, type(exc).__name__,
            )
            with self._lock:
                self._calls += 1
                self._missing += 1
        return finish_reason

    def _account(
        self,
        response: Any,
        finish_reason: str | None,
        *,
        chunk_index: int,
        pass_number: int,
        attempt: str,
        limit: int,
    ) -> None:
        """Add one response to the totals. Reads counts, never content."""
        prompt_tokens = _as_int(_attr(response, "usage", "prompt_tokens"))
        completion_tokens = _as_int(_attr(response, "usage", "completion_tokens"))
        total_tokens = _as_int(_attr(response, "usage", "total_tokens"))

        truncation: TruncatedCall | None = None
        if finish_reason == "length":
            truncation = TruncatedCall(
                chunk_index=chunk_index,
                pass_number=pass_number,
                attempt=attempt,
                output_tokens=completion_tokens or 0,
                limit=limit,
            )

        with self._lock:
            self._calls += 1
            if prompt_tokens is None and completion_tokens is None:
                self._missing += 1
            else:
                self._input += prompt_tokens or 0
                self._output += completion_tokens or 0
                # Prefer the provider's own total; fall back to the parts when
                # only those were reported.
                self._total += (
                    total_tokens
                    if total_tokens is not None
                    else (prompt_tokens or 0) + (completion_tokens or 0)
                )
            if truncation is not None:
                self._truncated.append(truncation)

    def record_pass1(self, outcome: str) -> None:
        """Count how one chunk's pass 1 turned out.

        ``outcome`` must be one of ``PASS1_OUTCOMES``; anything else is a
        programming error and says so, because a mistyped outcome would
        otherwise vanish into a counter nobody reads. Called once per chunk that
        reached pass 1, from the chunk worker threads.
        """
        if outcome not in self._pass1:
            raise ValueError(f"unknown pass-1 outcome {outcome!r}")
        with self._lock:
            self._pass1[outcome] += 1

    def record_pass2(self, outcome: str, *, retried: bool = False) -> None:
        """Count how one chunk's pass 2 turned out.

        ``outcome`` must be one of ``PASS2_OUTCOMES``; anything else is a
        programming error and says so, for the same reason ``record_pass1``
        refuses one — a mistyped outcome would otherwise vanish into a counter
        nobody reads. Called once per chunk, from the chunk worker threads.

        ``retried`` records that the chunk needed its one corrective retry,
        whether or not that retry settled everything.
        """
        if outcome not in self._pass2:
            raise ValueError(f"unknown pass-2 outcome {outcome!r}")
        with self._lock:
            self._pass2[outcome] += 1
            if retried:
                self._pass2_retried += 1

    def record_pass2_attempt(self, *, complete: bool) -> None:
        """Count one pass-2 response, and whether it was a usable READING.

        Separate from ``record_pass2`` because a chunk has one outcome but can
        have two attempts. ``complete=False`` is the diagnostic that a
        response arrived and was not a reading at all — truncated, filtered,
        empty, or not parseable as a decision array — which is a different
        problem from a reading that merely left answers out.
        """
        with self._lock:
            self._pass2_attempts += 1
            if not complete:
                self._pass2_incomplete += 1

    def snapshot(self) -> LlmUsage:
        """Freeze the current totals into the value that travels on the result."""
        with self._lock:
            return LlmUsage(
                calls=self._calls,
                input_tokens=self._input,
                output_tokens=self._output,
                total_tokens=self._total,
                calls_missing_usage=self._missing,
                truncated=tuple(self._truncated),
                pass1_success=self._pass1[PASS1_SUCCESS],
                pass1_parse_failure=self._pass1[PASS1_PARSE_FAILURE],
                pass1_output_truncated=self._pass1[PASS1_OUTPUT_TRUNCATED],
                pass2_skipped=self._pass2[PASS2_SKIPPED],
                pass2_executed=self._pass2[PASS2_EXECUTED],
                pass2_failed=self._pass2[PASS2_FAILED],
                pass2_retried=self._pass2_retried,
                pass2_attempts=self._pass2_attempts,
                pass2_incomplete_attempts=self._pass2_incomplete,
            )


def _attr(obj: Any, *path: str) -> Any:
    """Walk an attribute path, returning None the moment anything is missing.

    ``getattr`` with a default still raises when the attribute is a property
    that raises, and a provider SDK is free to make one. Accounting must not
    be able to fail a document, so the walk swallows that too.
    """
    for name in path:
        if obj is None:
            return None
        try:
            obj = getattr(obj, name, None)
        except Exception:
            return None
    return obj


def _as_int(value: Any) -> int | None:
    """Coerce a reported count to int, or None when it is not usable as one.

    NONE IS NOT ZERO, and the difference is the whole point. A count this
    function cannot read is UNKNOWN: the caller books the call under
    ``calls_missing_usage`` and the totals stay honest about being
    incomplete. Returning 0 instead would state that the call cost nothing,
    which is a measurement rather than an absence.

    Everything unusable maps here: missing, null, a bool (which is an int in
    Python and never a token count), a NaN or infinity (``int(inf)`` raises
    ``OverflowError``), a Decimal NaN, a string that is not a number, an
    object of some unrelated type, and a number too large to be real.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if not isinstance(value, (int, float, str, Decimal)):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, ArithmeticError, InvalidOperation):
        # ArithmeticError covers OverflowError, which is what int(inf) is.
        return None
    if number < 0 or number > _MAX_REPORTED_TOKENS:
        return None
    return number


def _finish_reason(response: Any) -> str | None:
    """The first choice's finish reason, or None when the shape is unfamiliar.

    The ``Sequence`` test is load-bearing: a dict is truthy and indexable, so
    a response whose ``choices`` is a mapping used to reach ``choices[0]``
    and raise ``KeyError`` — which is neither a TypeError nor an IndexError,
    and so escaped accounting entirely and failed the document.
    """
    choices = _attr(response, "choices")
    if isinstance(choices, (str, bytes)) or not isinstance(choices, Sequence):
        return None
    if not choices:
        return None
    try:
        first = choices[0]
    except Exception:
        return None
    reason = _attr(first, "finish_reason")
    if reason is None:
        return None
    try:
        return str(reason)
    except Exception:
        return None


__all__ = [
    "LlmUsage",
    "TruncatedCall",
    "UsageRecorder",
    "PASS1_SUCCESS",
    "PASS1_PARSE_FAILURE",
    "PASS1_OUTPUT_TRUNCATED",
    "PASS1_OUTCOMES",
    "PASS2_SKIPPED",
    "PASS2_EXECUTED",
    "PASS2_FAILED",
    "PASS2_OUTCOMES",
]
