from __future__ import annotations

import hashlib
from collections import defaultdict

from anonymizer.config import PolicySettings
from anonymizer.models import DocumentData, RedactionPlan, Span


# Structured identifier categories that earn the dedicated high-confidence
# redact tier. In-code constant by design — not policy-driven.
_STRUCTURED_REDACT_CATEGORIES = frozenset({"AFM", "AMKA", "IBAN", "EMAIL"})


# Priority tiers. Higher wins a contested character; an exact tie leaves the
# incumbent owner in place. The ladder IS the arbitration rule — there are no
# side overrides — and its shape encodes the pipeline's authority model:
#
#     hard policy decision              (deterministic, by CATEGORY)
#         v
#     pass-2 final decision             (the adjudicator's answer)
#         v
#     ordinary deterministic detection  (fallback evidence)
#
# Read top down:
#
#   * a HARD PRESERVE and a HARD REDACT are authoritative decisions, reached by
#     policy CATEGORY on a DETERMINISTIC span, and they sit above everything
#     else. Pass 2 cannot reach either tier — at any confidence, under any
#     category label it returns — so it can never overturn hard policy;
#   * a pass-2 decision comes next. Pass 2 is this pipeline's semantic
#     adjudicator: it read the surrounding text and answered the question the
#     rules could not, so where it has spoken its answer stands over every
#     ordinary rule span. A rule PRESERVE it overruled cannot reinstate itself
#     here, and neither can a rule REDACT it cleared;
#   * every ordinary deterministic span is FALLBACK EVIDENCE. It owns the
#     characters no higher authority claimed, and nothing more. Confidence moves
#     it between the ordinary tiers and nowhere else, so no confidence value
#     promotes it past a pass-2 decision or into hard-policy behavior.
#
# The two hard tiers are adjacent and ordered hard-redact-over-hard-preserve:
# an identifier the policy calls unsuppressable stays unsuppressable even under
# institutional boilerplate. The two pass-2 tiers are likewise adjacent, and
# ordered preserve-over-redact to match the ordinary rungs below them — so two
# overlapping pass-2 answers that disagree (a candidate, and a longer candidate
# containing it) resolve the same way as two overlapping rule spans would.
_TIER_HARD_REDACT = 8         # deterministic, hard_redact_categories at >= redact_high_confidence
_TIER_HARD_PRESERVE = 7       # deterministic, hard_preserve_categories, at any confidence
_TIER_PASS2_PRESERVE = 6      # pass-2 final PRESERVE, at any confidence
_TIER_PASS2_REDACT = 5        # pass-2 final REDACT, at any confidence
_TIER_STRUCTURED_REDACT = 4   # deterministic AFM/AMKA/IBAN/EMAIL at >= redact_high_confidence
_TIER_PRESERVE_CONFIDENT = 3  # ordinary deterministic PRESERVE at >= preserve_high_confidence
_TIER_REDACT = 2              # ordinary deterministic REDACT at >= redact_threshold
_TIER_PRESERVE = 1            # ordinary deterministic PRESERVE below the confidence bar
_TIER_IGNORED = 0             # can never claim a character


def _confidence(span: Span) -> float:
    """Coerce a span's confidence to float, returning 0.0 when it is missing or unparseable."""
    try:
        return float(span.confidence)
    except (TypeError, ValueError):
        return 0.0


def _length(span: Span) -> int:
    """Return the span's character length (end minus start), clamped to a minimum of 0."""
    return max(0, int(span.end) - int(span.start))


def is_pass2_decision(span: Span) -> bool:
    """Report whether the span is a final LLM pass-2 adjudication.

    Read off ``span.origin`` — the declared provenance — and never off the
    free-form ``detector`` name. That is the whole reason the field exists: a
    precedence rule keyed on a detector string would break silently the first
    time a producer was renamed, and it would break in the unsafe direction.
    """
    return span.origin == "llm_pass2"


def is_hard_preserve(span: Span, policy: PolicySettings) -> bool:
    """Report whether the span is a HARD PRESERVE: a PRESERVE in one of the policy's
    hard_preserve_categories.

    A hard preserve is authoritative rather than advisory. It is decided by
    category alone — confidence plays no part — it is withheld from the LLM
    pass-2 decision queue (see ``anonymizer.llm.detector``), and in this module
    it outranks every ordinary span and every pass-2 decision. Only a hard
    redact can still take it.

    Hard status is DETERMINISTIC-ONLY. A pass-2 span is never a hard preserve,
    whatever category it comes back with: hard policy is a rule-engine
    conclusion about a rule-engine detection, and a decision pass 2 was never
    asked to make is not one it can announce itself into.
    """
    return (
        not is_pass2_decision(span)
        and span.action == "PRESERVE"
        and span.category in policy.hard_preserve_categories
    )


def is_hard_redact(span: Span, policy: PolicySettings) -> bool:
    """Report whether the span is a HARD REDACT: a REDACT in a hard-redact policy
    category with confidence at or above the high-confidence redact threshold.

    Unlike a hard preserve, hard-redact status has to be earned with confidence.
    It is DETERMINISTIC-ONLY for the same reason a hard preserve is: could pass 2
    reach this tier by labelling a decision ``AFM`` at its fixed confidence, it
    would be able to overturn a hard preserve, and the guarantee that hard policy
    survives adjudication would be one relabelling away from failing.
    """
    return (
        not is_pass2_decision(span)
        and span.action == "REDACT"
        and span.category in policy.hard_redact_categories
        and _confidence(span) >= policy.redact_high_confidence_threshold
    )


def _priority(span: Span, policy: PolicySettings) -> int:
    """Rank a span on the tier ladder above.

    Matched in authority order: hard policy first (by category, on a
    deterministic span, so nothing reaches a hard tier on confidence alone),
    then pass-2 decisions, then ordinary deterministic evidence by confidence.

    This function reads provenance, action, category and confidence — and
    nothing about what the text MEANS. Whether a date is a decision date or a
    date of birth, whether a phone number is an authority's or a citizen's, is
    pass 2's question and is already answered by the time a span arrives here.
    The ladder only says whose answer wins where two of them overlap.
    """
    if is_hard_redact(span, policy):
        return _TIER_HARD_REDACT
    if is_hard_preserve(span, policy):
        return _TIER_HARD_PRESERVE

    if is_pass2_decision(span):
        # Deliberately confidence-blind. Pass-2 spans all carry one fixed
        # confidence (``llm.detector._LLM_CONFIDENCE``) because the model does
        # not score its own answers, so making the band depend on that constant
        # would let an edit to it silently reshuffle the ladder.
        if span.action == "REDACT":
            return _TIER_PASS2_REDACT
        if span.action == "PRESERVE":
            return _TIER_PASS2_PRESERVE
        return _TIER_IGNORED

    confidence = _confidence(span)

    if span.action == "REDACT":
        if (
            span.category in _STRUCTURED_REDACT_CATEGORIES
            and confidence >= policy.redact_high_confidence_threshold
        ):
            return _TIER_STRUCTURED_REDACT
        if confidence >= policy.redact_threshold:
            return _TIER_REDACT
        return _TIER_IGNORED

    if span.action == "PRESERVE":
        if confidence >= policy.preserve_high_confidence_threshold:
            return _TIER_PRESERVE_CONFIDENT
        return _TIER_PRESERVE

    return _TIER_IGNORED


def _incoming_replaces_existing(
    incoming: Span,
    existing: Span | None,
    policy: PolicySettings,
) -> bool:
    """Decide whether the incoming span should take over a character position from the
    existing owner span. Returns True if the incoming span wins.

    One comparison on the tier ladder settles it. The hard-preserve / hard-redact
    overrides that used to sit here are now tiers of their own, so the outcomes
    they produced fall out of the ordering instead of being special-cased:
    a hard redact takes a hard preserve, a hard preserve takes any redact that is
    not a hard redact, and a pass-2 decision takes any ordinary rule span while
    yielding to both hard tiers.
    """
    incoming_priority = _priority(incoming, policy)
    if incoming_priority <= _TIER_IGNORED:
        return False
    if existing is None:
        return True
    return incoming_priority > _priority(existing, policy)


def _make_span_from_run(source: Span, start: int, end: int, text: str) -> Span:
    """Build a new Span covering [start, end) with the given text, copying all other fields from the source span.

    ``origin`` travels with the rest: the plan then records which authority
    actually decided each surviving run, which is what makes the outcome
    auditable after the fact.
    """
    return Span(
        unit_id=source.unit_id,
        start=start,
        end=end,
        text=text,
        category=source.category,
        detector=source.detector,
        confidence=source.confidence,
        action=source.action,
        reason=source.reason,
        origin=source.origin,
    )


def _recover_spans_from_owners(normalized_text: str, owners: list[Span | None]) -> list[Span]:
    """Convert the per-character owners array back into a list of contiguous spans, one per run of characters owned by the same span. Returns the recovered spans in text order."""
    resolved: list[Span] = []
    i = 0
    n = len(owners)
    while i < n:
        owner = owners[i]
        if owner is None:
            i += 1
            continue

        start = i
        i += 1
        while i < n and owners[i] is owner:
            i += 1
        end = i

        resolved.append(_make_span_from_run(owner, start, end, normalized_text[start:end]))

    return resolved


def _ordering_key(span: Span) -> tuple:
    """Total order over one unit's candidates, so the plan cannot depend on the
    order the candidates arrived in.

    The ladder already decides every contested character, and each tier carries
    exactly one action, so the resolved ACTIONS never depended on input order.
    What did was the metadata of a run: two candidates identical in geometry,
    confidence and tier but differing in category or detector would both be
    correct owners, and whichever the caller happened to list first won — so
    concatenating the LLM spans before the rule spans, or after, could change
    the category recorded in the summary.

    Ordering on the span's own content instead of its position in the list
    removes that. Geometry first (earliest, longest, most confident), then every
    remaining field as a stable, meaningless-but-fixed tiebreak — every field, so
    that "the key is total" needs no argument about which of them can coincide.
    """
    return (
        int(span.start),
        -_length(span),
        -_confidence(span),
        span.action,
        span.origin,
        span.category,
        span.detector,
        span.reason,
    )


def _consistency_sweep(resolved_spans_by_unit: dict[str, list[Span]]) -> list[str]:
    """Scan resolved spans across all units for strings (casefolded) that are both redacted and preserved somewhere in the document. Returns a warning message per inconsistent string."""
    redacted_strings: set[str] = set()
    preserved_strings: set[str] = set()

    for unit_spans in resolved_spans_by_unit.values():
        for span in unit_spans:
            if span.action == "REDACT":
                redacted_strings.add(span.text.casefold())
            elif span.action == "PRESERVE":
                preserved_strings.add(span.text.casefold())

    warnings: list[str] = []
    for s in sorted(redacted_strings & preserved_strings):
        # Never quote the string itself: it was redacted somewhere, so it is
        # suspected PII, and these warnings flow to the API JSON and CLI
        # output. A short hash + length lets runs be correlated without leaking.
        digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]
        warnings.append(
            f"Inconsistent treatment of a span (sha256:{digest}, {len(s)} chars): "
            f"both redacted and preserved in different parts of the document."
        )
    return warnings


def resolve_redactions(
    document: DocumentData,
    candidate_spans: list[Span],
    policy: PolicySettings,
) -> RedactionPlan:
    """Resolve overlapping candidate REDACT/PRESERVE spans per text unit via character-level ownership and policy priorities, producing the final RedactionPlan with consistency warnings.

    ``candidate_spans`` mixes both authorities — pass-2 decisions and the
    deterministic spans behind them — and each one declares which it is through
    ``Span.origin``. Every character is then awarded to the highest-ranked span
    covering it, so a pass-2 decision governs the characters it actually spoke
    about while the rule spans stay as fallback evidence for the rest. Partial
    overlaps split accordingly, which is the intended reading of "the decision
    applies to the content it refers to".

    The list's ORDER carries no meaning: the outcome is a function of the spans
    alone (see ``_ordering_key``). Passing rules-then-LLM or LLM-then-rules
    produces the same plan.
    """
    # Invariant guard: the resolver only ever sees REDACT/PRESERVE. A REVIEW
    # span arriving here is a programming bug upstream, surfaced loudly.
    for span in candidate_spans:
        if span.action not in ("REDACT", "PRESERVE"):
            raise RuntimeError("REVIEW span reached the resolver — programming bug")

    candidate_spans_by_unit: dict[str, list[Span]] = defaultdict(list)
    for span in candidate_spans:
        candidate_spans_by_unit[span.unit_id].append(span)

    resolved_spans_by_unit: dict[str, list[Span]] = {}

    for unit in document.text_units:
        normalized_text = unit.normalized_text
        owners: list[Span | None] = [None] * len(normalized_text)

        unit_candidates = sorted(
            candidate_spans_by_unit.get(unit.unit_id, []), key=_ordering_key
        )

        for span in unit_candidates:
            start = max(0, min(len(normalized_text), int(span.start)))
            end = max(0, min(len(normalized_text), int(span.end)))
            if start >= end:
                continue

            for index in range(start, end):
                if _incoming_replaces_existing(span, owners[index], policy):
                    owners[index] = span

        resolved_spans_by_unit[unit.unit_id] = _recover_spans_from_owners(normalized_text, owners)

    warnings = _consistency_sweep(resolved_spans_by_unit)
    resolved_spans = [span for unit_spans in resolved_spans_by_unit.values() for span in unit_spans]
    resolved_spans.sort(key=lambda s: (s.unit_id, s.start))

    return RedactionPlan(
        document_id=document.document_id,
        spans=resolved_spans,
        warnings=warnings,
    )


__all__ = [
    "is_hard_preserve",
    "is_hard_redact",
    "is_pass2_decision",
    "resolve_redactions",
]
