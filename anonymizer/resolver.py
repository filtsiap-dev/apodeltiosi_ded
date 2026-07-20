from __future__ import annotations

from collections import defaultdict

from anonymizer.config import PolicySettings
from anonymizer.models import DocumentData, RedactionPlan, Span


# Structured identifier categories that earn the dedicated high-confidence
# redact tier. In-code constant by design — not policy-driven.
_STRUCTURED_REDACT_CATEGORIES = frozenset({"AFM", "AMKA", "IBAN", "EMAIL"})


def _confidence(span: Span) -> float:
    """Coerce a span's confidence to float, returning 0.0 when it is missing or unparseable."""
    try:
        return float(span.confidence)
    except (TypeError, ValueError):
        return 0.0


def _length(span: Span) -> int:
    """Return the span's character length (end minus start), clamped to a minimum of 0."""
    return max(0, int(span.end) - int(span.start))


def _priority(span: Span, policy: PolicySettings) -> int:
    """Priority tiers. No tier 2 — the REVIEW tier is deleted in v2."""
    confidence = _confidence(span)

    if span.action == "PRESERVE" and confidence >= policy.preserve_high_confidence_threshold:
        return 6
    if (
        span.action == "REDACT"
        and span.category in _STRUCTURED_REDACT_CATEGORIES
        and confidence >= policy.redact_high_confidence_threshold
    ):
        return 5
    if span.action == "REDACT" and confidence >= policy.redact_threshold:
        return 4
    if span.action == "PRESERVE" and confidence < policy.preserve_high_confidence_threshold:
        return 3
    return 0


def _is_hard_preserve(span: Span, policy: PolicySettings) -> bool:
    """Report whether the span is a PRESERVE in one of the policy's hard-preserve categories."""
    return span.action == "PRESERVE" and span.category in policy.hard_preserve_categories


def _is_hard_redact(span: Span, policy: PolicySettings) -> bool:
    """Report whether the span is a REDACT in a hard-redact policy category with confidence at or above the high-confidence redact threshold."""
    return (
        span.action == "REDACT"
        and span.category in policy.hard_redact_categories
        and _confidence(span) >= policy.redact_high_confidence_threshold
    )


def _incoming_replaces_existing(
    incoming: Span,
    existing: Span | None,
    policy: PolicySettings,
) -> bool:
    """Decide whether the incoming span should take over a character position from the existing owner span, honoring hard preserve/redact overrides before falling back to priority tiers. Returns True if the incoming span wins."""
    incoming_priority = _priority(incoming, policy)
    if incoming_priority <= 0:
        return False
    if existing is None:
        return True

    incoming_hard_redact = _is_hard_redact(incoming, policy)
    existing_hard_redact = _is_hard_redact(existing, policy)
    incoming_hard_preserve = _is_hard_preserve(incoming, policy)
    existing_hard_preserve = _is_hard_preserve(existing, policy)

    if incoming_hard_redact and existing_hard_preserve:
        return True
    if existing_hard_redact and incoming_hard_preserve:
        return False
    if incoming_hard_preserve and existing.action == "REDACT" and not existing_hard_redact:
        return True
    if existing_hard_preserve and incoming.action == "REDACT" and not incoming_hard_redact:
        return False

    return incoming_priority > _priority(existing, policy)


def _make_span_from_run(source: Span, start: int, end: int, text: str) -> Span:
    """Build a new Span covering [start, end) with the given text, copying all other fields from the source span."""
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
        warnings.append(
            f"Inconsistent treatment of {s!r}: both redacted and preserved "
            f"in different parts of the document."
        )
    return warnings


def resolve_redactions(
    document: DocumentData,
    candidate_spans: list[Span],
    policy: PolicySettings,
) -> RedactionPlan:
    """Resolve overlapping candidate REDACT/PRESERVE spans per text unit via character-level ownership and policy priorities, producing the final RedactionPlan with consistency warnings."""
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
            candidate_spans_by_unit.get(unit.unit_id, []),
            key=lambda s: (int(s.start), -_length(s), -_confidence(s)),
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


__all__ = ["resolve_redactions"]
