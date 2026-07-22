import collections

from anonymizer.models import PlanSummary, RedactionPlan


def build_summary(plan: RedactionPlan) -> PlanSummary:
    """Build a counts-only summary of a resolved redaction plan.

    Carries no span text, offsets, or unit ids — only aggregate counts and the
    plan's own warnings.
    """
    return PlanSummary(
        spans_total=len(plan.spans),
        by_action=dict(collections.Counter(span.action for span in plan.spans)),
        by_category=dict(collections.Counter(span.category for span in plan.spans)),
        by_detector=dict(collections.Counter(span.detector for span in plan.spans)),
        warnings=list(plan.warnings),
    )
