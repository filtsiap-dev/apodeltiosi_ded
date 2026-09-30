package dev.filtsiap.ded.anonymizer;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/** Counts-only plan summary (port of {@code summary.py}). */
public final class Summary {

    private Summary() {
    }

    /** No span text, offsets or unit ids: only aggregate counts (first-seen key order) and warnings. */
    public static PlanSummary buildSummary(RedactionPlan plan) {
        return new PlanSummary(
                plan.spans().size(),
                count(plan, s -> s.action().wire()),
                count(plan, s -> s.category().wire()),
                count(plan, Span::detector),
                plan.warnings());
    }

    private static Map<String, Integer> count(RedactionPlan plan, Function<Span, String> key) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        plan.spans().forEach(s -> counts.merge(key.apply(s), 1, Integer::sum));
        return counts;
    }
}
