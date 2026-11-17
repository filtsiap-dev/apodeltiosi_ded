package dev.filtsiap.ded.anonymizer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Counts-only summary of a plan: no span text, offsets or unit ids (port of {@code PlanSummary}). */
public record PlanSummary(int spansTotal, Map<String, Integer> byAction, Map<String, Integer> byCategory,
                          Map<String, Integer> byDetector, List<String> warnings) {
    public PlanSummary {
        byAction = Collections.unmodifiableMap(new LinkedHashMap<>(byAction));
        byCategory = Collections.unmodifiableMap(new LinkedHashMap<>(byCategory));
        byDetector = Collections.unmodifiableMap(new LinkedHashMap<>(byDetector));
        warnings = List.copyOf(warnings);
    }

    /** Python {@code dataclasses.asdict(summary)}. */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("spans_total", spansTotal);
        m.put("by_action", byAction);
        m.put("by_category", byCategory);
        m.put("by_detector", byDetector);
        m.put("warnings", warnings);
        return m;
    }
}
