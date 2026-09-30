package dev.filtsiap.ded.anonymizer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Result of the post-redaction scan (port of {@code postcheck.PostcheckSummary}). */
public record PostcheckSummary(boolean clean, int findingsTotal, Map<String, Integer> bySeverity,
                               Map<String, Integer> byKind, List<PostcheckFinding> findings) {
    public PostcheckSummary {
        bySeverity = Collections.unmodifiableMap(new LinkedHashMap<>(bySeverity));
        byKind = Collections.unmodifiableMap(new LinkedHashMap<>(byKind));
        findings = List.copyOf(findings);
    }

    /** Python {@code dataclasses.asdict(summary)}. */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("clean", clean);
        m.put("findings_total", findingsTotal);
        m.put("by_severity", bySeverity);
        m.put("by_kind", byKind);
        m.put("findings", findings.stream().map(PostcheckFinding::asMap).toList());
        return m;
    }
}
