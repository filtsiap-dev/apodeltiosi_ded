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

    /** The findings that name a slice of document text, in scan order: what is put to LLM pass 2. */
    public List<PostcheckFinding> remediable() {
        return findings.stream().filter(f -> f.span() != null).toList();
    }

    /** The HIGH findings nothing downstream can act on: they end the document. */
    public List<PostcheckFinding> blocking() {
        return findings.stream().filter(f -> f.severity() == PostcheckFinding.Severity.HIGH && f.span() == null)
                .toList();
    }

    /** Python {@code dataclasses.asdict(summary)}, spans left out (see {@link PostcheckFinding#asMap}). */
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
