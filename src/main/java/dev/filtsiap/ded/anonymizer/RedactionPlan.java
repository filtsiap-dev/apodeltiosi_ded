package dev.filtsiap.ded.anonymizer;

import java.util.List;

/** The resolved plan: only REDACT and PRESERVE spans (port of {@code RedactionPlan}). */
public record RedactionPlan(String documentId, List<Span> spans, List<String> warnings) {
    public RedactionPlan {
        spans = List.copyOf(spans);
        warnings = List.copyOf(warnings);
    }
}
