package dev.filtsiap.ded.anonymizer;

/**
 * A candidate or resolved span (port of {@code Span}). {@code start}/{@code end} are
 * code-point offsets into the unit's {@code normalizedText}.
 */
public record Span(
        String unitId,
        int start,
        int end,
        String text,
        SpanCategory category,
        String detector,
        double confidence,
        SpanAction action,
        String reason) {
}
