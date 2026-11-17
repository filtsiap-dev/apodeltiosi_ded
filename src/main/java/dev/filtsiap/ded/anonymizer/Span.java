package dev.filtsiap.ded.anonymizer;

import java.util.Objects;

/**
 * A candidate or resolved span (port of {@code Span}). {@code start}/{@code end} are
 * code-point offsets into the unit's {@code normalizedText}.
 *
 * <p>{@code origin} has no default here, unlike Python's {@code "deterministic"}: every producer
 * states which authority it speaks for, so a new one cannot borrow an authority by omission.
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
        String reason,
        SpanOrigin origin) {
    public Span {
        Objects.requireNonNull(origin, "origin");
    }
}
