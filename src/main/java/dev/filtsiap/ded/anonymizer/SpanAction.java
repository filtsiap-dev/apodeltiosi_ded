package dev.filtsiap.ded.anonymizer;

import java.util.Optional;

/**
 * Span actions (port of {@code SpanAction}). {@code REVIEW} exists only before resolution
 * (deterministic review hints and LLM pass-1 findings); it never appears in a RedactionPlan.
 */
public enum SpanAction {
    REDACT, PRESERVE, REVIEW;

    /** The wire string; equals {@link #name()}. */
    public String wire() {
        return name();
    }

    /** Parses a wire string; unknown values give empty, never an exception. */
    public static Optional<SpanAction> fromWire(String value) {
        for (SpanAction a : values()) {
            if (a.name().equals(value)) {
                return Optional.of(a);
            }
        }
        return Optional.empty();
    }
}
