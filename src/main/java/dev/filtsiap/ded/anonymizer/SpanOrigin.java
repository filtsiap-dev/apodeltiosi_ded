package dev.filtsiap.ded.anonymizer;

/**
 * Which authority produced a span (port of {@code SpanOrigin} in {@code models.py}). The
 * resolver arbitrates on this, so it is a contract rather than a label.
 *
 * <p>Distinct from {@link Span#detector()}, a free-form diagnostic name that ends up in the
 * summary. Precedence is never decided by matching a detector name; this type exists so that it
 * does not have to be.
 */
public enum SpanOrigin {
    /**
     * A rule-engine detection. In one of the policy's {@code hard_*_categories} it is an
     * authoritative policy decision; otherwise it is a recommendation for pass 2 to settle.
     */
    DETERMINISTIC("deterministic"),
    /**
     * A pass-1 decision applied without a pass-2 question: pass 1 and the rules agreed, only pass 1
     * spoke, or pass 2 was unavailable and pass 1's answer is the documented fallback. Never hard,
     * always outranked by a pass-2 decision; its REDACT outranks every ordinary deterministic span,
     * its PRESERVE loses to every ordinary deterministic REDACT.
     */
    LLM_PASS1("llm_pass1"),
    /** A final pass-2 adjudication: outranks every ordinary deterministic span and no hard-policy one. */
    LLM_PASS2("llm_pass2");

    private final String wire;

    SpanOrigin(String wire) {
        this.wire = wire;
    }

    /** The wire literal ({@code "deterministic"} / {@code "llm_pass1"} / {@code "llm_pass2"}). */
    public String wire() {
        return wire;
    }
}
