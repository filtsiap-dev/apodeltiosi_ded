package dev.filtsiap.ded.anonymizer;

/**
 * Where a residual is, in the parse of the bytes the scan ran on (port of
 * {@code postcheck.ResidualSpan}).
 *
 * <p>{@code unitId}/{@code start}/{@code end} are code-point coordinates in
 * {@link DocxEngine#parseDocx} of the REDACTED output: the document the remediation pass reads
 * and the one any further redaction is written to. They are exact and CARRIED rather than
 * recomputed, so the same value in two places gives two residuals with two slices, and nothing
 * downstream has to guess which of them a finding meant.
 *
 * <p>{@code text} is the document's own slice at those coordinates, because pass 2 cannot be
 * asked about a span without being shown it. It is kept OUT of {@link #toString()}, so that
 * logging, asserting on or printing a finding cannot spill it.
 */
public record ResidualSpan(String unitId, int start, int end, String text, SpanCategory category) {

    @Override
    public String toString() {
        return "ResidualSpan[unitId=" + unitId + ", start=" + start + ", end=" + end + ", category="
                + category.wire() + "]";
    }
}
