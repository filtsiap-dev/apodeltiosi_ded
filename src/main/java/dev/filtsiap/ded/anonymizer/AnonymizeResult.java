package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.llm.LlmUsage;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pipeline result (port of {@code AnonymizeResult}). Provenance keys: provider, model,
 * config_sha256, prompts_sha256, package_version.
 *
 * <p>{@code postcheck} describes {@code redactedDocx} itself: the deterministic scan of the returned
 * bytes (the post-redaction scan, or, when the remediation rewrote the document, the final scan
 * that followed it). A finding on a result is normal: a MEDIUM one was settled by pass 2's answer
 * either way. A HIGH one is settled only by being REDACTED: if pass 2 preserved it, or its
 * redaction did not cover the whole value, or the final scan still sees it, it is in
 * {@code unresolved} as a {@code HIGH_RESIDUAL_*} finding and the result is {@code needs-review}.
 * The HIGH findings that name no text slice stop the document with {@link ResidualPIIError}
 * instead of reaching here; {@code warnings} says how many were re-adjudicated.
 *
 * <p>{@code unresolved} is what a person still has to settle: what pass 2 could not decide after
 * its corrective retry (in the first adjudication or in the remediation), and every HIGH residual
 * still visible. A result can exist with these present: they are handed to a person rather than
 * guessed at.
 *
 * <p>{@code accounting} is what the document cost: time, LLM calls, tokens and (when prices are
 * configured) money, covering every provider response including the remediation's.
 */
public record AnonymizeResult(
        String documentId,
        byte[] redactedDocx,
        PlanSummary summary,
        List<String> warnings,
        String model,
        Map<String, Double> timings,
        PostcheckSummary postcheck,
        Map<String, String> provenance,
        List<UnresolvedFinding> unresolved,
        DocumentAccounting accounting) {

    public AnonymizeResult {
        warnings = List.copyOf(warnings);
        timings = Collections.unmodifiableMap(new LinkedHashMap<>(timings));
        provenance = Collections.unmodifiableMap(new LinkedHashMap<>(provenance));
        unresolved = List.copyOf(unresolved);
    }

    /** The document's whole LLM ledger (port of {@code AnonymizeResult.llm_usage}). */
    public LlmUsage llmUsage() {
        return accounting.usage();
    }

    /** How many findings a person still has to settle. */
    public int unresolvedCount() {
        return unresolved.size();
    }

    /** Whether this document carries work for a human reviewer. It never means nobody looked. */
    public boolean needsReview() {
        return !unresolved.isEmpty();
    }

    /**
     * Whether any pass-2 question was settled by the documented fallback (or left undecided) because
     * pass 2 was unavailable for it. Implies {@link #needsReview()}. Reported in the
     * {@code x-llm-fallback-used} header (only when true), the logs and {@code --summary-json}; never
     * in the document itself.
     */
    public boolean fallbackUsed() {
        return unresolved.stream().anyMatch(f -> f.kind() == UnresolvedFinding.Kind.PASS2_UNAVAILABLE);
    }

    /** The operational outcome, one spelling everywhere: the API header, the CLI line, --summary-json. */
    public String status() {
        return needsReview() ? "needs-review" : "processed";
    }
}
