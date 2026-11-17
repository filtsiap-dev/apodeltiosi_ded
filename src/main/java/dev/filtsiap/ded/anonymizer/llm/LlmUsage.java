package dev.filtsiap.ded.anonymizer.llm;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One document's finished LLM accounting (port of {@code llm/usage.LlmUsage}). Immutable by the
 * time anyone reads it, and counts only: no prompt, candidate or completion text is ever read for
 * it or stored in it.
 *
 * <p>{@code calls} counts provider RESPONSES: pass 1, pass 2 (first and corrective retry) and the
 * post-redaction remediation (first and retry), so
 * {@code calls == pass1Calls + pass2Calls + remediationCalls}. A transport attempt that failed
 * returned no response, so it is counted in {@code failedProviderAttempts} and given no tokens.
 *
 * <p>Token totals are what the provider REPORTED, summed over the responses that reported them.
 * {@code callsMissingUsage} counts the responses that did not (or reported nonsense); non-zero
 * means every total is incomplete, and that is said rather than estimated. {@code cachedInputTokens}
 * (a subset of {@code inputTokens}) and {@code reasoningTokens} (a subset of {@code outputTokens})
 * are null when no response reported them at all.
 *
 * <p>{@code providerTimeMs} is the time spent waiting on the provider, summed over every attempt,
 * failed ones included. Chunks run concurrently, so it can exceed the document's wall-clock time.
 *
 * @param truncated every response the provider cut off at {@code ANON_MAX_COMPLETION_TOKENS}
 */
public record LlmUsage(
        int calls,
        int pass1Calls,
        int pass2Calls,
        int pass2RetryCalls,
        int remediationCalls,
        int remediationRetryCalls,
        long inputTokens,
        Long cachedInputTokens,
        long outputTokens,
        Long reasoningTokens,
        long totalTokens,
        int callsMissingUsage,
        int failedProviderAttempts,
        long providerTimeMs,
        List<TruncatedCall> truncated,
        int pass1Success,
        int pass1ParseFailure,
        int pass1OutputTruncated,
        int pass2Skipped,
        int pass2Executed,
        int pass2Failed,
        int pass2Retried,
        int pass2Attempts,
        int pass2IncompleteAttempts,
        int pass1ProviderFailure) {

    public LlmUsage {
        truncated = List.copyOf(truncated);
    }

    /**
     * A response the provider ended at the output-token ceiling: the diagnostic that separates
     * "the model omitted a decision" from "the model ran out of room to answer", which need
     * opposite fixes.
     *
     * @param outputTokens the completion tokens it reported, or null when it reported none
     */
    public record TruncatedCall(int chunkIndex, CallKind kind, Long outputTokens, int limit) {

        /** The chunk as a person counts it: 1-based, like every other report. */
        public int chunkNumber() {
            return chunkIndex + 1;
        }

        Map<String, Object> asMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("chunk", chunkNumber());
            m.put("call", kind.wire());
            m.put("pass", kind.passNumber());
            m.put("attempt", kind.attempt());
            m.put("output_tokens", outputTokens);
            m.put("limit", limit);
            return m;
        }
    }

    /** Chunks whose pass 1 contributed nothing because its output was unusable. */
    public int pass1Degraded() {
        return pass1ParseFailure + pass1OutputTruncated + pass1ProviderFailure;
    }

    /** Whether every token total covers every response. */
    public boolean usageComplete() {
        return callsMissingUsage == 0;
    }

    /** The whole ledger with snake_case keys, for {@code --summary-json}: counts only. */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("calls", calls);
        m.put("pass1_calls", pass1Calls);
        m.put("pass2_calls", pass2Calls);
        m.put("pass2_retry_calls", pass2RetryCalls);
        m.put("remediation_calls", remediationCalls);
        m.put("remediation_retry_calls", remediationRetryCalls);
        m.put("input_tokens", inputTokens);
        m.put("cached_input_tokens", cachedInputTokens);
        m.put("output_tokens", outputTokens);
        m.put("reasoning_tokens", reasoningTokens);
        m.put("total_tokens", totalTokens);
        m.put("calls_missing_usage", callsMissingUsage);
        m.put("failed_provider_attempts", failedProviderAttempts);
        m.put("provider_time_ms", providerTimeMs);
        m.put("truncated", truncated.stream().map(TruncatedCall::asMap).toList());
        m.put("pass1_success", pass1Success);
        m.put("pass1_parse_failure", pass1ParseFailure);
        m.put("pass1_output_truncated", pass1OutputTruncated);
        m.put("pass1_provider_failure", pass1ProviderFailure);
        m.put("pass2_skipped", pass2Skipped);
        m.put("pass2_executed", pass2Executed);
        m.put("pass2_failed", pass2Failed);
        m.put("pass2_retried", pass2Retried);
        m.put("pass2_attempts", pass2Attempts);
        m.put("pass2_incomplete_attempts", pass2IncompleteAttempts);
        return m;
    }
}
