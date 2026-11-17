package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.llm.LlmUsage;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * What one document cost to process: time, provider calls, tokens and, when prices are
 * configured, money. Immutable, counts only, and safe to log: nothing in it is document text.
 *
 * <p>The token figures are {@link #usage()}'s, read through; this record adds time and price and
 * stores no second copy of any count.
 *
 * <p>{@code estimatedCost} is NULL, never zero, when it cannot be stated: no price configured
 * ({@code pricing_not_configured}), or a response that reported no usable token counts
 * ({@code calls_missing_usage}), since the cost of that call is unknown and so is the total. See
 * {@link LlmPricing#cost} for the formula; {@link #asMap()} carries the rates it used, so any
 * figure can be recomputed from the record alone.
 *
 * @param totalElapsedMs wall-clock time of the whole document
 * @param llmElapsedMs   wall-clock time of the LLM stage plus the remediation's pass-2 calls; null
 *                       when the document did not get that far
 * @param costUnavailableReason null exactly when {@code estimatedCost} is present
 */
public record DocumentAccounting(LlmUsage usage, long totalElapsedMs, Long llmElapsedMs, LlmPricing pricing,
                                 BigDecimal estimatedCost, String costUnavailableReason) {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.llm.usage");

    /**
     * The accounting for {@code usage} under {@code pricing}. Never throws: accounting must not be
     * able to fail a document, so a failure here costs the money figure and nothing else.
     */
    public static DocumentAccounting of(LlmUsage usage, long totalElapsedMs, Long llmElapsedMs, LlmPricing pricing) {
        if (!pricing.configured()) {
            return new DocumentAccounting(usage, totalElapsedMs, llmElapsedMs, pricing, null, "pricing_not_configured");
        }
        if (!usage.usageComplete()) {
            return new DocumentAccounting(usage, totalElapsedMs, llmElapsedMs, pricing, null, "calls_missing_usage");
        }
        try {
            return new DocumentAccounting(usage, totalElapsedMs, llmElapsedMs, pricing, pricing.cost(usage), null);
        } catch (RuntimeException e) {
            LOG.warn("cost_accounting_failed error={}", e.getClass().getSimpleName());
            return new DocumentAccounting(usage, totalElapsedMs, llmElapsedMs, pricing, null, "accounting_error");
        }
    }

    public int calls() {
        return usage.calls();
    }

    public long inputTokens() {
        return usage.inputTokens();
    }

    public Long cachedInputTokens() {
        return usage.cachedInputTokens();
    }

    public long outputTokens() {
        return usage.outputTokens();
    }

    public Long reasoningTokens() {
        return usage.reasoningTokens();
    }

    public long totalTokens() {
        return usage.totalTokens();
    }

    public int callsMissingUsage() {
        return usage.callsMissingUsage();
    }

    public String currency() {
        return pricing.currency();
    }

    /** The cost as plain decimal digits, or null when unavailable. A string, so no float ever holds it. */
    public String estimatedCostText() {
        return LlmPricing.plain(estimatedCost);
    }

    /**
     * Which rate the cached input was charged at: {@code cached} when one is configured, {@code input}
     * when none is (an upper bound, never an understatement), null when no cost was computed.
     */
    public String cachedInputRate() {
        if (estimatedCost == null) {
            return null;
        }
        return pricing.cachedInputPerMillion() != null ? "cached" : "input";
    }

    /** The whole record with snake_case keys, for {@code --summary-json}. */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("total_time_ms", totalElapsedMs);
        m.put("llm_time_ms", llmElapsedMs);
        m.put("provider_time_ms", usage.providerTimeMs());
        m.put("llm_calls", usage.calls());
        m.put("pass1_calls", usage.pass1Calls());
        m.put("pass2_calls", usage.pass2Calls());
        m.put("pass2_retry_calls", usage.pass2RetryCalls());
        m.put("remediation_calls", usage.remediationCalls());
        m.put("remediation_retry_calls", usage.remediationRetryCalls());
        m.put("corrective_retry_calls", usage.pass2RetryCalls() + usage.remediationRetryCalls());
        m.put("failed_provider_attempts", usage.failedProviderAttempts());
        m.put("input_tokens", usage.inputTokens());
        m.put("cached_input_tokens", usage.cachedInputTokens());
        m.put("output_tokens", usage.outputTokens());
        m.put("reasoning_tokens", usage.reasoningTokens());
        m.put("total_tokens", usage.totalTokens());
        m.put("calls_missing_usage", usage.callsMissingUsage());
        m.put("estimated_cost", estimatedCostText());
        m.put("currency", pricing.currency());
        m.put("cost_unavailable_reason", costUnavailableReason);
        m.put("cached_input_rate", cachedInputRate());
        m.put("pricing", pricing.asMap());
        return m;
    }

    /** The totals as {@code key=value} pairs for a log line; "-" for what is not known. */
    public String logFields() {
        return "llm_calls=" + usage.calls()
                + " tokens_in=" + usage.inputTokens()
                + " tokens_cached=" + dash(usage.cachedInputTokens())
                + " tokens_out=" + usage.outputTokens()
                + " tokens_reasoning=" + dash(usage.reasoningTokens())
                + " tokens_total=" + usage.totalTokens()
                + " calls_missing_usage=" + usage.callsMissingUsage()
                + " llm_ms=" + dash(llmElapsedMs)
                + " provider_ms=" + usage.providerTimeMs()
                + " total_ms=" + totalElapsedMs
                + " cost=" + dash(estimatedCostText())
                + " currency=" + pricing.currency()
                + " pass1_calls=" + usage.pass1Calls()
                + " pass2_calls=" + usage.pass2Calls()
                + " corrective_retry_calls=" + (usage.pass2RetryCalls() + usage.remediationRetryCalls())
                + " remediation_calls=" + usage.remediationCalls()
                + " failed_provider_attempts=" + usage.failedProviderAttempts()
                + " input_price=" + dash(LlmPricing.plain(pricing.inputPerMillion()))
                + " cached_input_price=" + dash(LlmPricing.plain(pricing.cachedInputPerMillion()))
                + " output_price=" + dash(LlmPricing.plain(pricing.outputPerMillion()));
    }

    private static String dash(Object value) {
        return value == null ? "-" : value.toString();
    }
}
