package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.llm.LlmUsage;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What the operator says one million tokens cost, from the environment
 * ({@code ANON_INPUT_COST_PER_1M_TOKENS}, {@code ANON_OUTPUT_COST_PER_1M_TOKENS},
 * {@code ANON_CACHED_INPUT_COST_PER_1M_TOKENS}, {@code ANON_COST_CURRENCY}).
 *
 * <p>NO PRICE IS BUILT IN. Provider prices change, and an Azure deployment is not priced like the
 * OpenAI model behind it, so a number compiled into this code would be wrong silently. Unset, the
 * token accounting still runs and the cost is reported as unavailable, never as zero.
 *
 * <p>Decimal throughout ({@link BigDecimal}): a price is a decimal number of a currency, and binary
 * floating point cannot represent most of them.
 *
 * @param inputPerMillion       per 1M prompt tokens; null when unset
 * @param cachedInputPerMillion per 1M prompt tokens served from the provider's cache; null when unset
 * @param outputPerMillion      per 1M completion tokens (reasoning tokens included); null when unset
 * @param currency              an ISO 4217 code, {@code USD} unless configured
 */
public record LlmPricing(BigDecimal inputPerMillion, BigDecimal cachedInputPerMillion, BigDecimal outputPerMillion,
                         String currency) {

    public static final String DEFAULT_CURRENCY = "USD";

    /** No price configured. */
    public static final LlmPricing UNSET = new LlmPricing(null, null, null, DEFAULT_CURRENCY);

    /** Whether a cost can be computed at all: the input and output rates are both known. */
    public boolean configured() {
        return inputPerMillion != null && outputPerMillion != null;
    }

    /** The rate the cached part of the prompt is charged at: its own when set, the input rate otherwise. */
    public BigDecimal cachedRate() {
        return cachedInputPerMillion != null ? cachedInputPerMillion : inputPerMillion;
    }

    /**
     * The exact cost of {@code usage}, in {@link #currency()}:
     *
     * <pre>
     *   (input_tokens - cached_input_tokens) x input_rate
     * +  cached_input_tokens                 x cached_rate
     * +  output_tokens                       x output_rate
     * ) / 1 000 000
     * </pre>
     *
     * <p>Cached tokens are a SUBSET of the input tokens, so they are moved to their own rate, never
     * added again; when no cached rate is configured they stay at the input rate, which can only
     * overstate the cost, never understate it. Reasoning tokens are a subset of the output tokens
     * and are billed as output, so they are not added either. Requires {@link #configured()}.
     */
    public BigDecimal cost(LlmUsage usage) {
        long cached = usage.cachedInputTokens() == null ? 0 : usage.cachedInputTokens();
        BigDecimal sum = inputPerMillion.multiply(BigDecimal.valueOf(usage.inputTokens() - cached))
                .add(cachedRate().multiply(BigDecimal.valueOf(cached)))
                .add(outputPerMillion.multiply(BigDecimal.valueOf(usage.outputTokens())));
        // Dividing by 10^6 only moves the decimal point: no rounding happens anywhere.
        return sum.movePointLeft(6).stripTrailingZeros();
    }

    /** The configured rates as decimal strings (null when unset): enough to redo {@link #cost}. */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("input_per_1m_tokens", plain(inputPerMillion));
        m.put("cached_input_per_1m_tokens", plain(cachedInputPerMillion));
        m.put("output_per_1m_tokens", plain(outputPerMillion));
        m.put("currency", currency);
        return m;
    }

    /** A decimal as plain digits ("0.00015", never "1.5E-4"); null stays null. */
    static String plain(BigDecimal value) {
        return value == null ? null : value.stripTrailingZeros().toPlainString();
    }
}
