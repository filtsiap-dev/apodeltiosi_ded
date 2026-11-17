package dev.filtsiap.ded.anonymizer;

/**
 * Runtime configuration from the process environment (port of {@code config.RuntimeConfig}).
 *
 * @param anonApiKey        bearer token for POST /anonymize; optional because the CLI never needs
 *                          it, the HTTP service refuses to start without it. Never logged or returned.
 * @param documentDeadlineS the end-to-end budget for one document, from authentication to the
 *                          bytes being ready: the upload, every stage, every provider call and retry
 * @param llmContextTokens  {@code ANON_LLM_CONTEXT_TOKENS}: the deployed model's whole context window
 *                          (input and completion), as the operator states it; 0 when not configured,
 *                          and then no whole-request check is made. Never inferred from a model name.
 * @param limits            finite bounds on one document's size, expansion and processing cost
 * @param pricing           what the operator says tokens cost, for per-document cost accounting;
 *                          {@link LlmPricing#UNSET} when no price is configured
 */
public record RuntimeConfig(
        Provider provider,
        String openaiApiKey,
        String openaiModel,
        String azureApiKey,
        String azureEndpoint,
        String azureDeployment,
        String azureApiVersion,
        String anonApiKey,
        double llmTimeoutS,
        int chunkSizeChars,
        int maxCompletionTokens,
        int llmContextTokens,
        int llmConcurrency,
        String logLevel,
        double documentDeadlineS,
        ResourceLimits limits,
        LlmPricing pricing) {

    /** Dataclass defaults. */
    public static final double DEFAULT_LLM_TIMEOUT_S = 60.0;
    public static final int DEFAULT_CHUNK_SIZE_CHARS = 7000;
    public static final int DEFAULT_MAX_COMPLETION_TOKENS = 3000;
    public static final int DEFAULT_LLM_CONCURRENCY = 8;
    public static final String DEFAULT_LOG_LEVEL = "INFO";
    public static final double DEFAULT_DOCUMENT_DEADLINE_S = 300.0;

    /**
     * LLM provider; {@link #wire()} is the {@code ANON_PROVIDER} value. {@code REGEX} has no model:
     * only the rule-based chat endpoints work, and nothing needs a model key.
     */
    public enum Provider {
        OPENAI("openai"), AZURE("azure"), REGEX("regex");

        private final String wire;

        Provider(String wire) {
            this.wire = wire;
        }

        public String wire() {
            return wire;
        }
    }

    /** OpenAI model name, the Azure deployment name, or null in regex mode. */
    public String modelHandle() {
        return switch (provider) {
            case OPENAI -> openaiModel;
            case AZURE -> azureDeployment;
            case REGEX -> null;
        };
    }

    /** Never print secrets. */
    @Override
    public String toString() {
        return "RuntimeConfig[provider=" + provider.wire() + ", model=" + modelHandle() + "]";
    }
}
