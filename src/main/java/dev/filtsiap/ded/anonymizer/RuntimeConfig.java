package dev.filtsiap.ded.anonymizer;

/**
 * Runtime configuration from the process environment (port of {@code config.RuntimeConfig}).
 *
 * @param anonApiKey bearer token for POST /anonymize; optional because the CLI never needs it,
 *                   the HTTP service refuses to start without it. Never logged or returned.
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
        int llmConcurrency,
        String logLevel,
        int maxUploadMb) {

    /** Dataclass defaults. */
    public static final double DEFAULT_LLM_TIMEOUT_S = 60.0;
    public static final int DEFAULT_CHUNK_SIZE_CHARS = 3000;
    public static final int DEFAULT_MAX_COMPLETION_TOKENS = 2000;
    public static final int DEFAULT_LLM_CONCURRENCY = 8;
    public static final String DEFAULT_LOG_LEVEL = "INFO";
    public static final int DEFAULT_MAX_UPLOAD_MB = 20;

    /** LLM provider; {@link #wire()} is the {@code ANON_PROVIDER} value. */
    public enum Provider {
        OPENAI("openai"), AZURE("azure");

        private final String wire;

        Provider(String wire) {
            this.wire = wire;
        }

        public String wire() {
            return wire;
        }
    }

    /** OpenAI model name, or the Azure deployment name. */
    public String modelHandle() {
        return provider == Provider.OPENAI ? openaiModel : azureDeployment;
    }

    /** Never print secrets. */
    @Override
    public String toString() {
        return "RuntimeConfig[provider=" + provider.wire() + ", model=" + modelHandle() + "]";
    }
}
