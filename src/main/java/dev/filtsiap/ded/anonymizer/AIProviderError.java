package dev.filtsiap.ded.anonymizer;

/** AI provider API error or unusable output. */
public class AIProviderError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public AIProviderError(String message) {
        super(message, "AI_PROVIDER_ERROR", null);
    }

    public AIProviderError(String message, Throwable cause) {
        super(message, "AI_PROVIDER_ERROR", cause);
    }

    @Override
    public String publicDetail() {
        return "the language-model provider failed; retry later";
    }

    @Override
    public String outcome() {
        return "provider_failure";
    }
}
