package dev.filtsiap.ded.anonymizer;

/** AI provider API error or unusable output. */
public class AIProviderError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public AIProviderError(String message) {
        super(message);
    }

    public AIProviderError(String message, Throwable cause) {
        super(message, cause);
    }
}
