package dev.filtsiap.ded.anonymizer;

/** AI provider unreachable (connection errors). */
public class AIUnavailableError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public AIUnavailableError(String message) {
        super(message, "AI_UNAVAILABLE", null);
    }

    public AIUnavailableError(String message, Throwable cause) {
        super(message, "AI_UNAVAILABLE", cause);
    }

    @Override
    public String publicDetail() {
        return "the language-model provider is unreachable; retry later";
    }

    @Override
    public String outcome() {
        return "provider_failure";
    }
}
