package dev.filtsiap.ded.anonymizer;

/** One provider call exceeded its per-call timeout (not the document deadline). */
public class AITimeoutError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public AITimeoutError(String message) {
        super(message, "AI_TIMEOUT", null);
    }

    public AITimeoutError(String message, Throwable cause) {
        super(message, "AI_TIMEOUT", cause);
    }

    @Override
    public String publicDetail() {
        return "the language-model provider timed out; retry later";
    }

    @Override
    public String outcome() {
        return "provider_failure";
    }
}
