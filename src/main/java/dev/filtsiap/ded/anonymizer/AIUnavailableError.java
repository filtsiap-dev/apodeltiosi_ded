package dev.filtsiap.ded.anonymizer;

/** AI provider unreachable (connection errors). */
public class AIUnavailableError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public AIUnavailableError(String message) {
        super(message);
    }

    public AIUnavailableError(String message, Throwable cause) {
        super(message, cause);
    }
}
