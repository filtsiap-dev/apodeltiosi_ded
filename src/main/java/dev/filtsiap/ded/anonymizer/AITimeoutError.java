package dev.filtsiap.ded.anonymizer;

/** Per-call AI timeout exceeded. */
public class AITimeoutError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public AITimeoutError(String message) {
        super(message);
    }

    public AITimeoutError(String message, Throwable cause) {
        super(message, cause);
    }
}
