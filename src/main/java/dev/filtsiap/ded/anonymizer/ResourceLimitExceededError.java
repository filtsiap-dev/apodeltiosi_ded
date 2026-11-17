package dev.filtsiap.ded.anonymizer;

/**
 * The request exceeds a configured size or expansion limit ({@link ResourceLimits}). Raised
 * before the work it would have cost is done, so it says what was refused, never what was in it.
 */
public class ResourceLimitExceededError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public ResourceLimitExceededError(String message, String code) {
        super(message, code, null);
    }

    @Override
    public String publicDetail() {
        return "the document exceeds a configured size or resource limit";
    }

    @Override
    public String outcome() {
        return "resource_limit";
    }
}
