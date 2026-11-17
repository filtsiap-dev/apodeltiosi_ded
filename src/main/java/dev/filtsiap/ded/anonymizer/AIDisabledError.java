package dev.filtsiap.ded.anonymizer;

/** An AI model endpoint called while the service runs with {@code ANON_PROVIDER=regex}. */
public class AIDisabledError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public AIDisabledError(String message) {
        super(message, "AI_DISABLED", null);
    }

    @Override
    public String publicDetail() {
        return "this service runs in regex mode and has no AI model; POST /anonymize-text and POST /anonymize-log "
                + "are available";
    }

    @Override
    public String outcome() {
        return "ai_disabled";
    }
}
