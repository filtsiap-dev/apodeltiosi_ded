package dev.filtsiap.ded.anonymizer;

/** Missing or invalid runtime configuration. */
public class ConfigurationError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public ConfigurationError(String message) {
        super(message, "CONFIGURATION_ERROR", null);
    }

    public ConfigurationError(String message, Throwable cause) {
        super(message, "CONFIGURATION_ERROR", cause);
    }

    @Override
    public String publicDetail() {
        return "the service is misconfigured";
    }

    @Override
    public String outcome() {
        return "configuration_error";
    }
}
