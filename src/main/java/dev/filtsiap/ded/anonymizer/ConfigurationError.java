package dev.filtsiap.ded.anonymizer;

/** Missing or invalid runtime configuration. */
public class ConfigurationError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public ConfigurationError(String message) {
        super(message);
    }

    public ConfigurationError(String message, Throwable cause) {
        super(message, cause);
    }
}
