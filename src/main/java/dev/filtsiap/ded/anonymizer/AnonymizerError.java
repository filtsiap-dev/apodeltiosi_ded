package dev.filtsiap.ded.anonymizer;

/**
 * Base class for all anonymizer errors (port of {@code errors.py}).
 *
 * <p>Unchecked, like Python exceptions. Subclass simple names equal the Python class names
 * exactly: the HTTP API returns {@code {"error": "<ClassName>"}}. Messages name finding kinds
 * and locations, never matched document text.
 */
public class AnonymizerError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public AnonymizerError(String message) {
        super(message);
    }

    public AnonymizerError(String message, Throwable cause) {
        super(message, cause);
    }
}
