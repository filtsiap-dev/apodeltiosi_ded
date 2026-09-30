package dev.filtsiap.ded.anonymizer;

/** The redacted DOCX failed its mandatory post-redaction scan: HIGH-severity personal
 * information survived. The document is never returned or saved; it needs manual review. */
public class ResidualPIIError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public ResidualPIIError(String message) {
        super(message);
    }

    public ResidualPIIError(String message, Throwable cause) {
        super(message, cause);
    }
}
