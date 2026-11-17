package dev.filtsiap.ded.anonymizer;

/** The redacted DOCX failed its mandatory post-redaction scan: HIGH-severity personal
 * information survived. The document is never returned or saved; it needs manual review. */
public class ResidualPIIError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public ResidualPIIError(String message) {
        super(message, "RESIDUAL_PII_FOUND", null);
    }

    public ResidualPIIError(String message, Throwable cause) {
        super(message, "RESIDUAL_PII_FOUND", cause);
    }

    @Override
    public String publicDetail() {
        return "the redacted document failed its post-redaction scan and needs manual review";
    }

    @Override
    public String outcome() {
        return "residual_pii";
    }
}
