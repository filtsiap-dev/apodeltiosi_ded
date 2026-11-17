package dev.filtsiap.ded.anonymizer;

/** Valid input from which this service could not produce valid output. */
public class DocumentProcessingError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public DocumentProcessingError(String message) {
        super(message, "DOCUMENT_PROCESSING_FAILED", null);
    }

    public DocumentProcessingError(String message, Throwable cause) {
        super(message, "DOCUMENT_PROCESSING_FAILED", cause);
    }

    public DocumentProcessingError(String message, String code, Throwable cause) {
        super(message, code, cause);
    }

    @Override
    public String publicDetail() {
        return "the redacted document could not be produced";
    }

    @Override
    public String outcome() {
        return "output_failure";
    }
}
