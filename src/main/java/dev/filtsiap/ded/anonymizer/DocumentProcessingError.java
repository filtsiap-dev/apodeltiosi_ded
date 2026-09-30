package dev.filtsiap.ded.anonymizer;

/** Valid DOCX but a redaction plan cannot be produced or applied. */
public class DocumentProcessingError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public DocumentProcessingError(String message) {
        super(message);
    }

    public DocumentProcessingError(String message, Throwable cause) {
        super(message, cause);
    }
}
