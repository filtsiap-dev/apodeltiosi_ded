package dev.filtsiap.ded.anonymizer;

/** Bad, corrupt, or non-DOCX upload. */
public class InvalidDocumentError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public InvalidDocumentError(String message) {
        super(message);
    }

    public InvalidDocumentError(String message, Throwable cause) {
        super(message, cause);
    }
}
