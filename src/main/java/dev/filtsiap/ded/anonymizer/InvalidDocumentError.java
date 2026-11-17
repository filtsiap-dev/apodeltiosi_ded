package dev.filtsiap.ded.anonymizer;

/** The upload is not a document this service can read: a broken or unsafe ZIP, missing parts, bad XML. */
public class InvalidDocumentError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public InvalidDocumentError(String message) {
        super(message, "INVALID_DOCUMENT", null);
    }

    public InvalidDocumentError(String message, Throwable cause) {
        super(message, "INVALID_DOCUMENT", cause);
    }

    public InvalidDocumentError(String message, String code) {
        super(message, code, null);
    }

    @Override
    public String publicDetail() {
        return "the request body is not a readable Word (OOXML) document";
    }

    @Override
    public String outcome() {
        return "invalid_input";
    }
}
