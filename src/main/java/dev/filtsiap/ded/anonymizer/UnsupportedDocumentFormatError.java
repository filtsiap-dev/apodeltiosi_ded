package dev.filtsiap.ded.anonymizer;

/**
 * A real document, in a format this service does not accept (port of
 * {@code UnsupportedDocumentFormatError}). Distinct from {@link InvalidDocumentError} because the
 * caller's remedy differs: nothing is wrong with the file, it has to arrive as a .docx.
 *
 * <p>v2 also accepts .docm, .dotx and .dotm, which its pipeline normalizes to a plain .docx
 * before parsing. This pipeline has no normalization stage, so it accepts .docx only and its
 * public detail says so.
 */
public class UnsupportedDocumentFormatError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public UnsupportedDocumentFormatError(String message) {
        super(message, "UNSUPPORTED_DOCUMENT_FORMAT", null);
    }

    public UnsupportedDocumentFormatError(String message, String code) {
        super(message, code, null);
    }

    @Override
    public String publicDetail() {
        return "unsupported document format; send a .docx file";
    }

    @Override
    public String outcome() {
        return "unsupported_format";
    }
}
