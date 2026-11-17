package dev.filtsiap.ded.anonymizer;

/**
 * Base class for all anonymizer errors (port of {@code errors.py}).
 *
 * <p>Unchecked, like Python exceptions. Subclass simple names equal the Python class names
 * exactly: the HTTP API returns {@code {"error": "<ClassName>", "code": ..., "detail": ...}}.
 *
 * <p>Three things, for three readers. {@link #code()} is stable and greppable: what a caller
 * branches on. {@link #publicDetail()} is the only sentence a caller is shown: fixed per class,
 * never document-derived. The exception MESSAGE is for the operator and can quote a ZIP member
 * name or a parser error from the upload, so it never goes into a response body.
 */
public class AnonymizerError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;

    public AnonymizerError(String message) {
        this(message, "ANONYMIZER_ERROR", null);
    }

    public AnonymizerError(String message, Throwable cause) {
        this(message, "ANONYMIZER_ERROR", cause);
    }

    protected AnonymizerError(String message, String code, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    /** Stable identifier for this failure; one class may cover several distinguishable causes. */
    public String code() {
        return code;
    }

    /** Safe to return to a caller. Never contains document-derived text. */
    public String publicDetail() {
        return "the request could not be processed";
    }

    /** How this failure is named in a document's one final log line; coarser than {@link #code()}. */
    public String outcome() {
        return "internal_error";
    }
}
