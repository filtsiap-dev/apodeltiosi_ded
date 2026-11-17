package dev.filtsiap.ded.anonymizer;

/**
 * An unexpected failure inside one document's handling, wrapped so it leaves by the typed path:
 * the caller gets the same fixed body, and the failure is logged once, as frames and ids, by
 * whoever wrapped it. Its message is fixed and the cause is kept only for the frames.
 *
 * <p>Named as v2's class because the name is on the wire ({@code "error": "InternalError"}). It
 * shadows {@code java.lang.InternalError} (a JVM error) in this package and wherever it is imported.
 */
public class InternalError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public InternalError(Throwable cause) {
        super("unexpected failure", "INTERNAL_ERROR", cause);
    }

    @Override
    public String publicDetail() {
        return "internal error";
    }

    @Override
    public String outcome() {
        return "internal_error";
    }
}
