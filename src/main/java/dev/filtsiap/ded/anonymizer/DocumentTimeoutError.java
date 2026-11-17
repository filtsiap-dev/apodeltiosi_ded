package dev.filtsiap.ded.anonymizer;

/**
 * The document ran out of its end-to-end budget ({@link Deadline}). Distinct from
 * {@link AITimeoutError}, which is one provider call taking too long: this is the whole document,
 * whatever it was doing, and it means no output is produced.
 */
public class DocumentTimeoutError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    private final String stage;

    /** {@code stage} is a fixed name from this code, never anything derived from the document. */
    public DocumentTimeoutError(String stage) {
        super("the document deadline expired during " + stage, "DOCUMENT_TIMEOUT", null);
        this.stage = stage;
    }

    /** The stage that was starting when the budget ran out. */
    public String stage() {
        return stage;
    }

    @Override
    public String publicDetail() {
        return "processing exceeded the document deadline";
    }

    @Override
    public String outcome() {
        return "timeout";
    }
}
