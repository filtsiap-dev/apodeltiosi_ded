package dev.filtsiap.ded.anonymizer.chat;

/** The NER model could not answer (crash, timeout, sidecar down). The rules' result still goes out. */
public final class NerUnavailableException extends Exception {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what went wrong, without any input text
     * @param cause   the underlying failure
     */
    public NerUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
