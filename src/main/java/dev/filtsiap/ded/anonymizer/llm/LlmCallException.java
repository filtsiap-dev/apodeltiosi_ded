package dev.filtsiap.ded.anonymizer.llm;

/**
 * A failed provider call, classified the way {@code llm/detector._call} distinguishes the
 * Python SDK's exceptions ({@code APITimeoutError}, {@code APIConnectionError},
 * {@code APIStatusError}, {@code OpenAIError}).
 */
public final class LlmCallException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** Failure classes, in Python's load-bearing check order. */
    public enum Kind { TIMEOUT, CONNECTION, STATUS, OTHER }

    private final Kind kind;
    private final int statusCode;

    public LlmCallException(Kind kind, int statusCode, Throwable cause) {
        super(kind + (kind == Kind.STATUS ? " " + statusCode : ""), cause);
        this.kind = kind;
        this.statusCode = statusCode;
    }

    public static LlmCallException timeout(Throwable cause) {
        return new LlmCallException(Kind.TIMEOUT, 0, cause);
    }

    public static LlmCallException connection(Throwable cause) {
        return new LlmCallException(Kind.CONNECTION, 0, cause);
    }

    public static LlmCallException status(int statusCode, Throwable cause) {
        return new LlmCallException(Kind.STATUS, statusCode, cause);
    }

    public static LlmCallException other(Throwable cause) {
        return new LlmCallException(Kind.OTHER, 0, cause);
    }

    public Kind kind() {
        return kind;
    }

    /** HTTP status for {@link Kind#STATUS}, else 0. */
    public int statusCode() {
        return statusCode;
    }
}
