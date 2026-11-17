package dev.filtsiap.ded.anonymizer.llm;

import java.util.regex.Pattern;

/**
 * A failed provider call, classified the way {@code llm/detector._call} distinguishes the
 * Python SDK's exceptions ({@code APITimeoutError}, {@code APIConnectionError},
 * {@code APIStatusError}, {@code OpenAIError}).
 *
 * <p>A {@link Kind#STATUS} failure also carries the provider's {@code retry-after-ms} response
 * header, parsed once here ({@link #parseRetryAfterMs}), for the detector's retry controller.
 */
public final class LlmCallException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** The response header naming how long, in milliseconds, the provider asks to be left alone. */
    public static final String RETRY_AFTER_MS_HEADER = "retry-after-ms";

    private static final Pattern DIGITS = Pattern.compile("[0-9]+");

    /** Failure classes, in Python's load-bearing check order. */
    public enum Kind { TIMEOUT, CONNECTION, STATUS, OTHER }

    private final Kind kind;
    private final int statusCode;
    private final Long retryAfterMs;

    public LlmCallException(Kind kind, int statusCode, Throwable cause) {
        this(kind, statusCode, null, cause);
    }

    private LlmCallException(Kind kind, int statusCode, Long retryAfterMs, Throwable cause) {
        super(kind + (kind == Kind.STATUS ? " " + statusCode : ""), cause);
        this.kind = kind;
        this.statusCode = statusCode;
        this.retryAfterMs = retryAfterMs;
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

    /**
     * An HTTP status failure with the delay its {@code retry-after-ms} header asked for: a valid
     * value from {@link #parseRetryAfterMs}, or null when the header was missing or unusable.
     */
    public static LlmCallException status(int statusCode, Long retryAfterMs, Throwable cause) {
        return new LlmCallException(Kind.STATUS, statusCode, retryAfterMs, cause);
    }

    public static LlmCallException other(Throwable cause) {
        return new LlmCallException(Kind.OTHER, 0, cause);
    }

    /**
     * A {@code retry-after-ms} header value as a delay: a non-negative integer number of
     * milliseconds, zero included. Null when the header is missing, malformed (not plain decimal
     * digits), negative, or too large for a {@code long}; the caller then uses its own backoff.
     * Surrounding whitespace is not part of a header value and is ignored.
     */
    public static Long parseRetryAfterMs(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.strip();
        if (!DIGITS.matcher(trimmed).matches()) {
            return null;
        }
        try {
            return Long.parseLong(trimmed);
        } catch (NumberFormatException overflow) {
            return null;
        }
    }

    public Kind kind() {
        return kind;
    }

    /** HTTP status for {@link Kind#STATUS}, else 0. */
    public int statusCode() {
        return statusCode;
    }

    /** The provider's valid {@code retry-after-ms} delay, or null when it gave none usable. */
    public Long retryAfterMs() {
        return retryAfterMs;
    }
}
