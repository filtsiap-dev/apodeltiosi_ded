package dev.filtsiap.ded.anonymizer.pycompat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Map;

/**
 * Python {@code json} module equivalents.
 *
 * <p>{@link #dumps} reproduces CPython's output byte for byte (it is used for prompt text,
 * whose exact bytes the LLM sees, and for API/CLI output). {@link #loads} parses into plain
 * Java values mirroring Python's: {@code Map} (insertion-ordered), {@code List}, {@code String},
 * {@code Integer}/{@code Long}/{@code BigInteger}, {@code Double}, {@code Boolean}, {@code null}.
 */
public final class PyJson {

    /** Python's default separators {@code (", ", ": ")}. */
    public static final String[] DEFAULT_SEPARATORS = {", ", ": "};
    /** Compact separators {@code (",", ":")}, as Starlette's {@code JSONResponse} uses. */
    public static final String[] COMPACT_SEPARATORS = {",", ":"};

    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .enable(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private PyJson() {
    }

    /** Raised where Python raises {@code json.JSONDecodeError}. */
    public static final class JsonDecodeError extends Exception {
        private static final long serialVersionUID = 1L;

        JsonDecodeError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Python {@code json.loads(raw)}. */
    public static Object loads(String raw) throws JsonDecodeError {
        try {
            return MAPPER.readValue(raw, Object.class);
        } catch (JsonProcessingException e) {
            throw new JsonDecodeError("invalid JSON", e);
        }
    }

    /** Python {@code json.dumps(value, ensure_ascii=False)}. */
    public static String dumps(Object value) {
        return dumps(value, DEFAULT_SEPARATORS, true);
    }

    /** Python {@code json.dumps(value, ensure_ascii=False, separators=seps, allow_nan=allowNan)}. */
    public static String dumps(Object value, String[] separators, boolean allowNan) {
        StringBuilder out = new StringBuilder();
        write(out, value, separators, allowNan);
        return out.toString();
    }

    private static void write(StringBuilder out, Object value, String[] seps, boolean allowNan) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            writeString(out, s);
        } else if (value instanceof Boolean b) {
            out.append(b ? "true" : "false");
        } else if (value instanceof Integer || value instanceof Long || value instanceof BigInteger
                || value instanceof Short || value instanceof Byte) {
            out.append(value);
        } else if (value instanceof Double || value instanceof Float || value instanceof BigDecimal) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                if (!allowNan) {
                    throw new IllegalArgumentException("Out of range float values are not JSON compliant");
                }
                out.append(Double.isNaN(d) ? "NaN" : (d > 0 ? "Infinity" : "-Infinity"));
            } else {
                out.append(PyFloat.repr(d));
            }
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) {
                    out.append(seps[0]);
                }
                first = false;
                writeString(out, String.valueOf(e.getKey()));
                out.append(seps[1]);
                write(out, e.getValue(), seps, allowNan);
            }
            out.append('}');
        } else if (value instanceof Collection<?> list) {
            out.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    out.append(seps[0]);
                }
                first = false;
                write(out, item, seps, allowNan);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("Object of type " + value.getClass().getSimpleName()
                    + " is not JSON serializable");
        }
    }

    /** CPython {@code py_encode_basestring}: escapes only {@code " \ } and C0 controls. */
    private static void writeString(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
