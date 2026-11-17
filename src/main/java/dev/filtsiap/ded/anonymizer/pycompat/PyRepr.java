package dev.filtsiap.ded.anonymizer.pycompat;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Map;

/**
 * Python {@code str()} and {@code repr()} for the value types that reach text output here:
 * {@code str(entry.get("text"))} on parsed LLM JSON, dict reprs in warnings and CLI lines
 * ({@code {'case_ref_leak': 1}}), and {@code {raw!r}} in error messages.
 */
public final class PyRepr {

    private PyRepr() {
    }

    /** Python {@code str(value)}. */
    public static String str(Object value) {
        if (value instanceof String s) {
            return s;
        }
        return repr(value);
    }

    /** Python {@code repr(value)}. */
    public static String repr(Object value) {
        if (value == null) {
            return "None";
        }
        if (value instanceof String s) {
            return reprString(s);
        }
        if (value instanceof Boolean b) {
            return b ? "True" : "False";
        }
        if (value instanceof Integer || value instanceof Long || value instanceof BigInteger
                || value instanceof Short || value instanceof Byte) {
            return value.toString();
        }
        if (value instanceof Double || value instanceof Float) {
            return PyFloat.repr(((Number) value).doubleValue());
        }
        if (value instanceof Map<?, ?> map) {
            StringBuilder out = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) {
                    out.append(", ");
                }
                first = false;
                out.append(repr(e.getKey())).append(": ").append(repr(e.getValue()));
            }
            return out.append('}').toString();
        }
        if (value instanceof Collection<?> list) {
            StringBuilder out = new StringBuilder("[");
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    out.append(", ");
                }
                first = false;
                out.append(repr(item));
            }
            return out.append(']').toString();
        }
        return value.toString();
    }

    /** CPython {@code unicode_repr}: quote choice and escapes. */
    public static String reprString(String s) {
        boolean hasSingle = s.indexOf('\'') >= 0;
        boolean hasDouble = s.indexOf('"') >= 0;
        char quote = (hasSingle && !hasDouble) ? '"' : '\'';
        StringBuilder out = new StringBuilder(s.length() + 2).append(quote);
        s.codePoints().forEach(cp -> {
            if (cp == quote || cp == '\\') {
                out.append('\\').appendCodePoint(cp);
            } else if (cp == '\t') {
                out.append("\\t");
            } else if (cp == '\n') {
                out.append("\\n");
            } else if (cp == '\r') {
                out.append("\\r");
            } else if (cp < 0x20 || cp == 0x7F) {
                out.append(String.format("\\x%02x", cp));
            } else if (cp < 0x7F) {
                out.appendCodePoint(cp);
            } else if (PyUnicode.isPrintable(cp)) {
                out.appendCodePoint(cp);
            } else if (cp <= 0xFF) {
                out.append(String.format("\\x%02x", cp));
            } else if (cp <= 0xFFFF) {
                out.append(String.format("\\u%04x", cp));
            } else {
                out.append(String.format("\\U%08x", cp));
            }
        });
        return out.append(quote).toString();
    }
}
