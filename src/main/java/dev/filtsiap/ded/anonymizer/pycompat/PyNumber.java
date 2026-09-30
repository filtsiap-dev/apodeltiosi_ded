package dev.filtsiap.ded.anonymizer.pycompat;

import java.math.BigInteger;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/** Python {@code int(str)} and {@code float(str)} parsing. Empty result where Python raises ValueError. */
public final class PyNumber {

    private static final Pattern FLOAT_LITERAL =
            Pattern.compile("[+-]?(?:\\d+(?:\\.\\d*)?|\\.\\d+)(?:[eE][+-]?\\d+)?");

    private PyNumber() {
    }

    /** Converts Unicode decimal digits to ASCII and validates Python's underscore rule. */
    private static Optional<String> normalizeDigits(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int prev = -1;
        int[] cps = s.codePoints().toArray();
        for (int i = 0; i < cps.length; i++) {
            int cp = cps[i];
            if (cp == '_') {
                boolean digitBefore = prev >= 0 && PyUnicode.isDecimal(prev);
                boolean digitAfter = i + 1 < cps.length && PyUnicode.isDecimal(cps[i + 1]);
                if (!digitBefore || !digitAfter) {
                    return Optional.empty();
                }
            } else if (PyUnicode.isDecimal(cp)) {
                out.append((char) ('0' + Character.digit(cp, 10)));
            } else {
                out.appendCodePoint(cp);
            }
            prev = cp;
        }
        return Optional.of(out.toString());
    }

    /** Python {@code int(s)}: surrounding whitespace, sign, Unicode digits, single underscores. */
    public static Optional<BigInteger> parseInt(String raw) {
        Optional<String> norm = normalizeDigits(PyStr.strip(raw));
        if (norm.isEmpty() || !norm.get().matches("[+-]?[0-9]+")) {
            return Optional.empty();
        }
        return Optional.of(new BigInteger(norm.get()));
    }

    /** Python {@code float(s)}, including {@code inf}/{@code infinity}/{@code nan} in any case. */
    public static Optional<Double> parseFloat(String raw) {
        String stripped = PyStr.strip(raw);
        String lower = stripped.toLowerCase(Locale.ROOT);
        String unsigned = lower.startsWith("+") || lower.startsWith("-") ? lower.substring(1) : lower;
        double sign = lower.startsWith("-") ? -1.0 : 1.0;
        if (unsigned.equals("inf") || unsigned.equals("infinity")) {
            return Optional.of(sign * Double.POSITIVE_INFINITY);
        }
        if (unsigned.equals("nan")) {
            return Optional.of(Double.NaN);
        }
        Optional<String> norm = normalizeDigits(stripped);
        if (norm.isEmpty() || !FLOAT_LITERAL.matcher(norm.get()).matches()) {
            return Optional.empty();
        }
        return Optional.of(Double.parseDouble(norm.get()));
    }

    /** Python {@code float(value)} for a YAML scalar; empty where Python raises. */
    public static Optional<Double> toFloat(Object value) {
        if (value instanceof Boolean b) {
            return Optional.of(b ? 1.0 : 0.0);
        }
        if (value instanceof Number n) {
            return Optional.of(n.doubleValue());
        }
        if (value instanceof String s) {
            return parseFloat(s);
        }
        return Optional.empty();
    }
}
