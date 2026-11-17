package dev.filtsiap.ded.anonymizer.pycompat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CPython {@code str} character predicates and case folding, code point by code point.
 *
 * <p>Java's {@code Character} methods disagree with Python in places that matter here:
 * {@code isWhitespace} excludes NBSP, {@code isDigit} excludes superscripts, and there is no
 * {@code casefold}. The case-folding and "digit but not decimal" data are generated from
 * CPython's {@code unicodedata} (resource {@code pyunicode.txt}); the rest follows the exact
 * category rules CPython uses. JDK 21 and CPython 3.12 both implement Unicode 15.0.
 */
public final class PyUnicode {

    private static final Map<Integer, String> CASEFOLD = new HashMap<>();
    private static final int[] DIGIT_EXTRA_RANGES;

    static {
        List<int[]> digitRanges = new ArrayList<>();
        try (InputStream in = PyUnicode.class.getResourceAsStream("/pyunicode.txt")) {
            if (in == null) {
                throw new IllegalStateException("resource pyunicode.txt missing from the classpath");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String section = "";
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }
                String[] fields = line.split(" ");
                switch (section) {
                    case "[casefold]" -> {
                        StringBuilder folded = new StringBuilder();
                        for (int i = 1; i < fields.length; i++) {
                            folded.appendCodePoint(Integer.parseInt(fields[i], 16));
                        }
                        CASEFOLD.put(Integer.parseInt(fields[0], 16), folded.toString());
                    }
                    case "[digit_extra]" -> digitRanges.add(
                            new int[] {Integer.parseInt(fields[0], 16), Integer.parseInt(fields[1], 16)});
                    default -> throw new IllegalStateException("unknown section in pyunicode.txt: " + section);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        DIGIT_EXTRA_RANGES = new int[digitRanges.size() * 2];
        for (int i = 0; i < digitRanges.size(); i++) {
            DIGIT_EXTRA_RANGES[2 * i] = digitRanges.get(i)[0];
            DIGIT_EXTRA_RANGES[2 * i + 1] = digitRanges.get(i)[1];
        }
    }

    private PyUnicode() {
    }

    /** Python {@code str.isspace()} for one code point. */
    public static boolean isSpace(int cp) {
        return switch (cp) {
            case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x85, 0xA0, 0x1680,
                    0x2028, 0x2029, 0x202F, 0x205F, 0x3000 -> true;
            default -> cp >= 0x2000 && cp <= 0x200A;
        };
    }

    /** Regex character-class body (no brackets) matching exactly the {@link #isSpace} set. */
    public static final String SPACE_CLASS_BODY =
            "\\t\\n\\x0B\\f\\r\\x1C-\\x1F \\x85\\xA0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000";

    /** Python {@code str.isalpha()}: general category L*. */
    public static boolean isAlpha(int cp) {
        return switch (Character.getType(cp)) {
            case Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
                    Character.MODIFIER_LETTER, Character.OTHER_LETTER -> true;
            default -> false;
        };
    }

    /** Python {@code str.isdecimal()}: general category Nd. */
    public static boolean isDecimal(int cp) {
        return Character.getType(cp) == Character.DECIMAL_DIGIT_NUMBER;
    }

    /** Python {@code str.isdigit()}: Nd plus Numeric_Type=Digit code points such as superscripts. */
    public static boolean isDigit(int cp) {
        if (isDecimal(cp)) {
            return true;
        }
        for (int i = 0; i < DIGIT_EXTRA_RANGES.length; i += 2) {
            if (cp >= DIGIT_EXTRA_RANGES[i] && cp <= DIGIT_EXTRA_RANGES[i + 1]) {
                return true;
            }
        }
        return false;
    }

    /** Python {@code str.isalnum()}: general category L* or N* (verified identical for Unicode 15.0). */
    public static boolean isAlnum(int cp) {
        if (isAlpha(cp)) {
            return true;
        }
        int type = Character.getType(cp);
        return type == Character.DECIMAL_DIGIT_NUMBER || type == Character.LETTER_NUMBER
                || type == Character.OTHER_NUMBER;
    }

    /** Python {@code str.isprintable()} for one code point. */
    public static boolean isPrintable(int cp) {
        if (cp == ' ') {
            return true;
        }
        return switch (Character.getType(cp)) {
            case Character.CONTROL, Character.FORMAT, Character.SURROGATE, Character.PRIVATE_USE,
                    Character.UNASSIGNED, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
                    Character.SPACE_SEPARATOR -> false;
            default -> true;
        };
    }

    /** Python {@code str.casefold()}: full Unicode case folding, per code point. */
    public static String casefold(String s) {
        StringBuilder out = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> {
            String folded = CASEFOLD.get(cp);
            if (folded != null) {
                out.append(folded);
            } else {
                out.appendCodePoint(cp);
            }
        });
        return out.toString();
    }
}
