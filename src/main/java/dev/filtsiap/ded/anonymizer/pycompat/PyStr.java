package dev.filtsiap.ded.anonymizer.pycompat;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Python {@code str} operations with Python semantics.
 *
 * <p>Every index in this class counts <b>code points</b>, as Python does; Java strings index
 * UTF-16 units. For BMP-only text (all ordinary Greek) the two coincide, and the fast paths
 * below skip any conversion.
 */
public final class PyStr {

    /** Orders strings by code point, like Python's {@code str} comparison ({@code String.compareTo} orders UTF-16 units). */
    public static final Comparator<String> CODE_POINT_ORDER = PyStr::compare;

    private PyStr() {
    }

    // ------------------------------------------------------------------ indexing

    private static boolean isBmpOnly(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isSurrogate(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /** Python {@code len(s)}. */
    public static int len(String s) {
        return s.codePointCount(0, s.length());
    }

    /** Converts a code-point index (0..len) to a UTF-16 index. */
    public static int toUtf16(String s, int cpIndex) {
        if (isBmpOnly(s)) {
            return cpIndex;
        }
        return s.offsetByCodePoints(0, cpIndex);
    }

    /** Converts a UTF-16 index to a code-point index. */
    public static int toCodePoint(String s, int utf16Index) {
        if (isBmpOnly(s)) {
            return utf16Index;
        }
        return s.codePointCount(0, utf16Index);
    }

    private static int clampSliceIndex(int index, int length) {
        if (index < 0) {
            index += length;
            return Math.max(index, 0);
        }
        return Math.min(index, length);
    }

    /** Python {@code s[start:end]}, including negative indices and clamping. */
    public static String slice(String s, int start, int end) {
        int n = len(s);
        int a = clampSliceIndex(start, n);
        int b = clampSliceIndex(end, n);
        if (a >= b) {
            return "";
        }
        return s.substring(toUtf16(s, a), toUtf16(s, b));
    }

    /** Python {@code s[start:]}. */
    public static String sliceFrom(String s, int start) {
        return slice(s, start, Integer.MAX_VALUE);
    }

    /** Python {@code s[i]} as a one-code-point string (non-negative {@code i} only). */
    public static String charAt(String s, int i) {
        int u = toUtf16(s, i);
        return new String(Character.toChars(s.codePointAt(u)));
    }

    /** Code point at code-point index {@code i}. */
    public static int codePointAt(String s, int i) {
        return s.codePointAt(toUtf16(s, i));
    }

    /** Python {@code s.find(sub, start)}. */
    public static int find(String s, String sub, int start) {
        int n = len(s);
        int from = clampSliceIndex(start, n);
        if (start > n) {
            return -1;
        }
        int idx = s.indexOf(sub, toUtf16(s, from));
        return idx < 0 ? -1 : toCodePoint(s, idx);
    }

    /** Python {@code s.find(sub)}. */
    public static int find(String s, String sub) {
        return find(s, sub, 0);
    }

    /** Python {@code s.rfind(sub, start, end)}. */
    public static int rfind(String s, String sub, int start, int end) {
        int n = len(s);
        int a = clampSliceIndex(start, n);
        int b = clampSliceIndex(end, n);
        String window = a < b ? s.substring(toUtf16(s, a), toUtf16(s, b)) : "";
        if (a > b && !sub.isEmpty()) {
            return -1;
        }
        int idx = window.lastIndexOf(sub);
        return idx < 0 ? -1 : a + toCodePoint(window, idx);
    }

    /** Python {@code sub in s}. */
    public static boolean contains(String s, String sub) {
        return s.contains(sub);
    }

    // ------------------------------------------------------------------ comparison

    /** Python {@code a < b} ordering: by code point. */
    public static int compare(String a, String b) {
        int i = 0;
        int j = 0;
        while (i < a.length() && j < b.length()) {
            int ca = a.codePointAt(i);
            int cb = b.codePointAt(j);
            if (ca != cb) {
                return Integer.compare(ca, cb);
            }
            i += Character.charCount(ca);
            j += Character.charCount(cb);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    // ------------------------------------------------------------------ whitespace

    /** Python {@code s.strip()}: strips every {@code isspace()} code point, NBSP included. */
    public static String strip(String s) {
        return rstrip(lstrip(s));
    }

    /** Python {@code s.lstrip()}. */
    public static String lstrip(String s) {
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            if (!PyUnicode.isSpace(cp)) {
                break;
            }
            i += Character.charCount(cp);
        }
        return s.substring(i);
    }

    /** Python {@code s.rstrip()}. */
    public static String rstrip(String s) {
        int end = s.length();
        while (end > 0) {
            int cp = s.codePointBefore(end);
            if (!PyUnicode.isSpace(cp)) {
                break;
            }
            end -= Character.charCount(cp);
        }
        return s.substring(0, end);
    }

    /** Python {@code s.strip(chars)}. */
    public static String strip(String s, String chars) {
        int start = 0;
        int end = s.length();
        while (start < end && chars.indexOf(s.codePointAt(start)) >= 0) {
            start += Character.charCount(s.codePointAt(start));
        }
        while (end > start && chars.indexOf(s.codePointBefore(end)) >= 0) {
            end -= Character.charCount(s.codePointBefore(end));
        }
        return s.substring(start, end);
    }

    /** Python {@code s.split()} with no argument: splits on runs of whitespace, drops empties. */
    public static List<String> split(String s) {
        List<String> parts = new ArrayList<>();
        int i = 0;
        int n = s.length();
        while (i < n) {
            while (i < n && PyUnicode.isSpace(s.codePointAt(i))) {
                i += Character.charCount(s.codePointAt(i));
            }
            if (i >= n) {
                break;
            }
            int start = i;
            while (i < n && !PyUnicode.isSpace(s.codePointAt(i))) {
                i += Character.charCount(s.codePointAt(i));
            }
            parts.add(s.substring(start, i));
        }
        return parts;
    }

    /** Python {@code " ".join(s.split())}. */
    public static String collapseWhitespace(String s) {
        return String.join(" ", split(s));
    }

    /** Python {@code s.splitlines()} (no keepends). */
    public static List<String> splitlines(String s) {
        List<String> lines = new ArrayList<>();
        int i = 0;
        int start = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            int eol = switch (c) {
                case '\n', '\u000B', '\u000C', '\u001C', '\u001D', '\u001E', '\u0085', '\u2028', '\u2029' -> 1;
                case '\r' -> (i + 1 < n && s.charAt(i + 1) == '\n') ? 2 : 1;
                default -> 0;
            };
            if (eol > 0) {
                lines.add(s.substring(start, i));
                i += eol;
                start = i;
            } else {
                i++;
            }
        }
        if (start < n) {
            lines.add(s.substring(start));
        }
        return lines;
    }

    /** Python {@code s.rsplit(sep, 1)[-1]}: the text after the last {@code sep}, or all of {@code s}. */
    public static String afterLast(String s, String sep) {
        int idx = s.lastIndexOf(sep);
        return idx < 0 ? s : s.substring(idx + sep.length());
    }

    // ------------------------------------------------------------------ case

    /** Python {@code s.casefold()}. */
    public static String casefold(String s) {
        return PyUnicode.casefold(s);
    }

    /** Python {@code s.upper()} (full case mapping, locale-independent). */
    public static String upper(String s) {
        return s.toUpperCase(Locale.ROOT);
    }

    /**
     * Python {@code s.lower()}: full lowercase mapping per code point, with CPython's
     * Final_Sigma rule (Java's rule treats case-ignorable characters differently).
     */
    public static String lower(String s) {
        int[] cps = s.codePoints().toArray();
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < cps.length; i++) {
            int cp = cps[i];
            if (cp == 0x03A3) {
                out.append(isFinalSigma(cps, i) ? '\u03C2' : '\u03C3');
            } else {
                out.append(new String(Character.toChars(cp)).toLowerCase(Locale.ROOT));
            }
        }
        return out.toString();
    }

    private static boolean isFinalSigma(int[] cps, int i) {
        int j = i - 1;
        while (j >= 0 && isCaseIgnorable(cps[j])) {
            j--;
        }
        if (j < 0 || !isCased(cps[j])) {
            return false;
        }
        int k = i + 1;
        while (k < cps.length && isCaseIgnorable(cps[k])) {
            k++;
        }
        return k >= cps.length || !isCased(cps[k]);
    }

    private static boolean isCased(int cp) {
        return Character.isUpperCase(cp) || Character.isLowerCase(cp) || Character.isTitleCase(cp);
    }

    private static boolean isCaseIgnorable(int cp) {
        switch (Character.getType(cp)) {
            case Character.NON_SPACING_MARK, Character.ENCLOSING_MARK, Character.FORMAT,
                    Character.MODIFIER_LETTER, Character.MODIFIER_SYMBOL -> {
                return true;
            }
            default -> {
                // Word_Break = MidLetter, MidNumLet or Single_Quote.
                return switch (cp) {
                    case 0x27, 0x2E, 0x3A, 0xB7, 0x387, 0x55F, 0x5F4, 0x2018, 0x2019, 0x2024, 0x2027,
                            0xFE13, 0xFE52, 0xFE55, 0xFF07, 0xFF0E, 0xFF1A -> true;
                    default -> false;
                };
            }
        }
    }

    // ------------------------------------------------------------------ predicates

    /** Python {@code s.isdigit()}: non-empty and every code point is a digit. */
    public static boolean isDigit(String s) {
        return !s.isEmpty() && s.codePoints().allMatch(PyUnicode::isDigit);
    }

    /** True when some code point of {@code s} satisfies Python {@code isdigit()}. */
    public static boolean anyDigit(String s) {
        return s.codePoints().anyMatch(PyUnicode::isDigit);
    }

    /** Python {@code s.isalnum()} for a one-code-point string (empty is false). */
    public static boolean isAlnum(String s) {
        return !s.isEmpty() && s.codePoints().allMatch(PyUnicode::isAlnum);
    }

    /**
     * Python {@code int(s)} for a digit string produced by {@code isdigit()} checks: Unicode
     * decimal digits are accepted. Throws {@link NumberFormatException} otherwise.
     */
    public static int digitValue(int cp) {
        if (!PyUnicode.isDecimal(cp)) {
            throw new NumberFormatException("invalid literal for int(): " + new String(Character.toChars(cp)));
        }
        return Character.digit(cp, 10);
    }

    /** Python {@code int(s)} for a short decimal string ({@code isdigit} strings of Nd characters). */
    public static int parseDecimal(String s) {
        int value = 0;
        for (int cp : s.codePoints().toArray()) {
            value = value * 10 + digitValue(cp);
        }
        return value;
    }
}
