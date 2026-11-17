package dev.filtsiap.ded.anonymizer.pycompat;

import java.lang.ref.WeakReference;
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

    /**
     * Index tables for one long string, so repeated {@link #slice} / {@link #toUtf16} calls on it
     * cost O(1) each instead of O(length). Strings are immutable, so an entry stays valid for as
     * long as the very same String object is passed in.
     */
    private static final class Index {
        private final WeakReference<String> text;
        private final int length;
        /** Code-point index to UTF-16 index (0..len); null when the text has no surrogates. */
        private final int[] utf16At;
        /** UTF-16 index to code-point count of the prefix (0..length); built on first use. */
        private int[] codePointsBefore;

        Index(String s) {
            text = new WeakReference<>(s);
            length = s.length();
            utf16At = isBmpOnly(s) ? null : buildUtf16At(s);
        }

        private static int[] buildUtf16At(String s) {
            int[] table = new int[s.codePointCount(0, s.length()) + 1];
            int cp = 0;
            for (int i = 0; i < s.length(); i += Character.charCount(s.codePointAt(i))) {
                table[cp++] = i;
            }
            table[cp] = s.length();
            return table;
        }

        int codePointLength() {
            return utf16At == null ? length : utf16At.length - 1;
        }

        int utf16Of(String s, int cpIndex) {
            if (utf16At == null) {
                return cpIndex;
            }
            return cpIndex >= 0 && cpIndex < utf16At.length ? utf16At[cpIndex] : s.offsetByCodePoints(0, cpIndex);
        }

        int codePointOf(String s, int utf16Index) {
            if (utf16At == null) {
                return utf16Index;
            }
            if (utf16Index < 0 || utf16Index > length) {
                return s.codePointCount(0, utf16Index);
            }
            if (codePointsBefore == null) {
                codePointsBefore = buildCodePointsBefore(s);
            }
            return codePointsBefore[utf16Index];
        }

        private static int[] buildCodePointsBefore(String s) {
            int[] table = new int[s.length() + 1];
            int cp = 0;
            int i = 0;
            while (i < s.length()) {
                int width = Character.charCount(s.codePointAt(i));
                table[i] = cp;
                for (int k = 1; k < width; k++) {
                    table[i + k] = cp + 1; // inside a pair: codePointCount counts the cut pair as one
                }
                i += width;
                cp++;
            }
            table[s.length()] = cp;
            return table;
        }
    }

    /** Strings shorter than this are scanned directly; building tables would not pay off. */
    private static final int INDEXED_MIN_LENGTH = 512;

    private static final ThreadLocal<Index> LAST_INDEX = new ThreadLocal<>();

    /** The index for {@code s}, rebuilt when {@code s} is not the previous long string; null if {@code s} is short. */
    private static Index indexOf(String s) {
        if (s.length() < INDEXED_MIN_LENGTH) {
            return null;
        }
        Index index = LAST_INDEX.get();
        if (index == null || index.text.get() != s) {
            index = new Index(s);
            LAST_INDEX.set(index);
        }
        return index;
    }

    /**
     * Python {@code len(s)}.
     *
     * @param s the text
     * @return the number of code points in {@code s}
     */
    public static int len(String s) {
        Index index = indexOf(s);
        return index == null ? s.codePointCount(0, s.length()) : index.codePointLength();
    }

    /**
     * Converts a code-point index (0..len) to a UTF-16 index.
     *
     * @param s the text
     * @param cpIndex the code-point index
     * @return the matching UTF-16 index
     * @throws IndexOutOfBoundsException if {@code s} has surrogates and {@code cpIndex} is outside 0..len
     */
    public static int toUtf16(String s, int cpIndex) {
        Index index = indexOf(s);
        if (index != null) {
            return index.utf16Of(s, cpIndex);
        }
        if (isBmpOnly(s)) {
            return cpIndex;
        }
        return s.offsetByCodePoints(0, cpIndex);
    }

    /**
     * Converts a UTF-16 index to a code-point index.
     *
     * @param s the text
     * @param utf16Index the UTF-16 index
     * @return the number of code points in {@code s} before {@code utf16Index}
     * @throws IndexOutOfBoundsException if {@code s} has surrogates and {@code utf16Index} is outside 0..length
     */
    public static int toCodePoint(String s, int utf16Index) {
        Index index = indexOf(s);
        if (index != null) {
            return index.codePointOf(s, utf16Index);
        }
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

    /**
     * Python {@code s[start:end]}, including negative indices and clamping.
     *
     * @param s the text
     * @param start the first code-point index, negative counting from the end
     * @param end the code-point index after the last one, negative counting from the end
     * @return the slice, empty when the range is empty
     */
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
