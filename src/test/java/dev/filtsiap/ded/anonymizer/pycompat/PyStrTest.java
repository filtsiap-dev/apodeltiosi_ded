package dev.filtsiap.ded.anonymizer.pycompat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Python string semantics the port depends on (CLAUDE.md §5.2, §5.3). */
class PyStrTest {

    @Test
    void casefoldFoldsFinalSigma() {
        assertEquals("οδοσ", PyStr.casefold("ΟΔΟΣ"));
        assertEquals("οδοσ", PyStr.casefold("οδος"));
        assertEquals("strasse", PyStr.casefold("Straße"));
    }

    @Test
    void lowerUsesPythonFinalSigmaRule() {
        assertEquals("οδός", PyStr.lower("ΟΔΌΣ"));
        assertEquals("σ", PyStr.lower("Σ"));
        // Case-ignorable characters between letters do not end the word (CPython rule).
        assertEquals("aς:\u200b", PyStr.lower("AΣ:\u200b"));
    }

    @Test
    void stripRemovesNbspAndUnicodeSpace() {
        assertEquals("ΑΦΜ", PyStr.strip("\u00a0 ΑΦΜ\u2003\n"));
        assertEquals("x", PyStr.strip("--x--", "-"));
    }

    @Test
    void splitDropsEmptiesOnAnyWhitespaceRun() {
        assertEquals(List.of("α", "β", "γ"), PyStr.split(" α\u00a0β \t\nγ "));
        assertEquals("α β γ", PyStr.collapseWhitespace(" α\u00a0β \t\nγ "));
    }

    @Test
    void indexesAreCodePoints() {
        String s = "a😀b";
        assertEquals(3, PyStr.len(s));
        assertEquals("b", PyStr.slice(s, 2, 3));
        assertEquals(2, PyStr.find(s, "b", 0));
        assertEquals("😀", PyStr.charAt(s, 1));
    }

    @Test
    void codePointOrderMatchesPythonStringOrder() {
        assertTrue(PyStr.CODE_POINT_ORDER.compare("u10", "u2") < 0);
        // UTF-16 order would put U+FFFD after an astral character; code point order does not.
        assertTrue(PyStr.CODE_POINT_ORDER.compare("\uFFFD", "😀") < 0);
    }

    @Test
    void digitPredicatesFollowPython() {
        assertTrue(PyStr.isDigit("١٢٣"));
        assertTrue(PyStr.isDigit("²"));
        assertFalse(PyStr.isDigit("½"));
        assertTrue(PyStr.isAlnum("ά"));
    }

    // ------------------------------------------------------------------ slice equivalence and cost

    private static final String PAIR = "😀";
    private static final String HIGH_ALONE = "\uD83D";
    private static final String LOW_ALONE = "\uDE00";

    // The original implementation, kept verbatim as the oracle for the cached one.
    private static boolean oracleIsBmpOnly(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isSurrogate(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static int oracleLen(String s) {
        return s.codePointCount(0, s.length());
    }

    private static int oracleToUtf16(String s, int cpIndex) {
        return oracleIsBmpOnly(s) ? cpIndex : s.offsetByCodePoints(0, cpIndex);
    }

    private static int oracleToCodePoint(String s, int utf16Index) {
        return oracleIsBmpOnly(s) ? utf16Index : s.codePointCount(0, utf16Index);
    }

    private static int oracleClamp(int index, int length) {
        if (index < 0) {
            return Math.max(index + length, 0);
        }
        return Math.min(index, length);
    }

    private static String oracleSlice(String s, int start, int end) {
        int n = oracleLen(s);
        int a = oracleClamp(start, n);
        int b = oracleClamp(end, n);
        if (a >= b) {
            return "";
        }
        return s.substring(oracleToUtf16(s, a), oracleToUtf16(s, b));
    }

    private static String repeat(String unit, int times) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) {
            sb.append(unit);
        }
        return sb.toString();
    }

    /** Short strings (below any cache threshold) and long ones: BMP, astral, with lone surrogates. */
    private static List<String> sampleStrings() {
        List<String> samples = new ArrayList<>(List.of(
                "", "a", "abc", "a" + PAIR + "b", PAIR, PAIR + PAIR, HIGH_ALONE, LOW_ALONE,
                "x" + HIGH_ALONE + "y", "x" + LOW_ALONE + "y", LOW_ALONE + HIGH_ALONE,
                HIGH_ALONE + HIGH_ALONE + LOW_ALONE, "ab" + HIGH_ALONE, LOW_ALONE + "ab",
                "Καλημέρα " + PAIR + " κόσμε"));
        samples.add(repeat("Καλημέρα κόσμε ", 5000));
        samples.add(repeat("ab" + PAIR + "γ", 5000));
        samples.add(repeat("a" + HIGH_ALONE + "b" + LOW_ALONE + PAIR + LOW_ALONE + HIGH_ALONE, 3000));
        samples.add(repeat("abc" + PAIR, 1000) + HIGH_ALONE);
        samples.add(LOW_ALONE + repeat("abc" + PAIR, 1000));
        return samples;
    }

    private static List<Integer> interestingIndexes(int n) {
        List<Integer> values = new ArrayList<>();
        if (n <= 12) {
            for (int i = -n - 3; i <= n + 3; i++) {
                values.add(i);
            }
        } else {
            Random random = new Random(n);
            int[] fixed = {Integer.MIN_VALUE, -n - 7, -n, -n + 1, -n / 2, -3, -2, -1, 0, 1, 2, 3, n / 3, n / 2,
                n - 3, n - 2, n - 1, n, n + 1, n + 9, Integer.MAX_VALUE};
            for (int v : fixed) {
                values.add(v);
            }
            for (int i = 0; i < 15; i++) {
                values.add(random.nextInt(2 * n + 1) - n);
            }
        }
        return values;
    }

    @Test
    void sliceMatchesTheOriginalImplementationForEveryIndexPair() {
        for (String s : sampleStrings()) {
            List<Integer> indexes = interestingIndexes(oracleLen(s));
            for (int start : indexes) {
                for (int end : indexes) {
                    assertEquals(oracleSlice(s, start, end), PyStr.slice(s, start, end),
                            "len=" + s.length() + " start=" + start + " end=" + end);
                }
            }
        }
    }

    @Test
    void lenAndIndexConversionsMatchTheOriginalImplementation() {
        for (String s : sampleStrings()) {
            assertEquals(oracleLen(s), PyStr.len(s));
            int stride = Math.max(1, s.length() / 400);
            for (int u = 0; u <= s.length(); u += stride) {
                assertEquals(oracleToCodePoint(s, u), PyStr.toCodePoint(s, u), "utf16 index " + u);
            }
            assertEquals(oracleToCodePoint(s, s.length()), PyStr.toCodePoint(s, s.length()));
            for (int cp = 0; cp <= oracleLen(s); cp += stride) {
                assertEquals(oracleToUtf16(s, cp), PyStr.toUtf16(s, cp), "cp index " + cp);
            }
            assertEquals(oracleToUtf16(s, oracleLen(s)), PyStr.toUtf16(s, oracleLen(s)));
        }
    }

    @Test
    void everyUtf16PositionOfAStringWithPairsAndLoneSurrogatesConverts() {
        String s = repeat("a" + HIGH_ALONE + PAIR + LOW_ALONE + "b", 600);
        for (int u = 0; u <= s.length(); u++) {
            assertEquals(oracleToCodePoint(s, u), PyStr.toCodePoint(s, u), "utf16 index " + u);
        }
        for (int cp = 0; cp <= oracleLen(s); cp++) {
            assertEquals(oracleToUtf16(s, cp), PyStr.toUtf16(s, cp), "cp index " + cp);
        }
    }

    @Test
    void outOfRangeConversionsStillThrowOnTextWithSurrogates() {
        String s = repeat("ab" + PAIR, 600);
        int n = oracleLen(s);
        assertThrows(IndexOutOfBoundsException.class, () -> PyStr.toUtf16(s, n + 1));
        assertThrows(IndexOutOfBoundsException.class, () -> PyStr.toUtf16(s, -1));
        assertThrows(IndexOutOfBoundsException.class, () -> PyStr.toCodePoint(s, s.length() + 1));
        assertThrows(IndexOutOfBoundsException.class, () -> PyStr.toCodePoint(s, -1));
    }

    @Test
    void alternatingBetweenStringsAndEqualCopiesStaysCorrect() {
        String a = repeat("ab" + PAIR, 1000);
        String b = repeat("xyz", 1000);
        String aCopy = new String(a.toCharArray());
        for (int i = 0; i < 50; i++) {
            assertEquals(oracleSlice(a, i, i + 40), PyStr.slice(a, i, i + 40));
            assertEquals(oracleSlice(b, i, i + 40), PyStr.slice(b, i, i + 40));
            assertEquals(oracleSlice(aCopy, -i - 5, -i), PyStr.slice(aCopy, -i - 5, -i));
        }
    }

    @Test
    void manySlicesOfOneLongBmpStringAreLinear() {
        String s = repeat("Καλημέρα κόσμε ", 30_000).substring(0, 400_000);
        assertManySlicesAreFast(s);
    }

    @Test
    void manySlicesOfOneLongStringWithAstralCharactersAreLinear() {
        String s = repeat("Καλημέρα " + PAIR + " κόσμε ", 30_000).substring(0, 400_000);
        assertManySlicesAreFast(s);
    }

    private static void assertManySlicesAreFast(String s) {
        int n = PyStr.len(s);
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
            long total = 0;
            for (int i = 0; i < 100_000; i++) {
                int start = (int) ((long) i * 3 % (n - 10));
                total += PyStr.slice(s, start, start + 8).length();
            }
            assertTrue(total > 0);
        });
    }
}
