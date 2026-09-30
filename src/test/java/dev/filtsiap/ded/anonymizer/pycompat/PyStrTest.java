package dev.filtsiap.ded.anonymizer.pycompat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
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
}
