package dev.filtsiap.ded.anonymizer.pycompat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Python {@code re} semantics (CLAUDE.md §5.1): a plain Java Pattern would under-match silently. */
class PyRegexTest {

    @Test
    void digitsAreUnicodeDecimal() {
        assertNotNull(PyRegex.compile("^\\d{3}$").search("٣٤٥"));
        assertNull(PyRegex.compile("^\\d$").search("²")); // isdigit but not Nd, as in Python
    }

    @Test
    void wordAndBoundaryCoverGreek() {
        assertEquals(List.of("Παπαδόπουλος", "ΑΦΜ"), PyRegex.compile("\\b\\w+\\b").findallStrings("Παπαδόπουλος, ΑΦΜ"));
    }

    @Test
    void whitespaceIncludesPythonSeparators() {
        assertTrue(PyRegex.compile("a\\sb").found("a\u001cb"));
        assertTrue(PyRegex.compile("a\\sb").found("a\u00a0b"));
    }

    @Test
    void offsetsAreCodePoints() {
        var m = PyRegex.compile("\\d+").search("😀😀123");
        assertEquals(2, m.start());
        assertEquals(5, m.end());
    }

    @Test
    void ignoreCaseIsUnicodeAware() {
        assertTrue(PyRegex.compile("οδός", PyRegex.IGNORECASE).found("ΟΔΌΣ"));
    }

    @Test
    void namedGroupsAndEndAnchorTranslate() {
        var m = PyRegex.compile("(?P<n>\\d+)\\Z").search("ab12");
        assertEquals("12", m.group(1));
        assertNull(PyRegex.compile("\\d\\Z").search("1\n"));
    }

    @Test
    void finditerOffsetsMatchCodePointCountsAroundSurrogates() {
        String text = "a😀b 😀😀 cd 😀";
        List<PyRegex.PyMatch> ms = PyRegex.compile("\\S+", 0).finditer(text);
        List<String> got = new ArrayList<>();
        for (PyRegex.PyMatch m : ms) {
            got.add(m.start() + "-" + m.end());
        }
        // code points: a 😀 b ␠ 😀 😀 ␠ c d ␠ 😀  → "a😀b"=0-3, "😀😀"=4-6, "cd"=7-9, "😀"=10-11
        assertEquals(List.of("0-3", "4-6", "7-9", "10-11"), got);
    }

    @Test
    void codePointIndexAgreesWithCodePointCountEverywhere() {
        String text = "x😀y😀😀z𝄞";
        PyRegex.CodePointIndex index = new PyRegex.CodePointIndex(text);
        for (int i = 0; i <= text.length(); i++) {
            assertEquals(text.codePointCount(0, i), index.toCodePoint(i), "utf16 index " + i);
        }
    }

    @Test
    void finditerIsLinearInTheNumberOfMatches() {
        String bmp = "λέξη ".repeat(100_000);
        String astral = "λέξη 😀 ".repeat(60_000);
        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> {
            assertEquals(100_000, PyRegex.compile("\\w+", 0).finditer(bmp).size());
            assertEquals(60_000, PyRegex.compile("λέξη", 0).finditer(astral).size());
        });
    }
}
