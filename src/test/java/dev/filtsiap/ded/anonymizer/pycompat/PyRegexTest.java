package dev.filtsiap.ded.anonymizer.pycompat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
