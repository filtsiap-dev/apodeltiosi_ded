package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class GreekFoldTest {

    private static int cpLen(String s) {
        return s.codePointCount(0, s.length());
    }

    @Test
    void lowercasesStripsAccentsAndFinalSigma() {
        assertEquals("γιωργοσ παπαδοπουλοσ", GreekFold.fold("Γιώργος ΠΑΠΑΔΌΠΟΥΛΟΣ"));
        assertEquals("ιι υυ", GreekFold.fold("ΐΪ ΰΫ"));
        assertEquals("john", GreekFold.fold("John"));
    }

    @Test
    void keepsCodePointLengthWithEmojiAndMarks() {
        for (String s : new String[] {"🙏 ΑΦΜ 090000045", "ά́x", "Ελένη\r\nBot", ""}) {
            assertEquals(cpLen(s), cpLen(GreekFold.fold(s)), s);
        }
        assertEquals("🙏 αφμ 090000045", GreekFold.fold("🙏 ΑΦΜ 090000045"));
    }
}
