package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class MaskerTest {

    private static ChatSpan span(int start, int end, PiiType type) {
        return new ChatSpan(start, end, type, "test");
    }

    @Test
    void masksEveryNonWhitespaceCodePointInsideSpans() {
        String text = "με λένε Γιώργο Παπαδόπουλο";
        assertEquals(expect(text, "Γιώργο Παπαδόπουλο"), Masker.mask(text, List.of(span(8, 26, PiiType.PERSON))));
    }

    @Test
    void overlappingSpansAreAUnion() {
        String text = "abcdefgh";
        assertEquals("........", Masker.mask(text, List.of(span(0, 4, PiiType.PERSON), span(2, 6, PiiType.AFM),
                span(6, 8, PiiType.PHONE))));
        assertEquals("a...efgh", Masker.mask(text, List.of(span(1, 3, PiiType.PERSON), span(2, 4, PiiType.AFM))));
    }

    @Test
    void offsetsAreCodePointsSoEmojiDoNotShiftTheMask() {
        String text = "🙏 090000045";
        assertEquals("🙏 .........", Masker.mask(text, List.of(span(2, 11, PiiType.AFM))));
    }

    @Test
    void outputKeepsLineBreaksAndCodePointLength() {
        String text = "a\r\nb";
        String masked = Masker.mask(text, List.of(span(0, 4, PiiType.OTHER)));
        assertEquals(".\r\n.", masked);
        assertEquals(text.codePointCount(0, text.length()), masked.codePointCount(0, masked.length()));
    }

    @Test
    void spansPastTheEndAreClamped() {
        assertEquals("a..", Masker.mask("abc", List.of(span(1, 99, PiiType.OTHER))));
    }

    @Test
    void countsMergeOverlappingAndTouchingRegionsPerType() {
        Map<PiiType, Integer> counts = Masker.counts(List.of(span(0, 3, PiiType.PERSON), span(2, 5, PiiType.PERSON),
                span(5, 6, PiiType.PERSON), span(8, 9, PiiType.PERSON), span(0, 3, PiiType.AFM),
                span(4, 4, PiiType.PHONE)));
        assertEquals(Map.of(PiiType.PERSON, 2, PiiType.AFM, 1), counts);
        assertEquals("PERSON=2,AFM=1", Masker.countsHeader(counts));
    }

    @Test
    void noSpansGiveTheNoneHeader() {
        assertEquals("none", Masker.countsHeader(Masker.counts(List.of())));
    }

    @Test
    void aSpanMustBeAForwardRange() {
        assertThrows(IllegalArgumentException.class, () -> span(5, 4, PiiType.PERSON));
        assertThrows(IllegalArgumentException.class, () -> span(-1, 4, PiiType.PERSON));
    }
}
