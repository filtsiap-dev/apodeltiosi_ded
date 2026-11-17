package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/** The committed lists load, hold what the detectors rely on, and fit the memory budget. */
class ChatListsRealConfigTest {
    static final ChatLists LISTS = ChatLists.load(Path.of("config", "chat"));

    @Test
    void theCommittedListsLoad() {
        assertTrue(LISTS.isName("γιωργοσ"));
        assertTrue(LISTS.isName("γιωργο"));
        assertTrue(LISTS.isName("μαρια"));
        assertTrue(LISTS.isName("μιχαλησ"));
        assertTrue(LISTS.isCommonWord("λογαριασμοσ"));
        assertTrue(LISTS.isCommonWord("bill"));
        assertTrue(LISTS.isCommonWord("δεη"));
        assertFalse(LISTS.isCommonWord("μπαλαμωτη"));
    }

    @Test
    void theListsStayUnderSixtyFourMegabytes() {
        // The JVM heap is shared with .docx processing (R-1); the lists are resident for the process's life.
        assertTrue(LISTS.footprintBytes() < 64L * 1024 * 1024, "footprint " + LISTS.footprintBytes());
    }
}
