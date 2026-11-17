package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.filtsiap.ded.anonymizer.ConfigurationError;

class ChatListsTest {

    @TempDir
    Path dir;

    @Test
    void namesAndCommonWordsAreSeparateQuestions() {
        ChatLists lists = ChatFixtures.LISTS;
        assertTrue(lists.isName("γιωργο"));
        assertFalse(lists.isCommonWord("γιωργο"));
        assertTrue(lists.isName("νικη"));
        assertTrue(lists.isCommonWord("νικη"));   // a name that is also a word: needs a cue
        assertTrue(lists.isCommonWord("bill"));
        assertTrue(lists.isCommonWord("δεη"));    // allowlisted
        assertTrue(lists.greekProper().contains("αμερικησ"));
    }

    @Test
    void loadReadsEveryFile() throws Exception {
        writeAll(dir);
        ChatLists lists = ChatLists.load(dir);
        assertTrue(lists.isName("γιωργοσ"));
        assertTrue(lists.isCommonWord("πλακα"));
        assertTrue(lists.isCommonWord("viber"));
    }

    @Test
    void aMissingFileStopsStartup() throws Exception {
        writeAll(dir);
        Files.delete(dir.resolve("el_common.txt.gz"));
        ConfigurationError e = assertThrows(ConfigurationError.class, () -> ChatLists.load(dir));
        assertTrue(e.getMessage().contains("el_common.txt.gz"));
    }

    static void writeAll(Path dir) throws Exception {
        Files.writeString(dir.resolve("given_names.txt"), "γιωργο\nγιωργοσ\n", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("surnames.txt"), "παπαδοπουλοσ\n", StandardCharsets.UTF_8);
        gz(dir.resolve("el_common.txt.gz"), "πλακα\n");
        gz(dir.resolve("el_proper.txt.gz"), "αθηνα\n");
        gz(dir.resolve("en_common.txt.gz"), "bill\n");
        Files.writeString(dir.resolve("slang.txt"), "κλπ\n", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("domain_allowlist.txt"), "Viber\n", StandardCharsets.UTF_8);
    }

    static void gz(Path path, String content) throws Exception {
        try (var out = new java.util.zip.GZIPOutputStream(Files.newOutputStream(path))) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
        }
    }
}
