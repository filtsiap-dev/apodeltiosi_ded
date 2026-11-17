package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.filtsiap.ded.anonymizer.ConfigurationError;

class WordSetTest {

    @TempDir
    Path dir;

    @Test
    void ofFoldsDedupesAndFinds() {
        WordSet set = WordSet.of(List.of("Λογαριασμός", "λογαριασμος", "πλάκα", " "));
        assertEquals(2, set.size());
        assertTrue(set.contains("λογαριασμοσ"));
        assertTrue(set.contains("πλακα"));
        assertFalse(set.contains("πλακ"));
        assertFalse(set.contains("πλακασ"));
        assertFalse(set.contains(""));
    }

    @Test
    void oneEditCoversSubstitutionInsertionDeletionAndTransposition() {
        WordSet set = WordSet.of(List.of("λογαριασμοσ"));
        assertTrue(set.containsWithinOneEdit("λογαριασμοσ"));
        assertTrue(set.containsWithinOneEdit("λογαριασμασ"));   // substitution
        assertTrue(set.containsWithinOneEdit("λογαριασμοοσ"));  // insertion
        assertTrue(set.containsWithinOneEdit("λογαριαμοσ"));    // deletion
        assertTrue(set.containsWithinOneEdit("λογαριασομσ"));   // transposition
        assertFalse(set.containsWithinOneEdit("λογαριαμασ"));   // two edits
    }

    @Test
    void loadsSortedPlainAndGzipFiles() throws Exception {
        Path plain = dir.resolve("a.txt");
        Files.writeString(plain, "αβγ\nδεζ\n", StandardCharsets.UTF_8);
        Path gz = dir.resolve("b.txt.gz");
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(gz))) {
            out.write("αβγ\nδεζ\n".getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(WordSet.loadSorted(plain).contains("δεζ"));
        assertTrue(WordSet.loadSorted(gz).contains("αβγ"));
    }

    @Test
    void anUnsortedOrUnfoldedGeneratedFileIsAConfigurationError() throws Exception {
        Path unsorted = dir.resolve("u.txt");
        Files.writeString(unsorted, "δεζ\nαβγ\n", StandardCharsets.UTF_8);
        assertThrows(ConfigurationError.class, () -> WordSet.loadSorted(unsorted));
        Path unfolded = dir.resolve("f.txt");
        Files.writeString(unfolded, "Άλφα\n", StandardCharsets.UTF_8);
        assertThrows(ConfigurationError.class, () -> WordSet.loadSorted(unfolded));
    }

    @Test
    void handListsSkipCommentsAndFold() throws Exception {
        Path list = dir.resolve("h.txt");
        Files.writeString(list, "# telecom words\nΔΕΗ\n\niPhone  # a phone\n", StandardCharsets.UTF_8);
        WordSet set = WordSet.loadList(list);
        assertTrue(set.contains("δεη"));
        assertTrue(set.contains("iphone"));
        assertEquals(2, set.size());
    }

    @Test
    void footprintIsCharsPlusOffsets() {
        WordSet set = WordSet.of(List.of("ab", "cde"));
        assertEquals(5 * 2 + 3 * 4, set.footprintBytes());
    }
}
