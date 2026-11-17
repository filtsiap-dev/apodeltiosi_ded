package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.filtsiap.ded.anonymizer.ConfigurationError;

class ChatSettingsTest {

    @TempDir
    Path dir;

    @Test
    void aMissingFileMeansDefaultsWithNerOff() {
        assertEquals(ChatSettings.DEFAULTS, ChatSettings.load(dir));
        assertFalse(ChatSettings.DEFAULTS.nerEnabled());
    }

    @Test
    void theShippedFileLoadsWithNerOff() {
        assertFalse(ChatSettings.load(Path.of("config", "chat")).nerEnabled());
    }

    @Test
    void enablingNerWithoutAProviderStopsStartup() throws Exception {
        Files.writeString(dir.resolve("chat.yaml"), "ner:\n  enabled: true\n  provider: none\n");
        assertThrows(ConfigurationError.class, () -> ChatSettings.load(dir));
    }

    @Test
    void aConfidenceOutsideZeroToOneIsRejected() throws Exception {
        Files.writeString(dir.resolve("chat.yaml"), "ner:\n  min_confidence: 1.5\n");
        assertThrows(ConfigurationError.class, () -> ChatSettings.load(dir));
    }
}
