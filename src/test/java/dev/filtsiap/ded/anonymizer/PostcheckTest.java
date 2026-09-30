package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class PostcheckTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));

    @Test
    void residualValidAfmIsHigh() {
        byte[] docx = TestDocx.paragraphs("ΑΦΜ " + TestDocx.validAfm("12345678")).bytes();
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(docx, FILES);
        assertEquals(1, s.bySeverity().get("HIGH"));
        assertEquals("residual_afm", s.findings().get(0).kind());
        assertEquals("word/document.xml:u0", s.findings().get(0).location());
    }

    @Test
    void detailsNeverEchoMatchedPii() {
        String afm = TestDocx.validAfm("87654321");
        byte[] docx = TestDocx.paragraphs("ΑΦΜ " + afm, "email x.y@example.com").bytes();
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(docx, FILES);
        assertTrue(s.findings().stream().noneMatch(f -> f.detail().contains(afm) || f.detail().contains("x.y@")));
    }

    @Test
    void cleanDocumentIsClean() {
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(TestDocx.paragraphs("Απόφαση χωρίς στοιχεία").bytes(), FILES);
        assertTrue(s.clean());
    }
}
