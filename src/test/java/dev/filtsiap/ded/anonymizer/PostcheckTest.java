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
    void residualAmkaIsHighWhateverTheBirthYear() {
        // DDMMYY: born 15/07/1985 and 03/11/1999. Before O7.3 the scan read YYMMDD and missed both.
        for (String amka : new String[] {"15078512345", "03119912345", "20040512345"}) {
            PostcheckSummary s = Postcheck.scanRedactedDocxBytes(TestDocx.paragraphs("ΑΜΚΑ " + amka).bytes(), FILES);
            assertEquals(1, s.byKind().get("residual_amka"), amka);
        }
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
