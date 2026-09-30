package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class DetectorsTest {

    static final DetectorRules RULES = Config.loadFileConfig(Path.of("config")).rules();

    static TextUnit unit(String text) {
        return new TextUnit("u0", "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    @Test
    void afmConfidenceFollowsChecksumAndLabel() {
        String valid = TestDocx.validAfm("12345678");
        String invalid = valid.substring(0, 8) + ((valid.charAt(8) - '0' + 1) % 10);
        List<Span> ok = Detectors.detectStructuredIds(unit("ΑΦΜ " + valid), RULES);
        assertEquals(1.0, ok.get(0).confidence());
        assertEquals(SpanCategory.AFM, ok.get(0).category());
        assertEquals(0.75, Detectors.detectStructuredIds(unit("ΑΦΜ: " + invalid), RULES).get(0).confidence());
        assertEquals(0.4, Detectors.detectStructuredIds(unit("αριθμός " + invalid), RULES).get(0).confidence());
    }

    @Test
    void publicEmailDomainIsPreserved() {
        List<Span> spans = Detectors.detectContacts(unit("info@aade.gr και x.y@example.com"), RULES);
        assertEquals(SpanAction.PRESERVE, spans.get(0).action());
        assertEquals(SpanAction.REDACT, spans.get(1).action());
    }

    @Test
    void phonesAreReviewHintsNotDecisions() {
        List<Span> spans = Detectors.detectContacts(unit("τηλ. 2101234567"), RULES);
        assertEquals(SpanAction.REVIEW, spans.get(0).action());
    }

    @Test
    void ibanChecksum() {
        assertTrue(DetectorSupport.ibanIsValid("GB82 WEST 1234 5698 7654 32"));
        assertFalse(DetectorSupport.ibanIsValid("GB82 WEST 1234 5698 7654 33"));
    }

    @Test
    void amkaBirthDate() {
        assertTrue(DetectorSupport.validAmkaBirthDate("01018512345", 2026));
        assertFalse(DetectorSupport.validAmkaBirthDate("32018512345", 2026));
    }

    @Test
    void detectAllSplitsReviewHintsFromResolverInput() {
        DocumentData doc = new DocumentData("d", List.of(unit("Ο Γεώργιος Παπαδόπουλος με ΑΦΜ " + TestDocx.validAfm("11111111"))),
                List.of(), List.of());
        Detectors.DetectionResult r = Detectors.detectAll(doc, RULES);
        assertTrue(r.reviewHints().stream().allMatch(s -> s.action() == SpanAction.REVIEW));
        assertTrue(r.resolverSpans().stream().noneMatch(s -> s.action() == SpanAction.REVIEW));
        assertTrue(r.resolverSpans().stream().anyMatch(s -> s.category() == SpanCategory.AFM));
    }
}
