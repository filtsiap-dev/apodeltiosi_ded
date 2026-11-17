package dev.filtsiap.ded.anonymizer.llm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.SpanOrigin;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.XmlCharRef;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The masked LLM view: which decisions mask, and that masking moves nothing. All values are synthetic. */
class HardDecisionsTest {

    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();

    static Span span(String unit, int start, int end, SpanCategory category, SpanAction action, double confidence,
                     SpanOrigin origin) {
        return new Span(unit, start, end, "", category, "test", confidence, action, "", origin);
    }

    static Span deterministic(String unit, int start, int end, SpanCategory category, SpanAction action,
                              double confidence) {
        return span(unit, start, end, category, action, confidence, SpanOrigin.DETERMINISTIC);
    }

    static TextUnit para(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(3));
    }

    static String masked(TextUnit unit, List<Span> spans) {
        DocumentData doc = new DocumentData("d", List.of(unit), List.of(), List.of());
        return HardDecisions.of(spans, POLICY).maskedView(doc).textUnits().get(0).normalizedText();
    }

    /**
     * Only the resolver's hard-redact predicate masks: deterministic origin, a configured hard-redact
     * category, and at least the high-confidence threshold, all three. Nothing else does, however it
     * is labelled.
     */
    @Test
    void onlyADeterministicConfidentRedactInAHardCategoryIsMasked() {
        TextUnit unit = para("u0", "123456783");
        double high = POLICY.redactHighConfidenceThreshold();
        assertTrue(POLICY.hardRedactCategories().contains("AFM"));
        assertFalse(POLICY.hardRedactCategories().contains("PHONE"));
        assertEquals(".........", masked(unit, List.of(deterministic("u0", 0, 9, SpanCategory.AFM, SpanAction.REDACT,
                high))));
        for (Span notHard : List.of(
                deterministic("u0", 0, 9, SpanCategory.AFM, SpanAction.REDACT, high - 0.01), // below the threshold
                deterministic("u0", 0, 9, SpanCategory.PHONE, SpanAction.REDACT, 1.0), // not a hard category
                deterministic("u0", 0, 9, SpanCategory.AFM, SpanAction.REVIEW, 1.0), // not a REDACT
                deterministic("u0", 0, 9, SpanCategory.AFM, SpanAction.PRESERVE, 1.0),
                span("u0", 0, 9, SpanCategory.AFM, SpanAction.REDACT, 1.0, SpanOrigin.LLM_PASS2))) { // not deterministic
            assertEquals("123456783", masked(unit, List.of(notHard)), notHard.toString());
        }
    }

    /** One dot per CODE POINT, so every offset in the view is the same offset in the document. */
    @Test
    void maskingKeepsCodePointLengthsUnitsAndLocations() {
        String text = "𝔄 ΑΦΜ 𝔅𝔅123 και ΑΜΚΑ 15078512345.";
        // Code points: "𝔄 ΑΦΜ " is 6, then "𝔅𝔅123" (5) is a hard AFM as far as this test is concerned.
        TextUnit unit = new TextUnit("u7", "word/footer1.xml", UnitType.PARAGRAPH, text, text,
                List.of(new XmlCharRef("word/footer1.xml", "/p", 0)), new TextUnit.ParagraphLocation(42));
        TextUnit untouched = para("u8", "Ουδέτερο.");
        DocumentData doc = new DocumentData("d", List.of(unit, untouched), List.of("word/document.xml"), List.of("w"));
        List<Span> spans = List.of(deterministic("u7", 6, 11, SpanCategory.AFM, SpanAction.REDACT, 0.95),
                deterministic("u7", 21, 32, SpanCategory.AMKA, SpanAction.REDACT, 0.95));
        HardDecisions hard = HardDecisions.of(spans, POLICY);
        DocumentData view = hard.maskedView(doc);

        TextUnit seen = view.textUnits().get(0);
        assertEquals("𝔄 ΑΦΜ ..... και ΑΜΚΑ ...........", seen.normalizedText().substring(0,
                seen.normalizedText().offsetByCodePoints(0, 32)));
        assertEquals(text.codePointCount(0, text.length()),
                seen.normalizedText().codePointCount(0, seen.normalizedText().length()));
        assertTrue(doc.sameUnitGeometry(view));
        assertEquals(unit.unitId(), seen.unitId());
        assertEquals(unit.partName(), seen.partName());
        assertEquals(unit.unitType(), seen.unitType());
        assertEquals(unit.location(), seen.location());
        assertEquals(unit.charMap(), seen.charMap());
        assertEquals(text, seen.text()); // only the text the passes read is masked
        assertSame(untouched, view.textUnits().get(1));
        assertEquals(doc.partsInventory(), view.partsInventory());
        assertEquals(text, doc.textUnits().get(0).normalizedText()); // the document itself is unchanged
        assertEquals(16, hard.maskedCodePoints());
        // No hard redaction at all: the view IS the document.
        assertSame(doc, HardDecisions.of(List.of(), POLICY).maskedView(doc));
    }

    @Test
    void overlappingAndOutOfRangeRedactsMaskTheirUnionAndNothingElse() {
        TextUnit unit = para("u0", "0123456789");
        assertEquals("01.....789", masked(unit, List.of(
                deterministic("u0", 2, 5, SpanCategory.AFM, SpanAction.REDACT, 0.95),
                deterministic("u0", 4, 7, SpanCategory.IBAN, SpanAction.REDACT, 0.95))));
        assertEquals("01234567..", masked(unit, List.of(
                deterministic("u0", 8, 40, SpanCategory.AFM, SpanAction.REDACT, 0.95))));
        assertEquals("0123456789", masked(unit, List.of(
                deterministic("u9", 0, 5, SpanCategory.AFM, SpanAction.REDACT, 0.95)))); // another unit's
    }

    @Test
    void unmaskedGivesTheContiguousRemaindersInTheSameCoordinates() {
        HardDecisions hard = HardDecisions.of(List.of(
                deterministic("u0", 2, 4, SpanCategory.AFM, SpanAction.REDACT, 0.95),
                deterministic("u0", 6, 8, SpanCategory.AFM, SpanAction.REDACT, 0.95)), POLICY);
        assertEquals(List.of(new UnitSlice("u0", 0, 2), new UnitSlice("u0", 4, 6), new UnitSlice("u0", 8, 10)),
                hard.unmasked(new UnitSlice("u0", 0, 10)));
        assertEquals(List.of(new UnitSlice("u0", 4, 6)), hard.unmasked(new UnitSlice("u0", 3, 7)));
        assertEquals(List.of(), hard.unmasked(new UnitSlice("u0", 2, 4)));
        assertEquals(List.of(new UnitSlice("u0", 4, 5)), hard.unmasked(new UnitSlice("u0", 4, 5)));
        assertEquals(List.of(new UnitSlice("u1", 2, 4)), hard.unmasked(new UnitSlice("u1", 2, 4)));
        // The masked parts are the exact complement: the two together cover the slice.
        assertEquals(List.of(new UnitSlice("u0", 2, 4), new UnitSlice("u0", 6, 8)),
                hard.masked(new UnitSlice("u0", 0, 10)));
        assertEquals(List.of(new UnitSlice("u0", 3, 4), new UnitSlice("u0", 6, 7)), hard.masked(new UnitSlice("u0", 3, 7)));
        assertEquals(List.of(), hard.masked(new UnitSlice("u0", 4, 6)));
        assertEquals(List.of(), hard.masked(new UnitSlice("u1", 2, 4)));
    }

    /**
     * A hard preserve, a label above all, is never masked: it stays readable, exactly as written, and a
     * place it covers whole is settled while one it only touches is not.
     */
    @Test
    void aHardPreserveStaysReadableAndSettlesOnlyWhatItCoversWhole() {
        TextUnit unit = para("u0", "με Α.Φ.Μ. 123456783 εδώ");
        Span label = deterministic("u0", 3, 9, SpanCategory.FIELD_LABEL, SpanAction.PRESERVE, 0.99);
        Span value = deterministic("u0", 10, 19, SpanCategory.AFM, SpanAction.REDACT, 0.95);
        assertTrue(POLICY.hardPreserveCategories().contains("FIELD_LABEL"));
        assertEquals("με Α.Φ.Μ. ......... εδώ", masked(unit, List.of(label, value)));
        HardDecisions hard = HardDecisions.of(List.of(label, value), POLICY);
        assertTrue(hard.preserved(new UnitSlice("u0", 3, 9)));
        assertTrue(hard.preserved(new UnitSlice("u0", 4, 6)));
        assertFalse(hard.preserved(new UnitSlice("u0", 0, 9)));
        assertFalse(hard.preserved(new UnitSlice("u0", 3, 10)));
        // Settled is a matter for hard PRESERVE: a redact-only mask settles nothing as preserved.
        assertFalse(HardDecisions.carried(List.of(value), List.of()).preserved(new UnitSlice("u0", 3, 9)));
        // Carried decisions are the same policy: the same mask, the same settled places.
        HardDecisions carried = HardDecisions.carried(List.of(value), List.of(label));
        assertTrue(carried.preserved(new UnitSlice("u0", 3, 9)));
        assertEquals(List.of(new UnitSlice("u0", 10, 19)), carried.masked(new UnitSlice("u0", 0, 23)));
    }

    /**
     * The official signatory's name is a hard preserve that is also SHIELDED: readable in the view, but
     * cut out of every question like a mask, while what is left of a wider proposal is still a question.
     * Any other hard preserve is not shielded (a place it covers whole is settled, as before).
     */
    @Test
    void theSignatoryNameIsCutOutOfEveryQuestionButStaysReadable() {
        TextUnit unit = para("u0", "Επανεξέτασης ΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ και ΔΟΥ Κέρκυρας");
        Span signatory = deterministic("u0", 13, 28, SpanCategory.OFFICIAL_SIGNATORY, SpanAction.PRESERVE, 0.95);
        Span dou = deterministic("u0", 33, 45, SpanCategory.DOU, SpanAction.PRESERVE, 0.95);
        HardDecisions hard = HardDecisions.of(List.of(signatory, dou), POLICY);
        assertEquals(unit.normalizedText(), masked(unit, List.of(signatory, dou))); // nothing is blanked
        UnitSlice wide = new UnitSlice("u0", 0, 28);
        assertEquals(List.of(new UnitSlice("u0", 0, 13)), hard.questionable(wide));
        assertEquals(List.of(new UnitSlice("u0", 13, 28)), hard.shieldedParts(wide));
        assertEquals(List.of(wide), hard.unmasked(wide)); // masking itself is unchanged
        // The DOU place is not shielded: a proposal over it stays whole, and is settled when it is covered whole.
        UnitSlice office = new UnitSlice("u0", 33, 45);
        assertEquals(List.of(office), hard.questionable(office));
        assertTrue(hard.preserved(office));
        // Carried into another document's coordinates, the shield goes with it.
        HardDecisions carried = HardDecisions.carried(List.of(), List.of(signatory));
        assertEquals(List.of(new UnitSlice("u0", 0, 13)), carried.questionable(wide));
    }

    /** Whitespace BETWEEN two kept stretches is settled with them; a word between them, or whitespace at an edge, is not. */
    @Test
    void whitespaceBetweenTwoKeptStretchesIsSettledWithThem() {
        TextUnit unit = para("u0", "ΔΙΑΦΟΡΩΝ\tΥΠΟΔΙΕΥΘΥΝΣΗ και ΤΜΗΜΑ ");
        DocumentData doc = new DocumentData("d", List.of(unit), List.of(), List.of());
        List<Span> kept = List.of(deterministic("u0", 0, 8, SpanCategory.PUBLIC_SERVICE, SpanAction.PRESERVE, 1.0),
                deterministic("u0", 9, 21, SpanCategory.PUBLIC_SERVICE, SpanAction.PRESERVE, 1.0),
                deterministic("u0", 26, 31, SpanCategory.PUBLIC_SERVICE, SpanAction.PRESERVE, 1.0));
        HardDecisions bridged = HardDecisions.of(kept, POLICY, doc);
        assertTrue(bridged.preserved(new UnitSlice("u0", 0, 21))); // the tab between them
        assertFalse(bridged.preserved(new UnitSlice("u0", 9, 31))); // " και " holds a word
        assertFalse(bridged.preserved(new UnitSlice("u0", 26, 32))); // trailing space: not between two
        assertFalse(HardDecisions.of(kept, POLICY).preserved(new UnitSlice("u0", 0, 21))); // without the text: exact
    }
}
