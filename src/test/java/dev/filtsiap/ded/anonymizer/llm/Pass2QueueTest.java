package dev.filtsiap.ded.anonymizer.llm;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.newFinding;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.Resolver;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.SpanOrigin;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.UnresolvedFinding;
import dev.filtsiap.ded.anonymizer.llm.Pass2Queue.Candidate;
import dev.filtsiap.ded.anonymizer.llm.Pass2Queue.Recommendation;
import dev.filtsiap.ded.anonymizer.llm.Pass2Queue.Validation;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The candidate queue, its strict validation, and the spans an answer writes. All text is invented. */
class Pass2QueueTest {

    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();

    static TextUnit para(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static Chunk chunk(TextUnit... units) {
        return new Chunk(List.of(units), false, null);
    }

    /** A deterministic span over the first occurrence of {@code text} in the unit. */
    static Span rule(TextUnit unit, String text, SpanCategory category, SpanAction action) {
        return rule(unit, text, category, action, 0.9);
    }

    static Span rule(TextUnit unit, String text, SpanCategory category, SpanAction action, double confidence) {
        int start = unit.normalizedText().indexOf(text);
        return new Span(unit.unitId(), start, start + text.length(), text, category, "test", confidence, action, "",
                SpanOrigin.DETERMINISTIC);
    }

    static List<Candidate> build(Chunk chunk, List<Span> rules, List<LlmDetector.Finding> findings) {
        return Pass2Queue.build(chunk, rules, List.of(), findings, chunk.render(), HardDecisions.NONE).candidates();
    }

    /** The queue as the detector builds it: over the masked view of {@code units}, hard decisions from {@code rules}. */
    static Pass2Queue.Queue masked(List<TextUnit> units, List<Span> rules, List<Span> hints,
                                   List<LlmDetector.Finding> findings) {
        HardDecisions hard = HardDecisions.of(rules, POLICY);
        DocumentData view = hard.maskedView(new DocumentData("d", units, List.of(), List.of()));
        Chunk chunk = new Chunk(view.textUnits(), false, null);
        return Pass2Queue.build(chunk, rules.stream().filter(s -> !dev.filtsiap.ded.anonymizer.Resolver.isHardRedact(s,
                POLICY) && !dev.filtsiap.ded.anonymizer.Resolver.isHardPreserve(s, POLICY)).toList(), hints, findings,
                chunk.render(), hard);
    }

    static Validation validate(List<Candidate> candidates, Object... entries) {
        Map<String, Candidate> byId = new LinkedHashMap<>();
        candidates.forEach(c -> byId.put(c.id(), c));
        return Pass2Queue.validate(PyJson.dumps(List.of(entries)), byId);
    }

    static LlmDetector.Finding finding(String text, SpanAction action, SpanCategory category) {
        return new LlmDetector.Finding(text, action, category);
    }

    // ------------------------------------------------------------------ building

    @Test
    void identicalTextInDifferentContextsStaysTwoCandidates() {
        TextUnit header = para("u0", "Τηλέφωνο: 6912345678");
        TextUnit body = para("u1", "Τηλέφωνο προσφεύγοντος: 6912345678");
        Chunk chunk = chunk(header, body);
        List<Candidate> candidates = build(chunk,
                List.of(rule(header, "6912345678", SpanCategory.PHONE, SpanAction.REVIEW),
                        rule(body, "6912345678", SpanCategory.PHONE, SpanAction.REVIEW)), List.of());
        assertEquals(List.of("C1", "C2"), candidates.stream().map(Candidate::id).toList());
        assertEquals(List.of(new UnitSlice("u0", 10, 20)), candidates.get(0).locations());
        assertEquals(List.of(new UnitSlice("u1", 24, 34)), candidates.get(1).locations());
        assertEquals("Τηλέφωνο: ", candidates.get(0).before());
        // 40 code points of the rendered chunk, crossing the paragraph join.
        assertEquals("ωνο: 6912345678\nΤηλέφωνο προσφεύγοντος: ", candidates.get(1).before());
    }

    @Test
    void locationsShareACandidateOnlyWhenTheWholeQuestionIsIdentical() {
        String pad = "x".repeat(45);
        String text = pad + " Νίκος Παππάς " + pad + " Νίκος Παππάς " + pad + " Νίκος Παππάς.";
        Chunk chunk = chunk(para("u0", text));
        List<Candidate> candidates = build(chunk, List.of(),
                List.of(finding("Νίκος Παππάς", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        // The first two occurrences have 40 identical characters on both sides; the third is followed by "."
        assertEquals(2, candidates.size());
        assertEquals(2, candidates.get(0).locations().size());
        assertEquals(1, candidates.get(1).locations().size());
        // The payload never says how many places an answer covers.
        assertEquals(Set.of("id", "text", "recommendations", "before", "after"), candidates.get(0).asPayload().keySet());
    }

    @Test
    void agreementIsOneRecommendationAndDisagreementIsTwo() {
        TextUnit unit = para("u0", "ΑΦΜ 123456783 και Σπύρος");
        Chunk chunk = chunk(unit);
        List<Candidate> candidates = build(chunk,
                List.of(rule(unit, "123456783", SpanCategory.AFM, SpanAction.REDACT),
                        rule(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON, SpanAction.REVIEW)),
                List.of(finding("123456783", SpanAction.REDACT, SpanCategory.AFM),
                        finding("Σπύρος", SpanAction.PRESERVE, SpanCategory.OFFICIAL_SIGNATORY)));
        assertEquals(List.of(new Recommendation(List.of("deterministic", "pass1"), SpanAction.REDACT, SpanCategory.AFM)),
                candidates.get(0).recommendations());
        assertEquals(List.of(
                        new Recommendation(List.of("deterministic"), SpanAction.REVIEW, SpanCategory.POSSIBLE_PERSON),
                        new Recommendation(List.of("pass1"), SpanAction.PRESERVE, SpanCategory.OFFICIAL_SIGNATORY)),
                candidates.get(1).recommendations());
        assertEquals(SpanCategory.POSSIBLE_PERSON, candidates.get(1).category()); // the rules outrank pass 1
    }

    @Test
    void aPass1FindingIsLocatedInTheRenderedChunkOrCarriedOutAsUnlocated() {
        Chunk chunk = chunk(para("u0", "Υπογράφει η Ελένη."), para("u1", "Ελένη Β."));
        LlmDetector.Finding paraphrase = finding("παράφραση", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON);
        LlmDetector.Finding letter = finding("Λ", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON);
        Pass2Queue.Queue queue = Pass2Queue.build(chunk, List.of(), List.of(), List.of(
                finding("Ελένη", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON), letter, paraphrase, paraphrase,
                finding("Ελένη.\nΕλένη", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)), chunk.render(),
                HardDecisions.NONE);
        // Located in both units, and a quote across the paragraph join is placed in both units too;
        // a short text only as a standalone token. Exact repeats are one unlocated finding, never dropped.
        assertEquals(List.of(new UnitSlice("u0", 12, 17), new UnitSlice("u1", 0, 5), new UnitSlice("u0", 12, 18)),
                queue.candidates().stream().flatMap(c -> c.locations().stream()).toList());
        assertEquals(List.of(letter, paraphrase), queue.unlocated());
    }

    // ------------------------------------------------------------------ eligibility

    /**
     * Built and merged first, then filtered: a REDACT or a REVIEW is a question; a place nobody
     * proposed anything but PRESERVE for is not; a PRESERVE that disagrees with a REDACT or a REVIEW
     * stays as part of the question. Ids are issued to eligible candidates only, in order.
     */
    @Test
    void onlyPlacesWithARedactOrAReviewAreQuestionsAndDisagreementIsKept() {
        TextUnit unit = para("u0", "Α 01/02/1980 Β 02/03/1981 Γ 03/04/1982 Δ Νίκος Ε 6912345678 Ζ Σπύρος.");
        List<Span> rules = List.of(
                rule(unit, "01/02/1980", SpanCategory.DATE, SpanAction.PRESERVE), // preserve-only
                rule(unit, "02/03/1981", SpanCategory.DATE, SpanAction.PRESERVE), // disputed by pass 1
                rule(unit, "6912345678", SpanCategory.PHONE, SpanAction.REVIEW)); // an official/private question
        List<LlmDetector.Finding> findings = List.of(
                finding("01/02/1980", SpanAction.PRESERVE, SpanCategory.DATE),
                finding("02/03/1981", SpanAction.REDACT, SpanCategory.DATE),
                finding("03/04/1982", SpanAction.PRESERVE, SpanCategory.DATE), // pass-1 preserve-only
                finding("Νίκος", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON),
                finding("Σπύρος", SpanAction.REVIEW, SpanCategory.POSSIBLE_PERSON));
        List<Candidate> candidates = build(chunk(unit), rules, findings);
        assertEquals(List.of("C1", "C2", "C3", "C4"), candidates.stream().map(Candidate::id).toList());
        assertEquals(List.of("02/03/1981", "6912345678", "Νίκος", "Σπύρος"),
                candidates.stream().map(Candidate::text).toList());
        assertEquals(List.of(new Recommendation(List.of("deterministic"), SpanAction.PRESERVE, SpanCategory.DATE),
                new Recommendation(List.of("pass1"), SpanAction.REDACT, SpanCategory.DATE)),
                candidates.get(0).recommendations());
    }

    /**
     * A category in the hard-redact list is not a hard decision by itself: only the resolver's own
     * predicate (deterministic, hard category, high confidence) masks and settles.
     */
    @Test
    void anOrdinaryRedactInAHardCategoryIsStillAQuestion() {
        TextUnit unit = para("u0", "ΑΦΜ 123456783 και ΑΦΜ 987654321.");
        Span hard = rule(unit, "123456783", SpanCategory.AFM, SpanAction.REDACT, 0.95);
        Span soft = rule(unit, "987654321", SpanCategory.AFM, SpanAction.REDACT, 0.85);
        Pass2Queue.Queue queue = masked(List.of(unit), List.of(hard, soft), List.of(),
                List.of(finding("987654321", SpanAction.REDACT, SpanCategory.AFM)));
        assertEquals(List.of("987654321"), queue.candidates().stream().map(Candidate::text).toList());
        assertEquals(List.of(new Recommendation(List.of("deterministic", "pass1"), SpanAction.REDACT, SpanCategory.AFM)),
                queue.candidates().get(0).recommendations());
        assertEquals("ΑΦΜ ......... και ΑΦΜ ", queue.candidates().get(0).before());
    }

    /**
     * What a hard redact blanked is cut out of every proposal, and what is left of it is still asked
     * about, at its own coordinates: never the whole proposal thrown away for an overlap.
     */
    @Test
    void proposalsAreCutFreeOfHardRedactionsAndTheRestIsStillAsked() {
        TextUnit unit = para("u0", "Ref ΚΑΕΚ 050011122234 και 5678/2020 τέλος.");
        int root = unit.normalizedText().indexOf("050011122234");
        Span hard = rule(unit, "050011122234", SpanCategory.PROPERTY_ID, SpanAction.REDACT, 0.95);
        // A REVIEW hint over the whole reference; a REDACT that runs from the root into what follows it.
        Span hint = rule(unit, "050011122234 και 5678/2020", SpanCategory.CASE_REF_NUMBER, SpanAction.REVIEW, 0.6);
        Span wide = new Span("u0", root + 4, root + 17, "", SpanCategory.CASE_REF_NUMBER, "test", 0.85,
                SpanAction.REDACT, "", SpanOrigin.DETERMINISTIC);
        Pass2Queue.Queue queue = masked(List.of(unit), List.of(hard, wide), List.of(hint), List.of(
                // Pass 1 quoted the masked stretch with its neighbours, and one that is nothing but dots.
                finding("ΚΑΕΚ ............ και", SpanAction.REDACT, SpanCategory.PROPERTY_ID),
                finding("............", SpanAction.REDACT, SpanCategory.PROPERTY_ID)));
        int after = root + 12;
        assertEquals(List.of(
                        List.of(new UnitSlice("u0", after, root + 17)), // the wide REDACT's remainder
                        List.of(new UnitSlice("u0", after, after + 14)), // the hint's remainder
                        List.of(new UnitSlice("u0", root - 5, root)), // pass 1's quote, before the mask
                        List.of(new UnitSlice("u0", after, after + 4))), // and after it
                queue.candidates().stream().map(Candidate::locations).toList());
        assertEquals(List.of(" και ", " και 5678/2020", "ΚΑΕΚ ", " και"),
                queue.candidates().stream().map(Candidate::text).toList());
        assertTrue(queue.candidates().stream().noneMatch(c -> c.text().contains("0500")));
        assertEquals(List.of(), queue.unlocated()); // the all-dots quote was found, and is wholly settled
    }

    @Test
    void aPlaceAHardPreserveCoversWholeIsSettledAndAPartialOverlapIsStillAsked() {
        TextUnit unit = para("u0", "Η ΔΟΥ Κέρκυρας Παππάς εξέδωσε.");
        Span dou = rule(unit, "ΔΟΥ Κέρκυρας", SpanCategory.DOU, SpanAction.PRESERVE, 0.95);
        Pass2Queue.Queue queue = masked(List.of(unit), List.of(dou), List.of(), List.of(
                finding("Κέρκυρας", SpanAction.REDACT, SpanCategory.LOCALITY),
                finding("Κέρκυρας Παππάς", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of("Κέρκυρας Παππάς"), queue.candidates().stream().map(Candidate::text).toList());
    }

    @Test
    void contextWindowsAreFortyCodePointsOfTheMaskedText() {
        String astral = "𝔄𝔅"; // two code points, four UTF-16 units
        TextUnit unit = para("u0", astral.repeat(30) + " ΑΦΜ 123456783 τηλ. 6912345678 " + astral.repeat(30));
        // Spans are in code points: 60 astral code points, then " ΑΦΜ " (5), the AFM (9) and " τηλ. " (6).
        Span hard = new Span("u0", 65, 74, "123456783", SpanCategory.AFM, "test", 0.95, SpanAction.REDACT, "",
                SpanOrigin.DETERMINISTIC);
        Span phoneHint = new Span("u0", 80, 90, "6912345678", SpanCategory.PHONE, "test", 0.6, SpanAction.REVIEW, "",
                SpanOrigin.DETERMINISTIC);
        Pass2Queue.Queue queue = masked(List.of(unit), List.of(hard), List.of(phoneHint), List.of());
        Candidate phone = queue.candidates().get(0);
        assertEquals("6912345678", phone.text());
        assertEquals(40, phone.before().codePointCount(0, phone.before().length()));
        assertEquals(40, phone.after().codePointCount(0, phone.after().length()));
        assertEquals(astral.repeat(10) + " ΑΦΜ ......... τηλ. ", phone.before());
        assertEquals(" " + astral.repeat(19) + "𝔄", phone.after());
        assertEquals(List.of(new UnitSlice("u0", 80, 90)), phone.locations()); // code-point coordinates
    }

    // ------------------------------------------------------------------ validating

    @Test
    void anAnswerIsKeyedByIdWithCategoryFallbackAndReviewCoerced() {
        TextUnit unit = para("u0", "Σπύρος και Μαρία");
        List<Candidate> candidates = build(chunk(unit), List.of(rule(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW), rule(unit, "Μαρία", SpanCategory.POSSIBLE_PERSON, SpanAction.REVIEW)), List.of());
        Validation v = validate(candidates, answer("c1", "review", "NOPE"), answer("C2", "PRESERVE", "PERSON"));
        assertEquals(List.of(), v.rejections());
        assertEquals(List.of(new Pass2Queue.Decision("C1", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT, true),
                new Pass2Queue.Decision("C2", SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE, false)), v.decisions());
    }

    @Test
    void skipIsNoAnswerAndAMissingIdIsUndecided() {
        TextUnit unit = para("u0", "Σπύρος και Μαρία");
        List<Candidate> candidates = build(chunk(unit), List.of(rule(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW), rule(unit, "Μαρία", SpanCategory.POSSIBLE_PERSON, SpanAction.REVIEW)), List.of());
        Validation v = validate(candidates, answer("C1", "SKIP", "POSSIBLE_PERSON"));
        assertEquals(List.of("C1 has no final REDACT/PRESERVE action"), v.rejections());
        assertEquals(List.of("C1", "C2"), Pass2Queue.unresolvedIds(v.decisions(), candidates));
        assertFalse(v.distrusted());
    }

    @Test
    void aDuplicatedIdVoidsEveryCopyWhicheverIsMalformed() {
        TextUnit unit = para("u0", "Σπύρος");
        List<Candidate> candidates = build(chunk(unit), List.of(rule(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW)), List.of());
        for (Object[] entries : List.of(
                new Object[] {answer("C1", "REDACT", "POSSIBLE_PERSON"), answer("C1", "PRESERVE", "POSSIBLE_PERSON")},
                new Object[] {answer("C1", "MAYBE", "POSSIBLE_PERSON"), answer("C1", "REDACT", "POSSIBLE_PERSON")},
                new Object[] {answer("C1", "REDACT", "POSSIBLE_PERSON"), answer("C1", "MAYBE", "POSSIBLE_PERSON")})) {
            Validation v = validate(candidates, entries);
            assertEquals(List.of(), v.decisions());
            assertEquals(List.of("C1"), v.voided());
            assertEquals(List.of("C1 is answered more than once; every answer for it was discarded and it must be "
                    + "decided again"), v.rejections());
        }
    }

    @Test
    void anInventedIdDistrustsTheResponseAndNeverEchoesText() {
        TextUnit unit = para("u0", "Σπύρος");
        List<Candidate> candidates = build(chunk(unit), List.of(rule(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW)), List.of());
        Validation v = validate(candidates, answer("C1", "REDACT", "POSSIBLE_PERSON"),
                answer("C7", "REDACT", "POSSIBLE_PERSON"), answer("Σπύρος Λάμπρου", "REDACT", "POSSIBLE_PERSON"), 5,
                Map.of("action", "REDACT"));
        assertTrue(v.distrusted());
        assertEquals(List.of("C7 is not a candidate in this queue", "<malformed id> is not a candidate in this queue",
                "entry 4 is not a JSON object", "entry 5 carries no candidate id"), v.rejections());
        assertThrows(AIProviderError.class, () -> Pass2Queue.validate("{\"not\": \"a list\"}", Map.of()));
    }

    /** "NEW" is an id this queue never issued, like any other: no discovery, no promotion, no text echoed. */
    @Test
    void aNewEntryIsAnUnissuedIdAndNothingElse() {
        TextUnit unit = para("u0", "Σπύρος και Μαρία");
        List<Candidate> candidates = build(chunk(unit), List.of(rule(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW)), List.of());
        Validation v = validate(candidates, answer("C1", "REDACT", "POSSIBLE_PERSON"),
                newFinding("Μαρία", "REDACT", "POSSIBLE_PERSON"), newFinding("Μαρία", "REDACT", "POSSIBLE_PERSON"));
        assertTrue(v.distrusted());
        assertEquals(List.of(new Pass2Queue.Decision("C1", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT, false)),
                v.decisions());
        assertEquals(List.of("<malformed id> is not a candidate in this queue",
                "<malformed id> is not a candidate in this queue"), v.rejections());
        assertEquals(List.of(), v.voided());
        assertTrue(v.rejections().stream().noneMatch(r -> r.contains("Μαρία")));
    }

    @Test
    void aCandidateWithNoCategoryToFallBackToRejectsAnOffVocabularyAnswer() {
        Candidate bare = new Candidate("C1", "Σπύρος", null,
                List.of(new Recommendation(List.of("deterministic"), SpanAction.REVIEW, null)),
                List.of(new UnitSlice("u0", 0, 6)), "", "");
        Map<String, Object> recommendation = bare.recommendations().get(0).asPayload();
        assertTrue(recommendation.containsKey("category"));
        Validation v = validate(List.of(bare), answer("C1", "REDACT", "NOPE"));
        assertEquals(List.of("C1 has a category outside the vocabulary and no recommended one to fall back to"),
                v.rejections());
    }

    // ------------------------------------------------------------------ writing

    @Test
    void aDecisionIsWrittenAtEveryStoredLocationWithPass2Origin() {
        Candidate c = new Candidate("C1", "Νίκος", SpanCategory.POSSIBLE_PERSON,
                List.of(new Recommendation(List.of("pass1"), SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)),
                List.of(new UnitSlice("u0", 0, 5), new UnitSlice("u3", 7, 12)), "", "");
        List<Span> spans = Pass2Queue.spansFromDecisions(
                List.of(new Pass2Queue.Decision("C1", SpanCategory.DATE, SpanAction.PRESERVE, false)), Map.of("C1", c),
                Map.of(), Set.of());
        assertEquals(2, spans.size());
        assertTrue(spans.stream().allMatch(s -> s.origin() == SpanOrigin.LLM_PASS2 && s.detector().equals("llm_pass2")
                && s.category() == SpanCategory.DATE && s.text().equals("Νίκος") && !s.reason().contains("C1")));
    }

    // ------------------------------------------------------------------ routing the first adjudication

    /** Routes {@code units} as one chunk of the masked view, the hard decisions taken from {@code rules}. */
    static Pass2Queue.Routed route(List<TextUnit> units, List<Span> rules, List<Span> hints,
                                   List<LlmDetector.Finding> findings) {
        HardDecisions hard = HardDecisions.of(rules, POLICY);
        DocumentData view = hard.maskedView(new DocumentData("d", units, List.of(), List.of()));
        Chunk chunk = new Chunk(view.textUnits(), false, null);
        Map<String, TextUnit> source = new LinkedHashMap<>();
        units.forEach(u -> source.put(u.unitId(), u));
        return Pass2Queue.route(0, chunk, rules.stream().filter(s -> !Resolver.isHardRedact(s, POLICY)
                && !Resolver.isHardPreserve(s, POLICY)).toList(), hints, findings, chunk.render(), hard, POLICY, source,
                Set.of());
    }

    static List<String> asked(Pass2Queue.Routed routed) {
        return routed.questions().stream().map(q -> q.text() + "@" + q.location().start()).toList();
    }

    static List<String> applied(Pass2Queue.Routed routed) {
        return routed.pass1Spans().stream().map(s -> s.action() + ":" + s.text() + "@" + s.start()).toList();
    }

    static final String NAME = "Γεώργιος Παπαδόπουλος";

    /**
     * The queue reuses its existing full-span hard-preserve filter, unchanged: with the real rules, a rule REDACT
     * or a shape hint that a hard preserve covers whole (the published instrument's "10", a heading read as a
     * name) is settled and never asked, while a hint that only partly overlaps a hard preserve is still asked,
     * whole, and a value next to the kept phrase is still a question.
     */
    @Test
    void aPlaceAHardPreserveCoversWholeIsNeverAskedButAPartialOverlapStillIs() {
        TextUnit u = para("u0", "«Με την απόφαση ΔΕΣ Α 1077357 ΕΞ 10.5.2013, όπως δημοσιεύθηκε. ΥΠΟΔΙΕΘΥΝΣΗ ΕΠΑΝΕΞΕΤΑΣΗΣ");
        dev.filtsiap.ded.anonymizer.Detectors.DetectionResult rules = dev.filtsiap.ded.anonymizer.Detectors.detectAll(
                new DocumentData("d", List.of(u), List.of(), List.of()), Config.loadFileConfig(Path.of("config")).rules());
        // The rules still propose the audit-order REDACT and the name-shape hint: both lie inside hard preserves.
        assertTrue(rules.resolverSpans().stream().anyMatch(s -> s.text().equals("10") && s.action() == SpanAction.REDACT));
        assertTrue(rules.reviewHints().stream().anyMatch(s -> s.text().equals("ΥΠΟΔΙΕΘΥΝΣΗ ΕΠΑΝΕΞΕΤΑΣΗΣ")));
        Pass2Queue.Routed settled = route(List.of(u), rules.resolverSpans(), rules.reviewHints(), List.of());
        assertEquals(List.of(), asked(settled));
        assertTrue(settled.counts().settled() >= 2, settled.counts().toString());

        TextUnit v = para("u1", "ΥΠΟΔΙΕΘΥΝΣΗ ΕΠΑΝΕΞΕΤΑΣΗΣ Γεώργιος Ιωάννου");
        List<Span> vRules = dev.filtsiap.ded.anonymizer.Detectors.detectAll(new DocumentData("d", List.of(v), List.of(),
                List.of()), Config.loadFileConfig(Path.of("config")).rules()).resolverSpans();
        Span partial = rule(v, "ΕΠΑΝΕΞΕΤΑΣΗΣ Γεώργιος", SpanCategory.POSSIBLE_PERSON, SpanAction.REVIEW);
        List<String> asked = asked(route(List.of(v), vRules, List.of(partial), List.of()));
        assertTrue(asked.contains("ΕΠΑΝΕΞΕΤΑΣΗΣ Γεώργιος@12"), asked.toString());
    }

    /** Rows A and B: both stages agree on the action (whatever category each named): no question. */
    @Test
    void agreementIsAppliedWithoutAQuestion() {
        TextUnit u = para("u0", "Ο " + NAME + " υπέγραψε την 01/02/2020.");
        Pass2Queue.Routed redact = route(List.of(u), List.of(rule(u, NAME, SpanCategory.APPELLANT_NAME, SpanAction.REDACT)),
                List.of(), List.of(finding(NAME, SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of(), asked(redact));
        assertEquals(List.of("REDACT:" + NAME + "@2"), applied(redact));
        assertEquals(SpanOrigin.LLM_PASS1, redact.pass1Spans().getFirst().origin());
        assertEquals(1, redact.counts().agreed());

        Pass2Queue.Routed preserve = route(List.of(u), List.of(rule(u, "01/02/2020", SpanCategory.DATE,
                SpanAction.PRESERVE, 0.95)), List.of(), List.of(finding("01/02/2020", SpanAction.PRESERVE, SpanCategory.DATE)));
        assertEquals(List.of(), asked(preserve));
        assertEquals(List.of("PRESERVE:01/02/2020@" + u.normalizedText().indexOf("01/02/2020")), applied(preserve));
    }

    /**
     * Row C: a cross-stage disagreement is a question, asked about the REDACT side's whole value (only a
     * PRESERVE at exactly that slice can reverse it), told what the other stage said and about which text.
     */
    @Test
    void aCrossStageDisagreementIsAskedAboutTheRedactSidesWholeValue() {
        TextUnit u = para("u0", "Ο " + NAME + " υπέγραψε.");
        Span rule = rule(u, NAME, SpanCategory.APPELLANT_NAME, SpanAction.REDACT);
        // Exactly the same place.
        Pass2Queue.Routed same = route(List.of(u), List.of(rule), List.of(),
                List.of(finding(NAME, SpanAction.PRESERVE, SpanCategory.OFFICIAL_SIGNATORY)));
        assertEquals(List.of(NAME + "@2"), asked(same));
        assertEquals(List.of(), applied(same)); // pass 1's PRESERVE there is pass 2's to settle
        assertEquals(List.of(new Recommendation(List.of("deterministic"), SpanAction.REDACT, SpanCategory.APPELLANT_NAME),
                new Recommendation(List.of("pass1"), SpanAction.PRESERVE, SpanCategory.OFFICIAL_SIGNATORY)),
                same.questions().getFirst().recommendations());
        assertEquals(new Pass2Queue.Fallback(null, null, SpanAction.REDACT, true), same.questions().getFirst().fallback());

        // A PRESERVE on a fragment of the rules' REDACT: the question is the whole rule span.
        Pass2Queue.Routed nested = route(List.of(u), List.of(rule), List.of(),
                List.of(finding("Παπαδόπουλος", SpanAction.PRESERVE, SpanCategory.OFFICIAL_SIGNATORY)));
        assertEquals(List.of(NAME + "@2"), asked(nested));
        assertEquals(new Recommendation(List.of("pass1"), SpanAction.PRESERVE, SpanCategory.OFFICIAL_SIGNATORY, null,
                "Παπαδόπουλος"), nested.questions().getFirst().recommendations().get(1));
        assertEquals(List.of("PRESERVE:Παπαδόπουλος@11"), applied(nested)); // harmless: it never outranks a rule REDACT

        // A pass-1 REDACT partly over the rules' PRESERVE: the question is pass 1's whole quote.
        TextUnit addr = para("u0", "κάτοικος Αθηνών, οδός Σόλωνος 5.");
        Span place = rule(addr, "Αθηνών", SpanCategory.LOCALITY, SpanAction.PRESERVE, 0.85);
        Pass2Queue.Routed partial = route(List.of(addr), List.of(place), List.of(),
                List.of(finding("Αθηνών, οδός Σόλωνος 5", SpanAction.REDACT, SpanCategory.PRIVATE_ADDRESS)));
        assertEquals(List.of("Αθηνών, οδός Σόλωνος 5@9"), asked(partial));
        assertEquals(List.of(), applied(partial));
        assertEquals(new Recommendation(List.of("deterministic"), SpanAction.PRESERVE, SpanCategory.LOCALITY, null,
                "Αθηνών"), partial.questions().getFirst().recommendations().get(1));
        assertEquals(SpanAction.REDACT, partial.questions().getFirst().fallback().pass1());
    }

    /** Row D: a REVIEW from either stage is a question at exactly its place. */
    @Test
    void aReviewFromEitherStageIsAQuestion() {
        TextUnit u = para("u0", "Ο Σπύρος και η Μαρία.");
        Pass2Queue.Routed routed = route(List.of(u), List.of(), List.of(rule(u, "Σπύρος", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW)), List.of(finding("Μαρία", SpanAction.REVIEW, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of("Σπύρος@2", "Μαρία@15"), asked(routed));
        assertEquals(new Pass2Queue.Fallback(null, null, null, false), routed.questions().getFirst().fallback());
        // A REVIEW at the place pass 1 decided: one question, pass 1's decision its fallback.
        Pass2Queue.Routed shared = route(List.of(u), List.of(), List.of(rule(u, "Σπύρος", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW)), List.of(finding("Σπύρος", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of("Σπύρος@2"), asked(shared));
        assertEquals(List.of(), applied(shared));
        assertEquals(SpanAction.REDACT, shared.questions().getFirst().fallback().pass1());
    }

    /** Row E: pass 1 alone is applied directly, REDACT narrowed; a quote that narrows to nothing is held. */
    @Test
    void aPass1OnlyDecisionIsAppliedDirectlyAndNeverDroppedSilently() {
        TextUnit u = para("u0", "Ο " + NAME + " και ο Δήμος Αθηναίων, δείτε (-) εδώ.");
        Pass2Queue.Routed routed = route(List.of(u), List.of(), List.of(), List.of(
                finding(NAME, SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON),
                finding("Δήμος Αθηναίων", SpanAction.PRESERVE, SpanCategory.PUBLIC_SERVICE),
                finding("(-)", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of(), asked(routed));
        assertEquals(List.of("REDACT:" + NAME + "@2", "PRESERVE:Δήμος Αθηναίων@30"), applied(routed));
        assertEquals(1, routed.unresolved().size());
        UnresolvedFinding held = routed.unresolved().getFirst();
        assertEquals(UnresolvedFinding.Kind.PASS1_REDACT_UNREPRESENTABLE, held.kind());
        int at = u.normalizedText().indexOf("(-)");
        assertEquals(List.of(new UnitSlice("u0", at, at + 3)), held.locations()); // exact source offsets
        assertEquals(3, routed.counts().pass1Only()); // routed without a question, the held one included
    }

    /**
     * Row F, under the LLM-to-resolver contract: a rule REDACT pass 1 decided nothing about is a question
     * at its own place (whatever its confidence: it is not turned into a REVIEW, and its fallback is the
     * rules' own ladder), while a rule PRESERVE alone asks nothing, since it changes nothing.
     */
    @Test
    void aRulesOnlyRedactIsAskedAndARulesOnlyPreserveIsNot() {
        TextUnit u = para("u0", "Ο " + NAME + " υπέγραψε την 01/02/2020.");
        Pass2Queue.Routed routed = route(List.of(u), List.of(
                rule(u, NAME, SpanCategory.APPELLANT_NAME, SpanAction.REDACT, 0.75),
                rule(u, "Παπαδόπουλος", SpanCategory.POSSIBLE_COMPANY, SpanAction.PRESERVE, 0.85),
                rule(u, "01/02/2020", SpanCategory.DATE, SpanAction.REDACT, 0.6)), List.of(), List.of());
        assertEquals(List.of(NAME + "@2", "01/02/2020@" + u.normalizedText().indexOf("01/02/2020")), asked(routed));
        assertEquals(List.of(), applied(routed));
        assertEquals(3, routed.counts().deterministicOnly());
        // No pass-1 decision: the fallback is the rules' own ladder (REDACT where its threshold is met, nothing below).
        assertEquals(List.of(SpanAction.REDACT, SpanAction.REDACT), routed.questions().stream()
                .map(q -> q.fallback().deterministic() == null ? SpanAction.REDACT : q.fallback().deterministic())
                .toList());
        assertEquals(null, routed.questions().getFirst().fallback().pass1());
        // Pass 1 against a sub-threshold rule REDACT: the rules decided nothing there, so pass 1 alone decides.
        Pass2Queue.Routed weak = route(List.of(u), List.of(rule(u, "01/02/2020", SpanCategory.DATE, SpanAction.REDACT,
                0.6)), List.of(), List.of(finding("01/02/2020", SpanAction.PRESERVE, SpanCategory.DATE)));
        assertEquals(List.of(), asked(weak));
        assertEquals(List.of("PRESERVE:01/02/2020@" + u.normalizedText().indexOf("01/02/2020")), applied(weak));
    }

    /** Row G: hard policy. A place it covers whole is settled; a masked value is never in a quote or question. */
    @Test
    void hardPolicyPlacesAreSettledAndMaskedValuesNeverAsked() {
        String afm = "123456783";
        TextUnit u = para("u0", "ΔΟΥ Κέρκυρας, Α.Φ.Μ. " + afm + " του " + NAME + ".");
        List<Span> rules = List.of(rule(u, "ΔΟΥ Κέρκυρας", SpanCategory.DOU, SpanAction.PRESERVE, 0.95),
                rule(u, afm, SpanCategory.AFM, SpanAction.REDACT, 0.95));
        Pass2Queue.Routed routed = route(List.of(u), rules, List.of(rule(u, "Κέρκυρας", SpanCategory.LOCALITY,
                SpanAction.REVIEW)), List.of(finding("Κέρκυρας", SpanAction.REDACT, SpanCategory.LOCALITY),
                finding("......... του " + NAME, SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of(), asked(routed)); // inside the hard preserve: settled, never asked
        assertEquals(1, routed.counts().settled());
        // The quote across the masked AFM keeps only what masking left (narrowed by the existing rules,
        // which keep a lowercase word before a name), and never reaches into the masked value.
        assertEquals(List.of("REDACT:του " + NAME + "@" + u.normalizedText().indexOf("του " + NAME)), applied(routed));
        assertTrue(routed.pass1Spans().stream().noneMatch(s -> s.text().contains(afm) || s.text().contains(".")));
    }

    /**
     * A quote is judged whole: a leftover label beside a value hard policy already masked, or the label
     * half of a quote across a paragraph break whose other half is written, is not a missing redaction.
     */
    @Test
    void aQuoteIsHeldOnlyWhenNoPartOfItCouldBeWritten() {
        String afm = "123456783";
        TextUnit u = para("u0", "Ο προσφεύγων με ΑΦΜ " + afm + " υπέγραψε.");
        Pass2Queue.Routed masked = route(List.of(u), List.of(rule(u, afm, SpanCategory.AFM, SpanAction.REDACT, 0.95)),
                List.of(), List.of(finding("ΑΦΜ .........", SpanAction.REDACT, SpanCategory.AFM)));
        assertEquals(List.of(), masked.unresolved());
        assertEquals(List.of(), asked(masked));

        TextUnit label = para("u0", "Ο προσφεύγων");
        TextUnit name = para("u1", NAME + " υπέγραψε.");
        Pass2Queue.Routed across = route(List.of(label, name), List.of(), List.of(),
                List.of(finding("προσφεύγων\n" + NAME, SpanAction.REDACT, SpanCategory.PRIVATE_ADDRESS)));
        assertEquals(List.of(), across.unresolved());
        assertTrue(applied(across).stream().anyMatch(s -> s.contains(NAME)), applied(across).toString());
    }

    /** Partial, nested and overlapping quotes: agreement and disagreement are found by exact coordinates. */
    @Test
    void partialNestedAndOverlappingQuotesAreJudgedInterval_by_interval() {
        TextUnit u = para("u0", "Ο " + NAME + " υπέγραψε.");
        Span rule = rule(u, NAME, SpanCategory.APPELLANT_NAME, SpanAction.REDACT);
        // Nested and agreeing: the pass-1 piece is applied; the rest of the rule's value, which pass 1 decided
        // nothing about, makes the rule span a question of its own.
        Pass2Queue.Routed nested = route(List.of(u), List.of(rule), List.of(),
                List.of(finding("Παπαδόπουλος", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of(NAME + "@2"), asked(nested));
        assertEquals(List.of("REDACT:Παπαδόπουλος@11"), applied(nested));
        // Overlapping past its end and agreeing where they meet: applied whole; the rule's first word, which
        // pass 1 did not cover, again makes the rule span a question.
        Pass2Queue.Routed overlapping = route(List.of(u), List.of(rule), List.of(),
                List.of(finding("Παπαδόπουλος υπέγραψε", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of(NAME + "@2"), asked(overlapping));
        assertEquals(List.of("REDACT:Παπαδόπουλος υπέγραψε@11"), applied(overlapping));
        // Covering the rule's whole value: agreement, no question.
        Pass2Queue.Routed covering = route(List.of(u), List.of(rule), List.of(),
                List.of(finding(NAME + " υπέγραψε", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of(), asked(covering));
        // A rule REDACT nested in a pass-1 PRESERVE: they disagree on the rule's whole slice, which is asked.
        Pass2Queue.Routed around = route(List.of(u), List.of(rule), List.of(),
                List.of(finding("Ο " + NAME + " υπέγραψε", SpanAction.PRESERVE, SpanCategory.OFFICIAL_SIGNATORY)));
        assertEquals(List.of(NAME + "@2"), asked(around));
    }

    /** Pass 1 answers once per text: a repeated text it alone decided is asked place by place. */
    @Test
    void aRepeatedTextPass1AloneDecidedIsAskedPerPlace() {
        TextUnit header = para("u0", "Ο ΠΡΟΪΣΤΑΜΕΝΟΣ: Νίκος Παππάς");
        TextUnit appeal = para("u1", "την προσφυγή του Νίκος Παππάς");
        LlmDetector.Finding f = finding("Νίκος Παππάς", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON);
        Pass2Queue.Routed routed = route(List.of(header, appeal), List.of(), List.of(), List.of(f));
        assertEquals(2, routed.questions().size());
        assertEquals(List.of(), applied(routed));
        assertTrue(routed.questions().stream().allMatch(q -> q.fallback().pass1() == SpanAction.REDACT));
        // Confirmed by the rules at every place: a decision, not a question.
        Pass2Queue.Routed confirmed = route(List.of(header, appeal), List.of(
                rule(header, "Νίκος Παππάς", SpanCategory.OFFICIAL_SIGNATORY, SpanAction.REDACT),
                rule(appeal, "Νίκος Παππάς", SpanCategory.APPELLANT_NAME, SpanAction.REDACT)), List.of(), List.of(f));
        assertEquals(List.of(), asked(confirmed));
        assertEquals(2, applied(confirmed).size());
    }

    /**
     * A REVIEW inside a value pass 1 redacts whole is not asked: the applied pass-1 REDACT outranks every
     * rule span and shields it from a pass-2 PRESERVE, so no answer could change it.
     */
    @Test
    void aQuestionNoAnswerCouldChangeIsNotAsked() {
        String company = "ΚΑΠΑ ΛΑΜΔΑ ΣΥΜΒΟΥΛΕΥΤΙΚΗ ΕΤΑΙΡΙΑ";
        TextUnit u = para("u0", "με την " + company + " για το 2020.");
        Pass2Queue.Routed routed = route(List.of(u), List.of(), List.of(rule(u, "ΚΑΠΑ ΛΑΜΔΑ", SpanCategory.POSSIBLE_PERSON,
                SpanAction.REVIEW)), List.of(finding(company, SpanAction.REDACT, SpanCategory.PRIVATE_COMPANY_NAME)));
        assertEquals(List.of(), asked(routed));
        assertEquals(1, routed.counts().redundant());
        assertEquals(List.of("REDACT:" + company + "@7"), applied(routed));
        // Partly outside it, the question can matter, and is asked.
        TextUnit wider = para("u0", "με την " + company + " Νίκος για το 2020.");
        Pass2Queue.Routed asked = route(List.of(wider), List.of(), List.of(rule(wider, "ΕΤΑΙΡΙΑ Νίκος",
                SpanCategory.POSSIBLE_PERSON, SpanAction.REVIEW)), List.of(finding(company, SpanAction.REDACT,
                SpanCategory.PRIVATE_COMPANY_NAME)));
        assertEquals(List.of("ΕΤΑΙΡΙΑ Νίκος@" + wider.normalizedText().indexOf("ΕΤΑΙΡΙΑ")), asked(asked));
    }

    /** The fallback table, row by row. */
    @Test
    void theFallbackTable() {
        Pass2Queue.Fallback redact = Pass2Queue.Fallback.of(SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON,
                SpanAction.PRESERVE);
        assertEquals(SpanAction.REDACT, redact.pass1());
        assertEquals(SpanAction.REDACT, redact.finalAction());
        Pass2Queue.Fallback conflict = Pass2Queue.Fallback.of(SpanAction.PRESERVE, SpanCategory.DATE, SpanAction.REDACT);
        assertEquals(null, conflict.pass1()); // the rules' REDACT stands
        assertEquals(SpanAction.REDACT, conflict.finalAction());
        assertTrue(conflict.conflict());
        assertEquals(SpanAction.PRESERVE, Pass2Queue.Fallback.of(SpanAction.PRESERVE, SpanCategory.DATE, null).finalAction());
        assertEquals(SpanAction.PRESERVE, Pass2Queue.Fallback.of(SpanAction.PRESERVE, SpanCategory.DATE,
                SpanAction.PRESERVE).pass1());
        assertEquals(SpanAction.REDACT, Pass2Queue.Fallback.of(null, null, SpanAction.REDACT).finalAction());
        assertEquals(SpanAction.PRESERVE, Pass2Queue.Fallback.of(null, null, SpanAction.PRESERVE).finalAction());
        assertEquals(null, Pass2Queue.Fallback.of(null, null, null).finalAction()); // only REVIEW: undecided
    }

    @Test
    void theFallbacksSpansAreLabelledAndNeverAPass2Decision() {
        TextUnit u = para("u0", "Ο " + NAME + " (-).");
        Candidate c = new Candidate("C7", NAME, SpanCategory.POSSIBLE_PERSON, List.of(), List.of(new UnitSlice("u0", 2, 23),
                new UnitSlice("u0", 24, 27)), "", "", 0, Pass2Queue.Fallback.of(SpanAction.REDACT,
                SpanCategory.POSSIBLE_PERSON, null));
        List<UnitSlice> unwritable = new java.util.ArrayList<>();
        List<Span> spans = Pass2Queue.fallbackSpans(c, Map.of("u0", u), Set.of(), unwritable);
        assertEquals(1, spans.size());
        Span s = spans.getFirst();
        assertEquals(SpanOrigin.LLM_PASS1, s.origin());
        assertEquals("llm_pass1_fallback", s.detector());
        assertEquals(NAME, s.text());
        assertEquals(List.of(new UnitSlice("u0", 24, 27)), unwritable); // "(-)" is not a value: held, not dropped
        // Nothing for pass 1 to apply: the rules' own spans stand, and nothing is written here.
        Candidate rulesOnly = new Candidate("C8", NAME, SpanCategory.POSSIBLE_PERSON, List.of(),
                List.of(new UnitSlice("u0", 2, 23)), "", "", 0, Pass2Queue.Fallback.of(null, null, SpanAction.REDACT));
        assertEquals(List.of(), Pass2Queue.fallbackSpans(rulesOnly, Map.of("u0", u), Set.of(), unwritable));
    }

    // ------------------------------------------------------------------ one document-wide queue

    static Pass2Queue.Question question(int chunk, String unit, int start, String text, String before, String after) {
        return new Pass2Queue.Question(chunk, new UnitSlice(unit, start, start + text.length()), text,
                List.of(new Recommendation(List.of("deterministic"), SpanAction.REVIEW, SpanCategory.POSSIBLE_PERSON)),
                before, after, Pass2Queue.Fallback.of(null, null, null));
    }

    /**
     * Ids are issued once, in order; only an IDENTICAL question folds (text, recommendations, both
     * windows and the fallback), across chunks too; the same name in another context stays separate.
     */
    @Test
    void theDocumentWideQueueHasStableIdsAndFoldsOnlyIdenticalQuestions() {
        List<Candidate> queue = Pass2Queue.consolidate(List.of(
                question(0, "u0", 3, "Σπύρος", "Ο ", " υπέγραψε"),
                question(2, "u9", 3, "Σπύρος", "Ο ", " υπέγραψε"), // identical, another chunk: folded
                question(1, "u4", 10, "Σπύρος", "Ο ΠΡΟΪΣΤΑΜΕΝΟΣ ", ""), // another context: its own question
                question(1, "u5", 0, "Μαρία", "", " και")));
        assertEquals(List.of("C1", "C2", "C3"), queue.stream().map(Candidate::id).toList());
        assertEquals(List.of(new UnitSlice("u0", 3, 9), new UnitSlice("u9", 3, 9)), queue.getFirst().locations());
        assertEquals(0, queue.getFirst().chunkIndex()); // where it was first seen
        assertEquals(1, queue.get(1).chunkIndex());
        // A different fallback is a different question, even at an otherwise identical place.
        Pass2Queue.Question q = question(0, "u0", 3, "Σπύρος", "Ο ", " υπέγραψε");
        Pass2Queue.Question other = new Pass2Queue.Question(1, new UnitSlice("u1", 3, 9), q.text(), q.recommendations(),
                q.before(), q.after(), Pass2Queue.Fallback.of(SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON, null));
        assertEquals(2, Pass2Queue.consolidate(List.of(q, other)).size());
        assertEquals(List.of(), Pass2Queue.consolidate(List.of()));
    }

    /**
     * Batches: at most 30, within the 7,000-token payload budget, the answers within the completion
     * limit, and (only when a model context limit is given) within what the whole request leaves; ids kept.
     */
    @Test
    void anOversizedQueueIsCutIntoBoundedBatchesKeepingEveryId() {
        assertEquals(30, Pass2Queue.PASS2_BATCH_MAX_CANDIDATES);
        assertEquals(7_000, Pass2Queue.PASS2_BATCH_TOKEN_BUDGET); // tokens, not the 7,000-character chunk size
        List<Pass2Queue.Question> questions = new java.util.ArrayList<>();
        for (int i = 0; i < 65; i++) {
            questions.add(question(0, "u" + i, 0, "Όνομα" + i, "", ""));
        }
        List<Candidate> queue = Pass2Queue.consolidate(questions);
        List<List<Candidate>> batches = Pass2Queue.batches(queue, 3000);
        assertEquals(List.of(30, 30, 5), batches.stream().map(List::size).toList());
        assertEquals(queue, batches.stream().flatMap(List::stream).toList()); // each once, in id order
        // The completion limit caps how many answers fit, never below one.
        assertEquals(30, Pass2Queue.maxCandidatesPerBatch(3000));
        assertEquals(10, Pass2Queue.maxCandidatesPerBatch(700));
        assertEquals(4, Pass2Queue.maxCandidatesPerBatch(300));
        assertEquals(1, Pass2Queue.maxCandidatesPerBatch(10));
        List<Candidate> first25 = queue.subList(0, 25);
        assertEquals(List.of(4, 4, 4, 4, 4, 4, 1), Pass2Queue.batches(first25, 300).stream().map(List::size).toList());

        // The token budget: long questions make smaller batches, and one over the budget goes alone, whole.
        String longText = "Α".repeat(3000); // ~2,000 estimated tokens of Greek alone
        List<Candidate> heavy = Pass2Queue.consolidate(List.of(question(0, "u0", 0, longText, "", ""),
                question(0, "u1", 0, longText, "x", ""), question(0, "u2", 0, longText, "y", ""),
                question(0, "u3", 0, "Ω".repeat(12000), "", ""), question(0, "u4", 0, "Μαρία", "", "")));
        List<List<Candidate>> cut = Pass2Queue.batches(heavy, 3000);
        assertTrue(cut.stream().allMatch(b -> b.size() == 1
                || b.stream().mapToInt(Pass2Queue::estimateTokens).sum() <= Pass2Queue.PASS2_BATCH_TOKEN_BUDGET), cut.toString());
        assertTrue(cut.contains(List.of(heavy.get(3))), "the oversized candidate is sent alone");
        assertEquals(heavy, cut.stream().flatMap(List::stream).toList());

        // The whole request, when a context limit is known: the window minus the fixed input and the whole
        // completion budget is what the payload may use. With none given, nothing is assumed.
        int each = Pass2Queue.estimateTokens(queue.getFirst());
        Pass2Queue.Batches windowed = Pass2Queue.batches(queue, 3000, 3000 + 1000 + 3 * each, 1000);
        assertTrue(windowed.sendable().stream().allMatch(b -> b.size() <= 3),
                windowed.sendable().stream().map(List::size).toList().toString());
        assertTrue(windowed.sendable().stream().allMatch(b -> 1000 + 3000
                + b.stream().mapToInt(Pass2Queue::estimateTokens).sum() <= 3000 + 1000 + 3 * each));
        assertEquals(queue, windowed.sendable().stream().flatMap(List::stream).toList());
        assertEquals(List.of(), windowed.unsendable());
        assertEquals(new Pass2Queue.Batches(batches, List.of()), Pass2Queue.batches(queue, 3000, 0, 1000));
        // A window too small for even one candidate sends none of them: each is returned, whole, as unsendable,
        // because that request is already known to exceed the limit.
        Pass2Queue.Batches none = Pass2Queue.batches(queue, 3000, 100, 1000);
        assertEquals(List.of(), none.sendable());
        assertEquals(queue, none.unsendable());
        // Only the candidate that cannot fit alone is held back; the rest are batched within the window.
        Pass2Queue.Batches mixed = Pass2Queue.batches(heavy, 3000, 1000 + 3000 + 3000, 1000);
        assertEquals(List.of(heavy.get(3)), mixed.unsendable());
        List<Candidate> sent = mixed.sendable().stream().flatMap(List::stream).toList();
        assertEquals(heavy.stream().filter(c -> c != heavy.get(3)).toList(), sent);
        assertTrue(mixed.sendable().stream().allMatch(b -> b.stream().mapToInt(Pass2Queue::estimateTokens).sum() <= 3000));
    }

    /** A deliberately high estimate: ASCII at three characters a token, Greek at one and a half. */
    @Test
    void theTokenEstimateIsConservativeForGreek() {
        assertEquals(1, Pass2Queue.estimateTokens("abc"));
        assertEquals(2, Pass2Queue.estimateTokens("αβγ"));
        assertEquals(0, Pass2Queue.estimateTokens(""));
        assertEquals(3, Pass2Queue.estimateTokens("ab αβ")); // 3 ASCII (1) + 2 Greek (1.33) -> 3
    }

    // ------------------------------------------------------------------ tables as work items

    static TextUnit tableCell(String id, int table, int row, int col, String text, boolean header, String title) {
        return new TextUnit(id, "word/document.xml", UnitType.TABLE_CELL, text, text, List.of(),
                new TextUnit.TableCellLocation(table, row, col, "", header, title));
    }

    /** Several small tables share one work item, each in its own block; a context window stays in its block. */
    @Test
    void smallTablesShareOneWorkItemEachInItsOwnBlock() {
        List<TextUnit> cells = List.of(tableCell("u0", 0, 0, 0, "Όνομα", true, null),
                tableCell("u1", 0, 1, 0, "Σπύρος", false, null), tableCell("u2", 1, 0, 0, "ΑΦΜ", true, null),
                tableCell("u3", 1, 1, 0, "123", false, null));
        List<Chunk> chunks = Chunk.split(new DocumentData("d", cells, List.of(), List.of()), 7000);
        assertEquals(1, chunks.size());
        Chunk.Rendered r = chunks.getFirst().render();
        assertEquals("TABLE:\nΌνομα\nΣπύρος\n\nTABLE:\nΑΦΜ\n123", r.text());
        int at = r.text().indexOf("Σπύρος");
        assertEquals(List.of(new UnitSlice("u1", 0, 6)), r.locate(at, at + 6));
        String[] window = Pass2Queue.windowsAt(r, new UnitSlice("u1", 0, 6));
        assertEquals("TABLE:\nΌνομα\n", window[0]);
        assertEquals("", window[1]); // the next table is another block: never shown as this cell's context
        assertEquals("TABLE:\nΑΦΜ\n", Pass2Queue.windowsAt(r, new UnitSlice("u3", 0, 3))[0]);
    }

    /** An empty cell has no unit, but keeps its column's place: the n-th cell is always the n-th column. */
    @Test
    void anEmptyCellKeepsItsColumnsPlace() {
        Chunk chunk = new Chunk(List.of(tableCell("u0", 0, 0, 0, "Α", true, null), tableCell("u1", 0, 0, 1, "Β", true, null),
                tableCell("u2", 0, 0, 2, "Γ", true, null), tableCell("u3", 0, 1, 0, "x", false, null),
                tableCell("u4", 0, 1, 2, "z", false, null)), true, 0);
        Chunk.Rendered r = chunk.render();
        assertEquals("TABLE:\nΑ | Β | Γ\nx |  | z", r.text());
        assertEquals(List.of(new UnitSlice("u4", 0, 1)), r.locate(r.text().length() - 1, r.text().length()));
    }

    /**
     * A table longer than a work item is cut into row groups: every cell in exactly one, at its own
     * coordinates; every group carries the table's title, and every later one a copy of its header rows,
     * both READ-ONLY: mapped to nothing, so a match on them (or across them and real text) writes nowhere.
     */
    @Test
    void aLargeTableIsSplitIntoRowGroupsWithReadOnlyContext() {
        List<TextUnit> cells = new java.util.ArrayList<>();
        cells.add(tableCell("h0", 0, 0, 0, "ΟΝΟΜΑ", true, "t"));
        cells.add(tableCell("h1", 0, 0, 1, "ΠΟΣΟ", true, "t"));
        for (int row = 1; row <= 40; row++) {
            cells.add(tableCell("a" + row, 0, row, 0, "Όνομα" + row, false, "t"));
            cells.add(tableCell("b" + row, 0, row, 1, "1.000,00", false, "t"));
        }
        List<TextUnit> units = new java.util.ArrayList<>(cells);
        units.add(para("t", "ΠΙΝΑΚΑΣ ΑΝΑΛΩΣΗΣ"));
        List<Chunk> tables = Chunk.split(new DocumentData("d", units, List.of(), List.of()), 200).stream()
                .filter(Chunk::isTable).toList();
        assertTrue(tables.size() > 1, String.valueOf(tables.size()));
        assertEquals(cells.stream().map(TextUnit::unitId).toList(),
                tables.stream().flatMap(c -> c.units().stream()).map(TextUnit::unitId).toList()); // each once, in order
        for (Chunk c : tables) {
            String text = c.render().text();
            assertTrue(text.codePointCount(0, text.length()) <= 200, text);
            assertTrue(text.contains("[context] text before the table: ΠΙΝΑΚΑΣ ΑΝΑΛΩΣΗΣ"), text);
        }
        // The first group holds the real header cells, which map to themselves.
        Chunk.Rendered first = tables.getFirst().render();
        int real = first.text().indexOf("ΟΝΟΜΑ");
        assertEquals(List.of(new UnitSlice("h0", 0, 5)), first.locate(real, real + 5));
        // A later group: the header is a copy, the title too; neither maps anywhere.
        Chunk.Rendered later = tables.get(1).render();
        assertTrue(later.text().startsWith("TABLE (continued):\n[context] text before the table: ΠΙΝΑΚΑΣ ΑΝΑΛΩΣΗΣ\n"
                + "[context] header row: ΟΝΟΜΑ | ΠΟΣΟ\n"), later.text());
        assertFalse(tables.get(1).unitIds().contains("h0"));
        int copy = later.text().indexOf("ΟΝΟΜΑ");
        assertTrue(later.inContext(copy, copy + 5));
        assertEquals(List.of(), later.locate(copy, copy + 5));
        int titleAt = later.text().indexOf("ΠΙΝΑΚΑΣ");
        assertEquals(List.of(), later.locate(titleAt, titleAt + 7));
        // A match across the copy and the first real row is no partial source match: it maps to nothing.
        int rowStart = later.text().indexOf("\nΌνομα") + 1;
        assertEquals(List.of(), later.locate(copy, rowStart + 3));
        // The windows of a real cell may show the copy (read-only), never another table.
        TextUnit firstRow = tables.get(1).units().getFirst();
        assertTrue(Pass2Queue.windowsAt(later, new UnitSlice(firstRow.unitId(), 0, 2))[0].contains("ΠΟΣΟ"));
    }

    /**
     * A row longer than a whole work item is cut between its cells, and a later part of it keeps its
     * columns: it starts with the empty places of the columns already rendered, so its cells stand under
     * their own header, not under the first columns'. Every cell is in exactly one group, at its own unit
     * and offsets.
     */
    @Test
    void aRowLongerThanAWorkItemKeepsItsColumnsInEveryGroup() {
        String a = "a".repeat(30);
        String b = "b".repeat(30);
        String c = "c".repeat(30);
        String d = "d".repeat(30);
        List<TextUnit> cells = List.of(tableCell("h0", 0, 0, 0, "A", true, null), tableCell("h1", 0, 0, 1, "B", true, null),
                tableCell("h2", 0, 0, 2, "C", true, null), tableCell("h3", 0, 0, 3, "D", true, null),
                tableCell("u0", 0, 1, 0, a, false, null), tableCell("u1", 0, 1, 1, b, false, null),
                tableCell("u2", 0, 1, 2, c, false, null), tableCell("u3", 0, 1, 3, d, false, null));
        List<Chunk> tables = Chunk.split(new DocumentData("d", cells, List.of(), List.of()), 125);
        List<String> texts = tables.stream().map(t -> t.render().text()).toList();
        assertEquals(List.of("TABLE:\nA | B | C | D",
                "TABLE (continued):\n[context] header row: A | B | C | D\n" + a + " | " + b,
                "TABLE (continued):\n[context] header row: A | B | C | D\n |  | " + c + " | " + d), texts);
        assertEquals(cells.stream().map(TextUnit::unitId).toList(),
                tables.stream().flatMap(t -> t.units().stream()).map(TextUnit::unitId).toList());
        Chunk.Rendered last = tables.getLast().render();
        String row = last.text().substring(last.text().lastIndexOf('\n') + 1);
        assertEquals(List.of("", "", c, d), List.of(row.split(" \\| ", -1)));
        int at = last.text().indexOf(c);
        assertEquals(List.of(new UnitSlice("u2", 0, 30)), last.locate(at, at + 30));
        int dAt = last.text().indexOf(d);
        assertEquals(List.of(new UnitSlice("u3", 0, 30)), last.locate(dAt, dAt + 30));
        assertEquals(List.of(), last.locate(at - 6, at)); // the empty places are synthetic: nowhere to write
    }

    /**
     * Sizes are counted, not rendered, while a table is cut: on random tables (empty cells, header rows,
     * rows longer than a work item) every work item still renders within the size unless it is one cell
     * too long on its own, every cell is in exactly one, in order, and every cell sits in its own column.
     */
    @Test
    void cuttingRandomTablesStaysWithinTheSizeAndKeepsEveryCellInItsColumn() {
        java.util.Random rnd = new java.util.Random(11);
        for (int t = 0; t < 200; t++) {
            int rows = 1 + rnd.nextInt(60);
            int cols = 1 + rnd.nextInt(7);
            int size = new int[] {80, 150, 400, 2000}[rnd.nextInt(4)];
            List<TextUnit> cells = new java.util.ArrayList<>();
            for (int r = 0; r < rows; r++) {
                for (int c = 0; c < cols; c++) {
                    if (r > 0 && rnd.nextInt(4) == 0) {
                        continue;
                    }
                    String text = "κ".repeat(1 + rnd.nextInt(t % 7 == 0 ? 200 : 25));
                    // Half the tables have a marked header row; the rest repeat their first row neutrally.
                    cells.add(tableCell("u" + cells.size(), 0, r, c, text, r == 0 && t % 2 == 0, null));
                }
            }
            List<Chunk> chunks = Chunk.split(new DocumentData("d", cells, List.of(), List.of()), size);
            assertEquals(cells.stream().map(TextUnit::unitId).toList(),
                    chunks.stream().flatMap(c -> c.units().stream()).map(TextUnit::unitId).toList());
            for (Chunk chunk : chunks) {
                Chunk.Rendered r = chunk.render();
                boolean loneOversizedCell = chunk.groups().size() == 1 && chunk.groups().getFirst().cells().size() == 1;
                assertTrue(r.text().codePointCount(0, r.text().length()) <= size || loneOversizedCell, r.text());
                for (TextUnit u : chunk.units()) {
                    int at = r.offsets().get(u.unitId());
                    int lineStart = r.text().lastIndexOf('\n', at) + 1;
                    String before = r.text().substring(lineStart, at);
                    int column = before.split(" \\| ", -1).length - 1;
                    assertEquals(((TextUnit.TableCellLocation) u.location()).colIndex(), column, r.text());
                }
            }
        }
    }

    /**
     * A table with no marked header: a later part repeats its FIRST row, read-only and labelled neutrally
     * ("first row", never "header row"), so pass 1 can tell for itself whether the table has a header and
     * where. A group that holds the first row itself does not repeat it.
     */
    @Test
    void anUnmarkedTableRepeatsItsFirstRowNeutrallyInALaterPart() {
        List<TextUnit> cells = new java.util.ArrayList<>();
        cells.add(tableCell("f0", 0, 0, 0, "Γεώργιος", false, null));
        cells.add(tableCell("f1", 0, 0, 1, "Λαμία", false, null));
        for (int row = 1; row <= 30; row++) {
            cells.add(tableCell("a" + row, 0, row, 0, "Όνομα" + row, false, null));
            cells.add(tableCell("b" + row, 0, row, 1, "Τόπος" + row, false, null));
        }
        List<Chunk> tables = Chunk.split(new DocumentData("d", cells, List.of(), List.of()), 150);
        assertTrue(tables.size() > 1);
        String first = tables.getFirst().render().text();
        assertTrue(first.startsWith("TABLE:\nΓεώργιος | Λαμία\n"), first); // the first part holds the row itself
        assertFalse(first.contains("[context]"), first);
        Chunk.Rendered later = tables.get(1).render();
        assertTrue(later.text().startsWith("TABLE (continued):\n[context] first row: Γεώργιος | Λαμία\n"), later.text());
        assertFalse(later.text().contains("header row"), later.text());
        int copy = later.text().indexOf("Γεώργιος");
        assertTrue(later.inContext(copy, copy + 8));
        assertEquals(List.of(), later.locate(copy, copy + 8)); // read-only: nothing can be written to it
        assertEquals(cells.stream().map(TextUnit::unitId).toList(),
                tables.stream().flatMap(c -> c.units().stream()).map(TextUnit::unitId).toList());
    }

    /** A pass-1 quote of read-only context alone is not written and not held: its real text is judged where it stands. */
    @Test
    void aQuoteOfReadOnlyContextIsNeitherWrittenNorHeld() {
        List<TextUnit> cells = new java.util.ArrayList<>();
        cells.add(tableCell("h0", 0, 0, 0, "ΕΠΩΝΥΜΟ", true, null));
        for (int row = 1; row <= 30; row++) {
            cells.add(tableCell("a" + row, 0, row, 0, "Τιμή" + row, false, null));
        }
        List<Chunk> tables = Chunk.split(new DocumentData("d", cells, List.of(), List.of()), 120);
        Chunk later = tables.get(1);
        Chunk.Rendered rendered = later.render();
        Map<String, TextUnit> source = new LinkedHashMap<>();
        cells.forEach(u -> source.put(u.unitId(), u));
        Pass2Queue.Routed routed = Pass2Queue.route(1, later, List.of(), List.of(), List.of(
                finding("ΕΠΩΝΥΜΟ", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON),
                finding("Κάτι που δεν υπάρχει", SpanAction.REDACT, SpanCategory.POSSIBLE_PERSON)), rendered,
                HardDecisions.NONE, POLICY, source, Set.of());
        assertTrue(Pass2Queue.onlyInContext(rendered, "ΕΠΩΝΥΜΟ"));
        assertEquals(List.of(), applied(routed));
        assertEquals(List.of(), asked(routed));
        // Only the quote that is nowhere at all is held as unlocatable.
        assertEquals(List.of("Κάτι που δεν υπάρχει"), routed.unlocated().stream().map(LlmDetector.Finding::text).toList());
    }

    // ------------------------------------------------------------------ the official signatory in routing

    /** The signatory's name is never part of a question; what is left of a wider proposal is still asked. */
    @Test
    void theSignatoryNameIsNeverPartOfAQuestion() {
        TextUnit u = para("u0", "ΕπανεξέτασηςΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ");
        Span signatory = rule(u, "ΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ", SpanCategory.OFFICIAL_SIGNATORY, SpanAction.PRESERVE, 0.95);
        assertTrue(Resolver.isHardPreserve(signatory, POLICY));
        Pass2Queue.Routed routed = route(List.of(u), List.of(signatory), List.of(rule(u, "ΕπανεξέτασηςΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ",
                SpanCategory.POSSIBLE_PERSON, SpanAction.REVIEW)), List.of(finding("ΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ", SpanAction.REDACT,
                SpanCategory.POSSIBLE_PERSON)));
        assertEquals(List.of("Επανεξέτασης@0"), asked(routed));
        assertEquals(List.of(), applied(routed)); // pass 1's REDACT of the name has nothing left to write
        assertEquals(List.of(), routed.unresolved()); // and is not a redaction that went missing
    }
}
