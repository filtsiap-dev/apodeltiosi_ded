package dev.filtsiap.ded.anonymizer.llm;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidates;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.SpanOrigin;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.anonymizer.RunContext;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The request-local document-wide decision registry. All names and numbers are invented. */
class DecisionRegistryTest {

    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));

    static TextUnit para(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static Span span(TextUnit unit, String text, SpanCategory category, SpanAction action, double confidence,
                     SpanOrigin origin) {
        int start = unit.normalizedText().indexOf(text);
        return new Span(unit.unitId(), start, start + text.length(), text, category, "t", confidence, action, "", origin);
    }

    static Span llm(TextUnit unit, String text, SpanCategory category, SpanAction action) {
        return span(unit, text, category, action, 0.9, SpanOrigin.LLM_PASS2);
    }

    @Test
    void valuesAreClassifiedForReuseAndAnLlmPreserveNeverBecomesGlobal() {
        TextUnit u = para("u0", "Ο Νίκος Παππάς, η ΚΑΠΑ ΛΑΜΔΑ, ο Μάρκος, 01/02/2020, ΑΦΜ 123456783, ΔΟΥ Κέρκυρας, Φορολογική Διοίκηση.");
        List<Span> rules = List.of(span(u, "123456783", SpanCategory.AFM, SpanAction.REDACT, 1.0, SpanOrigin.DETERMINISTIC),
                span(u, "Φορολογική Διοίκηση", SpanCategory.PUBLIC_SERVICE, SpanAction.PRESERVE, 1.0, SpanOrigin.DETERMINISTIC));
        List<Span> decisions = List.of(llm(u, "Νίκος Παππάς", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT),
                llm(u, "ΚΑΠΑ ΛΑΜΔΑ", SpanCategory.PRIVATE_COMPANY_NAME, SpanAction.REDACT),
                llm(u, "Μάρκος", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT),
                llm(u, "01/02/2020", SpanCategory.DATE, SpanAction.REDACT),
                llm(u, "ΔΟΥ Κέρκυρας", SpanCategory.DOU, SpanAction.PRESERVE));
        DecisionRegistry registry = DecisionRegistry.of(rules, decisions, POLICY);
        assertEquals(DecisionRegistry.Reuse.GLOBAL_REDACT, registry.classification("Νίκος Παππάς"));
        assertEquals(DecisionRegistry.Reuse.GLOBAL_REDACT, registry.classification("ΝΙΚΟΣ ΠΑΠΠΑΣ")); // case, accents
        assertEquals(DecisionRegistry.Reuse.CONTEXT_DEPENDENT, registry.classification("Νίκου Παππά")); // another form
        assertEquals(DecisionRegistry.Reuse.GLOBAL_REDACT, registry.classification("ΚΑΠΑ ΛΑΜΔΑ"));
        assertEquals(DecisionRegistry.Reuse.GLOBAL_REDACT, registry.classification("123456783")); // a verified identifier
        assertEquals(DecisionRegistry.Reuse.CONTEXT_DEPENDENT, registry.classification("Μάρκος")); // one word
        assertEquals(DecisionRegistry.Reuse.CONTEXT_DEPENDENT, registry.classification("01/02/2020")); // a date
        assertEquals(DecisionRegistry.Reuse.CONTEXT_DEPENDENT, registry.classification("ΔΟΥ Κέρκυρας")); // LLM PRESERVE
        assertEquals(DecisionRegistry.Reuse.GLOBAL_PRESERVE, registry.classification("Φορολογική Διοίκηση")); // hard rule
    }

    @Test
    void aConflictOrAHardPreservedValueIsNeverReusedAndTheResultDoesNotDependOnOrder() {
        TextUnit a = para("u1", "η προσφυγή του Νίκος Παππάς");
        TextUnit b = para("u2", "υπογράφει ο Νίκος Παππάς");
        Span redact = llm(a, "Νίκος Παππάς", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT);
        Span keep = llm(b, "Νίκος Παππάς", SpanCategory.OFFICIAL_SIGNATORY, SpanAction.PRESERVE);
        assertEquals(DecisionRegistry.Reuse.CONTEXT_DEPENDENT,
                DecisionRegistry.of(List.of(), List.of(redact, keep), POLICY).classification("Νίκος Παππάς"));
        assertEquals(DecisionRegistry.Reuse.CONTEXT_DEPENDENT,
                DecisionRegistry.of(List.of(), List.of(keep, redact), POLICY).classification("Νίκος Παππάς"));
        // A value the hard preserve rules keep vetoes a global REDACT of the same words.
        TextUnit c = para("u3", "Φορολογική Διοίκηση");
        Span kept = span(c, "Φορολογική Διοίκηση", SpanCategory.PUBLIC_SERVICE, SpanAction.PRESERVE, 1.0,
                SpanOrigin.DETERMINISTIC);
        Span wrong = llm(c, "Φορολογική Διοίκηση", SpanCategory.PRIVATE_COMPANY_NAME, SpanAction.REDACT);
        assertNull(DecisionRegistry.of(List.of(kept), List.of(wrong), POLICY).globalRedact("Φορολογική Διοίκηση"));
        // The official signatory's name is not a GLOBAL_PRESERVE value: no whitelist of names.
        Span signatory = span(b, "Νίκος Παππάς", SpanCategory.OFFICIAL_SIGNATORY, SpanAction.PRESERVE, 0.95,
                SpanOrigin.DETERMINISTIC);
        assertEquals(DecisionRegistry.Reuse.GLOBAL_REDACT,
                DecisionRegistry.of(List.of(signatory), List.of(redact), POLICY).classification("Νίκος Παππάς"));
    }

    @Test
    void aGlobalRedactIsAppliedAtEveryOtherWholeWordOccurrenceWithItsRealAuthority() {
        TextUnit a = para("u1", "η προσφυγή του Νίκος Παππάς");
        TextUnit b = para("u2", "ο ΝΙΚΟΣ ΠΑΠΠΑΣ πλήρωσε");
        TextUnit c = para("u3", "ο Νίκος Παππάςογλου και ο Νίκος Παππάς");
        TextUnit d = para("u4", "υπογράφει ο Νίκος Παππάς");
        Span decided = llm(a, "Νίκος Παππάς", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT);
        Span signatory = span(d, "Νίκος Παππάς", SpanCategory.OFFICIAL_SIGNATORY, SpanAction.PRESERVE, 0.95,
                SpanOrigin.DETERMINISTIC);
        HardDecisions hard = HardDecisions.of(List.of(signatory), POLICY);
        List<Span> reused = DecisionRegistry.of(List.of(signatory), List.of(decided), POLICY)
                .applyEverywhere(List.of(a, b, c, d), hard, List.of(decided));
        // Not again at its own place, not inside a longer word, never over the signatory; elsewhere, whole words.
        assertEquals(List.of("u2:2:ΝΙΚΟΣ ΠΑΠΠΑΣ", "u3:" + c.normalizedText().lastIndexOf("Νίκος") + ":Νίκος Παππάς"),
                reused.stream().map(s -> s.unitId() + ":" + s.start() + ":" + s.text()).toList());
        assertTrue(reused.stream().allMatch(s -> s.origin() == SpanOrigin.LLM_PASS2 && s.action() == SpanAction.REDACT
                && s.category() == SpanCategory.POSSIBLE_PERSON && s.detector().startsWith("registry_reuse:")));
        // A place with its own PRESERVE decision keeps it.
        Span ownPreserve = llm(b, "ΝΙΚΟΣ ΠΑΠΠΑΣ", SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE);
        List<Span> respecting = DecisionRegistry.of(List.of(), List.of(decided), POLICY)
                .applyEverywhere(List.of(a, b), HardDecisions.NONE, List.of(decided, ownPreserve));
        assertEquals(List.of(), respecting);
    }

    /**
     * Registering and searching share one definition of the same value: case, accents and final sigma
     * fold, and any run of horizontal whitespace between two words is one gap. A line break is not, another
     * grammatical form is not, a longer word is not, and hard policy still keeps its places.
     */
    @Test
    void equivalentWhitespaceIsTheSameValueButNotAnotherFormOrALineBreak() {
        TextUnit a = para("u1", "η προσφυγή του Νίκος  Παππάς");
        TextUnit b = para("u2", "ο ΝΙΚΟΣ ΠΑΠΠΑΣ πλήρωσε");
        TextUnit c = para("u3", "ο Νίκος\tΠαππάς και ο νίκος  παππάς");
        TextUnit d = para("u4", "ο Νίκου Παππά, ο Νίκος Παππάσογλου, ο Νίκος\nΠαππάς");
        TextUnit e = para("u5", "😀 Νίκος Παππάς");
        TextUnit f = para("u6", "υπογράφει ο Νίκος   Παππάς");
        Span decided = llm(a, "Νίκος  Παππάς", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT);
        Span signatory = span(f, "Νίκος   Παππάς", SpanCategory.OFFICIAL_SIGNATORY, SpanAction.PRESERVE, 0.95,
                SpanOrigin.DETERMINISTIC);
        List<Span> reused = DecisionRegistry.of(List.of(signatory), List.of(decided), POLICY)
                .applyEverywhere(List.of(a, b, c, d, e, f), HardDecisions.of(List.of(signatory), POLICY),
                        List.of(decided));
        assertEquals(List.of("u2:2:ΝΙΚΟΣ ΠΑΠΠΑΣ", "u3:2:Νίκος\tΠαππάς", "u3:21:νίκος  παππάς",
                        "u5:2:Νίκος Παππάς"),
                reused.stream().map(s -> s.unitId() + ":" + s.start() + ":" + s.text()).toList());
        // Code points, not UTF-16 units: the emoji before the name is one place.
        Span afterEmoji = reused.getLast();
        assertEquals(2 + 12, afterEmoji.end());
    }

    /** A company name's punctuation is literal: a dot, a bracket, a plus sign never act as a pattern. */
    @Test
    void aRegisteredValuesPunctuationIsLiteral() {
        TextUnit a = para("u1", "η εταιρεία Α.Β.Γ. (ΕΛΛΑΣ) Α.Ε. και η ΧΧΧ+ΥΥΥ & ΣΙΑ Ο.Ε. προσέφυγαν");
        TextUnit b = para("u2", "η Α.Β.Γ. (ΕΛΛΑΣ)\t Α.Ε., η ΑxΒxΓx (ΕΛΛΑΣ) Α.Ε., η Α.Β.Γ. ΕΛΛΑΣ Α.Ε., η ΧΧΧΧΥΥΥ & ΣΙΑ Ο.Ε., "
                + "η χχχ+υυυ  &  σια ο.ε.");
        Span first = llm(a, "Α.Β.Γ. (ΕΛΛΑΣ) Α.Ε.", SpanCategory.PRIVATE_COMPANY_NAME, SpanAction.REDACT);
        Span second = llm(a, "ΧΧΧ+ΥΥΥ & ΣΙΑ Ο.Ε.", SpanCategory.PRIVATE_COMPANY_NAME, SpanAction.REDACT);
        List<Span> reused = DecisionRegistry.of(List.of(), List.of(first, second), POLICY)
                .applyEverywhere(List.of(a, b), HardDecisions.NONE, List.of(first, second));
        assertEquals(List.of("Α.Β.Γ. (ΕΛΛΑΣ)\t Α.Ε.", "χχχ+υυυ  &  σια ο.ε."), reused.stream().map(Span::text).toList());
    }

    /**
     * End to end: pass 1 redacts a complete name in one place; the same name, flagged elsewhere only by a
     * rule hint, is answered by that decision (no pass-2 question), and a third, unflagged occurrence is
     * redacted too, through the ordinary span list.
     */
    @Test
    void aConfirmedNameIsReusedForItsOtherOccurrencesWithoutAnotherQuestion() {
        TextUnit first = para("u0", "Η προσφυγή του Ζυλφίκ Κραντάρ εξετάστηκε.");
        TextUnit flagged = para("u1", "Ο Ζυλφίκ Κραντάρ προσκόμισε στοιχεία.");
        TextUnit unflagged = para("u2", "Τα στοιχεία του Ζυλφίκ Κραντάρ.");
        int at = flagged.normalizedText().indexOf("Ζυλφίκ");
        Span hint = new Span("u1", at, at + 14, "Ζυλφίκ Κραντάρ", SpanCategory.POSSIBLE_PERSON, "greek_name_shape", 0.45,
                SpanAction.REVIEW, "", SpanOrigin.DETERMINISTIC);
        String pass1 = PyJson.dumps(List.of(Map.of("text", "Ζυλφίκ Κραντάρ", "action", "REDACT", "category", "PERSON")));
        ScriptedLlm llm = new ScriptedLlm(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return r.userMessage().contains("εξετάστηκε") ? pass1 : "[]";
            }
            return PyJson.dumps(candidates(r).stream().map(c -> answer((String) c.get("id"), "REDACT", "POSSIBLE_PERSON"))
                    .toList());
        });
        DocumentData doc = new DocumentData("d", List.of(first, flagged, unflagged), List.of(), List.of());
        RuntimeConfig small = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_CHUNK_SIZE_CHARS", "45"));
        LlmDetector.Result result = LlmDetector.runLlmDetection(doc, List.of(), List.of(hint), new LlmDetector.Provider(
                llm, small, millis -> { }, RunContext.start(300), () -> 0.5), POLICY, Set.of());
        assertEquals(0, llm.requests.stream().filter(r -> !ScriptedLlm.isPass1(r)).count()); // no pass-2 question
        List<String> redacted = result.spans().stream().filter(s -> s.action() == SpanAction.REDACT)
                .map(s -> s.unitId() + ":" + s.text() + ":" + s.origin()).toList();
        assertTrue(redacted.contains("u1:Ζυλφίκ Κραντάρ:LLM_PASS1"), redacted.toString());
        assertTrue(redacted.contains("u2:Ζυλφίκ Κραντάρ:LLM_PASS1"), redacted.toString());
        assertEquals(List.of(), result.unresolved());
    }
}
