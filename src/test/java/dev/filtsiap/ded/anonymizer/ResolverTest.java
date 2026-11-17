package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class ResolverTest {

    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();

    static TextUnit unit(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static DocumentData doc(String text) {
        return new DocumentData("d", List.of(unit("u0", text)), List.of(), List.of());
    }

    /** A deterministic (rule-engine) candidate. */
    static Span rule(int s, int e, SpanCategory c, double conf, SpanAction a) {
        return new Span("u0", s, e, "", c, "test", conf, a, "", SpanOrigin.DETERMINISTIC);
    }

    /** A pass-2 decision, at the fixed confidence LlmDetector gives every one. */
    static Span pass2(int s, int e, SpanCategory c, SpanAction a) {
        return new Span("u0", s, e, "", c, "llm_pass2", 0.9, a, "", SpanOrigin.LLM_PASS2);
    }

    /** Each resolved run as ACTION:CATEGORY:origin:'text'. */
    static List<String> runs(String text, Span... candidates) {
        return Resolver.resolveRedactions(doc(text), List.of(candidates), POLICY).spans().stream()
                .map(s -> s.action() + ":" + s.category() + ":" + s.origin().wire() + ":'" + s.text() + "'")
                .toList();
    }

    // ------------------------------------------------------------------ hard policy

    @Test
    void hardRedactBeatsHardPreserve() {
        assertEquals(List.of("PRESERVE:LEGAL_REF:deterministic:'01'", "REDACT:AFM:deterministic:'234'",
                        "PRESERVE:LEGAL_REF:deterministic:'56789'"),
                runs("0123456789", rule(0, 10, SpanCategory.LEGAL_REF, 0.95, SpanAction.PRESERVE),
                        rule(2, 5, SpanCategory.AFM, 1.0, SpanAction.REDACT)));
    }

    @Test
    void hardPreserveIsConfidenceIndependentAndBeatsOrdinaryRedact() {
        assertEquals(List.of("PRESERVE:LEGAL_REF:deterministic:'0123456789'"),
                runs("0123456789", rule(0, 10, SpanCategory.LEGAL_REF, 0.1, SpanAction.PRESERVE),
                        rule(2, 5, SpanCategory.APPELLANT_NAME, 0.9, SpanAction.REDACT)));
    }

    @Test
    void repositoryPolicyIsV2sWithPublicLocalityAndTheOfficialSignatoryAsTheNewHardPreserves() {
        // Two deliberate differences from v2. PUBLIC_LOCALITY (new gold), the public geography the rules
        // positively identify, is a hard PRESERVE. OFFICIAL_SIGNATORY is too: the final signatory's name,
        // positively identified after a signing title, is never redacted and never a pass-2 question. The
        // generic LOCALITY is in neither list: v2 lists it as hard REDACT for the toponym after an
        // authority cue, which the new gold keeps.
        assertEquals(Set.of("DOU", "PUBLIC_SERVICE", "LEGAL_REF", "MONEY", "TAX_YEAR", "ARTICLE_REF",
                "COURT_DECISION", "DECISION_METADATA", "PERCENTAGE", "FISCAL_PERIOD", "FIELD_LABEL",
                "PROCEDURAL_DATE", "PUBLIC_LOCALITY", "OFFICIAL_SIGNATORY"), POLICY.hardPreserveCategories());
        assertEquals(Set.of("AFM", "AMKA", "IBAN", "EMAIL", "PROPERTY_ID"), POLICY.hardRedactCategories());
    }

    // ------------------------------------------------------------------ A: date of birth

    @Test
    void genericDateIsOrdinaryEvidenceThatPass2CanRedact() {
        String text = "Ημερομηνία γέννησης 01/02/1980";
        Span date = rule(20, 30, SpanCategory.DATE, 0.95, SpanAction.PRESERVE);
        assertFalse(Resolver.isHardPreserve(date, POLICY));
        assertEquals(Resolver.TIER_PRESERVE_CONFIDENT, Resolver.priority(date, POLICY));
        assertEquals(List.of("REDACT:DATE:llm_pass2:'01/02/1980'"),
                runs(text, date, pass2(20, 30, SpanCategory.DATE, SpanAction.REDACT)));
        // With no pass-2 answer the rule still holds the date, and an ordinary REDACT cannot take it.
        assertEquals(List.of("PRESERVE:DATE:deterministic:'01/02/1980'"),
                runs(text, date, rule(20, 30, SpanCategory.APPELLANT_NAME, 0.9, SpanAction.REDACT)));
    }

    @Test
    void proceduralDateIsAHardPreservePass2CannotRedact() {
        Span date = rule(22, 32, SpanCategory.PROCEDURAL_DATE, 0.95, SpanAction.PRESERVE);
        assertTrue(Resolver.isHardPreserve(date, POLICY));
        assertEquals(List.of("PRESERVE:PROCEDURAL_DATE:deterministic:'15/03/2026'"),
                runs("ημερομηνία κατάθεσης: 15/03/2026", date, pass2(22, 32, SpanCategory.DATE, SpanAction.REDACT)));
    }

    // ------------------------------------------------------------------ B: category escalation

    @Test
    void pass2NeverReachesAHardTierWhateverCategoryItReturns() {
        for (SpanCategory category : SpanCategory.values()) {
            Span preserve = pass2(0, 5, category, SpanAction.PRESERVE);
            Span redact = new Span("u0", 0, 5, "", category, "llm_pass2", 1.0, SpanAction.REDACT, "",
                    SpanOrigin.LLM_PASS2);
            assertFalse(Resolver.isHardPreserve(preserve, POLICY), category.wire());
            assertFalse(Resolver.isHardRedact(redact, POLICY), category.wire());
            assertEquals(Resolver.TIER_PASS2_PRESERVE, Resolver.priority(preserve, POLICY), category.wire());
            assertEquals(Resolver.TIER_PASS2_REDACT, Resolver.priority(redact, POLICY), category.wire());
        }
    }

    /** A pass-1 decision applied without a question, at the confidence the router gives every one. */
    static Span pass1(int s, int e, SpanCategory c, SpanAction a) {
        return new Span("u0", s, e, "", c, "llm_pass1", 0.8, a, "", SpanOrigin.LLM_PASS1);
    }

    @Test
    void pass1NeverReachesAHardTierWhateverCategoryItReturns() {
        for (SpanCategory category : SpanCategory.values()) {
            Span preserve = pass1(0, 5, category, SpanAction.PRESERVE);
            Span redact = new Span("u0", 0, 5, "", category, "llm_pass1", 1.0, SpanAction.REDACT, "",
                    SpanOrigin.LLM_PASS1);
            assertFalse(Resolver.isHardPreserve(preserve, POLICY), category.wire());
            assertFalse(Resolver.isHardRedact(redact, POLICY), category.wire());
            assertEquals(Resolver.TIER_PASS1_PRESERVE, Resolver.priority(preserve, POLICY), category.wire());
            assertEquals(Resolver.TIER_PASS1_REDACT, Resolver.priority(redact, POLICY), category.wire());
        }
    }

    /**
     * Where pass 1 sits on the ladder: under hard policy and under every pass-2 answer; its REDACT over
     * every ordinary rule span (the fail-safe direction), its PRESERVE under every ordinary rule REDACT.
     */
    @Test
    void pass1DecisionsRankBetweenPass2AndTheOrdinaryRulesFailSafe() {
        String text = "0123456789";
        // Hard policy keeps its precedence over pass 1.
        assertEquals(List.of("PRESERVE:LEGAL_REF:deterministic:'0123456789'"),
                runs(text, rule(0, 10, SpanCategory.LEGAL_REF, 0.5, SpanAction.PRESERVE),
                        pass1(0, 10, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT)));
        assertEquals(List.of("REDACT:AFM:deterministic:'0123456789'"),
                runs(text, rule(0, 10, SpanCategory.AFM, 0.95, SpanAction.REDACT),
                        pass1(0, 10, SpanCategory.DATE, SpanAction.PRESERVE)));
        // A pass-2 answer at exactly the pass-1 slice governs it, either way.
        assertEquals(List.of("PRESERVE:DATE:llm_pass2:'0123456789'"),
                runs(text, pass1(0, 10, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT),
                        pass2(0, 10, SpanCategory.DATE, SpanAction.PRESERVE)));
        assertEquals(List.of("REDACT:POSSIBLE_PERSON:llm_pass2:'0123456789'"),
                runs(text, pass1(0, 10, SpanCategory.DATE, SpanAction.PRESERVE),
                        pass2(0, 10, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT)));
        // A pass-2 PRESERVE of a fragment still cannot carve a pass-1 REDACT it was not answering.
        assertEquals(List.of("REDACT:POSSIBLE_PERSON:llm_pass1:'0123456789'"),
                runs(text, pass1(0, 10, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT),
                        pass2(3, 6, SpanCategory.DATE, SpanAction.PRESERVE)));
        // Pass-1 REDACT over the most confident ordinary PRESERVE; pass-1 PRESERVE under any ordinary REDACT.
        assertEquals(List.of("REDACT:POSSIBLE_PERSON:llm_pass1:'0123456789'"),
                runs(text, rule(0, 10, SpanCategory.DATE, 1.0, SpanAction.PRESERVE),
                        pass1(0, 10, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT)));
        assertEquals(List.of("REDACT:APPELLANT_NAME:deterministic:'0123456789'"),
                runs(text, rule(0, 10, SpanCategory.APPELLANT_NAME, 0.7, SpanAction.REDACT),
                        pass1(0, 10, SpanCategory.DATE, SpanAction.PRESERVE)));
        // Against nothing, each is applied as it is.
        assertEquals(List.of("PRESERVE:DATE:llm_pass1:'0123456789'"),
                runs(text, pass1(0, 10, SpanCategory.DATE, SpanAction.PRESERVE)));
        assertEquals(List.of("PRESERVE:DATE:llm_pass1:'0123456789'"),
                runs(text, rule(0, 10, SpanCategory.DATE, 0.1, SpanAction.PRESERVE),
                        pass1(0, 10, SpanCategory.DATE, SpanAction.PRESERVE)));
        // Pass 1 against itself: REDACT over PRESERVE.
        assertEquals(List.of("REDACT:POSSIBLE_PERSON:llm_pass1:'0123456789'"),
                runs(text, pass1(0, 10, SpanCategory.DATE, SpanAction.PRESERVE),
                        pass1(0, 10, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT)));
    }

    /** What the rules alone decide at a place: the resolver's own ladder, thresholds included. */
    @Test
    void theRulesOwnDecisionIsTheLaddersAndIgnoresLlmSpans() {
        assertEquals(SpanAction.PRESERVE, Resolver.deterministicAction(List.of(
                rule(0, 5, SpanCategory.APPELLANT_NAME, 0.75, SpanAction.REDACT),
                rule(0, 5, SpanCategory.DATE, 0.85, SpanAction.PRESERVE)), POLICY)); // confident preserve > redact
        assertEquals(SpanAction.REDACT, Resolver.deterministicAction(List.of(
                rule(0, 5, SpanCategory.DATE, 0.5, SpanAction.PRESERVE),
                rule(0, 5, SpanCategory.APPELLANT_NAME, 0.75, SpanAction.REDACT)), POLICY));
        // Below its threshold a REDACT claims nothing, so it decides nothing (it is not turned into REVIEW).
        assertEquals(null, Resolver.deterministicAction(List.of(
                rule(0, 5, SpanCategory.APPELLANT_NAME, 0.6, SpanAction.REDACT)), POLICY));
        assertEquals(null, Resolver.deterministicAction(List.of(pass1(0, 5, SpanCategory.AFM, SpanAction.REDACT),
                pass2(0, 5, SpanCategory.AFM, SpanAction.REDACT)), POLICY));
        assertEquals(null, Resolver.deterministicAction(List.of(), POLICY));
    }

    @Test
    void pass2DatePreserveRanksAsAPass2DecisionNotAsHardPolicy() {
        String name = "ΝΙΚΟΣ ΠΑΠΑΔΟΠΟΥΛΟΣ";
        Span wrong = pass2(0, 18, SpanCategory.DATE, SpanAction.PRESERVE);
        // v2 semantics: pass 2 adjudicates ORDINARY evidence, so its answer stands over an ordinary
        // APPELLANT_NAME rule span — at the pass-2 tier, recorded as a pass-2 decision.
        assertEquals(List.of("PRESERVE:DATE:llm_pass2:'" + name + "'"),
                runs(name, rule(0, 18, SpanCategory.APPELLANT_NAME, 0.9, SpanAction.REDACT), wrong));
        // Labelling it DATE bought nothing: deterministic hard policy still outranks it.
        assertEquals(List.of("REDACT:PROPERTY_ID:deterministic:'" + name + "'"),
                runs(name, rule(0, 18, SpanCategory.PROPERTY_ID, 1.0, SpanAction.REDACT), wrong));
    }

    // ------------------------------------------------------------------ C: hard redact

    @Test
    void confidentAfmSurvivesAnyPass2Preserve() {
        String text = "ΑΦΜ " + TestDocx.validAfm("09401420");
        for (SpanCategory claimed : List.of(SpanCategory.AFM, SpanCategory.POSSIBLE_PERSON, SpanCategory.PUBLIC_SERVICE,
                SpanCategory.FIELD_LABEL)) {
            assertEquals(List.of("REDACT:AFM:deterministic:'" + text.substring(4) + "'"),
                    runs(text, rule(4, 13, SpanCategory.AFM, 1.0, SpanAction.REDACT),
                            pass2(4, 13, claimed, SpanAction.PRESERVE)), claimed.wire());
        }
    }

    @Test
    void hardRedactStatusMustBeEarnedWithConfidence() {
        // A failed checksum (0.75) is ordinary evidence, which a pass-2 PRESERVE settles.
        assertEquals(List.of("PRESERVE:POSSIBLE_PERSON:llm_pass2:'123456789'"),
                runs("ΑΦΜ 123456789", rule(4, 13, SpanCategory.AFM, 0.75, SpanAction.REDACT),
                        pass2(4, 13, SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE)));
    }

    // ------------------------------------------------------------------ D: hard preserve

    @Test
    void fieldLabelSurvivesAPass2RedactThatQuotesItWithTheValue() {
        String afm = TestDocx.validAfm("09401420");
        String text = "με Α.Φ.Μ. " + afm;
        List<String> runs = runs(text, rule(3, 9, SpanCategory.FIELD_LABEL, 1.0, SpanAction.PRESERVE),
                rule(10, 19, SpanCategory.AFM, 1.0, SpanAction.REDACT),
                pass2(0, 19, SpanCategory.AFM, SpanAction.REDACT));
        assertTrue(runs.contains("PRESERVE:FIELD_LABEL:deterministic:'Α.Φ.Μ.'"), runs.toString());
        assertTrue(runs.contains("REDACT:AFM:deterministic:'" + afm + "'"), runs.toString());
    }

    @Test
    void hardPreserveSurvivesAPass2RedactLabelledAsAHardRedactCategory() {
        assertEquals(List.of("PRESERVE:DOU:deterministic:'ΔΟΥ Χαλκίδας'"),
                runs("ΔΟΥ Χαλκίδας", rule(0, 12, SpanCategory.DOU, 0.95, SpanAction.PRESERVE),
                        pass2(0, 12, SpanCategory.AFM, SpanAction.REDACT)));
    }

    // ------------------------------------------------------------------ E: ordinary preserve

    @Test
    void pass2OverridesOrdinaryDeterministicPreserve() {
        assertEquals(List.of("REDACT:CASE_COURT_REFERENCE:llm_pass2:'231'"),
                runs("231/2020", rule(0, 3, SpanCategory.CASE_COURT_REFERENCE, 0.85, SpanAction.PRESERVE),
                        pass2(0, 3, SpanCategory.CASE_COURT_REFERENCE, SpanAction.REDACT)));
        // Formerly hard in Java: an authority header is now a recommendation pass 2 can overrule.
        assertEquals(List.of("REDACT:POSSIBLE_PERSON:llm_pass2:'Νίκος'"),
                runs("Νίκος", rule(0, 5, SpanCategory.PUBLIC_AUTHORITY_HEADER, 1.0, SpanAction.PRESERVE),
                        pass2(0, 5, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT)));
    }

    // ------------------------------------------------------------------ fallback evidence

    @Test
    void ruleSpansKeepTheCharactersNoPass2DecisionReached() {
        assertEquals(List.of("REDACT:POSSIBLE_PERSON:llm_pass2:'ΝΙΚΟΣ'",
                        "REDACT:APPELLANT_NAME:deterministic:' ΠΑΠΑΔΟΠΟΥΛΟΣ'"),
                runs("ΝΙΚΟΣ ΠΑΠΑΔΟΠΟΥΛΟΣ", rule(0, 18, SpanCategory.APPELLANT_NAME, 0.9, SpanAction.REDACT),
                        pass2(0, 5, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT)));
    }

    // ------------------------------------------------------------------ G: a PRESERVE never carves a REDACT it did not answer

    @Test
    void anExactSlicePass2PreserveStillCorrectsAnOrdinaryRuleRedact() {
        // Pass 2 answering the rule span's own candidate: the false positive is corrected.
        assertEquals(List.of("PRESERVE:PRIVATE_ADDRESS:llm_pass2:'Ιερά Οδός'"),
                runs("Ιερά Οδός", rule(0, 9, SpanCategory.FATHER_NAME, 0.85, SpanAction.REDACT),
                        pass2(0, 9, SpanCategory.PRIVATE_ADDRESS, SpanAction.PRESERVE)));
    }

    @Test
    void aNestedPass2PreserveCannotCarveALargerRedact() {
        String company = "ACME TRADING LTD";
        assertEquals(List.of("REDACT:PRIVATE_COMPANY_NAME:deterministic:'" + company + "'"),
                runs(company, rule(0, 16, SpanCategory.PRIVATE_COMPANY_NAME, 0.85, SpanAction.REDACT),
                        pass2(0, 12, SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE)));
        // A pass-2 REDACT is protected the same way: five fragments answered PRESERVE leave no island.
        Span[] fragments = {pass2(0, 16, SpanCategory.PRIVATE_COMPANY_NAME, SpanAction.REDACT),
            pass2(0, 4, SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE),
            pass2(5, 12, SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE),
            pass2(13, 16, SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE)};
        assertEquals(List.of("REDACT:PRIVATE_COMPANY_NAME:llm_pass2:'" + company + "'"), runs(company, fragments));
    }

    @Test
    void aPartlyOverlappingPass2PreserveExposesNoPartOfARedactedValue() {
        // "της Ιεράς" was a wrong patronymic that pass 2 PRESERVEd at its own slice; "Ιεράς Οδού" is a
        // REDACT it did not answer. The article stays, as the correction says; the street stays whole.
        String text = "της Ιεράς Οδού";
        assertEquals(List.of("PRESERVE:FATHER_NAME:llm_pass2:'της '", "REDACT:PRIVATE_ADDRESS:llm_pass2:'Ιεράς Οδού'"),
                runs(text, rule(0, 9, SpanCategory.FATHER_NAME, 0.85, SpanAction.REDACT),
                        pass2(0, 9, SpanCategory.FATHER_NAME, SpanAction.PRESERVE),
                        pass2(4, 14, SpanCategory.PRIVATE_ADDRESS, SpanAction.REDACT)));
        // A WIDER preserve is no different: it cannot take the REDACT it surrounds.
        assertEquals(List.of("PRESERVE:POSSIBLE_PERSON:llm_pass2:'της '", "REDACT:PRIVATE_ADDRESS:deterministic:'Ιεράς'",
                        "PRESERVE:POSSIBLE_PERSON:llm_pass2:' Οδού'"),
                runs(text, rule(4, 9, SpanCategory.PRIVATE_ADDRESS, 0.85, SpanAction.REDACT),
                        pass2(0, 14, SpanCategory.POSSIBLE_PERSON, SpanAction.PRESERVE)));
    }

    @Test
    void withoutThePass2PreserveTheRestOfTheLadderDecidesAsBefore() {
        // A date inside a wide rule REDACT is kept by the ordinary date rule (tier 3 over tier 2), with
        // or without a pass-2 PRESERVE on it: the rule removes only the PRESERVE's carving power.
        String text = "ΔΑ 1136/23-06-2026";
        List<String> expected = List.of("REDACT:INVOICE_TABLE_ID:deterministic:'1136/'",
                "PRESERVE:DATE:deterministic:'23-06-2026'");
        Span invoice = rule(3, 18, SpanCategory.INVOICE_TABLE_ID, 0.85, SpanAction.REDACT);
        Span date = rule(8, 18, SpanCategory.DATE, 0.95, SpanAction.PRESERVE);
        assertEquals(expected, runs(text, invoice, date));
        assertEquals(expected, runs(text, invoice, date, pass2(8, 18, SpanCategory.DATE, SpanAction.PRESERVE)));
    }

    @Test
    void hardPolicyIsUntouchedByTheOverlapRule() {
        // A hard preserve still carves an ordinary REDACT, and a hard redact still beats any preserve.
        assertEquals(List.of("REDACT:APPELLANT_NAME:llm_pass2:'Ο '", "PRESERVE:FIELD_LABEL:deterministic:'ΑΦΜ'"),
                runs("Ο ΑΦΜ", pass2(0, 5, SpanCategory.APPELLANT_NAME, SpanAction.REDACT),
                        rule(2, 5, SpanCategory.FIELD_LABEL, 1.0, SpanAction.PRESERVE)));
        assertEquals(List.of("REDACT:PROPERTY_ID:deterministic:'0123456789'"),
                runs("0123456789", rule(0, 10, SpanCategory.PROPERTY_ID, 1.0, SpanAction.REDACT),
                        pass2(0, 10, SpanCategory.PROPERTY_ID, SpanAction.PRESERVE),
                        pass2(2, 5, SpanCategory.MONEY, SpanAction.PRESERVE)));
    }

    // ------------------------------------------------------------------ the ordinary tiers

    static int tier(SpanCategory category, double confidence, SpanAction action) {
        return Resolver.priority(rule(0, 1, category, confidence, action), POLICY);
    }

    @Test
    void ordinaryTiersFollowTheV2Ladder() {
        assertEquals(Resolver.TIER_HARD_REDACT, tier(SpanCategory.AFM, 0.9, SpanAction.REDACT));
        assertEquals(Resolver.TIER_REDACT, tier(SpanCategory.AFM, 0.89, SpanAction.REDACT));
        assertEquals(Resolver.TIER_IGNORED, tier(SpanCategory.AFM, 0.69, SpanAction.REDACT));
        assertEquals(Resolver.TIER_PRESERVE_CONFIDENT, tier(SpanCategory.DATE, 0.8, SpanAction.PRESERVE));
        assertEquals(Resolver.TIER_PRESERVE, tier(SpanCategory.DATE, 0.79, SpanAction.PRESERVE));
        // The structured tier is reached only when policy does not already make the category hard,
        // and there it outranks a confident ordinary PRESERVE (v2 order; old Java had it below).
        PolicySettings noHardRedacts = new PolicySettings(0.8, 0.9, 0.7, POLICY.hardPreserveCategories(), Set.of());
        Span email = rule(0, 1, SpanCategory.EMAIL, 0.95, SpanAction.REDACT);
        assertEquals(Resolver.TIER_STRUCTURED_REDACT, Resolver.priority(email, noHardRedacts));
        assertTrue(Resolver.incomingReplacesExisting(email, rule(0, 1, SpanCategory.DATE, 0.95, SpanAction.PRESERVE),
                noHardRedacts));
    }

    @Test
    void overlappingPass2AnswersKeepTheRedactWhole() {
        // Was PRESERVE over REDACT (v2): a pass-2 PRESERVE at another slice may no longer carve it.
        assertEquals(List.of("REDACT:APPELLANT_NAME:llm_pass2:'Ο ΝΙΚΟΣ'"),
                runs("Ο ΝΙΚΟΣ", pass2(0, 7, SpanCategory.APPELLANT_NAME, SpanAction.REDACT),
                        pass2(2, 7, SpanCategory.OFFICIAL_SIGNATORY, SpanAction.PRESERVE)));
    }

    // ------------------------------------------------------------------ F: input order

    @Test
    void planDoesNotDependOnCandidateOrder() {
        // Ties sit at the WINNING tiers — same geometry, confidence and tier, differing only in
        // category or detector — so only the total ordering can make the recorded owner stable.
        List<Span> candidates = List.of(
                rule(0, 10, SpanCategory.DATE, 0.95, SpanAction.PRESERVE),
                new Span("u0", 0, 10, "", SpanCategory.DATE, "other_detector", 0.95, SpanAction.PRESERVE, "",
                        SpanOrigin.DETERMINISTIC),
                rule(0, 10, SpanCategory.CASE_COURT_REFERENCE, 0.95, SpanAction.PRESERVE),
                pass2(2, 6, SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT),
                pass2(2, 6, SpanCategory.APPELLANT_NAME, SpanAction.REDACT),
                rule(2, 6, SpanCategory.APPELLANT_NAME, 0.9, SpanAction.REDACT));
        Set<List<Span>> plans = new HashSet<>();
        for (int seed = 0; seed < 100; seed++) {
            List<Span> shuffled = new ArrayList<>(candidates);
            Collections.shuffle(shuffled, new Random(seed));
            plans.add(Resolver.resolveRedactions(doc("abcdefghij"), shuffled, POLICY).spans());
        }
        assertEquals(1, plans.size(), plans.stream().map(Object::toString).collect(Collectors.joining("\n")));
    }

    // ------------------------------------------------------------------ plan shape

    @Test
    void outputIsOrderedLikePythonStrings() {
        DocumentData doc = new DocumentData("d", List.of(unit("u2", "abc"), unit("u10", "abc")), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, List.of(
                new Span("u2", 0, 3, "", SpanCategory.EMAIL, "test", 0.95, SpanAction.REDACT, "",
                        SpanOrigin.DETERMINISTIC),
                new Span("u10", 0, 3, "", SpanCategory.EMAIL, "test", 0.95, SpanAction.REDACT, "",
                        SpanOrigin.DETERMINISTIC)), POLICY);
        assertEquals(List.of("u10", "u2"), plan.spans().stream().map(Span::unitId).toList());
    }

    @Test
    void inconsistencyWarningNeverQuotesText() {
        DocumentData doc = new DocumentData("d", List.of(unit("u0", "Νίκος"), unit("u1", "νίκος")), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, List.of(
                new Span("u0", 0, 5, "Νίκος", SpanCategory.POSSIBLE_PERSON, "t", 0.9, SpanAction.REDACT, "",
                        SpanOrigin.DETERMINISTIC),
                new Span("u1", 0, 5, "νίκος", SpanCategory.DATE, "t", 0.95, SpanAction.PRESERVE, "",
                        SpanOrigin.DETERMINISTIC)), POLICY);
        assertEquals(1, plan.warnings().size());
        assertEquals(false, plan.warnings().get(0).contains("ίκος"));
    }

    @Test
    void reviewSpansAreAProgrammingError() {
        assertThrows(IllegalStateException.class, () -> Resolver.resolveRedactions(doc("x"),
                List.of(rule(0, 1, SpanCategory.PHONE, 0.9, SpanAction.REVIEW)), POLICY));
    }
}
