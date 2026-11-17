package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidates;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.ChatRequest;
import dev.filtsiap.ded.anonymizer.llm.LlmDetector;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * THE POSTCHECK OUTCOME POLICY for HIGH textual residuals: a HIGH finding the scan made is settled
 * only by an actual redaction; a PRESERVE from pass 2 is written as decided but keeps the finding in
 * front of a person. MEDIUM findings keep v2's semantics. All values are synthetic.
 *
 * <p>To reach the scan with a HIGH value, the rule that would have caught it in the first pass is
 * narrowed until it matches nothing (a detector gap, which is exactly what the audit exists for),
 * and the first pass-2 call PRESERVEs whatever it is asked.
 */
class HighResidualPolicyTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));
    static final String AFM = TestDocx.validAfm("13579246");
    static final String IBAN = TestDocx.validGreekIban("01101230000012345678901");
    static final String EMAIL = "n.p@example.com";
    static final String PHONE = "6912345678";

    ListAppender<ILoggingEvent> logs;
    ch.qos.logback.classic.Logger root;

    @BeforeEach
    void captureLogs() {
        root = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        root.addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        root.detachAppender(logs);
    }

    /** The repository's rules with the named detectors narrowed until they match nothing. */
    static FileConfig without(String... rules) {
        Map<String, Map<String, String>> patterns = new LinkedHashMap<>(FILES.rules().patterns());
        for (String rule : rules) {
            patterns.put(rule, Map.of("body", "(\\d{9})(?=ΧΧΧ)"));
        }
        DetectorRules r = FILES.rules();
        return new FileConfig(FILES.policy(), new DetectorRules(patterns, r.douAllowlist(), r.publicServices(),
                r.legalRefs(), r.preserveEmailDomains(), r.regions(), r.preserveFamilies(), r.givenNames(),
                r.surnames()), FILES.injectionRules(), FILES.configSha256());
    }

    static final FileConfig GAPS = without("afm", "iban", "email");

    /** Pass 1 finds nothing; the first pass 2 PRESERVEs every candidate; the remediation answers {@code remediate}. */
    static ScriptedLlm model(Function<ChatRequest, List<?>> remediate) {
        return new ScriptedLlm(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return "[]";
            }
            if (ScriptedLlm.isRemediation(r)) {
                return PyJson.dumps(remediate.apply(r));
            }
            return PyJson.dumps(candidates(r).stream().map(c -> answer((String) c.get("id"), "PRESERVE", "PHONE"))
                    .toList());
        });
    }

    /** The remediation answers {@code action} for every candidate it is asked about. */
    static ScriptedLlm everyResidual(String action) {
        return model(r -> candidates(r).stream().map(c -> answer((String) c.get("id"), action, "AFM")).toList());
    }

    static AnonymizeResult run(String paragraph, FileConfig files, ScriptedLlm llm) {
        return Pipeline.anonymizeDocument(TestDocx.paragraphs(paragraph).bytes(), CFG, files, llm,
                RunContext.start(300, "high", System::nanoTime));
    }

    static String body(AnonymizeResult r) {
        return TestDocx.part(r.redactedDocx(), "word/document.xml");
    }

    static List<UnresolvedFinding.Kind> kinds(AnonymizeResult r) {
        return r.unresolved().stream().map(UnresolvedFinding::kind).toList();
    }

    // ------------------------------------------------------------------ 1-4: HIGH + REDACT / PRESERVE

    @Test
    void aHighAfmResidualThatPass2RedactsIsRedactedAndProcessed() {
        AnonymizeResult r = run("Ο κωδικός " + AFM + " στο μητρώο.", GAPS, everyResidual("REDACT"));
        assertTrue(r.warnings().contains("post-redaction scan: 1 finding(s) {'residual_afm': 1}"), r.warnings().toString());
        assertEquals(null, r.postcheck().byKind().get("residual_afm")); // the final scan of the returned bytes
        assertTrue(body(r).contains("Ο κωδικός ......... στο μητρώο."), body(r));
        assertEquals("processed", r.status());
        assertEquals(List.of(), r.unresolved());
    }

    @Test
    void aHighAfmResidualThatPass2PreservesStaysAsDecidedAndNeedsReview() {
        AnonymizeResult r = run("Ο κωδικός " + AFM + " στο μητρώο.", GAPS, everyResidual("PRESERVE"));
        assertTrue(body(r).contains(AFM), body(r)); // the model said PRESERVE, and the document says so too
        assertEquals("needs-review", r.status());
        assertEquals(1, r.unresolvedCount());
        UnresolvedFinding open = r.unresolved().get(0);
        assertEquals(UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED, open.kind());
        assertEquals("AFM", open.category());
        assertEquals("C1", open.candidateId());
        int at = "Ο κωδικός ".length();
        assertEquals(List.of(new UnitSlice("u0", at, at + 9)), open.locations()); // where, in the redacted parse
        // The structured provenance of the scan finding it came from, carried through the remediation.
        assertEquals(List.of(new UnresolvedFinding.AuditRef("P1", PostcheckFinding.Severity.HIGH, "residual_afm",
                "word/document.xml:u0")), open.audit());
        assertTrue(r.warnings().contains("1 HIGH post-redaction finding(s) are still visible after remediation "
                + "(preserved by LLM pass 2, or not fully redacted); this document needs human review"),
                r.warnings().toString());
    }

    @Test
    void aHighIbanResidualThatPass2PreservesNeedsReview() {
        AnonymizeResult r = run("Ο κωδικός " + IBAN + " στο μητρώο.", GAPS, everyResidual("PRESERVE"));
        assertEquals(1, r.postcheck().byKind().get("residual_iban"));
        assertTrue(body(r).contains(IBAN), body(r));
        assertEquals("needs-review", r.status());
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED), kinds(r));
        assertEquals("residual_iban", r.unresolved().get(0).audit().get(0).kind());
    }

    @Test
    void aHighEmailResidualThatPass2PreservesNeedsReview() {
        AnonymizeResult r = run("Επικοινωνία στο " + EMAIL + " για ενημέρωση.", GAPS, everyResidual("PRESERVE"));
        assertEquals(1, r.postcheck().byKind().get("residual_email"));
        assertTrue(body(r).contains(EMAIL), body(r));
        assertEquals("needs-review", r.status());
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED), kinds(r));
        assertEquals("EMAIL", r.unresolved().get(0).category());
    }

    // ------------------------------------------------------------------ 5: MEDIUM keeps v2's semantics

    @Test
    void aMediumResidualThatPass2PreservesIsSettledByThatAnswerAsBefore() {
        AnonymizeResult r = run("Επικοινωνία στο κινητό " + PHONE + " για ενημέρωση.", FILES,
                everyResidual("PRESERVE"));
        assertEquals(1, r.postcheck().byKind().get("phone_shape"));
        assertTrue(body(r).contains(PHONE));
        assertEquals("processed", r.status());
        assertEquals(List.of(), r.unresolved());
    }

    // ------------------------------------------------------------------ 6: HIGH + undecided

    @Test
    void aHighResidualLeftUndecidedAfterTheCorrectiveRetryNeedsReviewOnceWithItsProvenance() {
        ScriptedLlm silent = model(r -> List.of()); // the first ask and its corrective retry both answer nothing
        AnonymizeResult r = run("Ο κωδικός " + AFM + " στο μητρώο.", GAPS, silent);
        assertEquals(2, silent.requests.stream().filter(ScriptedLlm::isRemediation).count());
        assertEquals("needs-review", r.status());
        // Exactly one finding for the one residual: the adjudication's own, not a second HIGH one.
        assertEquals(List.of(UnresolvedFinding.Kind.CANDIDATE_UNDECIDED), kinds(r));
        assertEquals(PostcheckFinding.Severity.HIGH, r.unresolved().get(0).audit().get(0).severity());
        assertTrue(body(r).contains(AFM)); // nothing was invented for it
    }

    // ------------------------------------------------------------------ REDACT that hard policy did not let through

    @Test
    void aHighResidualKeptByHardPolicyIsThatPolicyDecisionAndStillNeedsReview() {
        // A decision number is a hard DECISION_METADATA preserve over its digits; these nine digits also
        // pass the AFM checksum, so the scan reports a HIGH residual_afm. The carried hard preserve covers
        // it whole, so the remediation applies the first adjudication's policy: it is that decision, not a
        // question, and the model is not asked. The value is still visible, and a HIGH finding with
        // neither a redaction nor a person is what this rule forbids.
        ScriptedLlm llm = everyResidual("REDACT");
        AnonymizeResult r = run("Αριθμός Απόφασης: " + AFM, without("afm"), llm);
        assertEquals(1, r.postcheck().byKind().get("residual_afm"));
        assertEquals(0, llm.requests.stream().filter(ScriptedLlm::isRemediation).count());
        assertTrue(body(r).contains(AFM), body(r));
        assertEquals("needs-review", r.status());
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED), kinds(r));
        assertTrue(r.unresolved().get(0).detail().endsWith("(residual_afm) is kept visible by hard policy; a person "
                + "must confirm it may stay visible"), r.unresolved().get(0).detail());
        assertEquals(PostcheckFinding.Severity.HIGH, r.unresolved().get(0).audit().get(0).severity());
    }

    @Test
    void aHighResidualNeverPutToPass2StaysOpen() {
        Span span = new Span("u7", 0, 9, AFM, SpanCategory.AFM, "postcheck_residual_afm", 1.0, SpanAction.REVIEW, "",
                SpanOrigin.DETERMINISTIC);
        LlmDetector.Residual residual = new LlmDetector.Residual(new UnresolvedFinding.AuditRef("P4",
                PostcheckFinding.Severity.HIGH, "residual_afm", "word/document.xml:u7"), span);
        LlmDetector.Residual medium = new LlmDetector.Residual(new UnresolvedFinding.AuditRef("P5",
                PostcheckFinding.Severity.MEDIUM, "phone_shape", "word/document.xml:u7"), span);
        UnitSlice slice = new UnitSlice("u7", 0, 9);
        List<UnresolvedFinding> open = Pipeline.unsettledHighResiduals(List.of(
                new LlmDetector.ResidualOutcome(residual, -1,
                        List.of(new LlmDetector.FragmentOutcome(slice, null, null, null))),
                new LlmDetector.ResidualOutcome(medium, -1,
                        List.of(new LlmDetector.FragmentOutcome(slice, null, null, null)))), null, List.of());
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED),
                open.stream().map(UnresolvedFinding::kind).toList());
        assertEquals("HIGH post-redaction finding P4 (residual_afm) could not be put to LLM pass 2",
                open.get(0).detail());
    }

    // ------------------------------------------------------------------ residual -> fragments -> ids -> decisions

    static TextUnit unit(String text) {
        return new TextUnit("u0", "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static Span over(TextUnit unit, String text, SpanCategory category, SpanAction action, double confidence,
                     String detector) {
        int start = unit.normalizedText().indexOf(text);
        return new Span(unit.unitId(), start, start + text.length(), text, category, detector, confidence, action, "",
                SpanOrigin.DETERMINISTIC);
    }

    static LlmDetector.Residual residualAt(TextUnit unit, String text, SpanCategory category, String kind,
                                           PostcheckFinding.Severity severity, String id) {
        return new LlmDetector.Residual(new UnresolvedFinding.AuditRef(id, severity, kind, "word/document.xml:u0"),
                over(unit, text, category, SpanAction.REVIEW, 1.0, "postcheck_" + kind));
    }

    static UnitSlice sliceOf(LlmDetector.Residual residual) {
        return new UnitSlice(residual.span().unitId(), residual.span().start(), residual.span().end());
    }

    static LlmDetector.Remediation remediate(TextUnit unit, List<LlmDetector.Residual> residuals,
                                             List<Span> hardRedacts, List<Span> hardPreserves, ScriptedLlm llm) {
        return LlmDetector.runPass2Remediation(new DocumentData("d", List.of(unit), List.of(), List.of()), residuals,
                List.of(), hardRedacts, hardPreserves, llm, CFG, FILES.rules().regions(), RunContext.start(300));
    }

    static ScriptedLlm redactingEveryCandidate(String category) {
        return new ScriptedLlm(r -> PyJson.dumps(candidates(r).stream()
                .map(c -> answer((String) c.get("id"), "REDACT", category)).toList()));
    }

    static ScriptedLlm neverAsked() {
        return new ScriptedLlm(r -> {
            throw new AssertionError("a place hard policy settled was put to the model");
        });
    }

    /**
     * Masking cuts one residual into fragments; each surviving fragment becomes a candidate of its own,
     * and both answers come back to the ONE residual. Its coverage counts what the hard redaction had
     * already blanked together with what the remediation redacted.
     */
    @Test
    void aResidualMaskingSplitsIsDecidedPartByPartAndJudgedWhole() {
        TextUnit u = unit("Λογαριασμός ΩΨ123456783ΦΧ τέλος.");
        Span hard = over(u, "123456783", SpanCategory.AFM, SpanAction.REDACT, 0.95, "afm");
        LlmDetector.Residual residual = residualAt(u, "ΩΨ123456783ΦΧ", SpanCategory.BANK_ACCOUNT, "account_leak",
                PostcheckFinding.Severity.HIGH, "P1");
        ScriptedLlm llm = redactingEveryCandidate("BANK_ACCOUNT");
        LlmDetector.Remediation out = remediate(u, List.of(residual), List.of(hard), List.of(), llm);

        assertEquals(1, llm.requests.size());
        assertFalse(llm.requests.get(0).userMessage().contains("123456783"));
        assertEquals(List.of("ΩΨ", "ΦΧ"), candidates(llm.requests.get(0)).stream().map(c -> c.get("text")).toList());
        int start = u.normalizedText().indexOf("ΩΨ");
        LlmDetector.ResidualOutcome outcome = out.outcomes().get(0);
        assertEquals(residual, outcome.residual()); // the audit reference stays with every part of it
        assertEquals(List.of(
                new LlmDetector.FragmentOutcome(new UnitSlice("u0", start, start + 2), "C1", SpanAction.REDACT, null),
                new LlmDetector.FragmentOutcome(new UnitSlice("u0", start + 2, start + 11), null, SpanAction.REDACT,
                        LlmDetector.SettledBy.HARD_REDACT),
                new LlmDetector.FragmentOutcome(new UnitSlice("u0", start + 11, start + 13), "C2", SpanAction.REDACT,
                        null)), outcome.fragments());
        assertEquals(SpanAction.REDACT, outcome.decision());
        assertEquals(List.of("C1", "C2"), outcome.candidateIds());

        DocumentData doc = new DocumentData("d", List.of(u), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, out.spans(), FILES.policy());
        assertEquals(List.of(), Pipeline.unsettledHighResiduals(out.outcomes(), plan, List.of(hard)));
        // Without the redaction that was already there, the same answers would not cover the value.
        List<UnresolvedFinding> uncovered = Pipeline.unsettledHighResiduals(out.outcomes(), plan, List.of());
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED),
                uncovered.stream().map(UnresolvedFinding::kind).toList());
        assertEquals("C1,C2", uncovered.get(0).candidateId());
        assertEquals(List.of(new UnitSlice("u0", start, start + 13)), uncovered.get(0).locations()); // the original slice
    }

    @Test
    void anUndecidedFragmentIsUnresolvedWithItsResidualsAuditReference() {
        TextUnit u = unit("Λογαριασμός ΩΨ123456783ΦΧ τέλος.");
        Span hard = over(u, "123456783", SpanCategory.AFM, SpanAction.REDACT, 0.95, "afm");
        LlmDetector.Residual residual = residualAt(u, "ΩΨ123456783ΦΧ", SpanCategory.BANK_ACCOUNT, "account_leak",
                PostcheckFinding.Severity.HIGH, "P1");
        // C1 is decided; C2 is never answered, not even by the corrective retry.
        ScriptedLlm llm = new ScriptedLlm(r -> PyJson.dumps(ScriptedLlm.isRetry(r) ? List.of()
                : List.of(answer("C1", "REDACT", "BANK_ACCOUNT"))));
        LlmDetector.Remediation out = remediate(u, List.of(residual), List.of(hard), List.of(), llm);

        assertEquals(2, out.pass2Calls());
        assertEquals(1, out.unresolved().size());
        UnresolvedFinding open = out.unresolved().get(0);
        assertEquals(UnresolvedFinding.Kind.CANDIDATE_UNDECIDED, open.kind());
        assertEquals("C2", open.candidateId());
        assertEquals(List.of(residual.ref()), open.audit()); // attributed though the fragment is not the residual's slice
        LlmDetector.ResidualOutcome outcome = out.outcomes().get(0);
        assertEquals(null, outcome.decision());
        assertTrue(outcome.considered());
        // Already in front of a person through the adjudication: not reported twice.
        assertEquals(List.of(), Pipeline.unsettledHighResiduals(out.outcomes(), null, List.of(hard)));
    }

    /**
     * The remediation applies the same hard policy as the first adjudication: a residual a carried hard
     * preserve covers whole is that policy decision, recorded as such, never put to the model and never
     * described as a missing adjudication. A HIGH one still needs a person: it stays visible.
     */
    @Test
    void aResidualAHardPreserveCoversWholeIsAPolicyDecisionNotAQuestion() {
        TextUnit u = unit("Η ΔΟΥ Κέρκυρας εξέδωσε την πράξη.");
        Span dou = over(u, "ΔΟΥ Κέρκυρας", SpanCategory.DOU, SpanAction.PRESERVE, 0.95, "dou_gazetteer");
        assertTrue(Resolver.isHardPreserve(dou, FILES.policy()));
        LlmDetector.Residual high = residualAt(u, "Κέρκυρας", SpanCategory.POSSIBLE_PERSON, "person_name_leak",
                PostcheckFinding.Severity.HIGH, "P2");
        LlmDetector.Residual medium = residualAt(u, "Κέρκυρας", SpanCategory.POSSIBLE_PERSON, "person_name_leak",
                PostcheckFinding.Severity.MEDIUM, "P3");
        ScriptedLlm llm = neverAsked();
        LlmDetector.Remediation out = remediate(u, List.of(high, medium), List.of(), List.of(dou), llm);

        assertEquals(0, llm.requests.size());
        assertEquals(0, out.pass2Calls());
        assertEquals(List.of(), out.candidateIds());
        assertEquals(List.of(), out.unresolved());
        for (LlmDetector.ResidualOutcome outcome : out.outcomes()) {
            assertEquals(List.of(new LlmDetector.FragmentOutcome(sliceOf(high), null, SpanAction.PRESERVE,
                    LlmDetector.SettledBy.HARD_PRESERVE)), outcome.fragments());
            assertTrue(outcome.preservedByPolicy());
            assertTrue(outcome.considered());
        }
        List<UnresolvedFinding> open = Pipeline.unsettledHighResiduals(out.outcomes(), null, List.of());
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED),
                open.stream().map(UnresolvedFinding::kind).toList());
        assertEquals("HIGH post-redaction finding P2 (person_name_leak) is kept visible by hard policy; a person must "
                + "confirm it may stay visible", open.get(0).detail());

        // A residual the hard preserve only touches is still a question.
        LlmDetector.Residual wider = residualAt(u, "Κέρκυρας εξέδωσε", SpanCategory.POSSIBLE_PERSON, "person_name_leak",
                PostcheckFinding.Severity.MEDIUM, "P4");
        ScriptedLlm asked = redactingEveryCandidate("POSSIBLE_PERSON");
        remediate(u, List.of(wider), List.of(), List.of(dou), asked);
        assertEquals(List.of("Κέρκυρας εξέδωσε"), candidates(asked.requests.get(0)).stream().map(c -> c.get("text"))
                .toList());
    }

    /** A residual a hard redaction already blanked whole is redacted by policy: no question, and covered. */
    @Test
    void aResidualAHardRedactionCoversWholeIsAlreadyRedacted() {
        TextUnit u = unit("ΑΦΜ " + AFM + " εδώ.");
        Span hard = over(u, AFM, SpanCategory.AFM, SpanAction.REDACT, 0.95, "afm");
        LlmDetector.Residual residual = residualAt(u, AFM, SpanCategory.AFM, "residual_afm",
                PostcheckFinding.Severity.HIGH, "P5");
        ScriptedLlm llm = neverAsked();
        LlmDetector.Remediation out = remediate(u, List.of(residual), List.of(hard), List.of(), llm);
        assertEquals(0, llm.requests.size());
        assertEquals(List.of(new LlmDetector.FragmentOutcome(sliceOf(residual), null, SpanAction.REDACT,
                LlmDetector.SettledBy.HARD_REDACT)), out.outcomes().get(0).fragments());
        assertEquals(List.of(), Pipeline.unsettledHighResiduals(out.outcomes(), null, List.of(hard)));
    }

    // ------------------------------------------------------------------ the final scan

    @Test
    void theFinalScanAuditsTheReturnedBytesOnceWithoutAModelAndCountsNothingTwice() {
        // Two residuals: pass 2 keeps the AFM and redacts the phone, so the document is rewritten and
        // scanned again. The AFM the final scan still sees is the one already in front of a person.
        ScriptedLlm llm = model(r -> candidates(r).stream().map(c -> answer((String) c.get("id"),
                AFM.equals(c.get("text")) ? "PRESERVE" : "REDACT", AFM.equals(c.get("text")) ? "AFM" : "PHONE"))
                .toList());
        AnonymizeResult r = run("Ο κωδικός " + AFM + " και το κινητό " + PHONE + " εδώ.", GAPS, llm);
        assertFalse(body(r).contains(PHONE), body(r));
        assertTrue(body(r).contains(AFM), body(r));
        assertEquals(1, r.postcheck().byKind().get("residual_afm")); // the returned bytes, after the correction
        assertEquals(null, r.postcheck().byKind().get("phone_shape"));
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED), kinds(r));
        assertEquals(3, llm.requests.size()); // pass 1, pass 2, one remediation; the final scan asked nobody
        assertEquals(1, logs.list.stream().filter(e -> e.getFormattedMessage().startsWith("stage=final_scan ")).count());
    }

    @Test
    void aHighValueOnlyTheFinalScanSeesIsHeldForAPerson() {
        ResidualSpan seen = new ResidualSpan("u3", 4, 13, AFM, SpanCategory.AFM);
        PostcheckFinding high = new PostcheckFinding(PostcheckFinding.Severity.HIGH, "residual_afm",
                "word/document.xml:u3", "valid-checksum 9-digit AFM survives", seen);
        PostcheckFinding medium = new PostcheckFinding(PostcheckFinding.Severity.MEDIUM, "phone_shape",
                "word/document.xml:u3", "Greek phone-shaped number survives", new ResidualSpan("u3", 20, 30, PHONE,
                        SpanCategory.PHONE));
        List<UnresolvedFinding> added = Pipeline.highResidualsNotYetOpen(List.of(medium, high), List.of());
        assertEquals(1, added.size());
        assertEquals(UnresolvedFinding.Kind.HIGH_RESIDUAL_UNREDACTED, added.get(0).kind());
        assertEquals(List.of(new UnitSlice("u3", 4, 13)), added.get(0).locations());
        assertEquals("F2", added.get(0).audit().get(0).findingId()); // its place in the final scan
        assertFalse(added.get(0).toString().contains(AFM));
        // Already in front of a person at that slice: not reported twice.
        UnresolvedFinding open = new UnresolvedFinding(0, UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED, "AFM",
                List.of(new UnitSlice("u3", 4, 13)), "C1", "kept",
                List.of(new UnresolvedFinding.AuditRef("P1", PostcheckFinding.Severity.HIGH,
                        "residual_afm", "word/document.xml:u3")));
        assertEquals(List.of(), Pipeline.highResidualsNotYetOpen(List.of(high), List.of(open)));
        UnresolvedFinding partial = new UnresolvedFinding(0, open.kind(), "AFM", List.of(new UnitSlice("u3", 4, 5)),
                "C1", "partial", open.audit());
        assertEquals(1, Pipeline.highResidualsNotYetOpen(List.of(high), List.of(partial)).size());
    }

    // ------------------------------------------------------------------ 7: structural HIGH still fails closed

    @Test
    void aNonTextHighFindingStillFailsClosedBeforeAnyRemediation() {
        byte[] docx = TestDocx.paragraphs("Ο κωδικός " + AFM + " στο μητρώο.")
                .put("word/vbaProject.bin", "synthetic macro payload").bytes();
        ScriptedLlm llm = everyResidual("PRESERVE");
        ResidualPIIError e = assertThrows(ResidualPIIError.class, () -> Pipeline.anonymizeDocument(docx, CFG, GAPS, llm,
                RunContext.start(300)));
        assertTrue(e.getMessage().contains("macro_part_survived@word/vbaProject.bin"), e.getMessage());
        assertEquals(0, llm.requests.stream().filter(ScriptedLlm::isRemediation).count());
        assertFalse(e.getMessage().contains(AFM));
    }

    // ------------------------------------------------------------------ 8: nothing quotes the value

    @Test
    void noHighValueReachesALogLineAnUnresolvedFindingOrASummary() {
        List<String> rendered = new ArrayList<>();
        for (String paragraph : List.of("Ο κωδικός " + AFM + " στο μητρώο.", "Ο κωδικός " + IBAN + " στο μητρώο.",
                "Επικοινωνία στο " + EMAIL + " για ενημέρωση.")) {
            AnonymizeResult r = run(paragraph, GAPS, everyResidual("PRESERVE"));
            assertEquals("needs-review", r.status());
            r.unresolved().forEach(f -> rendered.add(f.toString()));
            r.unresolved().forEach(f -> rendered.add(PyJson.dumps(f.asMap())));
            rendered.addAll(r.warnings());
            rendered.add(PyJson.dumps(r.postcheck().asMap()));
            rendered.add(PyJson.dumps(r.accounting().asMap()));
            rendered.add(r.accounting().logFields());
        }
        AnonymizeResult undecided = run("Ο κωδικός " + AFM + " στο μητρώο.", GAPS, model(q -> List.of()));
        undecided.unresolved().forEach(f -> rendered.add(f.toString()));
        logs.list.forEach(ev -> rendered.add(ev.getFormattedMessage()));
        assertTrue(rendered.size() > 20);
        for (String line : rendered) {
            for (String secret : List.of(AFM, IBAN, EMAIL, "example.com")) {
                assertFalse(line.contains(secret), line);
            }
        }
    }
}
