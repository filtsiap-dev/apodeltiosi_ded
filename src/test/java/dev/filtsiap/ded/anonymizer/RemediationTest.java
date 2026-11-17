package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidates;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
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
 * The post-redaction remediation, end to end on synthetic documents: scan -> pass 2 -> resolver
 * -> second apply, once. Every first pass here PRESERVEs whatever pass 2 is asked about, which is
 * how a residual reaches the scan; the remediation call is answered separately.
 */
class RemediationTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));
    static final String PHONE = "6912345678";
    static final String NAME = "Γεώργιου Παπαδόπουλου";

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

    List<String> lines() {
        return logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    /** Pass 1 finds nothing; first-pass pass 2 PRESERVEs every candidate; the remediation answers {@code remediate}. */
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

    static AnonymizeResult run(byte[] docx, FileConfig files, LlmClient llm) {
        return Pipeline.anonymizeDocument(docx, CFG, files, llm, RunContext.start(300, "rem", System::nanoTime));
    }

    static String body(AnonymizeResult r) {
        return TestDocx.part(r.redactedDocx(), "word/document.xml");
    }

    static List<ChatRequest> remediationCalls(ScriptedLlm llm) {
        return llm.requests.stream().filter(ScriptedLlm::isRemediation).toList();
    }

    static long pass1Calls(ScriptedLlm llm) {
        return llm.requests.stream().filter(ScriptedLlm::isPass1).count();
    }

    /** The rules with the AFM detector narrowed until it can match nothing: a detector gap the audit must catch. */
    static FileConfig withoutAfmRule() {
        Map<String, Map<String, String>> patterns = new LinkedHashMap<>(FILES.rules().patterns());
        patterns.put("afm", Map.of("body", "(\\d{9})(?=ΧΧΧ)"));
        DetectorRules r = FILES.rules();
        return new FileConfig(FILES.policy(), new DetectorRules(patterns, r.douAllowlist(), r.publicServices(),
                r.legalRefs(), r.preserveEmailDomains(), r.regions(), r.preserveFamilies(), r.givenNames(),
                r.surnames()), FILES.injectionRules(), FILES.configSha256());
    }

    static final String REMEDIATED = "post-redaction remediation: 1 residual finding(s) were re-adjudicated by LLM "
            + "pass 2 and 1 further redaction(s) applied; the returned document was scanned again, deterministically, "
            + "and the result's scan describes it";
    static final String REMEDIATED_NOTHING = "post-redaction remediation: 1 residual finding(s) were re-adjudicated "
            + "by LLM pass 2 and 0 further redaction(s) applied";

    // ------------------------------------------------------------------ remediable findings

    @Test
    void aResidualAfmIsReAskedOnceAndTheReturnedBytesAreScannedAgainWithoutAModel() {
        String afm = TestDocx.validAfm("09401420");
        byte[] docx = TestDocx.paragraphs("Ο κωδικός " + afm + " στο μητρώο.").bytes();
        ScriptedLlm llm = model(r -> List.of(answer("C1", "REDACT", "AFM")));
        AnonymizeResult r = run(docx, withoutAfmRule(), llm);

        assertTrue(body(r).contains("Ο κωδικός ......... στο μητρώο."), body(r));
        assertEquals("processed", r.status());
        // The HIGH residual was a question, not a failure. The post-redaction scan found it; the final
        // scan of the returned bytes, which is what the result carries, no longer does.
        assertTrue(r.warnings().contains("post-redaction scan: 1 finding(s) {'residual_afm': 1}"), r.warnings().toString());
        assertEquals(null, r.postcheck().byKind().get("residual_afm"));
        assertEquals(1, lines().stream().filter(l -> l.startsWith("stage=scan ")).count());
        assertEquals(1, lines().stream().filter(l -> l.startsWith("stage=final_scan ")).count());
        assertEquals(1, pass1Calls(llm));
        assertEquals(1, remediationCalls(llm).size());
        assertEquals(2, llm.requests.size()); // pass 1 and one remediation (no queue, no pass 2): the final scan asked nobody
        assertTrue(r.warnings().contains(REMEDIATED), r.warnings().toString());
        assertTrue(r.timings().containsKey("remediate"));
        assertTrue(r.timings().containsKey("final_scan"));

        Map<String, Object> candidate = candidates(remediationCalls(llm).get(0)).get(0);
        assertEquals("C1", candidate.get("id"));
        assertEquals(afm, candidate.get("text"));
        assertEquals(List.of(Map.of("sources", List.of("postcheck"), "action", "REVIEW", "category", "AFM",
                "check", "residual_afm")), candidate.get("recommendations"));
        assertTrue(lines().stream().anyMatch(l -> l.startsWith("stage=remediate request_id=")
                && l.contains(" postcheck_remediation=true candidate_count=1 candidate_ids=['remediation:chunk1:C1'] pass2_calls=1 "
                + "remediation_redactions=1 unresolved=0 ")), lines().toString());
    }

    @Test
    void aSurvivingNameIsAskedAboutExactlyAndNoLogLineQuotesIt() {
        byte[] docx = TestDocx.paragraphs("Η ενδικοφανή προσφυγή του " + NAME + " κατά της πράξης.").bytes();
        // Pass 1 PRESERVEs the name the rules propose to REDACT, so the disagreement is put to pass 2, which (in
        // this scripted model) PRESERVEs it, and the scan finds it still visible.
        ScriptedLlm llm = new ScriptedLlm(req -> {
            if (ScriptedLlm.isPass1(req)) {
                return "[{\"text\": \"" + NAME + "\", \"action\": \"PRESERVE\", \"category\": \"POSSIBLE_PERSON\"}]";
            }
            if (ScriptedLlm.isRemediation(req)) {
                return PyJson.dumps(List.of(answer("C1", "REDACT", "POSSIBLE_PERSON")));
            }
            return PyJson.dumps(candidates(req).stream().map(c -> answer((String) c.get("id"), "PRESERVE",
                    "POSSIBLE_PERSON")).toList());
        });
        AnonymizeResult r = run(docx, FILES, llm);

        assertFalse(body(r).contains("Γεώργιου") || body(r).contains("Παπαδόπουλου"), body(r));
        assertTrue(body(r).contains("ενδικοφανή προσφυγή του "), body(r));
        Map<String, Object> candidate = candidates(remediationCalls(llm).get(0)).get(0);
        assertEquals(NAME, candidate.get("text")); // the name and nothing of its cue
        // Why the scan flagged it, and what the rule engine said there before redaction, at the same
        // coordinates: the first adjudication's own question, carried, never searched for.
        // The name lists' proposal (a given name and a surname side by side) is part of that evidence too.
        assertEquals(List.of(Map.of("sources", List.of("postcheck"), "action", "REVIEW", "category", "POSSIBLE_PERSON",
                        "check", "person_name_leak"),
                Map.of("sources", List.of("deterministic"), "action", "REDACT", "category", "POSSIBLE_PERSON"),
                Map.of("sources", List.of("deterministic"), "action", "REDACT", "category", "APPELLANT_NAME"),
                Map.of("sources", List.of("pass1"), "action", "PRESERVE", "category", "POSSIBLE_PERSON")),
                candidate.get("recommendations"));
        for (String line : lines()) {
            assertFalse(line.contains("Γεώργιου") || line.contains("Παπαδόπουλου"), line);
        }
        assertFalse(r.postcheck().findings().toString().contains("Γεώργιου")); // the span hides its text
        assertFalse(PyJson.dumps(r.postcheck().asMap()).contains("Γεώργιου")); // and maps leave it out
    }

    @Test
    void aSurvivingPhoneIsTrimmedToTheValueAndRedacted() {
        byte[] docx = TestDocx.paragraphs("Επικοινωνία στο κινητό  " + PHONE + "  για ενημέρωση.").bytes();
        ScriptedLlm llm = model(r -> List.of(answer("C1", "REDACT", "PHONE")));
        AnonymizeResult r = run(docx, FILES, llm);
        assertEquals(PHONE, candidates(remediationCalls(llm).get(0)).get(0).get("text"));
        assertTrue(body(r).contains("κινητό  ..........  για"), body(r));
        assertEquals("processed", r.status());
    }

    @Test
    void aRemediationPreserveIsRespectedAndNothingIsRewritten() {
        byte[] docx = TestDocx.paragraphs("Επικοινωνία στο κινητό " + PHONE + " για ενημέρωση.").bytes();
        ScriptedLlm llm = model(r -> List.of(answer("C1", "PRESERVE", "PHONE")));
        AnonymizeResult r = run(docx, FILES, llm);
        assertTrue(body(r).contains(PHONE));
        assertEquals("processed", r.status());
        assertTrue(r.warnings().contains(REMEDIATED_NOTHING), r.warnings().toString());
        // Nothing was rewritten, so the post-redaction scan already audited the returned bytes.
        assertFalse(r.timings().containsKey("final_scan"));
        assertEquals(1, r.postcheck().byKind().get("phone_shape"));
    }

    @Test
    void whatTheRemediationCannotSettleIsUnresolvedNotGuessed() {
        byte[] docx = TestDocx.paragraphs("Επικοινωνία στο κινητό " + PHONE + " για ενημέρωση.").bytes();
        ScriptedLlm llm = model(r -> List.of());
        AnonymizeResult r = run(docx, FILES, llm);

        List<ChatRequest> calls = remediationCalls(llm);
        assertEquals(2, calls.size()); // the first ask and its one corrective retry, both remediation calls
        assertTrue(ScriptedLlm.isRetry(calls.get(1)));
        assertEquals("needs-review", r.status());
        assertEquals(1, r.unresolvedCount());
        UnresolvedFinding open = r.unresolved().get(0);
        assertEquals(UnresolvedFinding.Kind.CANDIDATE_UNDECIDED, open.kind());
        assertEquals(List.of(new UnitSlice("u0", 23, 33)), open.locations()); // where the residual is, in the redacted parse
        assertTrue(body(r).contains(PHONE)); // nothing was invented for it
        assertTrue(r.warnings().contains("LLM pass 2 left 1 finding(s) unresolved after its corrective retry; this "
                + "document needs human review"), r.warnings().toString());
    }

    /**
     * More residuals than one pass-2 request may carry: the remediation is asked in batches, as the first
     * adjudication is. One batch's provider stays down: the other batch's redactions are written, the rest is
     * PASS2_UNAVAILABLE, nothing is written for it, and the document comes back for human review.
     */
    @Test
    void aRemediationQueueLargerThanOneBatchIsBatchedAndAFailedBatchNeedsReview() {
        StringBuilder text = new StringBuilder("Τηλέφωνα επικοινωνίας:");
        List<String> phones = new ArrayList<>();
        for (int i = 0; i < 35; i++) {
            phones.add(String.valueOf(6900000100L + i));
            text.append(' ').append(phones.get(i)).append(',');
        }
        byte[] docx = TestDocx.paragraphs(text.append(" για ενημέρωση.").toString()).bytes();
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return ScriptedLlm.finished("[]");
            }
            List<?> answers = candidates(r).stream().map(c -> answer((String) c.get("id"),
                    ScriptedLlm.isRemediation(r) ? "REDACT" : "PRESERVE", "PHONE")).toList();
            if (ScriptedLlm.isRemediation(r) && ScriptedLlm.candidateIds(r).contains("C31")) {
                // Not retried by the transport (so no real backoff here), and absorbed as unavailable.
                throw dev.filtsiap.ded.anonymizer.llm.LlmCallException.status(400, null);
            }
            return ScriptedLlm.finished(PyJson.dumps(answers));
        });
        AnonymizeResult r = run(docx, FILES, llm);

        List<ChatRequest> remediation = remediationCalls(llm);
        List<List<String>> asked = remediation.stream().map(ScriptedLlm::candidateIds).distinct().toList();
        assertEquals(2, asked.size(), asked.toString());
        assertEquals(30, asked.get(0).size());
        assertEquals(5, asked.get(1).size());
        String body = body(r);
        for (int i = 0; i < 35; i++) {
            assertEquals(i >= 30, body.contains(phones.get(i)), phones.get(i));
        }
        assertEquals("needs-review", r.status());
        assertEquals(5, r.unresolved().stream().filter(f -> f.kind() == UnresolvedFinding.Kind.PASS2_UNAVAILABLE).count());
        assertTrue(r.warnings().contains("LLM pass 2 was unavailable for 5 candidate(s) after its retries; the "
                + "documented pass-1/deterministic fallback was applied where one exists (fallback_used); this "
                + "document needs human review"), r.warnings().toString());
    }

    // ------------------------------------------------------------------ the second resolve

    static final String LABELLED = "Η διεύθυνση είναι οδός Ερμού, στην πόλη.";
    static final String CONTACT = "Επικοινωνία στο κινητό " + PHONE + ".";

    /**
     * THE SECOND RESOLVE, as the pipeline runs it, for one remediation answer: a residual at
     * {@code quoted} (in the first paragraph holding it) is put to the remediation's pass 2, which
     * answers REDACT under {@code category}; its span and the carried hard preserves go through the
     * ordinary resolver and the write-back. The remediation's pass 2 answers only the slices the scan
     * named, so a REDACT that covers a label reaches this resolve only when a residual itself covers
     * one; the scan's own residuals here would not, which is why the residual is placed directly.
     * The document plays the redacted parse: nothing in it was redacted by a first pass.
     */
    static String secondResolve(byte[] docx, String quoted, String category) {
        return secondResolve(docx, quoted, category, 1);
    }

    /** The same, expecting {@code calls} pass-2 calls: none when hard policy settled the residual. */
    static String secondResolve(byte[] docx, String quoted, String category, int calls) {
        DocumentData parsed = DocxEngine.parseDocx(docx, "rem", CFG.limits());
        TextUnit unit = parsed.textUnits().stream().filter(u -> u.normalizedText().contains(quoted)).findFirst()
                .orElseThrow();
        int start = unit.normalizedText().indexOf(quoted);
        LlmDetector.Residual residual = new LlmDetector.Residual(new UnresolvedFinding.AuditRef("P1",
                PostcheckFinding.Severity.MEDIUM, "street_leak", unit.partName() + ":" + unit.unitId()),
                new Span(unit.unitId(), start, start + quoted.length(), quoted, SpanCategory.PRIVATE_ADDRESS,
                        "postcheck_street_leak", 1.0, SpanAction.REVIEW, "", SpanOrigin.DETERMINISTIC));
        ScriptedLlm llm = new ScriptedLlm(r -> PyJson.dumps(List.of(answer("C1", "REDACT", category))));
        // The hard decisions are carried exactly as the pipeline carries them: into the queue and the resolve.
        List<Span> rules = Detectors.detectAll(parsed, FILES.rules()).resolverSpans();
        List<Span> hardPreserves = Pipeline.carriedHardPreserves(parsed, parsed, rules, FILES.policy());
        LlmDetector.Remediation remediation = LlmDetector.runPass2Remediation(parsed, List.of(residual), List.of(),
                Pipeline.carriedHardRedacts(parsed, parsed, rules, FILES.policy()), hardPreserves, llm, CFG,
                FILES.rules().regions(), RunContext.start(300));
        assertEquals(calls, llm.requests.size());
        List<Span> second = new ArrayList<>(remediation.spans());
        second.addAll(hardPreserves);
        RedactionPlan plan = Resolver.resolveRedactions(parsed, second, FILES.policy());
        return TestDocx.part(DocxEngine.writeRedactedDocx(docx, parsed, plan, CFG.limits()), "word/document.xml");
    }

    @Test
    void aCarriedFieldLabelOutranksARemediationRedactThatCoversIt() {
        // Under a NAME category span narrowing never trims a cue: only the carried label protects it.
        String xml = secondResolve(TestDocx.paragraphs(LABELLED, CONTACT).bytes(), "οδός Ερμού", "POSSIBLE_PERSON");
        assertTrue(xml.contains("οδός......,"), xml); // the label is policy; the rest goes, as in v2
        assertFalse(xml.contains("Ερμού"), xml);
    }

    @Test
    void aRemediationRedactIsNarrowedToItsValue() {
        // The same slice as an address: the cue comes off before the span is written, so the plan
        // says what was redacted and the separating space stays.
        String xml = secondResolve(TestDocx.paragraphs(LABELLED, CONTACT).bytes(), "οδός Ερμού", "PRIVATE_ADDRESS");
        assertTrue(xml.contains("οδός .....,"), xml);
        assertFalse(xml.contains("Ερμού"), xml);
    }

    @Test
    void verifiedHardDecisionsSurviveCleanupElsewhereButUnverifiedGeometryDoesNot() {
        // A hidden run is part of the source unit and is dropped by the write path, so the redacted
        // parse no longer lines up with the source one: neither the labels' protection nor the hard
        // redactions' mask can be carried across it.
        String hidden = "<w:p><w:r><w:t xml:space=\"preserve\">ορατό </w:t></w:r><w:r><w:rPr><w:vanish/></w:rPr>"
                + "<w:t>κρυφό</w:t></w:r></w:p>";
        byte[] docx = TestDocx.paragraphs().document(TestDocx.p(LABELLED) + TestDocx.p(CONTACT) + hidden).bytes();
        AnonymizeResult r = run(docx, FILES, model(rq -> List.of(answer("C1", "REDACT", "PHONE"))));
        assertFalse(body(r).contains(PHONE), body(r));
        assertTrue(body(r).contains("οδός"));
        assertFalse(lines().stream().anyMatch(line -> line.contains("so no hard preserve was carried")));

        String afm = TestDocx.validAfm("09401420");
        DocumentData source = DocxEngine.parseDocx(TestDocx.paragraphs(LABELLED, "ΑΦΜ " + afm + ".", CONTACT).bytes(),
                "geo", CFG.limits());
        List<Span> rules = Detectors.detectAll(source, FILES.rules()).resolverSpans();
        List<TextUnit> moved = new ArrayList<>(source.textUnits());
        TextUnit last = moved.remove(moved.size() - 1);
        moved.add(new TextUnit(last.unitId(), last.partName(), last.unitType(), last.text(),
                last.normalizedText() + " ", last.charMap(), last.location()));
        DocumentData shifted = new DocumentData("geo", moved, source.partsInventory(), source.warnings());
        assertFalse(Pipeline.carriedHardPreserves(source, source, rules, FILES.policy()).isEmpty());
        assertFalse(Pipeline.carriedHardRedacts(source, source, rules, FILES.policy()).isEmpty());
        assertEquals(List.of(), Pipeline.carriedHardPreserves(source, shifted, rules, FILES.policy()));
        assertEquals(List.of(), Pipeline.carriedHardRedacts(source, shifted, rules, FILES.policy()));
        assertTrue(Pipeline.carriedHardRedacts(source, source, rules, FILES.policy()).stream()
                .allMatch(s -> Resolver.isHardRedact(s, FILES.policy())));
    }

    @Test
    void aRemediationRedactCannotClaimTheHardRedactTier() {
        // AFM is a hard-redact category and pass 2's confidence (0.9) meets the threshold: as a
        // deterministic span this would outrank the carried PUBLIC_LOCALITY preserve. As the pass-2 span it
        // is, it cannot. The residual reaches past the preserve, so it is a question; the answer still
        // cannot take the preserved place.
        String xml = secondResolve(TestDocx.paragraphs("Ο προσφεύγων, κάτοικος Χαλανδρίου Αττικής, ζητά.", CONTACT)
                .bytes(), "Χαλανδρίου Αττικής, ζητά", "AFM");
        assertTrue(xml.contains("κάτοικος Χαλανδρίου Αττικής"), xml);
        assertFalse(xml.contains("ζητά"), xml);
    }

    @Test
    void aResidualTheCarriedHardPreserveCoversWholeIsNeverAsked() {
        // The same place, exactly: hard policy has decided it, in the first adjudication and here alike.
        String xml = secondResolve(TestDocx.paragraphs("Ο προσφεύγων, κάτοικος Χαλανδρίου Αττικής, ζητά.", CONTACT)
                .bytes(), "Χαλανδρίου Αττικής", "AFM", 0);
        assertTrue(xml.contains("κάτοικος Χαλανδρίου Αττικής, ζητά."), xml);
    }

    /**
     * A document that uses U+2026 itself, in a run as long as the big test document's, gets past the
     * post-redaction scan and into the remediation: the audit no longer mistakes it for write-path residue.
     */
    @Test
    void theInputsOwnEllipsesDoNotStopTheDocumentBeforeRemediation() {
        byte[] docx = TestDocx.paragraphs("Η απόφαση " + "…".repeat(24) + " εκδόθηκε.", CONTACT).bytes();
        ScriptedLlm llm = model(r -> List.of(answer("C1", "REDACT", "PHONE")));
        AnonymizeResult r = run(docx, FILES, llm);
        assertEquals(1, remediationCalls(llm).size());
        assertTrue(body(r).contains("Η απόφαση " + "…".repeat(24) + " εκδόθηκε."), body(r));
        assertFalse(body(r).contains(PHONE), body(r));
        assertEquals(null, r.postcheck().byKind().get("ellipsis_residue"));
        assertEquals("processed", r.status());
    }

    /** The re-ask is the candidate-only contract too: the candidate and its context, never the redacted excerpt. */
    @Test
    void theRemediationIsAskedAboutItsCandidatesOnly() {
        String opening = "η πρώτη παράγραφος, που δεν αφορά κανέναν υποψήφιο, δεν στέλνεται.";
        byte[] docx = TestDocx.paragraphs(opening, "Επικοινωνία στο κινητό " + PHONE + " για ενημέρωση.").bytes();
        ScriptedLlm llm = model(r -> List.of(answer("C1", "REDACT", "PHONE")));
        AnonymizeResult r = run(docx, FILES, llm);
        ChatRequest asked = remediationCalls(llm).get(0);
        assertFalse(asked.userMessage().contains("DOCUMENT EXCERPT"), asked.userMessage());
        assertFalse(asked.userMessage().contains("η πρώτη παράγραφος"), asked.userMessage());
        assertEquals(List.of(PHONE), candidates(asked).stream().map(c -> c.get("text")).toList());
        assertTrue(body(r).contains("κινητό .........."), body(r));
        // The returned bytes were rewritten, so they were scanned again, deterministically.
        assertTrue(r.timings().containsKey("final_scan"));
        assertEquals(1, lines().stream().filter(l -> l.startsWith("stage=final_scan ")).count());
    }

    // ------------------------------------------------------------------ what still stops a document

    @Test
    void aBlockingPackageFindingFailsClosedBeforeAnyRemediation() {
        byte[] docx = TestDocx.paragraphs(CONTACT).put("word/vbaProject.bin", "synthetic macro payload").bytes();
        ScriptedLlm llm = model(r -> List.of(answer("C1", "REDACT", "PHONE")));
        ResidualPIIError e = assertThrows(ResidualPIIError.class, () -> run(docx, FILES, llm));
        assertEquals("post-redaction scan found 1 HIGH-severity finding(s) that no further redaction can settle; the "
                + "document needs manual review (macro_part_survived@word/vbaProject.bin)", e.getMessage());
        assertEquals(0, remediationCalls(llm).size()); // the residual phone was never re-asked
        assertFalse(e.getMessage().contains(PHONE));
    }

    @Test
    void theDeadlineIsCheckedBeforeTheRemediationIsWritten() {
        FakeClock clock = new FakeClock();
        ScriptedLlm llm = model(r -> {
            clock.advance(400); // the re-ask answers, after the document ran out of time
            return List.of(answer("C1", "REDACT", "PHONE"));
        });
        DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class, () -> Pipeline.anonymizeDocument(
                TestDocx.paragraphs(CONTACT).bytes(), CFG, FILES, llm, clock.context(300)));
        assertEquals("remediate apply", e.stage());
        assertEquals(1, remediationCalls(llm).size());
    }

    @Test
    void aCleanScanCostsNoRemediationCall() {
        ScriptedLlm llm = model(r -> new ArrayList<>());
        AnonymizeResult r = run(TestDocx.paragraphs("απλό κείμενο χωρίς στοιχεία.").bytes(), FILES, llm);
        assertEquals(0, remediationCalls(llm).size());
        assertFalse(r.timings().containsKey("remediate"));
        assertTrue(r.warnings().stream().noneMatch(w -> w.startsWith("post-redaction remediation")));
    }
}
