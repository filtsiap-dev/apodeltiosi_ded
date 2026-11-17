package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.llm.LlmCallException;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.Prompts;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class PipelineTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));

    /** The pipeline under a fresh default budget, with a fixed document id. */
    static AnonymizeResult run(byte[] docx, RuntimeConfig cfg, FileConfig files, LlmClient llm, String documentId) {
        return Pipeline.anonymizeDocument(docx, cfg, files, llm,
                RunContext.start(cfg.documentDeadlineS(), documentId, System::nanoTime));
    }

    /** A model that proposes nothing in pass 1 and gives {@code pass2} as every pass-2 answer. */
    static ScriptedLlm answering(Object... pass2) {
        return new ScriptedLlm(req -> ScriptedLlm.isPass1(req) ? "[]" : PyJson.dumps(List.of(pass2)));
    }

    @Test
    void redactsAndStampsProvenance() {
        String afm = TestDocx.validAfm("24681357");
        byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος με ΑΦΜ " + afm + ".").bytes();
        AnonymizeResult r = run(docx, CFG, FILES, ScriptedLlm.cooperative(), "doc1");
        String xml = TestDocx.part(r.redactedDocx(), "word/document.xml");
        assertFalse(xml.contains(afm));
        assertFalse(xml.contains("Παπαδόπουλος"));
        assertTrue(xml.contains("με ΑΦΜ ........."), xml); // the label stays, the value goes
        assertFalse(xml.contains("C1") || xml.contains("C2"), xml); // candidate ids are handles, never content
        assertEquals("processed", r.status());
        assertEquals("doc1", r.documentId());
        assertEquals(Prompts.PROMPTS_SHA256, r.provenance().get("prompts_sha256"));
        assertEquals(FILES.configSha256(), r.provenance().get("config_sha256"));
        assertEquals("openai", r.provenance().get("provider"));
        assertTrue(r.timings().keySet().containsAll(List.of("parse", "detect", "llm", "resolve", "apply", "scan", "total")));
    }

    @Test
    void aHighTextualResidualPreservedByPass2IsWrittenAsDecidedAndHeldForReview() {
        // 31/02 is not a date, so the detector gives this AMKA only an ordinary REDACT (0.75). Pass 1 reads
        // it as a date and PRESERVEs it: the disagreement is a pass-2 question about the rule's own span, and
        // a pass-2 PRESERVE at exactly that slice out-ranks ordinary evidence, so the number survives.
        // The scan's HIGH residual_amka names its slice, so it is put back to pass 2 rather than ending the
        // document; asked again, pass 2 says PRESERVE again, and the document goes out with that answer.
        // THE INTENTIONAL CHANGE FROM v2 (where this was "processed"): a HIGH finding is settled only by a
        // redaction, so a PRESERVE keeps it in front of a person and the document is needs-review.
        byte[] docx = TestDocx.paragraphs("ΑΜΚΑ 31021512345").bytes();
        ScriptedLlm llm = new ScriptedLlm(req -> ScriptedLlm.isPass1(req)
                ? "[{\"text\": \"31021512345\", \"action\": \"PRESERVE\", \"category\": \"DATE\"}]"
                : PyJson.dumps(List.of(answer("C1", "PRESERVE", "DATE"))));
        AnonymizeResult r = run(docx, CFG, FILES, llm, "doc2");
        assertTrue(TestDocx.part(r.redactedDocx(), "word/document.xml").contains("31021512345"));
        assertEquals(1, r.postcheck().byKind().get("residual_amka"));
        assertEquals(1, llm.requests.stream().filter(ScriptedLlm::isRemediation).count());
        assertEquals("needs-review", r.status());
        assertEquals(List.of(UnresolvedFinding.Kind.HIGH_RESIDUAL_PRESERVED),
                r.unresolved().stream().map(UnresolvedFinding::kind).toList());
    }

    /**
     * Discovery the provider never delivered is a warning, never a verdict on the document: it neither
     * fails delivery nor certifies coverage; the rules still work, and incomplete discovery requires review.
     */
    @Test
    void aDocumentWhosePass1NeverArrivesNeedsReview() {
        String afm = TestDocx.validAfm("24681357");
        byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος με ΑΦΜ " + afm + ".").bytes();
        ScriptedLlm llm = ScriptedLlm.completions(req -> {
            if (ScriptedLlm.isPass1(req)) {
                throw LlmCallException.status(503, 0L, null); // no wait: the provider asked for none
            }
            return ScriptedLlm.finished(PyJson.dumps(ScriptedLlm.agreeWithEveryCandidate(req)));
        });
        AnonymizeResult r = run(docx, CFG, FILES, llm, "nopass1");
        String xml = TestDocx.part(r.redactedDocx(), "word/document.xml");
        assertEquals("needs-review", r.status());
        assertEquals(1, r.unresolvedCount());
        assertEquals(UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE, r.unresolved().getFirst().kind());
        assertFalse(xml.contains(afm) || xml.contains("Παπαδόπουλος"), xml);
        assertEquals(6, llm.requests.stream().filter(ScriptedLlm::isPass1).count());
        assertTrue(llm.requests.stream().anyMatch(req -> !ScriptedLlm.isPass1(req)));
    }

    @Test
    void pass2CanRedactADateOfBirth() {
        // The rules propose every date as an ordinary PRESERVE; a place nobody proposed anything else
        // for is not a question. Pass 1 reads it as a birth date, so the disagreement goes to pass 2.
        byte[] docx = TestDocx.paragraphs("Ημερομηνία γέννησης 01/02/1980").bytes();
        ScriptedLlm llm = new ScriptedLlm(req -> ScriptedLlm.isPass1(req)
                ? "[{\"text\": \"01/02/1980\", \"action\": \"REDACT\", \"category\": \"DATE\"}]"
                : PyJson.dumps(List.of(answer("C1", "REDACT", "DATE"))));
        AnonymizeResult r = run(docx, CFG, FILES, llm, "dob");
        String xml = TestDocx.part(r.redactedDocx(), "word/document.xml");
        assertTrue(xml.contains("Ημερομηνία γέννησης .........."), xml);
        Map<String, Object> asked = ScriptedLlm.candidates(llm.requests.get(1)).get(0);
        assertEquals("01/02/1980", asked.get("text"));
        assertEquals(List.of(Map.of("sources", List.of("deterministic"), "action", "PRESERVE", "category", "DATE"),
                Map.of("sources", List.of("pass1"), "action", "REDACT", "category", "DATE")),
                asked.get("recommendations"));
    }

    @Test
    void fieldLabelSurvivesAPass2RedactThatQuotesItWithTheValue() {
        String afm = TestDocx.validAfm("13572468");
        byte[] docx = TestDocx.paragraphs("Ο προσφεύγων με Α.Φ.Μ. " + afm + ".").bytes();
        // Pass 1 sees the value already blanked and quotes the label with it, under a NAME category, which
        // span narrowing never trims a structural label from. Nothing disagrees, so the pass-1 REDACT is
        // applied without a pass-2 question, and hard policy still has the last word on the label.
        ScriptedLlm llm = new ScriptedLlm(req -> ScriptedLlm.isPass1(req)
                ? "[{\"text\": \"με Α.Φ.Μ. .........\", \"action\": \"REDACT\", \"category\": \"POSSIBLE_PERSON\"}]"
                : PyJson.dumps(ScriptedLlm.candidates(req).stream()
                        .map(c -> answer((String) c.get("id"), "REDACT", "POSSIBLE_PERSON")).toList()));
        AnonymizeResult r = run(docx, CFG, FILES, llm, "label");
        String xml = TestDocx.part(r.redactedDocx(), "word/document.xml");
        // The hard-preserved label keeps its characters; the hard-redacted value loses its own.
        assertTrue(xml.contains("με Α.Φ.Μ."), xml);
        assertTrue(xml.contains("........."), xml);
        assertFalse(xml.contains(afm), xml);
        // The label was redacted by pass 1's decision, applied directly, and the resolver kept it.
        assertTrue(llm.requests.stream().noneMatch(req -> !ScriptedLlm.isPass1(req) && !ScriptedLlm.isRemediation(req)));
        assertTrue(llm.requests.stream().noneMatch(req -> req.userMessage().contains(afm)));

        // Asked about it instead (pass 1 could not decide), the label goes to pass 2 with the rest of the
        // quote, pass 2 redacts it, and the resolver keeps it all the same.
        ScriptedLlm asked = new ScriptedLlm(req -> ScriptedLlm.isPass1(req)
                ? "[{\"text\": \"με Α.Φ.Μ. .........\", \"action\": \"REVIEW\", \"category\": \"POSSIBLE_PERSON\"}]"
                : PyJson.dumps(ScriptedLlm.candidates(req).stream()
                        .map(c -> answer((String) c.get("id"), "REDACT", "POSSIBLE_PERSON")).toList()));
        String askedXml = TestDocx.part(run(docx, CFG, FILES, asked, "label2").redactedDocx(), "word/document.xml");
        assertTrue(askedXml.contains("με Α.Φ.Μ."), askedXml);
        assertFalse(askedXml.contains(afm), askedXml);
        assertTrue(asked.requests.stream().filter(req -> !ScriptedLlm.isPass1(req))
                .flatMap(req -> ScriptedLlm.candidates(req).stream())
                .anyMatch(c -> ((String) c.get("text")).contains("Α.Φ.Μ.")));
    }

    @Test
    void theSamePhoneIsKeptInTheAuthorityHeaderAndRedactedForTheParty() {
        byte[] docx = TestDocx.paragraphs("Τηλέφωνο: 6912345678", "ΑΠΟΦΑΣΗ",
                "Τηλέφωνο προσφεύγοντος: 6912345678").bytes();
        ScriptedLlm llm = new ScriptedLlm(r -> ScriptedLlm.isPass1(r) ? "[]" : PyJson.dumps(ScriptedLlm.candidates(r)
                .stream().map(c -> answer((String) c.get("id"),
                        ((String) c.get("before")).contains("προσφεύγοντος") ? "REDACT" : "PRESERVE", "PHONE")).toList()));
        String xml = TestDocx.part(run(docx, CFG, FILES, llm, "phones").redactedDocx(),
                "word/document.xml");
        assertTrue(xml.contains(">Τηλέφωνο: 6912345678<"), xml);
        assertTrue(xml.contains(">Τηλέφωνο προσφεύγοντος: ..........<"), xml);
    }

    /** A model whose pass 1 returns one finding and whose pass 2 answers nothing. */
    static ScriptedLlm pass1Says(String text, String action, String category) {
        return new ScriptedLlm(r -> ScriptedLlm.isPass1(r) ? PyJson.dumps(List.of(Map.of("text", text, "action", action,
                "category", category))) : "[]");
    }

    /**
     * Pass-1 quotes that do not match the text as written (found in the real-model runs: a paraphrased legal
     * reference, a company name re-spaced by the model). A PRESERVE that cannot be placed changes nothing, so it
     * is audited in the log, not review work. A REDACT is placed whitespace-tolerantly at its ONE place; one that
     * fits two places is never guessed at: it stays unresolved, and the document needs review.
     */
    @Test
    void anUnplaceablePass1QuoteFlagsTheDocumentOnlyWhenItWouldRedact() {
        String law = "Σύμφωνα με τα άρθρα 28 και 50 «Αλληλέγγυα Ευθύνη» του ν. 4987/2022.";
        AnonymizeResult kept = run(TestDocx.paragraphs(law).bytes(), CFG, FILES,
                pass1Says("άρθρα 28 και 50 του ν. 4987/2022", "PRESERVE", "LEGAL_REF"), "preserve");
        assertEquals("processed", kept.status());
        assertEquals(List.of(), kept.unresolved());
        assertTrue(TestDocx.part(kept.redactedDocx(), "word/document.xml").contains(law));

        AnonymizeResult respaced = run(TestDocx.paragraphs("Η Acme   Trading υπέβαλε στοιχεία.").bytes(), CFG, FILES,
                pass1Says("Acme Trading", "REDACT", "PRIVATE_COMPANY_NAME"), "respaced");
        assertEquals("processed", respaced.status());
        assertTrue(TestDocx.part(respaced.redactedDocx(), "word/document.xml").contains("Η .............. υπέβαλε"));

        AnonymizeResult twoPlaces = run(TestDocx.paragraphs("Η Acme  Trading και η Acme   Trading.").bytes(), CFG, FILES,
                pass1Says("Acme Trading", "REDACT", "PRIVATE_COMPANY_NAME"), "ambiguous");
        assertEquals("needs-review", twoPlaces.status());
        assertEquals(List.of(UnresolvedFinding.Kind.DISCOVERY_UNLOCATABLE),
                twoPlaces.unresolved().stream().map(UnresolvedFinding::kind).toList());
        assertTrue(twoPlaces.warnings().contains("1 pass-1 finding(s) quote text that is not in their excerpt and could "
                + "not be placed; this document needs human review"), twoPlaces.warnings().toString());
        assertTrue(TestDocx.part(twoPlaces.redactedDocx(), "word/document.xml")
                .contains("Η Acme  Trading και η Acme   Trading."));
    }

    @Test
    void whatPass2CannotSettleIsLeftAsItWasAndFlaggedForReview() {
        // Two capitalised words no name list knows: only a REVIEW hint, no rule proposes an action.
        byte[] docx = TestDocx.paragraphs("Ο Ζυλφίκ Κραντάρ υπέγραψε.").bytes();
        ScriptedLlm silent = answering();
        AnonymizeResult r = run(docx, CFG, FILES, silent, "open");
        assertEquals(3, silent.requests.size()); // pass 1, pass 2, one corrective retry
        assertEquals("needs-review", r.status());
        assertEquals(1, r.unresolvedCount());
        assertEquals(UnresolvedFinding.Kind.CANDIDATE_UNDECIDED, r.unresolved().get(0).kind());
        assertTrue(r.warnings().contains("LLM pass 2 left 1 finding(s) unresolved after its corrective retry; this "
                + "document needs human review"), r.warnings().toString());
        // No answer was invented: the text is exactly as it was.
        assertTrue(TestDocx.part(r.redactedDocx(), "word/document.xml").contains("Ο Ζυλφίκ Κραντάρ υπέγραψε."));
    }

    @Test
    void theTextSizeIsBoundedBeforeDetectionOrTheModel() {
        RuntimeConfig ten = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_MAX_TEXT_CHARS", "10"));
        run(TestDocx.paragraphs("0123456789").bytes(), ten, FILES, ScriptedLlm.cooperative(), "at"); // at the limit
        ScriptedLlm llm = ScriptedLlm.cooperative();
        ResourceLimitExceededError e = assertThrows(ResourceLimitExceededError.class,
                () -> run(TestDocx.paragraphs("0123456789", "x").bytes(), ten, FILES, llm, "over"));
        assertEquals("TEXT_TOO_LARGE", e.code());
        // Stopped while extracting (R-1), so the message names the limit, not a full count.
        assertEquals("document holds more than 10 characters of text; the limit is 10", e.getMessage());
        assertEquals(0, llm.requests.size());
    }

    @Test
    void aDocumentOutOfTimeStartsNoFurtherStage() {
        byte[] docx = TestDocx.paragraphs("απλό κείμενο χωρίς στοιχεία.").bytes();
        FakeClock clock = new FakeClock();
        RunContext spent = clock.context(5);
        clock.advance(5);
        ScriptedLlm idle = ScriptedLlm.cooperative();
        assertEquals("parse", assertThrows(DocumentTimeoutError.class,
                () -> Pipeline.anonymizeDocument(docx, CFG, FILES, idle, spent)).stage());
        assertEquals(0, idle.requests.size());

        // The model answers, but only after the budget is gone: nothing after it runs, and no output exists.
        // Two checkpoints can see that first, both legitimately: the pipeline's own "resolve" check, and
        // the LLM stage's supervisor ("llm"), which waits on the chunk with whatever budget is left (see
        // LlmDetectorTest). Which one wins is scheduling, so the stage is one of the two, and what is
        // asserted exactly is that no stage after the LLM stage began.
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory
                .getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        root.addAppender(logs);
        try {
            FakeClock slow = new FakeClock();
            ScriptedLlm late = new ScriptedLlm(r -> {
                slow.advance(400);
                return "[]";
            });
            String stage = assertThrows(DocumentTimeoutError.class,
                    () -> Pipeline.anonymizeDocument(docx, CFG, FILES, late, slow.context(300))).stage();
            assertTrue(List.of("resolve", "llm").contains(stage), stage);
            assertEquals(1, late.requests.size());
            assertTrue(logs.list.stream().map(ILoggingEvent::getFormattedMessage)
                    .noneMatch(l -> l.startsWith("stage=resolve ") || l.startsWith("stage=apply ")
                            || l.startsWith("stage=scan ")), logs.list.toString());
        } finally {
            root.detachAppender(logs);
        }
    }

    @Test
    void invalidInputNeverReachesTheModel() {
        ScriptedLlm llm = ScriptedLlm.cooperative();
        assertThrows(InvalidDocumentError.class,
                () -> run("not a docx".getBytes(), CFG, FILES, llm, "d"));
        assertEquals(0, llm.requests.size());
    }

    @Test
    void aDeadlineSpentDuringTheLastScanCannotReturnAnOutput() {
        FakeClock clock = new FakeClock();
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory
                .getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        ListAppender<ILoggingEvent> logs = new ListAppender<>() {
            @Override
            protected void append(ILoggingEvent event) {
                if (event.getFormattedMessage().startsWith("stage=scan ")) {
                    clock.advance(400);
                }
            }
        };
        logs.start();
        root.addAppender(logs);
        try {
            assertEquals("finish", assertThrows(DocumentTimeoutError.class, () -> Pipeline.anonymizeDocument(
                    TestDocx.paragraphs("plain text").bytes(), CFG, FILES, ScriptedLlm.cooperative(),
                    clock.context(300))).stage());
        } finally {
            root.detachAppender(logs);
        }
    }
}
