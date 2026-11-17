package dev.filtsiap.ded.anonymizer.llm;

import static dev.filtsiap.ded.anonymizer.llm.LlmDetectorTest.CFG;
import static dev.filtsiap.ded.anonymizer.llm.LlmDetectorTest.doc;
import static dev.filtsiap.ded.anonymizer.llm.LlmDetectorTest.logged;
import static dev.filtsiap.ded.anonymizer.llm.LlmDetectorTest.para;
import static dev.filtsiap.ded.anonymizer.llm.LlmDetectorTest.residual;
import static dev.filtsiap.ded.anonymizer.llm.LlmDetectorTest.rule;
import static dev.filtsiap.ded.anonymizer.llm.LlmDetectorTest.withContextWindow;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidateIds;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.finished;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.isRetry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.PostcheckFinding;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnresolvedFinding;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.ChatRequest;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * The post-redaction remediation is asked in the first adjudication's batches: no more candidates or
 * payload per request, and nothing beyond a configured context window. Every candidate keeps the chunk's
 * id and its residual's provenance however the queue is cut, every batch keeps its own retry and
 * absorbs its own provider failure, and every candidate ends decided, undecided or unavailable, once.
 */
class RemediationBatchingTest {

    static final int PER_BATCH = Pass2Queue.maxCandidatesPerBatch(CFG.maxCompletionTokens());

    /** {@code n} distinct synthetic mobile numbers in one paragraph, each a MEDIUM phone residual. */
    static TextUnit phones(int n) {
        StringBuilder text = new StringBuilder("Τηλέφωνα:");
        for (int i = 0; i < n; i++) {
            text.append(' ').append(phone(i)).append(',');
        }
        return para("u0", text.append(" τέλος.").toString());
    }

    static String phone(int i) {
        return String.valueOf(6900000100L + i);
    }

    static List<LlmDetector.Residual> phoneResiduals(TextUnit unit, int n) {
        List<LlmDetector.Residual> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(residual(unit, phone(i), SpanCategory.PHONE, "phone_shape"));
        }
        return out;
    }

    static LlmDetector.Remediation remediate(DocumentData doc, List<LlmDetector.Residual> residuals, List<Span> hardRedacts,
                                             LlmClient llm, RuntimeConfig cfg) {
        return LlmDetector.runPass2Remediation(doc, residuals, List.of(), hardRedacts, List.of(),
                new LlmDetector.Provider(llm, cfg, millis -> { }, RunContext.start(300)), Set.of());
    }

    /** Every id asked, by request, first asks only (retries re-ask a subset of their own batch). */
    static List<List<String>> firstAsks(ScriptedLlm llm) {
        return llm.requests.stream().filter(r -> !isRetry(r)).map(ScriptedLlm::candidateIds).toList();
    }

    static ScriptedLlm answering(Function<ChatRequest, List<?>> answer) {
        return new ScriptedLlm(r -> PyJson.dumps(answer.apply(r)));
    }

    static List<Object> all(ChatRequest r, String action) {
        return candidateIds(r).stream().map(id -> (Object) answer(id, action, "PHONE")).toList();
    }

    @Test
    void moreThanOneBatchOfCandidatesIsAskedInBatchesWithDifferentOutcomesAndEveryOneIsAccounted() {
        assertEquals(30, PER_BATCH);
        TextUnit unit = phones(35);
        // The first batch's answers are REDACT, the second's PRESERVE: both are kept, each at its own places.
        ScriptedLlm llm = answering(r -> all(r, candidateIds(r).contains("C1") ? "REDACT" : "PRESERVE"));
        LlmDetector.Remediation out = remediate(doc(unit), phoneResiduals(unit, 35), List.of(), llm, CFG);

        List<List<String>> asked = firstAsks(llm);
        assertEquals(2, asked.size());
        assertEquals(30, asked.get(0).size());
        assertEquals(5, asked.get(1).size());
        Set<String> seen = new HashSet<>();
        asked.forEach(batch -> batch.forEach(id -> assertTrue(seen.add(id), "asked twice: " + id)));
        assertEquals(35, seen.size());
        assertTrue(llm.requests.stream().allMatch(ScriptedLlm::isRemediation));
        assertEquals(2, out.pass2Calls());
        assertEquals(35, out.candidateIds().size());
        assertEquals(35, new HashSet<>(out.candidateIds()).size());
        assertEquals(List.of(), out.unresolved());
        assertEquals(30, out.spans().stream().filter(s -> s.action() == SpanAction.REDACT).count());
        assertEquals(5, out.spans().stream().filter(s -> s.action() == SpanAction.PRESERVE).count());
        // Residual -> candidate -> decision, in the order given.
        for (int i = 0; i < 35; i++) {
            LlmDetector.ResidualOutcome o = out.outcomes().get(i);
            assertEquals(phone(i), o.residual().span().text());
            assertEquals(List.of("C" + (i + 1)), o.candidateIds());
            assertEquals(i < 30 ? SpanAction.REDACT : SpanAction.PRESERVE, o.decision(), phone(i));
        }
    }

    /** One batch's provider stays down: the other batch's decisions stand, its own candidates are unavailable. */
    @Test
    void aProviderFailureInOneBatchLeavesTheOtherBatchesDecisions() {
        TextUnit unit = phones(35);
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (candidateIds(r).contains("C31")) {
                throw LlmCallException.status(503, null);
            }
            return finished(PyJson.dumps(all(r, "REDACT")));
        });
        List<LlmDetector.Remediation> holder = new ArrayList<>();
        List<String> lines = logged(() -> holder.add(remediate(doc(unit), phoneResiduals(unit, 35), List.of(), llm,
                CFG)));
        LlmDetector.Remediation out = holder.getFirst();
        assertEquals(30, out.spans().size());
        assertTrue(out.spans().stream().allMatch(s -> s.action() == SpanAction.REDACT));
        assertEquals(5, out.unresolved().size());
        for (UnresolvedFinding f : out.unresolved()) {
            assertEquals(UnresolvedFinding.Kind.PASS2_UNAVAILABLE, f.kind());
            assertTrue(f.detail().startsWith("pass 2 unavailable (cause=http_503)"), f.detail());
            assertEquals(1, f.audit().size(), f.toString()); // its residual's scan finding, carried
        }
        for (int i = 0; i < 35; i++) {
            assertEquals(i < 30 ? SpanAction.REDACT : null, out.outcomes().get(i).decision(), phone(i));
        }
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("postcheck_remediation: pass2_fallback fallback_used=true "
                + "candidates=5 cause=[http_503] needs_review=true")), lines.toString());
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("chunk 1/1 batch 2/2: postcheck remediation pass 2 (5 "
                + "candidate(s))")), lines.toString());
        for (String line : lines) {
            assertFalse(line.contains(phone(0)) || line.contains(phone(34)), line);
        }
    }

    /**
     * Within a configured context window, a candidate no request can carry even alone is never sent: it is
     * PASS2_UNAVAILABLE with cause=context_limit, with its residual's audit reference, and nothing is written.
     */
    @Test
    void aCandidateThatCannotFitTheWindowIsNeverSentAndLeftForReview() {
        TextUnit unit = para("u0", "κινητό 6912345678 και " + "Α".repeat(1500) + " τέλος.");
        RuntimeConfig cfg = withContextWindow(String.valueOf(Pass2Queue.pass2FixedInputTokens()
                + RuntimeConfig.DEFAULT_MAX_COMPLETION_TOKENS + 500));
        ScriptedLlm llm = answering(r -> all(r, "REDACT"));
        List<LlmDetector.Residual> residuals = List.of(residual(unit, "6912345678", SpanCategory.PHONE, "phone_shape"),
                residual(unit, "Α".repeat(1500), SpanCategory.POSSIBLE_PERSON, "person_name_leak",
                        PostcheckFinding.Severity.HIGH));
        List<LlmDetector.Remediation> holder = new ArrayList<>();
        List<String> lines = logged(() -> holder.add(remediate(doc(unit), residuals, List.of(), llm, cfg)));
        LlmDetector.Remediation out = holder.getFirst();

        assertEquals(List.of(List.of("C1")), firstAsks(llm));
        assertEquals(List.of("6912345678"), out.spans().stream().map(Span::text).toList());
        assertEquals(1, out.unresolved().size());
        UnresolvedFinding unsent = out.unresolved().getFirst();
        assertEquals(UnresolvedFinding.Kind.PASS2_UNAVAILABLE, unsent.kind());
        assertEquals("C2", unsent.candidateId());
        assertTrue(unsent.detail().contains("cause=context_limit"), unsent.detail());
        assertEquals(List.of(residuals.get(1).ref()), unsent.audit());
        assertNull(out.outcomes().get(1).decision()); // a HIGH residual left open: the outcome policy keeps it for review
        assertEquals(List.of("C2"), out.outcomes().get(1).candidateIds());
        assertEquals(List.of("remediation:chunk1:C1", "remediation:chunk1:C2"), out.candidateIds());
        assertTrue(lines.stream().anyMatch(l -> l.contains("cause=[context_limit] needs_review=true")), lines.toString());
    }

    /** A repeated id in one batch is re-asked in that batch alone, with the partial-acceptance wording. */
    @Test
    void aDuplicatedIdIsReaskedInItsOwnBatchOnly() {
        TextUnit unit = phones(35);
        ScriptedLlm llm = answering(r -> {
            List<Object> answers = new ArrayList<>(all(r, "REDACT"));
            if (!isRetry(r) && candidateIds(r).contains("C32")) {
                answers.add(answer("C32", "PRESERVE", "PHONE"));
            }
            return answers;
        });
        LlmDetector.Remediation out = remediate(doc(unit), phoneResiduals(unit, 35), List.of(), llm, CFG);
        List<ChatRequest> retries = llm.requests.stream().filter(ScriptedLlm::isRetry).toList();
        assertEquals(1, retries.size());
        assertEquals(List.of("C32"), candidateIds(retries.getFirst()));
        String message = retries.getFirst().userMessage();
        assertTrue(message.contains("This is a correction, not a fresh start."), message);
        assertTrue(message.contains("These entries could not be used, so only the candidates they were about are asked "
                + "again; do not repeat them:"), message);
        assertFalse(message.contains("makes the whole"), message);
        assertEquals(3, out.pass2Calls());
        assertEquals(List.of(), out.unresolved());
        assertEquals(35, out.spans().stream().filter(s -> s.action() == SpanAction.REDACT).count());
    }

    /**
     * An id from ANOTHER batch is an id this request never issued: that batch's response is not trusted and its
     * whole queue is asked again, once, with the distrust wording; the other batch is untouched.
     */
    @Test
    void anIdFromAnotherBatchIsDistrustedAndOnlyThatBatchIsAskedAgain() {
        TextUnit unit = phones(35);
        ScriptedLlm llm = answering(r -> {
            List<Object> answers = new ArrayList<>(all(r, "REDACT"));
            if (!isRetry(r) && candidateIds(r).contains("C31")) {
                answers.add(answer("C1", "PRESERVE", "PHONE"));
            }
            return answers;
        });
        LlmDetector.Remediation out = remediate(doc(unit), phoneResiduals(unit, 35), List.of(), llm, CFG);
        ChatRequest retry = llm.requests.stream().filter(ScriptedLlm::isRetry).findFirst().orElseThrow();
        assertEquals(List.of("C31", "C32", "C33", "C34", "C35"), candidateIds(retry));
        String message = retry.userMessage();
        assertTrue(message.contains("Nothing from your previous response could be kept"), message);
        assertTrue(message.contains("An id that is not in CANDIDATES, an entry with no id, or one that is not an "
                + "object means the response was not tracking the list, so none of it was kept"), message);
        assertTrue(message.contains("\"C1 is not a candidate in this queue\""), message);
        assertEquals(List.of(), out.unresolved());
        assertTrue(out.spans().stream().allMatch(s -> s.action() == SpanAction.REDACT));
        assertEquals(35, out.spans().size());
    }

    /**
     * One residual cut by a hard redaction into two fragments that fall into different batches: its outcome is
     * built from both batches' answers, and a fragment left open still names the residual's audit reference.
     */
    @Test
    void aResidualSplitIntoFragmentsAcrossBatchesKeepsItsProvenance() {
        String afm = "123456783";
        String person = "Γεώργιος " + afm + " Παπαδόπουλος";
        StringBuilder text = new StringBuilder("Τηλέφωνα:");
        for (int i = 0; i < 29; i++) {
            text.append(' ').append(phone(i)).append(',');
        }
        TextUnit unit = para("u0", text.append(" και ").append(person).append(" τέλος.").toString());
        List<LlmDetector.Residual> residuals = new ArrayList<>(phoneResiduals(unit, 29));
        LlmDetector.Residual split = residual(unit, person, SpanCategory.POSSIBLE_PERSON, "person_name_leak",
                PostcheckFinding.Severity.HIGH);
        residuals.add(split);
        List<Span> hard = List.of(rule(unit, afm, SpanCategory.AFM, SpanAction.REDACT, 1.0));

        // Both batches answer: the residual is REDACT through its two candidates and its hard-redacted middle.
        ScriptedLlm both = answering(r -> candidateIds(r).stream().map(id -> (Object) answer(id, "REDACT",
                id.equals("C30") || id.equals("C31") ? "POSSIBLE_PERSON" : "PHONE")).toList());
        LlmDetector.Remediation answered = remediate(doc(unit), residuals, hard, both, CFG);
        assertEquals(List.of(List.of("C30"), List.of("C31")), firstAsks(both).stream()
                .map(b -> b.stream().filter(id -> id.equals("C30") || id.equals("C31")).toList()).toList());
        LlmDetector.ResidualOutcome outcome = answered.outcomes().getLast();
        assertEquals(List.of("C30", "C31"), outcome.candidateIds());
        assertEquals(List.of(LlmDetector.SettledBy.HARD_REDACT), outcome.fragments().stream()
                .map(LlmDetector.FragmentOutcome::settledBy).filter(java.util.Objects::nonNull).toList());
        assertEquals(SpanAction.REDACT, outcome.decision());
        assertFalse(answered.spans().stream().anyMatch(s -> s.text().contains(afm)));

        // The second batch's provider is down: the first fragment is decided, the second is open, the residual
        // is undecided, and the open item carries the residual's own audit reference.
        ScriptedLlm half = ScriptedLlm.completions(r -> {
            if (candidateIds(r).contains("C31")) {
                throw LlmCallException.status(503, null);
            }
            return finished(both.complete(r).text());
        });
        LlmDetector.Remediation partial = remediate(doc(unit), residuals, hard, half, CFG);
        LlmDetector.ResidualOutcome open = partial.outcomes().getLast();
        assertEquals(List.of(SpanAction.REDACT, SpanAction.REDACT), open.fragments().stream()
                .map(LlmDetector.FragmentOutcome::decision).filter(java.util.Objects::nonNull).toList());
        assertNull(open.decision());
        assertEquals(1, partial.unresolved().size());
        assertEquals("C31", partial.unresolved().getFirst().candidateId());
        assertEquals(List.of(split.ref()), partial.unresolved().getFirst().audit());
        assertEquals(29, partial.outcomes().stream().filter(o -> o.decision() == SpanAction.REDACT).count());
    }

    /** Without residuals nothing is asked; a single small queue is still one call, as before. */
    @Test
    void aSmallQueueIsStillOneCall() {
        TextUnit unit = phones(3);
        ScriptedLlm llm = answering(r -> all(r, "REDACT"));
        LlmDetector.Remediation out = remediate(doc(unit), phoneResiduals(unit, 3), List.of(), llm, CFG);
        assertEquals(1, llm.requests.size());
        assertEquals(List.of("C1", "C2", "C3"), candidateIds(llm.requests.getFirst()));
        assertEquals(1, out.pass2Calls());
    }
}
