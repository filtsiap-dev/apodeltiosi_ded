package dev.filtsiap.ded.anonymizer.llm;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidateIds;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.candidates;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.finished;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.isPass1;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.isRetry;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.newFinding;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.AITimeoutError;
import dev.filtsiap.ded.anonymizer.AIUnavailableError;
import dev.filtsiap.ded.anonymizer.AnonymizerError;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.DocumentTimeoutError;
import dev.filtsiap.ded.anonymizer.FakeClock;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.PostcheckFinding;
import dev.filtsiap.ded.anonymizer.ResourceLimitExceededError;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.SpanOrigin;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.UnresolvedFinding;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.ChatRequest;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.Completion;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class LlmDetectorTest {

    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));
    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();
    /** A completion budget (700 tokens) that can answer only 10 candidates per batch: 0.6 x 700 / 40. */
    static final RuntimeConfig CFG_TEN_PER_BATCH = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test", "ANON_MAX_COMPLETION_TOKENS", "700"));
    /** A fixed backoff jitter: every backoff wait is exactly 3/4 of its nominal value (1.5, 3, 6, 12, 24 s). */
    static final java.util.function.DoubleSupplier JITTER = () -> 0.5;
    /** The backoff waits {@link #JITTER} gives for retries 1 to 5. */
    static final List<Long> BACKOFF = List.of(1_500L, 3_000L, 6_000L, 12_000L, 24_000L);

    static TextUnit para(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static TextUnit cell(String id, int row, int col, String text) {
        return cell(id, 0, row, col, text);
    }

    static TextUnit cell(String id, int table, int row, int col, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.TABLE_CELL, text, text, List.of(),
                new TextUnit.TableCellLocation(table, row, col, "", row == 0));
    }

    static DocumentData doc(TextUnit... units) {
        return new DocumentData("d", List.of(units), List.of(), List.of());
    }

    /** A deterministic REVIEW hint over the first occurrence of {@code text}. */
    static Span hint(TextUnit unit, String text, SpanCategory category) {
        return rule(unit, text, category, SpanAction.REVIEW, 0.6);
    }

    /** A deterministic span over the first occurrence of {@code text}. */
    static Span rule(TextUnit unit, String text, SpanCategory category, SpanAction action, double confidence) {
        int start = unit.normalizedText().indexOf(text);
        return new Span(unit.unitId(), start, start + text.length(), text, category, "t", confidence, action, "",
                SpanOrigin.DETERMINISTIC);
    }

    /** Pass 1 answers {@code pass1}; pass 2 answers {@code pass2} of the request (which may be a retry). */
    static ScriptedLlm model(String pass1, Function<ChatRequest, List<?>> pass2) {
        return new ScriptedLlm(r -> isPass1(r) ? pass1 : PyJson.dumps(pass2.apply(r)));
    }

    /** A pass-1 answer proposing each {@code text} for redaction as a {@code category}. */
    static String proposing(String category, String... texts) {
        List<Object> findings = new ArrayList<>();
        for (String t : texts) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("text", t);
            f.put("action", "REDACT");
            f.put("category", category);
            findings.add(f);
        }
        return PyJson.dumps(findings);
    }

    static LlmDetector.Result run(DocumentData doc, List<Span> hints, LlmClient llm) {
        return run(doc, hints, llm, millis -> { });
    }

    static LlmDetector.Result run(DocumentData doc, List<Span> hints, LlmClient llm, LlmDetector.Sleeper sleeper) {
        return LlmDetector.runLlmDetection(doc, List.of(), hints, new LlmDetector.Provider(llm, CFG, sleeper,
                RunContext.start(CFG.documentDeadlineS()), JITTER), POLICY, Set.of());
    }

    /** The whole stage, with the rule engine's own spans as well as review hints. */
    static LlmDetector.Result detect(DocumentData doc, List<Span> rules, List<Span> hints, LlmClient llm) {
        return LlmDetector.runLlmDetection(doc, rules, hints, new LlmDetector.Provider(llm, CFG, millis -> { },
                RunContext.start(CFG.documentDeadlineS()), JITTER), POLICY, Set.of());
    }

    /** Each span as ACTION:text@unit:start. */
    static List<String> decided(LlmDetector.Result result) {
        return result.spans().stream().map(s -> s.action() + ":" + s.text() + "@" + s.unitId() + ":" + s.start()).toList();
    }

    static List<ChatRequest> pass2Requests(ScriptedLlm llm) {
        return llm.requests.stream().filter(r -> !isPass1(r)).toList();
    }

    /** Runs {@code body} with every log line captured; returns the formatted messages. */
    static List<String> logged(Runnable body) {
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory
                .getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        root.addAppender(appender);
        try {
            body.run();
        } finally {
            root.detachAppender(appender);
        }
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    // ------------------------------------------------------------------ chunks and parsing

    @Test
    void tablesFirstThenParagraphsWithinTheLimit() {
        DocumentData d = doc(para("u0", "0123456789"), cell("u1", 0, 1, "B"), cell("u2", 0, 0, "A"),
                para("u3", "abcdefghi"), para("u4", "long paragraph here!"));
        List<Chunk> chunks = Chunk.split(d, 20);
        assertEquals("TABLE:\nA | B", chunks.get(0).render().text());
        assertEquals(List.of(new UnitSlice("u2", 0, 1), new UnitSlice("u1", 0, 1)), chunks.get(0).render().locate(0, 12));
        assertEquals("0123456789\nabcdefghi", chunks.get(1).render().text());
        assertEquals("long paragraph here!", chunks.get(2).render().text());
    }

    /**
     * The default paragraph target is 7,000 code points: paragraphs accumulate while the joined text
     * fits it (counted in code points, not UTF-16 units), a paragraph is never split and an oversized
     * one is a chunk of its own, and every table is one chunk whatever its size.
     */
    @Test
    void paragraphsAccumulateToSevenThousandCodePointsAndTablesStayWhole() {
        assertEquals(7000, RuntimeConfig.DEFAULT_CHUNK_SIZE_CHARS);
        assertEquals(7000, CFG.chunkSizeChars());
        String p0 = "α".repeat(3000);
        String p1 = "𝔅".repeat(3999); // astral: 3999 code points, 7998 UTF-16 units
        String bigTable = "x".repeat(8000);
        DocumentData d = doc(para("p0", p0), cell("t0", 0, 0, 0, bigTable), para("p1", p1), para("p2", "γ"),
                cell("t1", 1, 0, 0, "Α"), cell("t2", 1, 0, 1, "Β"), para("p3", "δ".repeat(9000)), para("p4", "ε"));
        List<Chunk> chunks = Chunk.split(d, CFG.chunkSizeChars());
        assertEquals(List.of(true, true, false, false, false, false), chunks.stream().map(Chunk::isTable).toList());
        assertEquals(List.of(List.of("t0"), List.of("t1", "t2"), List.of("p0", "p1"), List.of("p2"), List.of("p3"),
                List.of("p4")), chunks.stream().map(c -> c.units().stream().map(TextUnit::unitId).toList()).toList());
        // Exactly at the target: 3000 + 1 joining newline + 3999 code points.
        String joined = chunks.get(2).render().text();
        assertEquals(7000, joined.codePointCount(0, joined.length()));

        // One pass-1 request per chunk, the oversized table and paragraph each whole in theirs.
        ScriptedLlm llm = new ScriptedLlm(r -> "[]");
        run(d, List.of(), llm);
        assertEquals(6, llm.requests.size());
        assertTrue(llm.requests.stream().anyMatch(r -> r.userMessage().equals("DOCUMENT EXCERPT:\nTABLE:\n" + bigTable)));
        assertTrue(llm.requests.stream().anyMatch(r -> r.userMessage().equals("DOCUMENT EXCERPT:\n" + "δ".repeat(9000))));
    }

    @Test
    void jsonArrayExtractionFallsBackToBrackets() {
        assertEquals(1, LlmDetector.extractJsonArray("Sure:\n```json\n[{\"a\": 1}]\n```").size());
        assertNull(LlmDetector.extractJsonArray("{\"not\": \"a list\"}"));
        assertNull(LlmDetector.extractJsonArray("no json"));
    }

    // ------------------------------------------------------------------ identical text, different places

    @Test
    void samePhoneInOfficialAndPrivateContextsIsDecidedPerPlace() {
        TextUnit header = para("u0", "Τηλέφωνο: 6912345678");
        TextUnit party = para("u1", "Τηλέφωνο προσφεύγοντος: 6912345678");
        // Pass 1 makes the bare-text mistake: one answer for the digits wherever they are.
        ScriptedLlm llm = model("[{\"text\": \"6912345678\", \"action\": \"REDACT\", \"category\": \"PHONE\"}]",
                r -> candidates(r).stream().map(c -> answer((String) c.get("id"),
                        ((String) c.get("before")).contains("προσφεύγοντος") ? "REDACT" : "PRESERVE", "PHONE")).toList());
        LlmDetector.Result result = run(doc(header, party),
                List.of(hint(header, "6912345678", SpanCategory.PHONE), hint(party, "6912345678", SpanCategory.PHONE)),
                llm);
        assertEquals(List.of("PRESERVE:6912345678@u0:10", "REDACT:6912345678@u1:24"), decided(result));
        assertEquals(List.of("C1", "C2"), candidateIds(llm.requests.get(1)));
    }

    /**
     * Pass 1 answers once per TEXT. A pass-1 finding whose text occurs more than once is therefore not a
     * decision about any one place: unconfirmed by the rules, each occurrence is a question of its own.
     */
    @Test
    void sameNameRepeatedInDifferentContextsIsDecidedPerPlace() {
        TextUnit signature = para("u0", "Ο ΠΡΟΪΣΤΑΜΕΝΟΣ: Νίκος Παππάς");
        TextUnit appeal = para("u1", "την προσφυγή του Νίκος Παππάς");
        ScriptedLlm llm = model("[{\"text\": \"Νίκος Παππάς\", \"action\": \"REDACT\", \"category\": \"PERSON\"}]",
                r -> candidates(r).stream().map(c -> ((String) c.get("before")).endsWith("ΠΡΟΪΣΤΑΜΕΝΟΣ: ")
                        ? answer((String) c.get("id"), "PRESERVE", "OFFICIAL_SIGNATORY")
                        : answer((String) c.get("id"), "REDACT", "APPELLANT_NAME")).toList());
        LlmDetector.Result result = run(doc(signature, appeal), List.of(), llm);
        assertEquals(List.of("PRESERVE:Νίκος Παππάς@u0:" + signature.normalizedText().indexOf("Νίκος"),
                "REDACT:Νίκος Παππάς@u1:" + appeal.normalizedText().indexOf("Νίκος")), decided(result));
        assertEquals(List.of(SpanCategory.OFFICIAL_SIGNATORY, SpanCategory.APPELLANT_NAME),
                result.spans().stream().map(Span::category).toList());
        assertEquals(List.of("C1", "C2"), candidateIds(llm.requests.get(1)));

        // Once, it is a decision about that one place, applied without a question.
        TextUnit once = para("u0", "την προσφυγή του Νίκος Παππάς");
        ScriptedLlm single = model("[{\"text\": \"Νίκος Παππάς\", \"action\": \"REDACT\", \"category\": \"PERSON\"}]",
                r -> {
                    throw new AssertionError("a single pass-1-only finding is not a question");
                });
        LlmDetector.Result direct = run(doc(once), List.of(), single);
        assertEquals(1, single.requests.size());
        assertEquals(List.of("REDACT:Νίκος Παππάς@u0:" + once.normalizedText().indexOf("Νίκος")), decided(direct));
        assertEquals(SpanOrigin.LLM_PASS1, direct.spans().getFirst().origin());
    }

    // ------------------------------------------------------------------ locating pass-1 findings

    @Test
    void aCrossUnitPass1QuoteIsPlacedThroughTheRenderedText() {
        // A pass-1-only REDACT: applied without a question, one span per unit the quote crosses.
        ScriptedLlm llm = model(proposing("PERSON", "alpha\nbeta"), ScriptedLlm::agreeWithEveryCandidate);
        LlmDetector.Result result = run(doc(para("u0", "alpha"), para("u1", "beta")), List.of(), llm);
        assertEquals(1, llm.requests.size());
        assertEquals(List.of("REDACT:alpha@u0:0", "REDACT:beta@u1:0"), decided(result));
        assertTrue(result.spans().stream().allMatch(s -> s.origin() == SpanOrigin.LLM_PASS1));
        assertEquals(List.of(), result.unresolved());

        // Asked about (pass 1 could not decide), it is one candidate per unit.
        ScriptedLlm asked = model("[{\"text\": \"alpha\\nbeta\", \"action\": \"REVIEW\", \"category\": \"PERSON\"}]",
                ScriptedLlm::agreeWithEveryCandidate);
        run(doc(para("u0", "alpha"), para("u1", "beta")), List.of(), asked);
        assertEquals(List.of("alpha", "beta"), candidates(asked.requests.get(1)).stream().map(c -> c.get("text")).toList());
    }

    @Test
    void aUsablePass1FindingThatCannotBeLocatedIsUnresolvedNeverDropped() {
        TextUnit unit = para("u0", "Ο Σπύρος υπέγραψε.");
        UnresolvedFinding expected = new UnresolvedFinding(0, UnresolvedFinding.Kind.DISCOVERY_UNLOCATABLE,
                "POSSIBLE_PERSON", List.of(), null, "a pass-1 finding (7 chars) is not in the excerpt");

        ScriptedLlm llm = model(proposing("PERSON", "Άννα Ζ.", "Σπύρος"), ScriptedLlm::agreeWithEveryCandidate);
        LlmDetector.Result result = run(doc(unit), List.of(), llm);
        assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(result)); // the located one, applied directly
        assertEquals(1, llm.requests.size());
        assertEquals(List.of(expected), result.unresolved());

        // Alone, it is still carried out, though nothing is left to ask pass 2 about.
        ScriptedLlm alone = model(proposing("PERSON", "Άννα Ζ."), r -> {
            throw new AssertionError("pass 2 must not be asked an empty queue");
        });
        LlmDetector.Result unasked = run(doc(unit), List.of(), alone);
        assertEquals(1, alone.requests.size());
        assertEquals(List.of(expected), unasked.unresolved());
    }

    // ------------------------------------------------------------------ completeness

    @Test
    void aPass1OnlyFindingOmittedByTheFirstAnswerIsReaskedAlone() {
        TextUnit unit = para("u0", "Ο Σπύρος και η Μαρία.");
        // Pass 1 could not decide "Μαρία", so it is a question beside the rules' hint.
        ScriptedLlm llm = model("[{\"text\": \"Μαρία\", \"action\": \"REVIEW\", \"category\": \"POSSIBLE_PERSON\"}]",
                r -> isRetry(r) ? List.of(answer("C2", "REDACT", "POSSIBLE_PERSON"))
                        : List.of(answer("C1", "REDACT", "POSSIBLE_PERSON")));
        LlmDetector.Result result = run(doc(unit), List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON)), llm);
        assertEquals(List.of("REDACT:Σπύρος@u0:2", "REDACT:Μαρία@u0:15"), decided(result));
        assertEquals(3, llm.requests.size()); // pass 1, pass 2, one targeted retry
        assertEquals(List.of("C2"), candidateIds(llm.requests.get(2)));
        assertTrue(llm.requests.get(2).userMessage().contains("This is a correction, not a fresh start."));
    }

    @Test
    void aMissingCandidateStillMissingAfterTheRetryIsUnresolvedNotGuessed() {
        TextUnit unit = para("u0", "Ο Σπύρος και η Μαρία.");
        ScriptedLlm llm = model("[]", r -> isRetry(r) ? List.of() : List.of(answer("C1", "REDACT", "POSSIBLE_PERSON")));
        LlmDetector.Result result = run(doc(unit), List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON),
                hint(unit, "Μαρία", SpanCategory.POSSIBLE_PERSON)), llm);
        assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(result)); // what the first reading decided is kept
        assertEquals(List.of(new UnresolvedFinding(0, UnresolvedFinding.Kind.CANDIDATE_UNDECIDED, "POSSIBLE_PERSON",
                List.of(new UnitSlice("u0", 15, 20)), "C2", "no final decision after the corrective retry")),
                result.unresolved());
        assertEquals(3, llm.requests.size()); // never a third pass-2 call
    }

    @Test
    void aDuplicatedIdIsReaskedAndNeitherCopyIsEverKept() {
        TextUnit unit = para("u0", "Ο Σπύρος.");
        List<Span> hints = List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON));
        List<Object> conflicting = List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"),
                answer("C1", "PRESERVE", "POSSIBLE_PERSON"));

        ScriptedLlm silentRetry = model("[]", r -> isRetry(r) ? List.of() : conflicting);
        LlmDetector.Result open = run(doc(unit), hints, silentRetry);
        assertEquals(List.of(), open.spans());
        assertEquals(UnresolvedFinding.Kind.CANDIDATE_DUPLICATED, open.unresolved().get(0).kind());
        assertTrue(silentRetry.requests.get(2).userMessage().contains(
                "C1 is answered more than once; every answer for it was discarded and it must be decided again"));

        ScriptedLlm decidingRetry = model("[]", r -> isRetry(r) ? List.of(answer("C1", "PRESERVE", "OFFICIAL_SIGNATORY"))
                : conflicting);
        assertEquals(List.of("PRESERVE:Σπύρος@u0:2"), decided(run(doc(unit), hints, decidingRetry)));
    }

    @Test
    void aDuplicatedIdWithOneMalformedCopyIsVoidedToo() {
        TextUnit unit = para("u0", "Ο Σπύρος.");
        ScriptedLlm llm = model("[]", r -> isRetry(r) ? List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"))
                : List.of(answer("C1", "PRESERVE", "POSSIBLE_PERSON"), answer("C1", "MAYBE", "POSSIBLE_PERSON")));
        LlmDetector.Result result = run(doc(unit), List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON)), llm);
        assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(result)); // the retry's answer, not the valid copy's
        assertEquals(List.of("C1"), candidateIds(llm.requests.get(2)));
    }

    /**
     * Pass 2 answers ONLY issued ids. An invented id and a "NEW" entry alike are ids this queue never
     * issued: the response is not trusted, the whole queue is asked again, and nothing in it becomes a
     * candidate or a span. Still untracked after the retry, the chunk fails, as before.
     */
    @Test
    void anInventedIdOrANewEntryIsAnUnissuedIdAndNeverADiscovery() {
        TextUnit unit = para("u0", "Ο Σπύρος και η Μαρία.");
        List<Span> hints = List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON));
        List<Object> untracked = List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"), answer("C5", "PRESERVE", "DATE"),
                newFinding("Μαρία", "REDACT", "POSSIBLE_PERSON"));

        ScriptedLlm llm = model("[]", r -> isRetry(r) ? List.of(answer("C1", "PRESERVE", "OFFICIAL_SIGNATORY"))
                : untracked);
        LlmDetector.Result result = run(doc(unit), hints, llm);
        assertEquals(List.of("PRESERVE:Σπύρος@u0:2"), decided(result)); // "Μαρία" was never written
        assertEquals(List.of(), result.unresolved());
        assertEquals(3, llm.requests.size());
        ChatRequest retry = llm.requests.get(2);
        assertEquals(List.of("C1"), candidateIds(retry)); // the same queue, nothing promoted into it
        assertTrue(retry.userMessage().contains("Nothing from your previous response could be kept"));
        assertTrue(retry.userMessage().contains("\"C5 is not a candidate in this queue\""), retry.userMessage());
        assertTrue(retry.userMessage().contains("\"<malformed id> is not a candidate in this queue\""));
        assertFalse(retry.userMessage().contains("NEW"), retry.userMessage());

        // Still untracked after the retry: pass 2 is unavailable for that queue, nothing it said is used,
        // and the candidate gets the fallback (a REVIEW hint alone: nothing) and a finding of its own.
        ScriptedLlm stillUntracked = model("[]", r -> untracked);
        List<LlmDetector.Result> out = new ArrayList<>();
        List<String> lines = logged(() -> out.add(run(doc(unit), hints, stillUntracked)));
        LlmDetector.Result failed = out.getFirst();
        assertEquals(List.of(), failed.spans());
        assertEquals(List.of(UnresolvedFinding.Kind.PASS2_UNAVAILABLE),
                failed.unresolved().stream().map(UnresolvedFinding::kind).toList());
        assertTrue(failed.unresolved().getFirst().detail().startsWith("pass 2 unavailable (cause=no_usable_reading)"),
                failed.unresolved().getFirst().detail());
        assertTrue(lines.stream().anyMatch(l -> l.contains("pass2_unavailable cause=no_usable_reading error="
                + "AIProviderError")), lines.toString());
        assertEquals(3, stillUntracked.requests.size());

        // A "NEW" entry alone, beside a complete answer, is enough to distrust the response.
        ScriptedLlm newOnly = model("[]", r -> isRetry(r) ? List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"))
                : List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"), newFinding("Μαρία", "REDACT", "POSSIBLE_PERSON")));
        assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(run(doc(unit), hints, newOnly)));
        assertEquals(3, newOnly.requests.size());
    }

    @Test
    void answerOrderDoesNotChangeTheResult() {
        TextUnit unit = para("u0", "Ο Σπύρος, η Μαρία και ο Λάμπρου.");
        List<Span> hints = List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON),
                hint(unit, "Μαρία", SpanCategory.POSSIBLE_PERSON), hint(unit, "Λάμπρου", SpanCategory.POSSIBLE_PERSON));
        List<Object> entries = List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"),
                answer("C2", "PRESERVE", "OFFICIAL_SIGNATORY"), answer("C3", "REDACT", "POSSIBLE_PERSON"));
        List<Object> reversed = new ArrayList<>(entries);
        java.util.Collections.reverse(reversed);
        assertEquals(run(doc(unit), hints, model("[]", r -> entries)).spans(),
                run(doc(unit), hints, model("[]", r -> reversed)).spans());
    }

    // ------------------------------------------------------------------ candidate-only pass 2

    /**
     * Pass 2 is shown its candidates and nothing else: no excerpt in its first ask, its corrective
     * retry or the remediation's, and no document text further than 40 code points from a candidate.
     */
    @Test
    void noPass2PromptCarriesTheExcerpt() {
        String far = "ΑΠΟΜΑΚΡΥΣΜΕΝΗ ΠΡΟΤΑΣΗ ΠΟΥ ΔΕΝ ΣΤΕΛΝΕΤΑΙ ΠΟΤΕ ΣΤΟ ΔΕΥΤΕΡΟ ΠΕΡΑΣΜΑ";
        TextUnit opening = para("u0", far + " " + far);
        TextUnit unit = para("u1", "Ο Σπύρος και η Μαρία.");
        TextUnit closing = para("u2", far + " " + far);
        ScriptedLlm llm = model("[]", r -> isRetry(r) ? List.of(answer("C2", "REDACT", "POSSIBLE_PERSON"))
                : List.of(answer("C1", "REDACT", "POSSIBLE_PERSON")));
        LlmDetector.Result result = run(doc(opening, unit, closing), List.of(hint(unit, "Σπύρος",
                SpanCategory.POSSIBLE_PERSON), hint(unit, "Μαρία", SpanCategory.POSSIBLE_PERSON)), llm);
        assertEquals(2, result.spans().size());
        assertTrue(llm.requests.get(0).userMessage().contains(far)); // pass 1 reads the chunk
        List<ChatRequest> pass2 = pass2Requests(llm);
        assertEquals(2, pass2.size());
        assertTrue(isRetry(pass2.get(1)));
        for (ChatRequest r : pass2) {
            assertFalse(r.userMessage().contains("DOCUMENT EXCERPT"), r.userMessage());
            assertFalse(r.userMessage().contains(far), r.userMessage());
            assertTrue(r.userMessage().startsWith("Return one decision for every candidate id below, and no other "
                    + "entries.\n\nCANDIDATES:\n"), r.userMessage());
            for (Map<String, Object> c : candidates(r)) {
                assertEquals(Set.of("id", "text", "recommendations", "before", "after"), c.keySet());
                String before = (String) c.get("before");
                String after = (String) c.get("after");
                assertTrue(before.codePointCount(0, before.length()) <= Pass2Queue.CONTEXT_WINDOW);
                assertTrue(after.codePointCount(0, after.length()) <= Pass2Queue.CONTEXT_WINDOW);
            }
        }
        // The remediation's ask is the same contract.
        ScriptedLlm remediation = model("[]", r -> List.of(answer("C1", "REDACT", "PHONE")));
        TextUnit phone = para("u1", "κινητό 6912345678 εδώ.");
        remediate(doc(opening, phone, closing), List.of(residual(phone, "6912345678", SpanCategory.PHONE,
                "phone_shape")), remediation, RunContext.start(300));
        ChatRequest asked = remediation.requests.get(0);
        assertTrue(ScriptedLlm.isRemediation(asked));
        assertFalse(asked.userMessage().contains("DOCUMENT EXCERPT") || asked.userMessage().contains(far),
                asked.userMessage());
    }

    @Test
    void pass2IsSkippedWheneverItsQueueIsEmpty() {
        DocumentData plain = doc(para("u0", "Κείμενο χωρίς στοιχεία."));
        ScriptedLlm clean = new ScriptedLlm(r -> "[]");
        assertEquals(List.of(), run(plain, List.of(), clean).spans());
        assertEquals(1, clean.requests.size());

        // Only PRESERVE proposed, by the rules and by pass 1: they agree, so nothing is asked, and pass
        // 1's agreeing PRESERVE goes to the resolver beside the rule's.
        TextUnit unit = para("u0", "Ημερομηνία 01/02/2020.");
        ScriptedLlm keepers = model("[{\"text\": \"01/02/2020\", \"action\": \"PRESERVE\", \"category\": \"DATE\"}]",
                r -> {
                    throw new AssertionError("pass 2 must not be asked an empty queue");
                });
        Span date = rule(unit, "01/02/2020", SpanCategory.DATE, SpanAction.PRESERVE, 0.95);
        LlmDetector.Result result = detect(doc(unit), List.of(date), List.of(), keepers);
        assertEquals(1, keepers.requests.size());
        assertEquals(List.of("PRESERVE:01/02/2020@u0:11"), decided(result));
        assertEquals(SpanOrigin.LLM_PASS1, result.spans().getFirst().origin());
        assertEquals(List.of(), result.unresolved());
    }

    // ------------------------------------------------------------------ the masked view

    /**
     * A hard redact is blanked, one dot per code point, in EVERYTHING the model is shown: the pass-1
     * excerpt, the pass-1 corrective call, every candidate's text and context, and pass 2's retry;
     * the document's own text is what pass 2's decisions are written from.
     */
    @Test
    void aHardRedactIsMaskedInEveryPromptAndCandidate() {
        String afm = "123456783";
        TextUnit unit = para("u0", "Ο Σπύρος Λάμπρου, Α.Φ.Μ. " + afm + ", τηλ. 6912345678.");
        Span hardAfm = rule(unit, afm, SpanCategory.AFM, SpanAction.REDACT, 0.95);
        AtomicInteger pass1Calls = new AtomicInteger();
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (isPass1(r)) {
                // The first reading is unusable, so the excerpt is sent twice; the name is a question.
                return pass1Calls.getAndIncrement() == 0 ? finished("not json")
                        : finished("[{\"text\": \"Σπύρος Λάμπρου\", \"action\": \"REVIEW\", \"category\": \"PERSON\"}]");
            }
            return finished(PyJson.dumps(isRetry(r) ? List.of(answer("C2", "REDACT", "POSSIBLE_PERSON"))
                    : List.of(answer("C1", "REDACT", "PHONE"))));
        });
        LlmDetector.Result result = detect(doc(unit), List.of(hardAfm),
                List.of(hint(unit, "6912345678", SpanCategory.PHONE)), llm);

        assertEquals(4, llm.requests.size()); // pass 1, its corrective call, pass 2, pass 2's retry
        for (ChatRequest r : llm.requests) {
            assertFalse(r.userMessage().contains(afm), r.userMessage());
        }
        assertEquals(List.of(true, true, false, false), llm.requests.stream().map(ScriptedLlm::isPass1).toList());
        String masked = "Ο Σπύρος Λάμπρου, Α.Φ.Μ. ........., τηλ. 6912345678.";
        assertEquals("DOCUMENT EXCERPT:\n" + masked, llm.requests.get(0).userMessage());
        assertTrue(llm.requests.get(1).userMessage().startsWith("DOCUMENT EXCERPT:\n" + masked + "\n\nYOUR PREVIOUS "
                + "RESPONSE COULD NOT BE USED: the output was not a JSON array.\n"), llm.requests.get(1).userMessage());
        Map<String, Object> phone = candidates(llm.requests.get(2)).get(0);
        assertEquals("6912345678", phone.get("text"));
        assertEquals(" Σπύρος Λάμπρου, Α.Φ.Μ. ........., τηλ. ", phone.get("before"));
        Map<String, Object> name = candidates(llm.requests.get(3)).get(0);
        assertEquals("Σπύρος Λάμπρου", name.get("text"));
        assertEquals(", Α.Φ.Μ. ........., τηλ. 6912345678.", name.get("after"));
        // The decisions are written from the document: the hard redact itself is the resolver's, not pass 2's.
        assertEquals(List.of("REDACT:6912345678@u0:41", "REDACT:Σπύρος Λάμπρου@u0:2"), decided(result));
    }

    /**
     * Only the resolver's own hard-redact predicate masks or withholds: a deterministic REDACT in a
     * hard-redact category but below the high-confidence threshold is an ordinary rule span, and so is
     * a confident REDACT in a category that is not hard. Pass 1 decided neither, so each is a pass-2
     * question (every actionable candidate gets an LLM decision); the hard one never is. A hard preserve
     * is withheld but stays readable, a place it covers whole is settled, and a place only PRESERVE was
     * proposed for is not asked.
     */
    @Test
    void onlyHardDecisionsAreMaskedOrWithheldAndPreserveOnlyPlacesAreNotAsked() {
        String hardAfm = "123456783";
        String softAfm = "987654321";
        TextUnit unit = para("u0", "ΑΦΜ " + hardAfm + " και ΑΦΜ " + softAfm + ", ΔΟΥ Κέρκυρας 01/02/1980, τηλ. "
                + "6912345678.");
        List<Span> rules = List.of(
                rule(unit, hardAfm, SpanCategory.AFM, SpanAction.REDACT, 0.95),
                rule(unit, softAfm, SpanCategory.AFM, SpanAction.REDACT, 0.85),
                rule(unit, "ΔΟΥ Κέρκυρας", SpanCategory.DOU, SpanAction.PRESERVE, 0.95),
                rule(unit, "01/02/1980", SpanCategory.DATE, SpanAction.PRESERVE, 0.95),
                rule(unit, "6912345678", SpanCategory.PHONE, SpanAction.REDACT, 0.95));
        // Pass 1 proposes the place inside the hard preserve: that question is settled already.
        ScriptedLlm llm = model(proposing("LOCALITY", "Κέρκυρας"), ScriptedLlm::agreeWithEveryCandidate);
        LlmDetector.Result result = detect(doc(unit), rules, List.of(), llm);

        assertEquals("DOCUMENT EXCERPT:\nΑΦΜ ......... και ΑΦΜ " + softAfm + ", ΔΟΥ Κέρκυρας 01/02/1980, τηλ. "
                + "6912345678.", llm.requests.get(0).userMessage());
        assertEquals(2, llm.requests.size()); // pass 1, then ONE pass-2 call for the two ordinary REDACTs
        assertEquals(List.of(softAfm, "6912345678"), candidates(llm.requests.get(1)).stream().map(c -> c.get("text"))
                .toList());
        assertEquals(List.of("REDACT:" + softAfm + "@u0:" + unit.normalizedText().indexOf(softAfm),
                "REDACT:6912345678@u0:" + unit.normalizedText().indexOf("6912345678")), decided(result));
        assertTrue(result.spans().stream().allMatch(s -> s.origin() == SpanOrigin.LLM_PASS2));
    }

    // ------------------------------------------------------------------ incomplete responses and pass 1

    @Test
    void aTruncatedPass2IsNotReadAndTheWholeQueueIsAskedAgain() {
        TextUnit unit = para("u0", "Ο Σπύρος.");
        List<Span> hints = List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON));
        String decidedBody = PyJson.dumps(List.of(answer("C1", "REDACT", "POSSIBLE_PERSON")));

        ScriptedLlm recovers = ScriptedLlm.completions(r -> isPass1(r) ? finished("[]") : isRetry(r)
                ? finished(PyJson.dumps(List.of(answer("C1", "PRESERVE", "OFFICIAL_SIGNATORY"))))
                : new Completion(decidedBody, "length", false));
        assertEquals(List.of("PRESERVE:Σπύρος@u0:2"), decided(run(doc(unit), hints, recovers)));
        assertTrue(recovers.requests.get(2).userMessage().contains("REJECTED: the completion stopped at the "
                + "output-token limit (finish_reason=length)."));

        // Never a reading, even after the retry: pass 2 is unavailable for the queue. Nothing it said is
        // used; the candidate gets the fallback and a finding of its own, and the document goes on.
        ScriptedLlm neverFinishes = ScriptedLlm.completions(r -> isPass1(r) ? finished("[]")
                : new Completion(decidedBody, "length", false));
        List<LlmDetector.Result> out = new ArrayList<>();
        List<String> lines = logged(() -> out.add(run(doc(unit), hints, neverFinishes)));
        assertEquals(List.of(), out.getFirst().spans());
        assertEquals(List.of(UnresolvedFinding.Kind.PASS2_UNAVAILABLE),
                out.getFirst().unresolved().stream().map(UnresolvedFinding::kind).toList());
        assertEquals(3, neverFinishes.requests.size()); // pass 1, pass 2, its one retry
        assertTrue(lines.stream().anyMatch(l -> l.contains("pass2_unavailable cause=no_usable_reading")), lines.toString());

        ScriptedLlm refuses = ScriptedLlm.completions(r -> isPass1(r) ? finished("[]")
                : new Completion("", "stop", true));
        LlmDetector.Result refused = run(doc(unit), hints, refuses);
        assertEquals(UnresolvedFinding.Kind.PASS2_UNAVAILABLE, refused.unresolved().getFirst().kind());
        assertEquals(List.of(), refused.spans());
    }

    /**
     * An unusable completed pass 1 gets exactly ONE corrective call, with the same masked excerpt;
     * still unusable, the chunk continues with an explicit incomplete-discovery review item.
     */
    @Test
    void anUnusablePass1GetsOneCorrectiveCallAndThenNoMore() {
        DocumentData plain = doc(para("u0", "Κείμενο χωρίς στοιχεία."));
        for (Completion unusable : List.of(new Completion("[{\"text\": \"x\"", "length", false), finished(""),
                finished("not json"), new Completion("", "stop", true),
                finished("[{\"text\": \"x\", \"action\": \"MAYBE\", \"category\": \"PERSON\"}]"))) {
            ScriptedLlm llm = ScriptedLlm.completions(r -> unusable);
            List<LlmDetector.Result> out = new ArrayList<>();
            List<String> lines = logged(() -> out.add(run(plain, List.of(), llm)));
            LlmDetector.Result result = out.get(0);
            assertEquals(2, llm.requests.size(), unusable.toString()); // the call and one correction, no pass 2
            assertTrue(llm.requests.stream().allMatch(ScriptedLlm::isPass1));
            String corrective = llm.requests.get(1).userMessage();
            assertTrue(corrective.startsWith(llm.requests.get(0).userMessage() + "\n\nYOUR PREVIOUS RESPONSE COULD "
                    + "NOT BE USED: "), corrective);
            assertTrue(corrective.endsWith("Return the complete JSON array in the schema above — valid JSON, no "
                    + "markdown, no prose."), corrective);
            assertEquals(List.of(), result.spans());
            assertEquals(List.of(UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE),
                    result.unresolved().stream().map(UnresolvedFinding::kind).toList());
            assertTrue(lines.stream().anyMatch(l -> l.startsWith("pass1_discovery_degraded request_id=")
                    && l.contains(" chunk=1 pass=1 ") && l.contains(" reason=pass1_")), lines.toString());
        }

        // A correction that IS usable is read like any first reading.
        AtomicInteger calls = new AtomicInteger();
        TextUnit unit = para("u0", "Ο Σπύρος υπέγραψε.");
        ScriptedLlm recovers = ScriptedLlm.completions(r -> isPass1(r)
                ? (calls.getAndIncrement() == 0 ? finished("not json") : finished(proposing("PERSON", "Σπύρος")))
                : finished(PyJson.dumps(ScriptedLlm.agreeWithEveryCandidate(r))));
        assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(run(doc(unit), List.of(), recovers)));
        assertEquals(2, recovers.requests.size()); // its pass-1-only REDACT needs no question
    }

    /**
     * Discovery the provider never delivered is a warning, not a failure: no corrective call (it would
     * be another transport ladder in disguise), an incomplete-discovery review item, and
     * the rules' proposals still go to pass 2.
     */
    @Test
    void aPass1TheProviderNeverDeliveredIsAWarningAndTheRulesProposalsAreStillAdjudicated() {
        TextUnit unit = para("u0", "Ο Σπύρος υπέγραψε.");
        List<Span> hints = List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON));
        for (Supplier<LlmCallException> failure : List.<Supplier<LlmCallException>>of(
                () -> LlmCallException.status(503, null), () -> LlmCallException.timeout(null),
                () -> LlmCallException.connection(null), () -> LlmCallException.status(400, null),
                () -> LlmCallException.other(null))) {
            ScriptedLlm llm = ScriptedLlm.completions(r -> {
                if (isPass1(r)) {
                    throw failure.get();
                }
                return finished(PyJson.dumps(ScriptedLlm.agreeWithEveryCandidate(r)));
            });
            List<LlmDetector.Result> out = new ArrayList<>();
            List<String> lines = logged(() -> out.add(run(doc(unit), hints, llm)));
            LlmDetector.Result result = out.get(0);
            assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(result));
            assertEquals(List.of(UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE),
                    result.unresolved().stream().map(UnresolvedFinding::kind).toList());
            long pass1 = llm.requests.stream().filter(ScriptedLlm::isPass1).count();
            assertTrue(pass1 == 1 || pass1 == LlmDetector.MAX_PROVIDER_ATTEMPTS, String.valueOf(pass1));
            assertEquals(1, pass2Requests(llm).size());
            assertTrue(lines.stream().anyMatch(l -> l.startsWith("pass1_discovery_degraded request_id=")
                    && l.contains(" chunk=1 pass=1 attempt=first reason=pass1_provider_failure error=")), lines.toString());
            for (String line : lines) {
                assertFalse(line.contains("Σπύρος"), line);
            }
        }
        // With nothing for the rules to propose either, pass 2 is skipped, but lost discovery still requires review.
        ScriptedLlm down = failing(Integer.MAX_VALUE, () -> LlmCallException.status(503, null));
        LlmDetector.Result clean = run(doc(para("u0", "κείμενο")), List.of(), down);
        assertEquals(LlmDetector.MAX_PROVIDER_ATTEMPTS, down.requests.size());
        assertEquals(List.of(), clean.spans());
        assertEquals(UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE, clean.unresolved().getFirst().kind());
    }

    @Test
    void aTransportFailureOnTheCorrectiveCallEndsDiscoveryWithoutAnotherCall() {
        DocumentData plain = doc(para("u0", "κείμενο"));
        for (int status : new int[] {400, 503}) {
            AtomicInteger calls = new AtomicInteger();
            ScriptedLlm llm = ScriptedLlm.completions(r -> {
                if (calls.getAndIncrement() == 0) {
                    return finished("not json");
                }
                throw LlmCallException.status(status, null);
            });
            LlmDetector.Result result = run(plain, List.of(), llm);
            // The first reading, then the corrective request's own transport attempts, and nothing after.
            assertEquals(1 + (status == 400 ? 1 : LlmDetector.MAX_PROVIDER_ATTEMPTS), llm.requests.size());
            assertEquals(List.of(UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE),
                    result.unresolved().stream().map(UnresolvedFinding::kind).toList());
        }
    }

    /** Only provider failures are absorbed: an interrupted wait is cancellation, and it propagates. */
    @Test
    void anInterruptedRetryWaitInPass1IsNeverMistakenForAProviderFailure() {
        ScriptedLlm llm = failing(Integer.MAX_VALUE, () -> LlmCallException.status(503, null));
        AIProviderError e = assertThrows(AIProviderError.class, () -> run(doc(para("u0", "κείμενο")), List.of(), llm,
                millis -> {
                    throw new InterruptedException("cancelled");
                }));
        assertEquals("LLM detection interrupted", e.getMessage());
        assertEquals(1, llm.requests.size());
    }

    // ------------------------------------------------------------------ provider retries

    /** Throws {@code failure} for the first {@code failures} calls, then answers "[]". */
    static ScriptedLlm failing(int failures, Supplier<LlmCallException> failure) {
        AtomicInteger calls = new AtomicInteger();
        return ScriptedLlm.completions(r -> {
            if (calls.getAndIncrement() < failures) {
                throw failure.get();
            }
            return finished("[]");
        });
    }

    static LlmDetector.Provider provider(LlmClient llm, RunContext ctx, LlmDetector.Sleeper sleeper) {
        return new LlmDetector.Provider(llm, CFG, sleeper, ctx, JITTER);
    }

    static Completion callPass1(LlmDetector.Provider provider) {
        return provider.call(Prompts.SYSTEM_PROMPT_PASS1, "DOCUMENT EXCERPT:\nκείμενο", 0, CallKind.PASS1);
    }

    @Test
    void transientProviderFailuresAreRetriedWithBackoff() {
        for (int status : new int[] {408, 409, 429, 500, 502, 503, 504}) {
            List<Long> slept = new ArrayList<>();
            ScriptedLlm llm = failing(2, () -> LlmCallException.status(status, null));
            assertEquals("[]", callPass1(provider(llm, RunContext.start(300), slept::add)).text());
            assertEquals(3, llm.requests.size(), "status " + status); // two failures, then it answers
            assertEquals(BACKOFF.subList(0, 2), slept);
        }
        for (Supplier<LlmCallException> f : List.<Supplier<LlmCallException>>of(
                () -> LlmCallException.timeout(null), () -> LlmCallException.connection(null))) {
            List<Long> slept = new ArrayList<>();
            ScriptedLlm llm = failing(5, f);
            List<String> lines = logged(() -> callPass1(provider(llm, RunContext.start(300), slept::add)));
            assertEquals(6, llm.requests.size());
            assertEquals(BACKOFF, slept);
            assertTrue(lines.stream().anyMatch(l -> l.startsWith("llm_retry_succeeded ")
                    && l.contains(" transport_attempt=6")), lines.toString());
        }
    }

    @Test
    void nonRetryableFailuresStopAtTheFirstAttempt() {
        for (int status : new int[] {400, 401, 403, 404, 422}) {
            ScriptedLlm llm = failing(Integer.MAX_VALUE, () -> LlmCallException.status(status, null));
            assertEquals("provider returned HTTP " + status + " (chunk 1, pass 1)", assertThrows(AIProviderError.class,
                    () -> callPass1(provider(llm, RunContext.start(300), millis -> { }))).getMessage());
            assertEquals(1, llm.requests.size());
        }
        ScriptedLlm other = failing(Integer.MAX_VALUE, () -> LlmCallException.other(null));
        assertEquals("provider error (chunk 1, pass 1)", assertThrows(AIProviderError.class,
                () -> callPass1(provider(other, RunContext.start(300), millis -> { }))).getMessage());
        assertEquals(1, other.requests.size());

        // In pass 2 the same failure no longer fails the document: one attempt, then the fallback. A
        // REVIEW-only place has no definitive decision to fall back to, so it is left for a person.
        TextUnit unit = para("u0", "Ο Σπύρος.");
        ScriptedLlm pass2Fails = ScriptedLlm.completions(r -> {
            if (isPass1(r)) {
                return finished("[]");
            }
            throw LlmCallException.status(400, null);
        });
        LlmDetector.Result result = run(doc(unit), List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON)),
                pass2Fails);
        assertEquals(2, pass2Fails.requests.size()); // pass 1, one pass-2 attempt
        assertEquals(List.of(), result.spans());
        assertEquals(1, result.unresolved().size());
        UnresolvedFinding open = result.unresolved().getFirst();
        assertEquals(UnresolvedFinding.Kind.PASS2_UNAVAILABLE, open.kind());
        assertEquals("C1", open.candidateId());
        assertEquals(List.of(new UnitSlice("u0", 2, 8)), open.locations());
        assertTrue(open.detail().contains("cause=http_400") && open.detail().contains("fallback=none (undecided)")
                && open.detail().contains("deterministic:REVIEW/POSSIBLE_PERSON"), open.detail());
    }

    @Test
    void anExhaustedLadderIsSixAttemptsAndRaisesTheTypedError() {
        assertEquals(6, LlmDetector.MAX_PROVIDER_ATTEMPTS);
        List<Long> slept = new ArrayList<>();
        ScriptedLlm busy = failing(Integer.MAX_VALUE, () -> LlmCallException.status(503, null));
        List<String> lines = logged(() -> assertEquals("provider returned HTTP 503 (chunk 1, pass 1)",
                assertThrows(AIProviderError.class,
                        () -> callPass1(provider(busy, RunContext.start(300), slept::add))).getMessage()));
        assertEquals(6, busy.requests.size());
        assertEquals(BACKOFF, slept);
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("llm_retry_exhausted ") && l.contains(" attempts=6 ")),
                lines.toString());
        assertEquals("LLM call timed out after 60.0s (chunk 1, pass 1)", assertThrows(AITimeoutError.class,
                () -> callPass1(provider(failing(Integer.MAX_VALUE, () -> LlmCallException.timeout(null)),
                        RunContext.start(300), millis -> { }))).getMessage());
        assertEquals("LLM provider unreachable (chunk 1, pass 1)", assertThrows(AIUnavailableError.class,
                () -> callPass1(provider(failing(Integer.MAX_VALUE, () -> LlmCallException.connection(null)),
                        RunContext.start(300), millis -> { }))).getMessage());
        // Six 429s with a valid header: each wait is the header's, then the ladder is exhausted.
        List<Long> limited = new ArrayList<>();
        ScriptedLlm throttled = failing(Integer.MAX_VALUE, () -> LlmCallException.status(429, 2_000L, null));
        assertEquals("provider returned HTTP 429 (chunk 1, pass 1)", assertThrows(AIProviderError.class,
                () -> callPass1(provider(throttled, RunContext.start(300), limited::add))).getMessage());
        assertEquals(6, throttled.requests.size());
        assertEquals(List.of(2_000L, 2_000L, 2_000L, 2_000L, 2_000L), limited);
    }

    /**
     * A valid {@code retry-after-ms} is waited EXACTLY, whatever it is: shorter than the backoff
     * (zero included: the provider asked for no wait) or longer. Never shortened, never lengthened.
     */
    @Test
    void aValidRetryAfterMsIsWaitedExactlyZeroIncluded() {
        for (long header : new long[] {0, 1, 250, 1_500, 5_000, 12_345, 60_000}) {
            List<Long> slept = new ArrayList<>();
            ScriptedLlm llm = failing(1, () -> LlmCallException.status(429, header, null));
            List<String> lines = logged(() -> callPass1(provider(llm, RunContext.start(300), slept::add)));
            assertEquals(List.of(header), slept);
            assertEquals(2, llm.requests.size());
            assertTrue(lines.stream().anyMatch(l -> l.startsWith("llm_retry ") && l.contains(" retry=1/5 delay_ms="
                    + header + " delay_source=header error=rate_limited ")), lines.toString());
        }
        // Mixed: a header on one failure, none on the next; each retry is judged on its own failure.
        AtomicInteger calls = new AtomicInteger();
        List<Long> slept = new ArrayList<>();
        ScriptedLlm mixed = ScriptedLlm.completions(r -> {
            int n = calls.getAndIncrement();
            if (n == 0) {
                throw LlmCallException.status(503, 17_000L, null);
            }
            if (n == 1) {
                throw LlmCallException.status(503, null);
            }
            return finished("[]");
        });
        callPass1(provider(mixed, RunContext.start(300), slept::add));
        assertEquals(List.of(17_000L, BACKOFF.get(1)), slept);
    }

    /**
     * Without a usable header the wait is an exponential backoff with equal jitter: nominal 2, 4, 8,
     * 16 and 32 seconds, drawn from [nominal/2, nominal). A missing, malformed or negative header is
     * no header at all.
     */
    @Test
    void theFallbackBackoffIsExponentialWithJitter() {
        long nominal = LlmDetector.BACKOFF_BASE_MS;
        for (int retry = 1; retry <= 5; retry++, nominal *= 2) {
            LlmDetector.RetryDelay low = LlmDetector.retryDelay(retry, null, 0.0);
            LlmDetector.RetryDelay mid = LlmDetector.retryDelay(retry, null, 0.5);
            LlmDetector.RetryDelay high = LlmDetector.retryDelay(retry, null, Math.nextDown(1.0));
            assertEquals("backoff", low.source());
            assertEquals(nominal / 2, low.millis());
            assertEquals(BACKOFF.get(retry - 1), mid.millis());
            assertTrue(high.millis() < nominal && high.millis() >= nominal - 1, String.valueOf(high.millis()));
            // An out-of-range jitter source cannot leave the band.
            assertEquals(nominal / 2, LlmDetector.retryDelay(retry, null, -3.0).millis());
            assertTrue(LlmDetector.retryDelay(retry, null, 7.0).millis() < nominal);
        }
        // Even the longest jittered ladder fits the cumulative cap.
        assertTrue(1_999L + 3_999L + 7_999L + 15_999L + 31_999L <= LlmDetector.MAX_CUMULATIVE_WAIT_MS);
        // An invalid header reaches the controller as null (see LlmCallException.parseRetryAfterMs).
        for (String invalid : new String[] {null, "", "abc", "-1", "1.5", " ", "+5", "99999999999999999999"}) {
            assertNull(LlmCallException.parseRetryAfterMs(invalid), String.valueOf(invalid));
        }
        assertEquals(0L, LlmCallException.parseRetryAfterMs("0"));
        List<Long> slept = new ArrayList<>();
        ScriptedLlm llm = failing(1, () -> LlmCallException.status(503, LlmCallException.parseRetryAfterMs("soon"), null));
        List<String> lines = logged(() -> callPass1(provider(llm, RunContext.start(300), slept::add)));
        assertEquals(List.of(BACKOFF.getFirst()), slept);
        assertTrue(lines.stream().anyMatch(l -> l.contains(" delay_source=backoff ")), lines.toString());
    }

    /**
     * All the waits of one request together never exceed 65 s: a backoff wait is clipped to what is
     * left, and a provider-requested wait that does not fit ends the retries (it is never shortened).
     * Either way the classified provider error is raised, which the caller's fallback handles.
     */
    @Test
    void allTheWaitsOfOneRequestStayWithinTheCumulativeCap() {
        assertEquals(65_000L, LlmDetector.MAX_CUMULATIVE_WAIT_MS);
        List<Long> slept = new ArrayList<>();
        ScriptedLlm halfMinute = failing(Integer.MAX_VALUE, () -> LlmCallException.status(429, 30_000L, null));
        List<String> lines = logged(() -> assertThrows(AIProviderError.class,
                () -> callPass1(provider(halfMinute, RunContext.start(300), slept::add))));
        assertEquals(List.of(30_000L, 30_000L), slept); // a third 30 s wait would make 90 s
        assertEquals(3, halfMinute.requests.size());
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("llm_retry_skipped ") && l.contains(" reason=wait_budget ")
                && l.contains(" delay_ms=30000 delay_source=header waited_ms=60000 ")), lines.toString());

        // A long header first, then backoff: the backoff is clipped to what is left, then the ladder ends.
        AtomicInteger calls = new AtomicInteger();
        List<Long> clipped = new ArrayList<>();
        ScriptedLlm mixed = ScriptedLlm.completions(r -> {
            throw calls.getAndIncrement() == 0 ? LlmCallException.status(503, 50_000L, null)
                    : LlmCallException.status(503, null);
        });
        assertThrows(AIProviderError.class, () -> callPass1(provider(mixed, RunContext.start(300), clipped::add)));
        assertEquals(List.of(50_000L, 3_000L, 6_000L, 6_000L), clipped); // 12 s clipped to the 6 s left
        assertEquals(65_000L, clipped.stream().mapToLong(Long::longValue).sum());
        assertEquals(5, mixed.requests.size());
    }

    @Test
    void theCorrectiveRetryIsItselfOneRequestOnTheLadder() {
        TextUnit unit = para("u0", "Ο Σπύρος και η Μαρία.");
        AtomicInteger retryCalls = new AtomicInteger();
        List<Long> slept = new ArrayList<>();
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (isPass1(r)) {
                return finished("[]");
            }
            if (!isRetry(r)) {
                return finished(PyJson.dumps(List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"))));
            }
            if (retryCalls.getAndIncrement() == 0) {
                throw LlmCallException.status(429, 250L, null);
            }
            return finished(PyJson.dumps(List.of(answer("C2", "REDACT", "POSSIBLE_PERSON"))));
        });
        LlmDetector.Result result = run(doc(unit), List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON),
                hint(unit, "Μαρία", SpanCategory.POSSIBLE_PERSON)), llm, slept::add);
        assertEquals(2, result.spans().size());
        assertEquals(4, llm.requests.size()); // pass 1, pass 2, retry (429), retry again
        assertEquals(List.of(250L), slept); // exactly what the provider asked for
    }

    @Test
    void aCancelledDocumentNeitherWaitsNorTriesAgain() {
        // Cancelled while the attempt was in flight: no wait begins.
        RunContext early = RunContext.start(300);
        List<Long> slept = new ArrayList<>();
        ScriptedLlm cancels = ScriptedLlm.completions(r -> {
            early.deadline().cancel();
            throw LlmCallException.status(503, null);
        });
        List<String> lines = logged(() -> assertEquals("llm pass 1", assertThrows(DocumentTimeoutError.class,
                () -> callPass1(provider(cancels, early, slept::add))).stage()));
        assertEquals(1, cancels.requests.size());
        assertEquals(List.of(), slept);
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("llm_retry_skipped ") && l.contains(" reason=cancelled ")),
                lines.toString());

        // Cancelled during the wait: no further attempt.
        RunContext during = RunContext.start(300);
        ScriptedLlm busy = failing(Integer.MAX_VALUE, () -> LlmCallException.status(503, null));
        assertEquals("llm pass 1", assertThrows(DocumentTimeoutError.class,
                () -> callPass1(provider(busy, during, millis -> during.deadline().cancel()))).stage());
        assertEquals(1, busy.requests.size());
    }

    // ------------------------------------------------------------------ the document budget

    static LlmDetector.Result run(DocumentData doc, List<Span> hints, LlmClient llm, RunContext ctx,
                                  LlmDetector.Sleeper sleeper) {
        return LlmDetector.runLlmDetection(doc, List.of(), hints, new LlmDetector.Provider(llm, CFG, sleeper,
                ctx, JITTER), POLICY, Set.of());
    }

    static List<Double> timeouts(ScriptedLlm llm) {
        return llm.requests.stream().map(ChatRequest::timeoutSeconds).toList();
    }

    @Test
    void everyRequestIsCutToWhatIsLeftOfTheBudget() {
        FakeClock clock = new FakeClock();
        ScriptedLlm tight = ScriptedLlm.cooperative();
        run(doc(para("u0", "κείμενο")), List.of(), tight, clock.context(30), millis -> { });
        assertEquals(List.of(30.0), timeouts(tight)); // less than the configured 60 s
        ScriptedLlm roomy = ScriptedLlm.cooperative();
        run(doc(para("u0", "κείμενο")), List.of(), roomy, clock.context(300), millis -> { });
        assertEquals(List.of(60.0), timeouts(roomy));
    }

    @Test
    void noRequestStartsWithoutTheFloorLeft() {
        ScriptedLlm llm = ScriptedLlm.cooperative();
        DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class,
                () -> run(doc(para("u0", "κείμενο")), List.of(), llm, new FakeClock().context(1.0), millis -> { }));
        assertEquals("llm pass 1", e.stage());
        assertEquals(0, llm.requests.size());
    }

    /**
     * A wait the provider asked for is never shortened to fit the budget. When the call after it could
     * not finish but time is still left, the retries end with the provider's error, which the stage
     * absorbs (pass 1: incomplete discovery; pass 2: the fallback). When no more than the floor is
     * left, it is the document running out of time, even in pass 1.
     */
    @Test
    void retriesSpendTheDocumentBudgetAndAServerDelayIsNeverShortened() {
        // Each failed attempt costs 1 s of a 10 s budget and asks for 7 s: the first wait fits; after the
        // second failure 1 s is left, which is the floor: the document is out of time.
        FakeClock clock = new FakeClock();
        List<Long> slept = new ArrayList<>();
        ScriptedLlm busy = ScriptedLlm.completions(r -> {
            clock.advance(1.0);
            throw LlmCallException.status(503, 7_000L, null);
        });
        LlmDetector.Sleeper sleeper = millis -> {
            slept.add(millis);
            clock.advance(millis / 1000.0);
        };
        List<String> lines = logged(() -> assertEquals("llm pass 1", assertThrows(DocumentTimeoutError.class,
                () -> run(doc(para("u0", "κείμενο")), List.of(), busy, clock.context(10), sleeper)).stage()));
        assertEquals(List.of(10.0, 2.0), timeouts(busy));
        assertEquals(List.of(7_000L), slept);
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("llm_retry_skipped ") && l.contains(
                " reason=deadline delay_ms=7000 delay_source=header remaining_s=1.0 error=http_503")), lines.toString());

        // Time is left, but not for the wait the provider asked for plus a call: the provider is
        // unavailable in time. Pass 1 records incomplete discovery and the document goes on.
        FakeClock roomy = new FakeClock();
        ScriptedLlm slowDown = ScriptedLlm.completions(r -> {
            throw LlmCallException.status(429, 60_000L, null);
        });
        List<Long> none = new ArrayList<>();
        LlmDetector.Result degraded = run(doc(para("u0", "κείμενο")), List.of(), slowDown, roomy.context(30), none::add);
        assertEquals(List.of(), none); // never shortened to 29 s to squeeze a call in
        assertEquals(1, slowDown.requests.size());
        assertEquals(UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE, degraded.unresolved().getFirst().kind());

        // A failure that lands after the deadline is the deadline's, not the provider's. Asked of
        // the provider ladder directly, on this thread: through runLlmDetection the supervisor's
        // own "llm" checkpoint could see the expiry first (see the corrective-retry tests below).
        FakeClock late = new FakeClock();
        ScriptedLlm slow = ScriptedLlm.completions(r -> {
            late.advance(10);
            throw LlmCallException.timeout(null);
        });
        List<String> expired = logged(() -> assertEquals("llm pass 1", assertThrows(DocumentTimeoutError.class,
                () -> callPass1(provider(slow, late.context(8), millis -> { }))).stage()));
        assertEquals(1, slow.requests.size());
        assertTrue(expired.stream().anyMatch(l -> l.startsWith("llm_deadline_expired ")));
    }

    /**
     * A scripted model that records, for every request it receives, whether the document's budget
     * was already spent when the request began: the observable form of "no provider request begins
     * after the deadline".
     */
    static ScriptedLlm recordingStarts(RunContext ctx, List<Boolean> startedLate, Function<ChatRequest, Completion> answer) {
        return ScriptedLlm.completions(r -> {
            startedLate.add(ctx.deadline().expired());
            return answer.apply(r);
        });
    }

    /**
     * TWO LEGITIMATE CHECKPOINTS RACE in these concurrent tests, in Java as in v2: the chunk's own
     * check before its next pass or retry, and the supervisor in runLlmDetection, which waits for the
     * chunks with whatever budget is left and calls check("llm") when nothing finished in it. When a
     * worker spends the budget (here: the fake clock jumps inside a provider call), whichever thread
     * reads the clock next names the stage. Both are correct, so the stage is asserted to be one of
     * the two; what is asserted exactly is the safety requirement, through the requests themselves.
     */
    static final String SUPERVISOR_STAGE = "llm";

    @Test
    void passTwoIsNotStartedOnceTheBudgetIsGone() {
        FakeClock clock = new FakeClock();
        RunContext ctx = clock.context(300);
        TextUnit unit = para("u0", "Ο Σπύρος υπέγραψε.");
        List<Boolean> startedLate = new CopyOnWriteArrayList<>();
        ScriptedLlm llm = recordingStarts(ctx, startedLate, r -> {
            clock.advance(400); // pass 1 answers, after the document ran out of time
            return finished("[]");
        });
        DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class, () -> run(doc(unit),
                List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON)), llm, ctx, millis -> { }));
        assertTrue(Set.of("llm pass 2", "llm pass 2 (batch 1/1)", SUPERVISOR_STAGE).contains(e.stage()), e.stage());
        assertEquals(1, llm.requests.size()); // pass 1 only: pass 2 never began
        assertEquals(List.of(false), startedLate);
    }

    @Test
    void thePass1CorrectiveCallIsNotSentOnceTheBudgetIsGone() {
        FakeClock clock = new FakeClock();
        RunContext ctx = clock.context(300);
        List<Boolean> startedLate = new CopyOnWriteArrayList<>();
        ScriptedLlm llm = recordingStarts(ctx, startedLate, r -> {
            clock.advance(400); // an unusable pass 1, after the document ran out of time
            return finished("not json");
        });
        DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class, () -> run(doc(para("u0", "κείμενο")),
                List.of(), llm, ctx, millis -> { }));
        assertTrue(Set.of("llm pass 1 corrective retry", SUPERVISOR_STAGE).contains(e.stage()), e.stage());
        assertEquals(1, llm.requests.size());
        assertEquals(List.of(false), startedLate);
    }

    @Test
    void theCorrectiveRetryIsNotSentOnceTheBudgetIsGone() {
        FakeClock clock = new FakeClock();
        RunContext ctx = clock.context(300);
        TextUnit unit = para("u0", "Ο Σπύρος και η Μαρία.");
        List<Boolean> startedLate = new CopyOnWriteArrayList<>();
        ScriptedLlm llm = recordingStarts(ctx, startedLate, r -> {
            if (isPass1(r)) {
                return finished("[]");
            }
            clock.advance(400); // pass 2 leaves C2 open, and answers too late for a retry
            return finished(PyJson.dumps(List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"))));
        });
        DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class, () -> run(doc(unit),
                List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON), hint(unit, "Μαρία", SpanCategory.POSSIBLE_PERSON)),
                llm, ctx, millis -> { }));
        assertTrue(Set.of("llm pass 2 corrective retry", SUPERVISOR_STAGE).contains(e.stage()), e.stage());
        // Pass 1 and the first pass 2, both begun inside the budget; the corrective retry was never sent.
        assertEquals(2, llm.requests.size());
        assertEquals(List.of(false, false), startedLate);
        assertTrue(llm.requests.stream().noneMatch(ScriptedLlm::isRetry));
    }

    /**
     * The corrective-retry checkpoint itself, DETERMINISTICALLY. The remediation adjudicates its
     * chunks one after another on the calling thread, through the same Adjudicator and the same
     * checkpoint, with no supervisor to race it, so the stage is exact. Every way into the retry is
     * covered: a reading that left a candidate open, a response that was not a reading, and one that
     * answered an id the queue never issued.
     */
    @Test
    void theCorrectiveRetryCheckpointHoldsOnEveryRetryPath() {
        TextUnit unit = para("u0", "κινητό 6912345678 και σταθερό 2101234567 εδώ.");
        List<LlmDetector.Residual> residuals = List.of(residual(unit, "6912345678", SpanCategory.PHONE, "phone_shape"),
                residual(unit, "2101234567", SpanCategory.PHONE, "phone_shape"));
        Map<String, Completion> lateAnswers = Map.of(
                "a reading that left C2 open",
                finished(PyJson.dumps(List.of(answer("C1", "REDACT", "PHONE")))),
                "not a reading at all", new Completion("[{\"id\": \"C1\"", "length", false),
                "an id this queue never issued", finished(PyJson.dumps(List.of(answer("C1", "REDACT", "PHONE"),
                        answer("C2", "REDACT", "PHONE"), answer("C9", "REDACT", "PHONE")))));
        lateAnswers.forEach((path, late) -> {
            FakeClock clock = new FakeClock();
            RunContext ctx = clock.context(300);
            List<Boolean> startedLate = new ArrayList<>();
            ScriptedLlm llm = recordingStarts(ctx, startedLate, r -> {
                clock.advance(400); // the first answer arrives after the budget is gone
                return late;
            });
            DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class, () -> remediate(doc(unit), residuals, llm,
                    ctx), path);
            assertEquals(late.truncated() ? "llm pass 2 length split" : "llm pass 2 corrective retry", e.stage(), path);
            assertEquals(1, llm.requests.size(), path); // the first ask; the retry was never sent
            assertEquals(List.of(false), startedLate, path);
        });
    }

    @Test
    void theChunkCountIsBoundedBeforeAnyRequest() {
        RuntimeConfig two = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_CHUNK_SIZE_CHARS", "10", "ANON_MAX_CHUNKS", "2"));
        ScriptedLlm llm = ScriptedLlm.cooperative();
        DocumentData three = doc(para("u0", "0123456789"), para("u1", "abcdefghij"), para("u2", "klmnopqrst"));
        ResourceLimitExceededError e = assertThrows(ResourceLimitExceededError.class, () -> LlmDetector.runLlmDetection(
                three, List.of(), List.of(), new LlmDetector.Provider(llm, two, millis -> { }, RunContext.start(300)),
                POLICY, Set.of()));
        assertEquals("TOO_MANY_CHUNKS", e.code());
        assertEquals("document splits into 3 chunks; the limit is 2", e.getMessage());
        assertEquals(0, llm.requests.size());
        LlmDetector.runLlmDetection(doc(para("u0", "0123456789"), para("u1", "abcdefghij")), List.of(), List.of(),
                new LlmDetector.Provider(llm, two, millis -> { }, RunContext.start(300)), POLICY, Set.of());
        assertEquals(2, llm.requests.size()); // exactly at the limit: one pass-1 call per chunk
    }

    // ------------------------------------------------------------------ post-redaction remediation

    /** A MEDIUM residual REVIEW proposal with its provenance, as the pipeline builds one from a scan finding. */
    static LlmDetector.Residual residual(TextUnit unit, String text, SpanCategory category, String kind) {
        return residual(unit, text, category, kind, PostcheckFinding.Severity.MEDIUM);
    }

    static LlmDetector.Residual residual(TextUnit unit, String text, SpanCategory category, String kind,
                                         PostcheckFinding.Severity severity) {
        int start = unit.normalizedText().indexOf(text);
        return new LlmDetector.Residual(new UnresolvedFinding.AuditRef("P" + unit.unitId() + "_" + start, severity, kind,
                "word/document.xml:" + unit.unitId()), new Span(unit.unitId(), start, start + text.length(), text,
                category, "postcheck_" + kind, 1.0, SpanAction.REVIEW, "post-redaction scan: " + kind,
                SpanOrigin.DETERMINISTIC));
    }

    static LlmDetector.Remediation remediate(DocumentData doc, List<LlmDetector.Residual> residuals, LlmClient llm,
                                             RunContext ctx) {
        return remediate(doc, residuals, List.of(), llm, ctx);
    }

    static LlmDetector.Remediation remediate(DocumentData doc, List<LlmDetector.Residual> residuals,
                                             List<Span> hardRedacts, LlmClient llm, RunContext ctx) {
        return LlmDetector.runPass2Remediation(doc, residuals, List.of(), hardRedacts, List.of(),
                new LlmDetector.Provider(llm, CFG, millis -> { }, ctx), Set.of());
    }

    @Test
    void theRemediationIsPass2OnlyOverItsCandidatesWithOrdinaryPass2Spans() {
        TextUnit unit = para("u0", "Ο ......... με κινητό 6912345678 και email x.y@example.com.");
        // Its opening falls inside the last candidate's 40-code-point window; its end never does.
        TextUnit elsewhere = para("u1", "Ουδέτερο κείμενο που συνεχίζεται αρκετά ώστε να μη χωρά: ΤΕΛΟΣ_ΠΑΡΑΓΡΑΦΟΥ.");
        ScriptedLlm llm = model("[]", r -> List.of(answer("C1", "REDACT", "PHONE"), answer("C2", "PRESERVE", "EMAIL")));
        LlmDetector.Remediation out = remediate(doc(unit, elsewhere), List.of(
                residual(unit, "6912345678", SpanCategory.PHONE, "phone_shape"),
                residual(unit, "x.y@example.com", SpanCategory.EMAIL, "residual_email"),
                new LlmDetector.Residual(new UnresolvedFinding.AuditRef("P9", PostcheckFinding.Severity.MEDIUM,
                        "phone_shape", "word/document.xml:u9"), new Span("u9", 0, 3, "abc", SpanCategory.PHONE,
                        "postcheck_phone_shape", 1.0, SpanAction.REVIEW, "", SpanOrigin.DETERMINISTIC))),
                // the last names a unit no chunk holds: nothing to show, nothing asked
                llm, RunContext.start(300));

        assertEquals(1, llm.requests.size()); // no pass 1, one pass-2 call for the one chunk with residuals
        ChatRequest call = llm.requests.get(0);
        assertEquals(Prompts.SYSTEM_PROMPT_PASS2, call.systemPrompt());
        assertTrue(ScriptedLlm.isRemediation(call));
        assertFalse(call.userMessage().contains("DOCUMENT EXCERPT") || call.userMessage().contains("ΤΕΛΟΣ_ΠΑΡΑΓΡΑΦΟΥ"),
                call.userMessage());
        assertEquals("Ο ......... με κινητό ", candidates(call).get(0).get("before"));
        assertEquals(List.of(List.of("postcheck"), List.of("postcheck")), candidates(call).stream()
                .map(c -> ((List<?>) c.get("recommendations")).stream().map(x -> ((Map<?, ?>) x).get("sources"))
                        .findFirst().orElseThrow()).toList());
        assertEquals(List.of("REDACT:6912345678@u0:22", "PRESERVE:x.y@example.com@u0:43"), out.spans().stream()
                .map(sp -> sp.action() + ":" + sp.text() + "@" + sp.unitId() + ":" + sp.start()).toList());
        assertTrue(out.spans().stream().allMatch(sp -> sp.origin() == SpanOrigin.LLM_PASS2));
        assertEquals(List.of("remediation:chunk1:C1", "remediation:chunk1:C2"), out.candidateIds());
        assertEquals(1, out.pass2Calls());
        assertTrue(out.unresolved().isEmpty());
    }

    /** The same mask rule applies to the re-ask: a carried hard redact is never shown, even where the bytes still hold it. */
    @Test
    void theRemediationMasksTheHardRedactsItIsGiven() {
        String afm = "123456783";
        TextUnit unit = para("u0", "ΑΦΜ " + afm + ", κινητό 6912345678.");
        ScriptedLlm llm = model("[]", r -> List.of(answer("C1", "REDACT", "PHONE")));
        LlmDetector.Remediation out = remediate(doc(unit), List.of(residual(unit, "6912345678", SpanCategory.PHONE,
                "phone_shape")), List.of(rule(unit, afm, SpanCategory.AFM, SpanAction.REDACT, 0.95)), llm,
                RunContext.start(300));
        ChatRequest call = llm.requests.get(0);
        assertFalse(call.userMessage().contains(afm), call.userMessage());
        assertEquals("ΑΦΜ ........., κινητό ", candidates(call).get(0).get("before"));
        assertEquals(List.of("6912345678"), out.spans().stream().map(Span::text).toList());
    }

    @Test
    void aRemediationRetryIsStillARemediationCallAndWhatItLeavesIsUnresolved() {
        TextUnit unit = para("u0", "κινητό 6912345678 εδώ.");
        ScriptedLlm llm = model("[]", r -> List.of());
        LlmDetector.Remediation out = remediate(doc(unit),
                List.of(residual(unit, "6912345678", SpanCategory.PHONE, "phone_shape")), llm, RunContext.start(300));
        assertEquals(2, llm.requests.size());
        assertTrue(llm.requests.stream().allMatch(ScriptedLlm::isRemediation));
        assertTrue(isRetry(llm.requests.get(1)));
        assertFalse(llm.requests.get(1).userMessage().contains("DOCUMENT EXCERPT"));
        assertEquals(2, out.pass2Calls());
        assertEquals(List.of(UnresolvedFinding.Kind.CANDIDATE_UNDECIDED),
                out.unresolved().stream().map(UnresolvedFinding::kind).toList());
        assertEquals(List.of(new UnitSlice("u0", 7, 17)), out.unresolved().get(0).locations());
        assertTrue(out.spans().isEmpty());
    }

    @Test
    void noRemediationCallStartsOnADocumentOutOfTime() {
        TextUnit unit = para("u0", "κινητό 6912345678 εδώ.");
        FakeClock clock = new FakeClock();
        RunContext spent = clock.context(5);
        clock.advance(5);
        ScriptedLlm llm = ScriptedLlm.cooperative();
        DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class, () -> remediate(doc(unit),
                List.of(residual(unit, "6912345678", SpanCategory.PHONE, "phone_shape")), llm, spent));
        assertEquals("postcheck remediation (chunk 1/1)", e.stage());
        assertEquals(0, llm.requests.size());
        assertEquals(0, remediate(doc(unit), List.of(), llm, RunContext.start(300)).pass2Calls()); // nothing to ask
    }

    // ------------------------------------------------------------------ routing: the decision table

    static long pass2Calls(ScriptedLlm llm) {
        return llm.requests.stream().filter(r -> !isPass1(r)).count();
    }

    static LlmDetector.Result detect(DocumentData doc, List<Span> rules, List<Span> hints, LlmClient llm, RunContext ctx) {
        return LlmDetector.runLlmDetection(doc, rules, hints, new LlmDetector.Provider(llm, CFG, millis -> { }, ctx,
                JITTER), POLICY, Set.of());
    }

    static final Function<ChatRequest, List<?>> NO_QUESTION = r -> {
        throw new AssertionError("pass 2 must not be asked: " + r.userMessage());
    };

    /**
     * Rows A, B, E and F: agreement either way and pass 1 alone are decided without a question. Row H
     * changed with the LLM-to-resolver contract: a rule REDACT pass 1 said nothing about has no LLM
     * decision yet, so it is the one pass-2 question (the rules' span stays evidence and fallback).
     */
    @Test
    void agreementAndPass1DecisionsMakeNoQuestionAndARulesOnlyRedactIsAsked() {
        TextUnit unit = para("u0", "Ο Γεώργιος Παπαδόπουλος υπέγραψε την 01/02/2020 με την Άννα Ζαχαρίου, ΑΜΚΑ 31021512345.");
        String pass1 = "[{\"text\": \"Γεώργιος Παπαδόπουλος\", \"action\": \"REDACT\", \"category\": \"PERSON\"}, "
                + "{\"text\": \"01/02/2020\", \"action\": \"PRESERVE\", \"category\": \"DATE\"}, "
                + "{\"text\": \"Άννα Ζαχαρίου\", \"action\": \"REDACT\", \"category\": \"PERSON\"}]";
        List<Span> rules = List.of(rule(unit, "Γεώργιος Παπαδόπουλος", SpanCategory.APPELLANT_NAME, SpanAction.REDACT, 0.9),
                rule(unit, "01/02/2020", SpanCategory.DATE, SpanAction.PRESERVE, 0.95),
                rule(unit, "31021512345", SpanCategory.AMKA, SpanAction.REDACT, 0.75));
        Function<ChatRequest, List<?>> amkaOnly = r -> {
            assertEquals(List.of("31021512345"), candidates(r).stream().map(c -> c.get("text")).toList());
            return List.of(answer("C1", "REDACT", "AMKA"));
        };
        ScriptedLlm llm = model(pass1, amkaOnly);
        RunContext ctx = RunContext.start(300);
        List<String> lines = logged(() -> detect(doc(unit), rules, List.of(), llm, ctx));
        LlmDetector.Result result = detect(doc(unit), rules, List.of(), model(pass1, amkaOnly));
        assertEquals(1, pass2Calls(llm));
        String text = unit.normalizedText();
        assertEquals(List.of("REDACT:Γεώργιος Παπαδόπουλος@u0:2", "PRESERVE:01/02/2020@u0:" + text.indexOf("01/02"),
                "REDACT:Άννα Ζαχαρίου@u0:" + text.indexOf("Άννα"), "REDACT:31021512345@u0:" + text.indexOf("3102")),
                decided(result));
        assertEquals(List.of(SpanOrigin.LLM_PASS1, SpanOrigin.LLM_PASS1, SpanOrigin.LLM_PASS1, SpanOrigin.LLM_PASS2),
                result.spans().stream().map(Span::origin).toList());
        assertEquals(List.of(), result.unresolved());
        assertEquals(1, ctx.usage().snapshot().pass2Calls());
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("llm_routing pass1_agreed=2 pass1_only=1 deterministic_only=1 ")
                && l.contains(" pass2_candidates=1 ")), lines.toString());
    }

    /** Row C: a disagreement is ONE question, about the REDACT side, and pass 2's answer governs it. */
    @Test
    void aDisagreementIsOnePass2QuestionAndItsAnswerGoverns() {
        TextUnit unit = para("u0", "Ο Γεώργιος Παπαδόπουλος υπέγραψε.");
        List<Span> rules = List.of(rule(unit, "Γεώργιος Παπαδόπουλος", SpanCategory.APPELLANT_NAME, SpanAction.REDACT, 0.9));
        ScriptedLlm llm = model("[{\"text\": \"Γεώργιος Παπαδόπουλος\", \"action\": \"PRESERVE\", \"category\": "
                + "\"OFFICIAL_SIGNATORY\"}]", r -> List.of(answer("C1", "PRESERVE", "OFFICIAL_SIGNATORY")));
        LlmDetector.Result result = detect(doc(unit), rules, List.of(), llm);
        assertEquals(1, pass2Calls(llm));
        List<Map<String, Object>> asked = candidates(pass2Requests(llm).getFirst());
        assertEquals(List.of("Γεώργιος Παπαδόπουλος"), asked.stream().map(c -> c.get("text")).toList());
        assertEquals(List.of(Map.of("sources", List.of("deterministic"), "action", "REDACT", "category", "APPELLANT_NAME"),
                Map.of("sources", List.of("pass1"), "action", "PRESERVE", "category", "OFFICIAL_SIGNATORY")),
                asked.getFirst().get("recommendations"));
        assertEquals(List.of("PRESERVE:Γεώργιος Παπαδόπουλος@u0:2"), decided(result));
        assertEquals(SpanOrigin.LLM_PASS2, result.spans().getFirst().origin());
    }

    /**
     * Rows I, K, L and the partial failure: 15 questions are two batches (10 and 5), run concurrently;
     * a completion budget that can answer only 10 per batch shrinks the batch below its 30-candidate cap.
     * The second batch's provider stays unavailable after its whole ladder; the first batch's answers
     * are kept, and every candidate of the second gets the fallback and a finding of its own, with its
     * own id: pass 1's REDACT where pass 1 had one, nothing (undecided) where there was only a REVIEW.
     */
    @Test
    void aFailedBatchFallsBackAndEveryOtherBatchKeepsItsAnswers() {
        List<TextUnit> units = new ArrayList<>();
        List<Span> hints = new ArrayList<>();
        StringBuilder pass1 = new StringBuilder("[");
        for (int i = 1; i <= 15; i++) {
            TextUnit u = para("u" + i, "Ο Πελάτης" + i + " πλήρωσε.");
            units.add(u);
            hints.add(hint(u, "Πελάτης" + i, SpanCategory.POSSIBLE_PERSON));
            if (i == 11 || i == 12) {
                pass1.append(pass1.length() > 1 ? ", " : "").append("{\"text\": \"Πελάτης").append(i)
                        .append("\", \"action\": \"REDACT\", \"category\": \"PERSON\"}");
            }
        }
        String discovery = pass1.append("]").toString();
        AtomicInteger secondBatchAttempts = new AtomicInteger();
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (isPass1(r)) {
                return finished(discovery);
            }
            if (candidateIds(r).contains("C11")) {
                secondBatchAttempts.incrementAndGet();
                throw LlmCallException.status(503, 0L, null);
            }
            return finished(PyJson.dumps(ScriptedLlm.agreeWithEveryCandidate(r)));
        });
        RunContext ctx = RunContext.start(300);
        List<LlmDetector.Result> out = new ArrayList<>();
        List<String> lines = logged(() -> out.add(LlmDetector.runLlmDetection(doc(units.toArray(TextUnit[]::new)),
                List.of(), hints, new LlmDetector.Provider(llm, CFG_TEN_PER_BATCH, millis -> { }, ctx, JITTER), POLICY,
                Set.of())));
        LlmDetector.Result result = out.getFirst();

        assertEquals(LlmDetector.MAX_PROVIDER_ATTEMPTS, secondBatchAttempts.get());
        // Concurrent batches may reach the provider in either order.
        assertEquals(List.of(5, 10), pass2Requests(llm).stream().map(r -> candidateIds(r).size()).distinct().sorted().toList());
        // The first batch's decisions, by id, at their own places.
        List<Span> decidedByPass2 = result.spans().stream().filter(s -> s.origin() == SpanOrigin.LLM_PASS2).toList();
        assertEquals(10, decidedByPass2.size());
        assertEquals(List.of("u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9", "u10"),
                decidedByPass2.stream().map(Span::unitId).toList());
        // The fallback: pass 1's REDACT applied for C11 and C12, as pass 1's, never as a pass-2 answer.
        List<Span> fellBack = result.spans().stream().filter(s -> s.detector().equals("llm_pass1_fallback")).toList();
        assertEquals(List.of("REDACT:Πελάτης11@u11", "REDACT:Πελάτης12@u12"),
                fellBack.stream().map(s -> s.action() + ":" + s.text() + "@" + s.unitId()).toList());
        assertTrue(fellBack.stream().allMatch(s -> s.origin() == SpanOrigin.LLM_PASS1));
        // One finding per affected candidate, with its own id, location and outcome.
        List<UnresolvedFinding> open = result.unresolved();
        assertEquals(List.of("C11", "C12", "C13", "C14", "C15"), open.stream().map(UnresolvedFinding::candidateId).toList());
        assertTrue(open.stream().allMatch(f -> f.kind() == UnresolvedFinding.Kind.PASS2_UNAVAILABLE
                && f.detail().contains("cause=http_503") && f.locations().size() == 1));
        assertTrue(open.get(0).detail().contains("fallback=pass1_REDACT")
                && open.get(0).detail().contains("deterministic:REVIEW/POSSIBLE_PERSON")
                && open.get(0).detail().contains("pass1:REDACT/POSSIBLE_PERSON"), open.get(0).detail());
        assertTrue(open.get(2).detail().contains("fallback=none (undecided)"), open.get(2).detail());
        assertEquals(1, ctx.usage().snapshot().pass2Executed());
        assertEquals(1, ctx.usage().snapshot().pass2Failed());
        // The log line counts; it names no candidate id and no text.
        String summary = lines.stream().filter(l -> l.startsWith("pass2_fallback ")).findFirst().orElseThrow();
        assertTrue(summary.contains(" candidates=5 batches_failed=1 pass1_applied=2 rules_applied=0 conflicts=0 "
                + "undecided=3 "), summary);
        assertFalse(summary.contains("C11") || summary.contains("Πελάτης"), summary);
    }

    /**
     * A question pass 2 answered but never decided, even after its corrective retry, gets the same
     * documented fallback as one it was unavailable for: pass 1's REDACT is applied (as pass 1's, labelled
     * as the fallback), and the finding stays CANDIDATE_UNDECIDED, saying so. A sloppy model is never
     * less safe than a dead one.
     */
    @Test
    void anUndecidedQuestionGetsTheSameFallbackAsAnUnavailableOne() {
        TextUnit unit = para("u0", "Ο Γεώργιος Παπαδόπουλος υπέγραψε.");
        List<Span> rules = List.of(rule(unit, "Γεώργιος Παπαδόπουλος", SpanCategory.POSSIBLE_COMPANY,
                SpanAction.PRESERVE, 0.85));
        ScriptedLlm silent = model("[{\"text\": \"Γεώργιος Παπαδόπουλος\", \"action\": \"REDACT\", \"category\": "
                + "\"PERSON\"}]", r -> List.of());
        LlmDetector.Result result = detect(doc(unit), rules, List.of(), silent);
        assertEquals(2, pass2Calls(silent)); // the question, and its one corrective retry
        assertEquals(List.of("REDACT:Γεώργιος Παπαδόπουλος@u0:2"), decided(result));
        assertEquals("llm_pass1_fallback", result.spans().getFirst().detector());
        assertEquals(SpanOrigin.LLM_PASS1, result.spans().getFirst().origin());
        UnresolvedFinding open = result.unresolved().getFirst();
        assertEquals(UnresolvedFinding.Kind.CANDIDATE_UNDECIDED, open.kind());
        assertTrue(open.detail().endsWith("; fallback=pass1_REDACT applied"), open.detail());
    }

    /**
     * A misconfigured service (a wrong key, no access, no such deployment) is not an outage to work
     * around: pass 2's 401, 403 or 404 still fails the document, as before, rather than quietly
     * returning every document needs-review. A 400 (a request the provider refused) still falls back.
     */
    @Test
    void aMisconfiguredServiceStillFailsLoudly() {
        TextUnit unit = para("u0", "Ο Σπύρος υπέγραψε.");
        List<Span> hints = List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON));
        for (int status : new int[] {401, 403, 404}) {
            ScriptedLlm misconfigured = model("[]", r -> {
                throw LlmCallException.status(status, null);
            });
            assertEquals("provider returned HTTP " + status + " (batch 1, pass 2)", assertThrows(AIProviderError.class,
                    () -> run(doc(unit), hints, misconfigured)).getMessage());
        }
        ScriptedLlm refused = model("[]", r -> {
            throw LlmCallException.status(400, null);
        });
        assertEquals(UnresolvedFinding.Kind.PASS2_UNAVAILABLE, run(doc(unit), hints, refused).unresolved().getFirst().kind());
    }

    /** Row 15: two documents, one after the other, share nothing: ids restart and no answer carries over. */
    @Test
    void consecutiveDocumentsShareNoState() {
        TextUnit unit = para("u0", "Ο Σπύρος υπέγραψε.");
        List<Span> hints = List.of(hint(unit, "Σπύρος", SpanCategory.POSSIBLE_PERSON));
        ScriptedLlm first = model("[]", r -> List.of(answer("C1", "REDACT", "POSSIBLE_PERSON")));
        ScriptedLlm second = model("[]", r -> List.of(answer("C1", "PRESERVE", "OFFICIAL_SIGNATORY")));
        assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(run(doc(unit), hints, first)));
        assertEquals(List.of("PRESERVE:Σπύρος@u0:2"), decided(run(doc(unit), hints, second)));
        assertEquals(List.of("C1"), candidateIds(pass2Requests(second).getFirst()));
        // And a failure in one leaves the next untouched.
        ScriptedLlm down = model("[]", r -> {
            throw LlmCallException.status(400, null);
        });
        assertEquals(UnresolvedFinding.Kind.PASS2_UNAVAILABLE, run(doc(unit), hints, down).unresolved().getFirst().kind());
        assertEquals(List.of("REDACT:Σπύρος@u0:2"), decided(run(doc(unit), hints, first)));
    }

    // ------------------------------------------------------------------ what leaves the stage

    @Test
    void unresolvedFindingsAndLogsCarryNoDocumentText() {
        TextUnit unit = para("u0", "Ο Σπύρος Λάμπρου, τηλ. 6912345678.");
        List<Span> hints = List.of(hint(unit, "6912345678", SpanCategory.PHONE));
        // A located finding pass 1 could not decide (so it is a question), and one nowhere in the excerpt.
        String pass1 = "[{\"text\": \"Σπύρος Λάμπρου\", \"action\": \"REVIEW\", \"category\": \"PERSON\"}, "
                + "{\"text\": \"Σπύρου Λ.\", \"action\": \"REDACT\", \"category\": \"PERSON\"}]";
        // A duplicated id, document text in the id field, and a "NEW" entry.
        List<Object> untracked = List.of(answer("C1", "REDACT", "PHONE"), answer("C1", "PRESERVE", "PHONE"),
                answer("Σπύρος Λάμπρου", "REDACT", "PERSON"), newFinding("Σπύρου Λ.", "REDACT", "PERSON"));
        List<String> seen = new ArrayList<>();
        List<LlmDetector.Result> out = new ArrayList<>();
        seen.addAll(logged(() -> {
            out.add(run(doc(unit), hints, model(pass1, r -> isRetry(r) ? List.of() : untracked)));
            // Untracked twice: pass 2 unavailable, every candidate falls back with a finding of its own.
            LlmDetector.Result fellBack = run(doc(unit), hints, model(pass1, r -> untracked));
            assertEquals(List.of(UnresolvedFinding.Kind.DISCOVERY_UNLOCATABLE, UnresolvedFinding.Kind.PASS2_UNAVAILABLE,
                    UnresolvedFinding.Kind.PASS2_UNAVAILABLE),
                    fellBack.unresolved().stream().map(UnresolvedFinding::kind).toList());
            fellBack.unresolved().forEach(f -> seen.add(f.toString()));
        }));
        LlmDetector.Result open = out.get(0);
        assertEquals(List.of(UnresolvedFinding.Kind.DISCOVERY_UNLOCATABLE, UnresolvedFinding.Kind.CANDIDATE_DUPLICATED,
                UnresolvedFinding.Kind.CANDIDATE_UNDECIDED), open.unresolved().stream().map(UnresolvedFinding::kind).toList());
        open.unresolved().forEach(f -> seen.add(f.toString()));
        assertTrue(seen.size() > 10);

        for (String line : seen) {
            for (String secret : List.of("Σπύρος", "Λάμπρου", "6912345678", "Σπύρου")) {
                assertFalse(line.contains(secret), line);
            }
        }
    }

    static RuntimeConfig withContextWindow(String tokens) {
        return Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_LLM_CONTEXT_TOKENS", tokens));
    }

    /**
     * With a configured context window, a candidate whose request would exceed it even alone is never
     * sent: it takes the documented fallback as an unavailable candidate (cause=context_limit) and is set
     * aside for review; the others are asked as usual. Without a window nothing is held back.
     */
    @Test
    void aCandidateThatCannotFitTheConfiguredWindowIsNeverSentAndFallsBack() {
        TextUnit small = para("u0", "Ο Σπύρος υπέγραψε.");
        TextUnit large = para("u1", "Α".repeat(1500));
        List<Span> hints = List.of(hint(small, "Σπύρος", SpanCategory.POSSIBLE_PERSON),
                hint(large, large.normalizedText(), SpanCategory.POSSIBLE_PERSON));
        // Room for the small candidate (well under 500 estimated tokens), not for the 1,500-letter one.
        RuntimeConfig cfg = withContextWindow(String.valueOf(Pass2Queue.pass2FixedInputTokens()
                + RuntimeConfig.DEFAULT_MAX_COMPLETION_TOKENS + 500));
        ScriptedLlm llm = model("[]", r -> candidates(r).stream().map(c -> answer((String) c.get("id"), "REDACT",
                "POSSIBLE_PERSON")).toList());
        LlmDetector.Result result = LlmDetector.runLlmDetection(doc(small, large), List.of(), hints,
                new LlmDetector.Provider(llm, cfg, millis -> { }, RunContext.start(cfg.documentDeadlineS()), JITTER),
                POLICY, Set.of());
        List<String> sent = pass2Requests(llm).stream().flatMap(r -> candidates(r).stream())
                .map(c -> (String) c.get("text")).toList();
        assertEquals(List.of("Σπύρος"), sent);
        assertTrue(decided(result).contains("REDACT:Σπύρος@u0:2"), decided(result).toString());
        List<UnresolvedFinding> open = result.unresolved();
        assertEquals(1, open.size(), open.toString());
        assertEquals(UnresolvedFinding.Kind.PASS2_UNAVAILABLE, open.getFirst().kind());
        assertTrue(open.getFirst().detail().contains("cause=context_limit"), open.getFirst().detail());
        assertEquals(List.of(new UnitSlice("u1", 0, 1500)), open.getFirst().locations());
        // Without a configured window the same queue is sent whole.
        ScriptedLlm unbounded = model("[]", r -> candidates(r).stream().map(c -> answer((String) c.get("id"), "REDACT",
                "POSSIBLE_PERSON")).toList());
        assertEquals(List.of(), run(doc(small, large), hints, unbounded).unresolved());
        assertEquals(2, pass2Requests(unbounded).stream().mapToLong(r -> candidates(r).size()).sum());
    }

    /** Unset: no check and no claim of one. Set: it must hold one ordinary request, checked at startup. */
    @Test
    void aConfiguredContextWindowIsCheckedAtStartup() {
        assertEquals(0, CFG.llmContextTokens());
        List<String> lines = logged(() -> LlmDetector.checkContextLimit(CFG));
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("context-window check disabled")), lines.toString());
        lines = logged(() -> LlmDetector.checkContextLimit(withContextWindow("128000")));
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("context-window check enabled: ANON_LLM_CONTEXT_TOKENS=128000")),
                lines.toString());
        String message = assertThrows(dev.filtsiap.ded.anonymizer.ConfigurationError.class,
                () -> LlmDetector.checkContextLimit(withContextWindow("8000"))).getMessage();
        assertTrue(message.startsWith("ANON_LLM_CONTEXT_TOKENS=8000 cannot hold one ordinary request"), message);
        assertThrows(dev.filtsiap.ded.anonymizer.ConfigurationError.class, () -> withContextWindow("0"));
        assertThrows(dev.filtsiap.ded.anonymizer.ConfigurationError.class, () -> withContextWindow("-5"));
    }

    /**
     * The prompts are PINNED: any edit to them changes this hash, and this test is where that edit is
     * acknowledged. They intentionally no longer hash to v2's (the new gold's place-name, chamber and
     * residence rules, the masked view and candidate-only pass 2; see PromptText), and the v2 hash is
     * kept to name the text they derive from.
     */
    @Test
    void thePromptTextIsPinnedAndIntentionallyDiffersFromV2() {
        // Revised: bare residence locality kept, the masked view and pass 2's real validation contract described,
        // look-alike categories defined; pass 1 decides a table's header (first row, first column, elsewhere or
        // none) and has a label | value table example; pass 2's example is the real queue (phones as REVIEW);
        // the authority header is no longer called hard policy, and "err toward REDACT" has no exception.
        // Revised again: pass 1 leaves out what hard policy settles (its examples no longer list settled text),
        // quotes whole values and never joins header fields; pass 2 reads a REVIEW as a question, not evidence.
        assertEquals("3a42f89af0c5d45997553a5cd7db710f7161e155ab1816a9dff0cc8b3e808657", Prompts.PROMPTS_SHA256);
        assertFalse(PromptText.V2_PROMPTS_SHA256.equals(Prompts.PROMPTS_SHA256));
    }

    /** Pass 1 is told it reads the masked view and the dots are removed values; pass 2 has no excerpt and no NEW. */
    @Test
    void thePassTailsDescribeTheMaskedViewAndTheCandidateOnlyContract() {
        String pass1 = Prompts.SYSTEM_PROMPT_PASS1.replaceAll("\\s+", " ");
        assertTrue(pass1.contains("You are given one excerpt of the document in its MASKED view"));
        assertFalse(pass1.contains("raw excerpt"));
        assertTrue(pass1.contains("A run of redaction dots (\"..........\") in the excerpt is a value that has already "
                + "been removed. Never propose a run of dots, or any part of one, as a finding."));
        // Pass 1's decisions are applied as they stand: it is no longer told a later pass decides everything.
        assertFalse(pass1.contains("a later pass decides each one."));
        assertTrue(pass1.contains("Your answers are DECISIONS: a REDACT or PRESERVE you return is applied as it stands"));
        assertTrue(pass1.contains("REVIEW is NOT a legal action."));
        assertFalse(pass1.contains("reads this excerpt for itself"));
        // Tables: several per excerpt, row groups, empty columns kept, read-only context; no "first row is the header".
        assertFalse(pass1.contains("The first row is the header row"));
        assertFalse(pass1.contains("Column header text itself → SKIP"));
        assertTrue(pass1.contains("Each table begins with a \"TABLE:\" line (\"TABLE (continued):\" for a later part"));
        assertTrue(pass1.contains("an empty cell keeps its place as nothing between two \" | \""));
        assertTrue(pass1.contains("in a later part of a long table a row may start with empty places"));
        assertTrue(pass1.contains("Never quote from a \"[context]\" line"));
        // Pass 1 decides whether a table has a header, and where; a first row is shown neutrally when unmarked.
        assertTrue(pass1.contains("Decide for every table whether it has a header, and where. Usually it is the FIRST "
                + "ROW"));
        assertTrue(pass1.contains("Often it is the FIRST COLUMN: a label | value table"));
        assertTrue(pass1.contains("\"[context] first row:\", which may be a header or data"));
        assertTrue(pass1.contains("Read every value under its column label or beside its row label"));
        assertTrue(pass1.contains("A row or column that holds names, numbers or other values is data even when it comes "
                + "first"));
        // What hard policy settles is left out (output it would only spend), and a private value beside it is not.
        assertTrue(pass1.contains("LEAVE OUT WHAT IS SETTLED, what the rule engine keeps by fixed policy:"));
        assertTrue(pass1.contains("amounts and percentages (a person's income or tax too)"));
        assertTrue(pass1.contains("A private name, company, address or file number next to, inside or overlapping such "
                + "text is still yours to REDACT."));
        assertTrue(pass1.contains("never join separate header fields into one finding"));
        String pass2 = Prompts.SYSTEM_PROMPT_PASS2.replaceAll("\\s+", " ");
        for (String gone : List.of("\"NEW\"", "DOCUMENT EXCERPT", "SCAN THE EXCERPT", "THE EXCERPT IS THE AUTHORITY",
                "TWO jobs", "rejects the WHOLE response", "Breaking ANY of them", "by exact match only")) {
            assertFalse(pass2.contains(gone), gone);
        }
        assertTrue(pass2.contains("Your job is to DECIDE every candidate you are given, and nothing else."));
        assertTrue(pass2.contains("A REVIEW, the post-check's included, is a question, not evidence that the text is "
                + "personal"));
        assertTrue(pass2.contains("Hard redactions (verified identifiers) are never candidates, and no answer undoes one."));
        assertTrue(pass2.contains("They are all the context you are given"));
        assertTrue(pass2.contains("Copy every id from the CANDIDATES block of the message you are answering. Never "
                + "invent, renumber or reuse an id, and never use the ids of the example below."));
        // The caller's real contract (Pass2Queue.validate and the corrective retry): entry by entry.
        assertTrue(pass2.contains("Every entry is checked on its own, and a usable entry is kept even when another is not"));
        assertTrue(pass2.contains("Only those candidates are sent back to you, once, with the reasons."));
        assertTrue(pass2.contains("the response is not trusted and the whole queue is asked again, once"));
        assertTrue(pass2.contains("REVIEW is not a legal action and is recorded as REDACT"));
        assertTrue(pass2.contains("every answer for a repeated id is thrown away"));
        assertTrue(pass2.contains("Candidates are merged only when their text, recommendations and surrounding context "
                + "are all identical"));
        // The flow as implemented: which places are questions, and that hard policy never is one.
        assertTrue(pass2.contains("the rule engine proposed a REDACT the first reading decided nothing about"));
        assertTrue(pass2.contains("the first reading's own decisions are applied as they stand"));
        assertTrue(pass2.contains("the official signatory) is never a question"));
        // Retry and fallback as implemented: an unreadable response no longer fails the document.
        assertFalse(pass2.contains("fails the document outright"));
        assertTrue(pass2.contains("a long batch cut short is asked again in smaller parts"));
        assertTrue(pass2.contains("keep the earlier recommendations' documented fallback and are set aside for a human "
                + "reviewer"));
        assertTrue(pass2.contains("When the visible words and the recommendations still do not settle a candidate, "
                + "REDACT it."));
        assertTrue(pass2.contains("they never run into another table"));
        // The shared category policy is the same text in both.
        assertTrue(Prompts.SYSTEM_PROMPT_PASS1.startsWith(PromptText.CATEGORY_POLICY));
        assertTrue(Prompts.SYSTEM_PROMPT_PASS2.startsWith(PromptText.CATEGORY_POLICY));
    }

    /** The gold corrections the model is taught, in both passes; the answer semantics in pass 2's tail. */
    @Test
    void bothPassesTeachTheGoldCorrectionsAndPass2WhatAnAnswerMeans() {
        for (String prompt : List.of(Prompts.SYSTEM_PROMPT_PASS1, Prompts.SYSTEM_PROMPT_PASS2)) {
            String flat = prompt.replaceAll("\\s+", " ");
            // Owner policy: a bank's name and a foreign public body stay; a bank account and an ΑΤΒ number go.
            for (String rule : List.of("Greek or foreign", "a foreign pension fund",
                    "and a bank's name (\"ΕΤΕ\", \"Τράπεζα Πειραιώς\", in text and in tables): only its account number is redacted",
                    "\"ΑΤΒ 48213\" keeps \"ΑΤΒ\"",
                    "the ΦΕΚ issue that published its statute",
                    "ΦΕΚ (Government Gazette) references to laws, decrees, regulations and plans",
                    "\"η προσφεύγουσα εταιρεία\"",
                    "case-law cited as precedent: keep",
                    "IS THE DOCUMENT BEHIND THE NUMBER PUBLISHED TO THE WORLD, OR DOES IT BELONG TO THIS TAXPAYER'S FILE?",
                    "Quote the VALUE, never the label that introduces it",
                    "\"του ΔΗΜΗΤΡΙΟΥ\" is redacted whole, article included",
                    "Two capitalised words are a name only if they name a person or a company",
                    "CONTACT DETAILS AND NAMES are decided by whose they are, not by their shape",
                    "the public e-mail addresses of official bodies (@aade.gr, @gov.gr)",
                    "The role stays; only a proper name next to it is redacted",
                    "is redacted value by value",
                    "When uncertain, err toward REDACT.",
                    "is theirs, and so is every later mention of it",
                    "\"ΔΕΔ 123456 ΕΞ 2026 ΕΜΠ / 01-06-2026\" redacts \"123456\"",
                    "\"επί της\"", "gives up \"4321\" and keeps \"της 18-3-2011\"")) {
                assertTrue(flat.contains(rule), rule);
            }
            assertFalse(flat.contains("case-law of any court"), "the blanket case-law rule is gone");
            // The authority's header is an ordinary preserve (Detectors.detectAuthorityHeader), not hard policy; and
            // "err toward REDACT" has no exception for the very candidates (phones, names) it matters most for.
            assertFalse(flat.contains("the issuing authority's header and the official signatory"));
            assertTrue(flat.contains("the decision's own number and place/date line, and the official signatory"));
            assertFalse(flat.contains("Exception: phone, fax and name candidates"));
            assertFalse(flat.contains("a commercial bank is a private company"), "the bank-name REDACT is gone");
            for (String observed : List.of("EUROBANK", "6306", "1398", "Ιεράς", "25761", "ΓΙΕ ΝΤΑ")) {
                assertFalse(prompt.contains(observed), observed); // examples are synthetic
            }
        }
        String pass2 = Prompts.SYSTEM_PROMPT_PASS2.replaceAll("\\s+", " ");
        assertTrue(pass2.contains("a wrong category is never a reason to PRESERVE"));
        assertTrue(pass2.contains("never PRESERVE a fragment of something that must be redacted"));
        assertFalse(Prompts.SYSTEM_PROMPT_PASS1.contains("WHAT AN ANSWER MEANS"));
        assertTrue(Prompts.SYSTEM_PROMPT_PASS2.contains("WHAT AN ANSWER MEANS"));
        assertTrue(Prompts.SYSTEM_PROMPT_PASS1.replaceAll("\\s+", " ")
                .contains("\"ΤΡΑΠΕΖΑ\" or \"ΠΙΣΤΩΤΙΚΟ ΙΔΡΥΜΑ\" → PRESERVE (a bank's name)"));
    }

    /** Both passes, and so the corrective retry and the remediation (which reuse pass 2's), read the same rule. */
    @Test
    void bothPassesTeachTheNewGoldPlaceNameRules() {
        for (String prompt : List.of(Prompts.SYSTEM_PROMPT_PASS1, Prompts.SYSTEM_PROMPT_PASS2)) {
            String flat = prompt.replaceAll("\\s+", " ");
            for (String rule : List.of("A place that is PART OF A PUBLIC INSTITUTION'S NAME",
                    "\"Δήμου Νέας Σμύρνης\"", "keep EVERY word of it, never half of it",
                    "the municipality stays and the person's name is redacted",
                    "\"(Τμήμα 1ο Τριμελές)\", \"Τμήμα 2ο Μονομελές\"",
                    "PUBLIC GEOGRAPHY (PUBLIC_LOCALITY)",
                    // The residence locality is kept with or without its region; the address around it is not.
                    "with or without an administrative region after it (PUBLIC_LOCALITY)",
                    "\"κατοίκου Λαμίας\" keeps \"Λαμίας\"", "\"κάτοικος Πατρών\" keeps \"Πατρών\"",
                    "keeps \"Αγίας Παρασκευής Αττικής\" whole", "This is a convention about the LOCALITY only.",
                    "PUBLIC GEOGRAPHY IS NOT A PRIVATE ADDRESS",
                    "keeps \"Αγίας Παρασκευής Αττικής\" and redacts \"Ερμού\", \"5\" and \"15231\"",
                    "only an all-zero suffix (\"/0/0\") stays", "\"PUBLIC_LOCALITY\"")) {
                assertTrue(flat.contains(rule), rule);
            }
            // v2's instructions that the new gold overrides are gone, not merely outvoted; and the bare-locality
            // REDACT this policy used to teach is gone too.
            for (String v2 : List.of("REDACT the toponym after", "-> redact \"Χαλκιδέων\"", "-> redact \"Χαλκίδας\"",
                    "the serial and the chamber are theirs", "Keep the region visible and redact the municipality",
                    "give theirs up", "037173570", "is redacted as before", "This is a convention about THAT SHAPE",
                    "is not covered by it")) {
                assertFalse(flat.contains(v2), v2);
            }
        }
    }

    /** Every category name the prompts offer is a SpanCategory, and every SpanCategory is offered: one vocabulary. */
    @Test
    void thePromptVocabularyIsExactlyTheSpanCategories() {
        String flat = PromptText.CATEGORY_POLICY.replaceAll("\\s+", " ");
        int start = flat.indexOf("CATEGORIES. Use these names exactly: ");
        int end = flat.indexOf(" Choose between look-alikes this way:");
        assertTrue(start >= 0 && end > start);
        List<String> offered = java.util.Arrays.stream(flat.substring(start + 37, end).split(" \\| "))
                .map(s -> s.replace("\"", "").replace(" |", "").strip()).toList();
        assertEquals(java.util.Arrays.stream(SpanCategory.values()).map(SpanCategory::wire).toList(), offered);
        assertTrue(offered.stream().allMatch(c -> SpanCategory.fromWire(c).isPresent()));
    }

    /** The text between two markers of a prompt, exactly. */
    static String between(String text, String from, String to) {
        int start = text.indexOf(from);
        int end = text.indexOf(to, start + from.length());
        assertTrue(start >= 0 && end > start, from + " ... " + to);
        return text.substring(start + from.length(), end);
    }

    static final dev.filtsiap.ded.anonymizer.FileConfig FILES = Config.loadFileConfig(Path.of("config"));

    /** The masked work items the real pipeline makes of {@code docx}: parse, rules, hard-redaction mask, chunks. */
    static List<Chunk> realChunks(byte[] docx) {
        DocumentData doc = dev.filtsiap.ded.anonymizer.DocxEngine.parseDocx(docx, "d", CFG.limits());
        List<Span> rules = dev.filtsiap.ded.anonymizer.Detectors.detectAll(doc, FILES.rules()).resolverSpans();
        return Chunk.split(HardDecisions.of(rules, POLICY, doc).maskedView(doc), CFG.chunkSizeChars());
    }

    /**
     * Each finding parses, survives the real reader, and LOCATES in the real rendering: every slice it maps
     * to is a slice of a unit holding exactly that text (labels and cues outside the spans).
     */
    static void assertLocates(Chunk.Rendered rendered, Chunk chunk, List<LlmDetector.Finding> findings) {
        Map<String, TextUnit> units = new LinkedHashMap<>();
        chunk.units().forEach(u -> units.put(u.unitId(), u));
        for (LlmDetector.Finding f : findings) {
            List<UnitSlice> at = Pass2Queue.locateInRendered(rendered, f.text());
            assertFalse(at.isEmpty(), f.text());
            for (UnitSlice s : at) {
                assertEquals(f.text(), dev.filtsiap.ded.anonymizer.pycompat.PyStr.slice(
                        units.get(s.unitId()).normalizedText(), s.start(), s.end()), f.text());
            }
        }
    }

    /**
     * Both pass-1 examples are valid answers to excerpts the pipeline really produces: the paragraph as its
     * own work item, and the label | value table as the chunker renders it from a real DOCX (its banner, its
     * read-only title line, one line per row, the verified ΑΦΜ already masked). The table's labels are in its
     * first column and are not findings; its values are decided one by one.
     */
    @Test
    void thePass1ExamplesAreValidAnswersToRealExcerpts() {
        String examples = between(Prompts.SYSTEM_PROMPT_PASS1, "EXAMPLES (synthetic", "Do not return markdown");
        String paragraph = between(examples, "DOCUMENT EXCERPT:\n", "\nAnswer:");
        String answer1 = between(examples, "Answer:\n", "\n\nA label | value table");
        String table = examples.substring(examples.indexOf("A label | value table"));
        String tableExcerpt = between(table, "DOCUMENT EXCERPT:\n", "\nAnswer:");
        String answer2 = table.substring(table.indexOf("Answer:\n") + 8).strip();

        List<LlmDetector.Finding> findings1 = LlmDetector.parsePass1Findings(answer1);
        assertEquals(5, findings1.size());
        assertEquals(5, LlmDetector.extractJsonArray(answer1).size()); // nothing dropped by the lenient reader
        assertTrue(findings1.contains(new LlmDetector.Finding("Λαμίας", SpanAction.PRESERVE, SpanCategory.PUBLIC_LOCALITY)));
        assertTrue(findings1.contains(new LlmDetector.Finding("231", SpanAction.REDACT, SpanCategory.CASE_COURT_REFERENCE)));
        // The example leaves out what the rules settle, and the rules really do settle it in this excerpt.
        assertTrue(findings1.stream().noneMatch(f -> f.text().contains("Δήμου") || f.text().contains("ΣτΕ")
                || f.text().contains("Πρωτοδικείου")));
        List<String> settled = dev.filtsiap.ded.anonymizer.Detectors.detectAll(dev.filtsiap.ded.anonymizer.DocxEngine
                        .parseDocx(dev.filtsiap.ded.anonymizer.TestDocx.paragraphs(paragraph).bytes(), "d", CFG.limits()),
                FILES.rules()).resolverSpans().stream()
                .filter(s -> dev.filtsiap.ded.anonymizer.Resolver.isHardPreserve(s, POLICY)).map(Span::text).toList();
        for (String kept : List.of("Δήμου Νέας Σμύρνης", "ΣτΕ 8721/1992", "1ο Τριμελές")) {
            assertTrue(settled.contains(kept), kept + " / " + settled);
        }
        List<Chunk> paragraphChunks = realChunks(dev.filtsiap.ded.anonymizer.TestDocx.paragraphs(paragraph).bytes());
        assertEquals(1, paragraphChunks.size());
        Chunk.Rendered renderedParagraph = paragraphChunks.getFirst().render();
        assertEquals(paragraph, renderedParagraph.text());
        assertLocates(renderedParagraph, paragraphChunks.getFirst(), findings1);

        String row = "<w:tr><w:tc>%s</w:tc><w:tc>%s</w:tc></w:tr>";
        String p = "<w:p><w:r><w:t xml:space=\"preserve\">%s</w:t></w:r></w:p>";
        String body = String.format(p, "Στοιχεία προσφεύγοντος") + "<w:tbl>"
                + String.format(row, String.format(p, "Ονοματεπώνυμο"), String.format(p, "Γεώργιος Παπαδόπουλος"))
                + String.format(row, String.format(p, "ΑΦΜ"), String.format(p, "123456783"))
                + String.format(row, String.format(p, "Ποσό"), String.format(p, "1.250,00")) + "</w:tbl>";
        Chunk tableChunk = realChunks(dev.filtsiap.ded.anonymizer.TestDocx.paragraphs().document(body).bytes()).stream()
                .filter(Chunk::isTable).findFirst().orElseThrow();
        Chunk.Rendered renderedTable = tableChunk.render();
        assertEquals(tableExcerpt, renderedTable.text());
        assertTrue(tableChunk.units().stream().noneMatch(u -> u.location().columnHeader().length() > 0),
                "a label | value table has no column header: its first row is data");
        List<LlmDetector.Finding> findings2 = LlmDetector.parsePass1Findings(answer2);
        // The amount is settled by the rules (a hard MONEY preserve), so the example leaves it out.
        assertEquals(List.of(new LlmDetector.Finding("Γεώργιος Παπαδόπουλος", SpanAction.REDACT, SpanCategory.APPELLANT_NAME)),
                findings2);
        assertLocates(renderedTable, tableChunk, findings2);
    }

    /**
     * The pass-2 example is the REAL queue: its example document, through the real detectors, a pass-1 reading
     * and the real router, yields these candidates (ids aside, in this order; the queue's address question is
     * left out of the example), serialized exactly as sent. The phone numbers are the detector's
     * {@code REVIEW} questions, never a deterministic REDACT, and the answer passes the real validator. The
     * town after the residence cue is hard-kept by policy, so it is never a question at all.
     */
    @Test
    void thePass2ExampleIsTheRealQueueForItsDocumentAndValidates() {
        String example = between(Prompts.SYSTEM_PROMPT_PASS2, "EXAMPLE (synthetic", "Do not return markdown");
        String shown = between(example, "CANDIDATES:\n", "\nAnswer:").replace(",\n ", ", ");
        String answer = example.substring(example.indexOf("Answer:\n") + 8).strip();

        byte[] docx = dev.filtsiap.ded.anonymizer.TestDocx.paragraphs(
                "Ο Γεώργιος Παπαδόπουλος, κάτοικος Λαμίας, οδός Ερμού αρ. 5, προσέφυγε κατά της πράξης.",
                "Για πληροφορίες: Τμήμα Επανεξέτασης, τηλέφωνο 2105551234.",
                "Ο προσφεύγων δήλωσε ως τηλέφωνο επικοινωνίας το 2105551234.").bytes();
        DocumentData doc = dev.filtsiap.ded.anonymizer.DocxEngine.parseDocx(docx, "d", CFG.limits());
        dev.filtsiap.ded.anonymizer.Detectors.DetectionResult rules =
                dev.filtsiap.ded.anonymizer.Detectors.detectAll(doc, FILES.rules());
        String pass1 = "[{\"text\": \"Γεώργιος Παπαδόπουλος\", \"action\": \"REDACT\", \"category\": \"APPELLANT_NAME\"}, "
                + "{\"text\": \"Λαμίας\", \"action\": \"PRESERVE\", \"category\": \"PUBLIC_LOCALITY\"}, "
                + "{\"text\": \"Ερμού\", \"action\": \"REDACT\", \"category\": \"PRIVATE_ADDRESS\"}, "
                + "{\"text\": \"5\", \"action\": \"REDACT\", \"category\": \"PRIVATE_ADDRESS\"}]";
        ScriptedLlm llm = model(pass1, ScriptedLlm::agreeWithEveryCandidate);
        LlmDetector.runLlmDetection(doc, rules.resolverSpans(), rules.reviewHints(), new LlmDetector.Provider(llm, CFG,
                millis -> { }, RunContext.start(300)), FILES.policy(), FILES.rules().regions());
        List<Map<String, Object>> real = candidates(pass2Requests(llm).getFirst());

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> exampleCandidates = (List<Map<String, Object>>) loads(shown);
        List<Map<String, Object>> picked = new ArrayList<>();
        int previous = -1;
        for (Map<String, Object> e : exampleCandidates) {
            Map<String, Object> wanted = new LinkedHashMap<>(e);
            wanted.remove("id");
            int at = -1;
            for (int i = 0; i < real.size(); i++) {
                Map<String, Object> r = new LinkedHashMap<>(real.get(i));
                r.remove("id");
                if (r.equals(wanted)) {
                    at = i;
                }
            }
            assertTrue(at > previous, "not in the real queue, in this order: " + e + " / " + real);
            previous = at;
            Map<String, Object> renumbered = new LinkedHashMap<>(real.get(at));
            renumbered.put("id", e.get("id"));
            picked.add(renumbered);
        }
        assertEquals(shown, PyJson.dumps(picked)); // byte for byte what the caller serializes
        assertEquals(List.of(Map.of("sources", List.of("deterministic"), "action", "REVIEW", "category", "PHONE")),
                exampleCandidates.get(0).get("recommendations"));
        assertEquals(exampleCandidates.get(0).get("recommendations"), exampleCandidates.get(1).get("recommendations"));
        assertEquals(exampleCandidates.get(0).get("text"), exampleCandidates.get(1).get("text"));
        assertTrue(real.stream().noneMatch(c -> "Λαμίας".equals(c.get("text"))), real.toString());

        Map<String, Pass2Queue.Candidate> byId = new LinkedHashMap<>();
        for (Map<String, Object> e : exampleCandidates) {
            String text = (String) e.get("text");
            byId.put((String) e.get("id"), new Pass2Queue.Candidate((String) e.get("id"), text, SpanCategory.PHONE,
                    List.of(), List.of(new UnitSlice("u0", 0, text.length())), (String) e.get("before"),
                    (String) e.get("after")));
        }
        Pass2Queue.Validation v = Pass2Queue.validate(answer, byId);
        assertEquals(List.of(), v.rejections());
        assertFalse(v.distrusted());
        assertEquals(List.of("C1:PRESERVE", "C2:REDACT"),
                v.decisions().stream().map(d -> d.candidateId() + ":" + d.action()).toList());
    }

    static Object loads(String json) {
        try {
            return PyJson.loads(json);
        } catch (PyJson.JsonDecodeError e) {
            throw new AssertionError(e);
        }
    }

    /**
     * The retry message, the pass-2 prompt and {@link Pass2Queue#validate} say the same thing: a rejected
     * entry costs only its own candidate (re-asked alone, every usable answer kept) unless an entry shows the
     * response is not tracking the list, which sets the whole response aside. A repeated id, REVIEW and an
     * unknown category keep their own rules.
     */
    @Test
    void theRetryMessageThePromptAndTheValidatorAgree() {
        Map<String, Pass2Queue.Candidate> byId = new LinkedHashMap<>();
        for (String id : List.of("C1", "C2")) {
            byId.put(id, new Pass2Queue.Candidate(id, "Σπύρος", SpanCategory.POSSIBLE_PERSON, List.of(),
                    List.of(new UnitSlice("u0", 0, 6)), "", ""));
        }
        String flat = Prompts.SYSTEM_PROMPT_PASS2.replaceAll("\\s+", " ");

        // A repeated id: its own answers are discarded, the response is still trusted, the other answer is kept.
        Pass2Queue.Validation repeated = Pass2Queue.validate("[" + PyJson.dumps(answer("C1", "REDACT", "POSSIBLE_PERSON"))
                + ", " + PyJson.dumps(answer("C2", "REDACT", "POSSIBLE_PERSON")) + ", "
                + PyJson.dumps(answer("C2", "PRESERVE", "POSSIBLE_PERSON")) + "]", byId);
        assertFalse(repeated.distrusted());
        assertEquals(List.of("C1"), repeated.decisions().stream().map(Pass2Queue.Decision::candidateId).toList());
        assertEquals(List.of("C2"), repeated.voided());
        String kept = Prompts.buildPass2RetryMessage(List.of(byId.get("C2").asPayload()), repeated.rejections(),
                "1 unusable entry/entries", true, false);
        assertTrue(kept.contains("anything you already decided correctly has been kept"), kept);
        assertTrue(kept.contains("These entries could not be used, so only the candidates they were about are asked "
                + "again; do not repeat them:"), kept);
        assertFalse(kept.contains("whole"), kept);
        assertTrue(flat.contains("Every entry is checked on its own, and a usable entry is kept even when another is not"));
        assertTrue(flat.contains("every answer for a repeated id is thrown away"));

        // An id this queue never issued: the response is not trusted, nothing in it is kept, the whole queue again.
        Pass2Queue.Validation foreign = Pass2Queue.validate("[" + PyJson.dumps(answer("C1", "REDACT", "POSSIBLE_PERSON"))
                + ", " + PyJson.dumps(answer("C9", "REDACT", "POSSIBLE_PERSON")) + "]", byId);
        assertTrue(foreign.distrusted());
        String whole = Prompts.buildPass2RetryMessage(byId.values().stream().map(Pass2Queue.Candidate::asPayload)
                .toList(), foreign.rejections(), "1 unusable entry/entries", false, false);
        assertTrue(whole.contains("Nothing from your previous response could be kept"), whole);
        assertTrue(whole.contains("means the response was not tracking the list, so none of it was kept"), whole);
        assertTrue(flat.contains("the response is not trusted and the whole queue is asked again, once"));
        for (String message : List.of(kept, whole)) {
            assertFalse(message.contains("Every one of them makes the whole"), message);
        }

        // REVIEW is recorded as REDACT, and a category outside the vocabulary falls back to the recommended one.
        Pass2Queue.Validation lenient = Pass2Queue.validate("[" + PyJson.dumps(answer("C1", "REVIEW", "NOT_A_CATEGORY"))
                + "]", byId);
        assertEquals(List.of(new Pass2Queue.Decision("C1", SpanCategory.POSSIBLE_PERSON, SpanAction.REDACT, true)),
                lenient.decisions());
        assertTrue(flat.contains("REVIEW is not a legal action and is recorded as REDACT"));
        assertTrue(flat.contains("a category outside the vocabulary falls back to the recommended one"));
    }

    /** A budget guard: the system prompts may not grow past these estimates without this test being revised. */
    @Test
    void theSystemPromptsStayWithinTheirTokenEstimates() {
        assertTrue(Pass2Queue.estimateTokens(Prompts.SYSTEM_PROMPT_PASS1) <= 6_500,
                String.valueOf(Pass2Queue.estimateTokens(Prompts.SYSTEM_PROMPT_PASS1)));
        assertTrue(Pass2Queue.estimateTokens(Prompts.SYSTEM_PROMPT_PASS2) <= 7_100,
                String.valueOf(Pass2Queue.estimateTokens(Prompts.SYSTEM_PROMPT_PASS2)));
    }
}
