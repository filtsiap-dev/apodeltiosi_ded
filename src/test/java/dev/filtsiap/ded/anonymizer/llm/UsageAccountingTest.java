package dev.filtsiap.ded.anonymizer.llm;

import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.answer;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.finished;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.isPass1;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.isRetry;
import static dev.filtsiap.ded.anonymizer.llm.ScriptedLlm.usage;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DocumentAccounting;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.LlmPricing;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.PostcheckFinding;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.SpanOrigin;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.UnresolvedFinding;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.Completion;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.TokenUsage;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.math.BigDecimal;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Per-document token, time and cost accounting, all on synthetic usage reports: what is booked for
 * every kind of provider response, what is refused, and how the cost is computed from it.
 */
class UsageAccountingTest {

    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));
    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();
    /** Synthetic prices per 1M tokens; nothing here is a real provider's price list. */
    static final LlmPricing PRICED = new LlmPricing(new BigDecimal("2.50"), null, new BigDecimal("10.00"), "USD");

    static TextUnit para(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static DocumentData doc(TextUnit... units) {
        return new DocumentData("d", List.of(units), List.of(), List.of());
    }

    static Span hint(TextUnit unit, String text) {
        int start = unit.normalizedText().indexOf(text);
        return new Span(unit.unitId(), start, start + text.length(), text, SpanCategory.POSSIBLE_PERSON, "t", 0.6,
                SpanAction.REVIEW, "", SpanOrigin.DETERMINISTIC);
    }

    static LlmUsage detect(DocumentData d, List<Span> hints, LlmClient llm, RuntimeConfig cfg) {
        RunContext ctx = RunContext.start(300);
        LlmDetector.runLlmDetection(d, List.of(), hints, new LlmDetector.Provider(llm, cfg, s -> { }, ctx), POLICY,
                Set.of());
        return ctx.usage().snapshot();
    }

    // ------------------------------------------------------------------ what each response books

    @Test
    void oneNormalCallIsBookedWithWhatTheProviderReported() {
        LlmUsage u = detect(doc(para("u0", "Κείμενο χωρίς στοιχεία.")), List.of(),
                ScriptedLlm.completions(r -> finished("[]", usage(1200, 30))), CFG);
        assertEquals(1, u.calls());
        assertEquals(1, u.pass1Calls());
        assertEquals(0, u.pass2Calls());
        assertEquals(1200, u.inputTokens());
        assertEquals(30, u.outputTokens());
        assertEquals(1230, u.totalTokens());
        assertNull(u.cachedInputTokens()); // not reported, so not zero: unknown
        assertNull(u.reasoningTokens());
        assertEquals(0, u.callsMissingUsage());
        assertEquals(1, u.pass1Success());
        assertEquals(1, u.pass2Skipped());
    }

    @Test
    void concurrentChunksAddUpExactlyOnOneDocumentsLedger() {
        RuntimeConfig small = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_CHUNK_SIZE_CHARS", "10", "ANON_LLM_CONCURRENCY", "8"));
        List<TextUnit> units = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            units.add(para("u" + i, "κείμενο" + (char) ('α' + i)));
        }
        for (int run = 0; run < 25; run++) {
            LlmUsage u = detect(new DocumentData("d", units, List.of(), List.of()), List.of(),
                    ScriptedLlm.completions(r -> finished("[]", usage(100, 7))), small);
            assertEquals(12, u.calls());
            assertEquals(1200, u.inputTokens());
            assertEquals(84, u.outputTokens());
            assertEquals(12, u.pass1Success());
        }
        // The recorder itself, hammered from many threads at once: no update is lost.
        UsageRecorder recorder = new UsageRecorder();
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < 16; t++) {
            threads.add(Thread.ofVirtual().start(() -> {
                for (int i = 0; i < 1000; i++) {
                    recorder.record(finished("[]", new TokenUsage(3L, 2L, 5L, 1L, 1L)), 0, CallKind.PASS1, 3000, 10);
                }
            }));
        }
        threads.forEach(th -> {
            try {
                th.join();
            } catch (InterruptedException e) {
                throw new IllegalStateException(e);
            }
        });
        LlmUsage hammered = recorder.snapshot();
        assertEquals(16_000, hammered.calls());
        assertEquals(48_000, hammered.inputTokens());
        assertEquals(16_000L, hammered.cachedInputTokens());
        assertEquals(80_000, hammered.totalTokens());
    }

    @Test
    void theCorrectiveRetryIsBookedAsAPass2CallOfItsOwnKind() {
        TextUnit unit = para("u0", "Ο Σπύρος και η Μαρία.");
        ScriptedLlm llm = ScriptedLlm.reporting(new ScriptedLlm(r -> isPass1(r) ? "[]" : PyJson.dumps(isRetry(r)
                        ? List.of(answer("C2", "REDACT", "POSSIBLE_PERSON"))
                        : List.of(answer("C1", "REDACT", "POSSIBLE_PERSON")))),
                r -> isPass1(r) ? usage(1000, 50) : isRetry(r) ? usage(2500, 40) : usage(2000, 100));
        LlmUsage u = detect(doc(unit), List.of(hint(unit, "Σπύρος"), hint(unit, "Μαρία")), llm, CFG);
        assertEquals(3, u.calls());
        assertEquals(1, u.pass1Calls());
        assertEquals(2, u.pass2Calls());
        assertEquals(1, u.pass2RetryCalls());
        assertEquals(5500, u.inputTokens());
        assertEquals(190, u.outputTokens());
        assertEquals(1, u.pass2Executed());
        assertEquals(1, u.pass2Retried());
        assertEquals(2, u.pass2Attempts());
        assertEquals(0, u.pass2IncompleteAttempts());
    }

    /**
     * Pass 1's one corrective call is a pass-1 call like the first, on the same ledger, with no new
     * kind of entry; the chunk's pass-1 outcome is counted once, as it finally stood. Discovery that
     * never arrived costs its failed attempts and books no outcome at all.
     */
    @Test
    void thePass1CorrectiveCallIsBookedAsAPass1Call() {
        DocumentData plain = doc(para("u0", "Κείμενο χωρίς στοιχεία."));
        AtomicInteger asked = new AtomicInteger();
        ScriptedLlm recovers = ScriptedLlm.completions(r -> asked.getAndIncrement() == 0
                ? finished("not json", usage(1000, 40)) : finished("[]", usage(1100, 2)));
        LlmUsage u = detect(plain, List.of(), recovers, CFG);
        assertEquals(2, u.calls());
        assertEquals(2, u.pass1Calls());
        assertEquals(0, u.pass2Calls());
        assertEquals(2100, u.inputTokens());
        assertEquals(42, u.outputTokens());
        assertEquals(1, u.pass1Success());
        assertEquals(0, u.pass1Degraded());
        assertEquals(1, u.pass2Skipped());

        LlmUsage stillBad = detect(plain, List.of(),
                ScriptedLlm.completions(r -> new Completion("[{\"text\"", "length", false, usage(900, 3000))), CFG);
        assertEquals(2, stillBad.calls()); // never a third
        assertEquals(2, stillBad.pass1Calls());
        assertEquals(1, stillBad.pass1OutputTruncated());
        assertEquals(0, stillBad.pass1Success());
        assertEquals(2, stillBad.truncated().size());
        assertTrue(stillBad.truncated().stream().allMatch(t -> t.kind() == CallKind.PASS1));

        LlmUsage down = detect(plain, List.of(), ScriptedLlm.completions(r -> {
            throw LlmCallException.status(503, 0L, null);
        }), CFG);
        assertEquals(0, down.calls());
        assertEquals(LlmDetector.MAX_PROVIDER_ATTEMPTS, down.failedProviderAttempts());
        assertEquals(0, down.pass1Success());
        assertEquals(1, down.pass1Degraded());
        assertEquals(1, down.pass1ProviderFailure());
        assertEquals(1, down.pass2Skipped());
    }

    @Test
    void theRemediationIsBookedOnTheSameLedgerUnderItsOwnKinds() {
        TextUnit unit = para("u0", "κινητό 6912345678 εδώ.");
        int start = unit.normalizedText().indexOf("6912345678");
        List<LlmDetector.Residual> residuals = List.of(new LlmDetector.Residual(new UnresolvedFinding.AuditRef("P1",
                PostcheckFinding.Severity.MEDIUM, "phone_shape", "word/document.xml:u0"), new Span("u0", start,
                start + 10, "6912345678", SpanCategory.PHONE, "postcheck_phone_shape", 1.0, SpanAction.REVIEW, "",
                SpanOrigin.DETERMINISTIC)));
        RunContext ctx = RunContext.start(300);
        // Silent once, so the corrective retry runs; both are remediation calls.
        AtomicInteger asked = new AtomicInteger();
        ScriptedLlm llm = ScriptedLlm.completions(r -> asked.getAndIncrement() == 0 ? finished("[]", usage(800, 5))
                : finished(PyJson.dumps(List.of(answer("C1", "REDACT", "PHONE"))), usage(900, 20)));
        LlmDetector.runPass2Remediation(doc(unit), residuals, List.of(), List.of(), List.of(),
                new LlmDetector.Provider(llm, CFG, s -> { }, ctx), Set.of());
        LlmUsage u = ctx.usage().snapshot();
        assertEquals(2, u.calls());
        assertEquals(0, u.pass1Calls());
        assertEquals(0, u.pass2Calls());
        assertEquals(2, u.remediationCalls());
        assertEquals(1, u.remediationRetryCalls());
        assertEquals(1700, u.inputTokens());
        assertEquals(25, u.outputTokens());
        assertEquals(2, u.pass2Attempts()); // the remediation's attempts are pass-2 attempts, as in v2
        assertEquals(0, u.pass2Executed()); // ... but not one of the main stage's chunk outcomes
    }

    @Test
    void aResponseWithNoUsableUsageIsCountedNeverGuessedAndCostsTheMoneyFigure() {
        TextUnit unit = para("u0", "Ο Σπύρος.");
        ScriptedLlm llm = ScriptedLlm.completions(r -> isPass1(r) ? finished("[]", usage(1000, 10))
                : finished(PyJson.dumps(List.of(answer("C1", "REDACT", "POSSIBLE_PERSON"))))); // no usage block
        LlmUsage u = detect(doc(unit), List.of(hint(unit, "Σπύρος")), llm, CFG);
        assertEquals(2, u.calls());
        assertEquals(1, u.callsMissingUsage());
        assertEquals(1000, u.inputTokens()); // what WAS reported, and nothing invented for the rest
        assertFalse(u.usageComplete());
        DocumentAccounting a = DocumentAccounting.of(u, 10, 5L, PRICED);
        assertNull(a.estimatedCost());
        assertEquals("calls_missing_usage", a.costUnavailableReason());
    }

    @Test
    void failedTransportAttemptsCostTimeButNoTokens() {
        AtomicInteger calls = new AtomicInteger();
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (calls.getAndIncrement() < 2) {
                throw LlmCallException.status(503, null);
            }
            return finished("[]", usage(400, 4));
        });
        LlmUsage u = detect(doc(para("u0", "κείμενο")), List.of(), llm, CFG);
        assertEquals(1, u.calls()); // one response
        assertEquals(2, u.failedProviderAttempts()); // two attempts that returned none
        assertEquals(400, u.inputTokens());
        assertEquals(0, u.callsMissingUsage()); // a failed attempt is not a response missing usage
    }

    @Test
    void aTruncatedCompletionIsBookedAndRecordedAsTruncated() {
        // Pass 1 is cut off, and so is its one corrective call; there is nothing for pass 2 to decide.
        LlmUsage u = detect(doc(para("u0", "κείμενο")), List.of(),
                ScriptedLlm.completions(r -> isPass1(r) ? new Completion("[{\"text\"", "length", false, usage(900, 3000))
                        : finished("[]", usage(950, 2))), CFG);
        LlmUsage.TruncatedCall cut = new LlmUsage.TruncatedCall(0, CallKind.PASS1, 3000L, CFG.maxCompletionTokens());
        assertEquals(List.of(cut, cut), u.truncated());
        assertEquals(1, u.pass1OutputTruncated());
        assertEquals(6000, u.outputTokens()); // a truncated answer still cost its tokens
    }

    @Test
    void nonsenseCountsAreRefusedAndCannotFailTheDocument() {
        UsageRecorder r = new UsageRecorder();
        r.record(finished("[]", new TokenUsage(-5L, 10L, 5L, null, null)), 0, CallKind.PASS1, 3000, 1);
        r.record(finished("[]", new TokenUsage(2_000_000_000L, 10L, null, null, null)), 0, CallKind.PASS1, 3000, 1);
        r.record(finished("[]", new TokenUsage(100L, null, 100L, null, null)), 0, CallKind.PASS1, 3000, 1);
        // A total below its parts, and subsets larger than their wholes, are not believed.
        r.record(finished("[]", new TokenUsage(100L, 10L, 5L, 500L, 50L)), 0, CallKind.PASS2, 3000, 1);
        LlmUsage u = r.snapshot();
        assertEquals(4, u.calls());
        assertEquals(3, u.callsMissingUsage());
        assertEquals(100, u.inputTokens());
        assertEquals(10, u.outputTokens());
        assertEquals(110, u.totalTokens());
        assertNull(u.cachedInputTokens());
        assertNull(u.reasoningTokens());
        // And through the detector: a provider reporting garbage on every call still gets its document read.
        TextUnit unit = para("u0", "Ο Σπύρος.");
        ScriptedLlm garbage = ScriptedLlm.reporting(ScriptedLlm.cooperative(), q -> new TokenUsage(-1L, -1L, -1L, -1L,
                -1L));
        RunContext ctx = RunContext.start(300);
        LlmDetector.Result result = LlmDetector.runLlmDetection(doc(unit), List.of(), List.of(hint(unit, "Σπύρος")),
                new LlmDetector.Provider(garbage, CFG, s -> { }, ctx), POLICY, Set.of());
        assertEquals(1, result.spans().size());
        assertEquals(2, ctx.usage().snapshot().callsMissingUsage());
    }

    // ------------------------------------------------------------------ the money

    @Test
    void noPriceConfiguredMeansCostUnavailableNeverZero() {
        LlmUsage u = detect(doc(para("u0", "κείμενο")), List.of(),
                ScriptedLlm.completions(r -> finished("[]", usage(1000, 10))), CFG);
        DocumentAccounting a = DocumentAccounting.of(u, 10, 5L, CFG.pricing());
        assertEquals(LlmPricing.UNSET, CFG.pricing());
        assertNull(a.estimatedCost());
        assertNull(a.estimatedCostText());
        assertEquals("pricing_not_configured", a.costUnavailableReason());
        assertEquals(1000, a.inputTokens()); // the tokens are still counted
        assertEquals("USD", a.currency());
    }

    @Test
    void aConfiguredPriceGivesTheExactDecimalCost() {
        UsageRecorder r = new UsageRecorder();
        r.record(finished("[]", usage(123_456, 7_890)), 0, CallKind.PASS1, 3000, 1);
        DocumentAccounting a = DocumentAccounting.of(r.snapshot(), 10, 5L, PRICED);
        // (123456 x 2.50 + 7890 x 10.00) / 1 000 000 = 0.38754, exactly.
        assertEquals(0, new BigDecimal("0.38754").compareTo(a.estimatedCost()));
        assertEquals("0.38754", a.estimatedCostText());
        assertNull(a.costUnavailableReason());

        // Decimal, not binary: 3 x 0.1 is 0.3 here, where a double gives 0.30000000000000004.
        UsageRecorder tiny = new UsageRecorder();
        tiny.record(finished("[]", usage(3, 3)), 0, CallKind.PASS1, 3000, 1);
        DocumentAccounting t = DocumentAccounting.of(tiny.snapshot(), 1, 1L,
                new LlmPricing(new BigDecimal("0.1"), null, new BigDecimal("0.2"), "EUR"));
        assertEquals("0.0000009", t.estimatedCostText());
        assertEquals("EUR", t.currency());

        // A document that made no call cost exactly nothing.
        assertEquals("0", DocumentAccounting.of(new UsageRecorder().snapshot(), 1, null, PRICED).estimatedCostText());
    }

    @Test
    void cachedInputIsASubsetMovedToItsOwnRateOrLeftAtTheInputRate() {
        UsageRecorder r = new UsageRecorder();
        r.record(finished("[]", new TokenUsage(10_000L, 500L, 10_500L, 4_000L, 120L)), 0, CallKind.PASS2, 3000, 1);
        LlmUsage u = r.snapshot();
        assertEquals(4_000L, u.cachedInputTokens());
        assertEquals(120L, u.reasoningTokens());
        // With a cached rate: (6000 x 0.40 + 4000 x 0.10 + 500 x 1.60) / 1e6 = 0.0036
        DocumentAccounting cached = DocumentAccounting.of(u, 1, 1L, new LlmPricing(new BigDecimal("0.40"),
                new BigDecimal("0.10"), new BigDecimal("1.60"), "USD"));
        assertEquals("0.0036", cached.estimatedCostText());
        assertEquals("cached", cached.cachedInputRate());
        // Without one, cached tokens stay at the input rate (an upper bound, never an understatement), and
        // reasoning tokens are already inside the output count: (10000 x 0.40 + 500 x 1.60) / 1e6 = 0.0048
        DocumentAccounting uncached = DocumentAccounting.of(u, 1, 1L, new LlmPricing(new BigDecimal("0.40"), null,
                new BigDecimal("1.60"), "USD"));
        assertEquals("0.0048", uncached.estimatedCostText());
        assertEquals("input", uncached.cachedInputRate());
        // The rates travel with the figure, so it can be recomputed from the record alone.
        assertEquals(Map.of("input_per_1m_tokens", "0.4", "output_per_1m_tokens", "1.6", "currency", "USD"),
                withoutNulls(uncached.asMap().get("pricing")));
    }

    static Map<?, ?> withoutNulls(Object map) {
        Map<Object, Object> out = new java.util.HashMap<>();
        ((Map<?, ?>) map).forEach((k, v) -> {
            if (v != null) {
                out.put(k, v);
            }
        });
        return out;
    }

    // ------------------------------------------------------------------ what never enters the ledger

    @Test
    void theLedgerAndEveryRenderingOfItCarryNoDocumentText() {
        TextUnit unit = para("u0", "Ο Σπύρος Λάμπρου, τηλ. 6912345678.");
        ScriptedLlm llm = ScriptedLlm.reporting(new ScriptedLlm(r -> isPass1(r)
                ? "[{\"text\": \"Σπύρος Λάμπρου\", \"action\": \"REDACT\", \"category\": \"PERSON\"}]"
                : PyJson.dumps(ScriptedLlm.agreeWithEveryCandidate(r))), r -> usage(700, 20));
        LlmUsage u = detect(doc(unit), List.of(hint(unit, "6912345678")), llm, CFG);
        DocumentAccounting a = DocumentAccounting.of(u, 10, 5L, PRICED);
        for (String rendered : List.of(u.toString(), PyJson.dumps(u.asMap()), a.toString(), PyJson.dumps(a.asMap()),
                a.logFields())) {
            for (String secret : List.of("Σπύρος", "Λάμπρου", "6912345678")) {
                assertFalse(rendered.contains(secret), rendered);
            }
        }
    }
}
