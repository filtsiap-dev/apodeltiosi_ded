package dev.filtsiap.ded.anonymizer.llm;

import static dev.filtsiap.ded.anonymizer.LogCapture.count;
import static dev.filtsiap.ded.anonymizer.LogCapture.one;
import static dev.filtsiap.ded.anonymizer.llm.FlakyLlm.ok;
import static dev.filtsiap.ded.anonymizer.llm.FlakyLlm.rateLimited;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.DocumentTimeoutError;
import dev.filtsiap.ded.anonymizer.FakeClock;
import dev.filtsiap.ded.anonymizer.LogCapture;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.RequestProgress;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitType;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

/**
 * The provider retry lifecycle, end to end through the pass-1 stage, against a simulated provider.
 * Fourteen chunks, one short paragraph each, so chunk N is paragraph N: "para-0N-xx" for N below 10.
 * The sleeper records each wait and does not sleep.
 */
class RetryLifecycleLoggingTest {

    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();

    /** The marker that identifies chunk {@code chunk} (1-based) in its excerpt. */
    static String marker(int chunk) {
        return String.format("para-%02d-xx", chunk);
    }

    static DocumentData document() {
        List<TextUnit> units = new ArrayList<>();
        for (int chunk = 1; chunk <= 14; chunk++) {
            String text = marker(chunk);
            units.add(new TextUnit("u" + chunk, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                    new TextUnit.ParagraphLocation(chunk - 1)));
        }
        return new DocumentData("d", units, List.of(), List.of());
    }

    static LlmDetector.Result run(FlakyLlm llm, RunContext ctx, LlmDetector.Sleeper sleeper, int workers) {
        RuntimeConfig cfg = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_CHUNK_SIZE_CHARS", "10", "ANON_LLM_CONCURRENCY",
                Integer.toString(workers)));
        return LlmDetector.runLlmDetection(document(), List.of(), List.of(),
                new LlmDetector.Provider(llm, cfg, sleeper, ctx, () -> 0.5), POLICY, Set.of());
    }

    /** One 429 for chunk 9 that asks for 8.371 s, then a success: the incident's shape, in isolation. */
    @Test
    void aRateLimitedChunkRetriesAndEachStepIsLogged() {
        FlakyLlm llm = new FlakyLlm().script(marker(9), rateLimited(8371L), ok());
        RunContext ctx = RunContext.start(300);
        List<Long> slept = new CopyOnWriteArrayList<>();
        List<String> log;
        try (LogCapture logs = new LogCapture()) {
            run(llm, ctx, slept::add, 4);
            log = logs.lines();
        }
        String scheduled = one(log, "llm_retry ", "chunk=9 pass=1", "transport_attempt=1", "delay_ms=8371",
                "delay_source=header", "error=rate_limited", "http_status=429", "will_retry=yes");
        String started = one(log, "llm_retry_started", "chunk=9 pass=1", "transport_attempt=2", "waited_ms=8371");
        String succeeded = one(log, "llm_retry_succeeded", "chunk=9 pass=1", "transport_attempt=2", "waited_ms=8371");
        assertTrue(log.indexOf(scheduled) < log.indexOf(started), "scheduled before started");
        assertTrue(log.indexOf(started) < log.indexOf(succeeded), "started before succeeded");
        assertEquals(List.of(8371L), slept);
        assertEquals(2, llm.attempts(marker(9)));
        assertEquals(0, count(log, "llm_retry_exhausted"));

        RequestProgress.Snapshot progress = ctx.progress().snapshot();
        assertEquals(14, progress.chunksCompleted());
        assertEquals(14, progress.chunksTotal());
        assertEquals("rate_limited", progress.failure().label());
        assertTrue(progress.failure().recovered(), "the 429 was recovered from");
        assertEquals(1, ctx.usage().snapshot().failedProviderAttempts());
    }

    /** Three chunks rate-limited at the same moment: each has its own complete lifecycle, none is mixed up. */
    @Test
    void severalChunksRateLimitedAtOnceEachHaveTheirOwnLifecycle() {
        FlakyLlm llm = new FlakyLlm().script(marker(3), rateLimited(0L), ok())
                .script(marker(6), rateLimited(0L), ok())
                .script(marker(9), rateLimited(0L), ok());
        RunContext ctx = RunContext.start(300);
        List<String> log;
        try (LogCapture logs = new LogCapture()) {
            run(llm, ctx, millis -> { }, 4);
            log = logs.lines();
        }
        assertEquals(3, count(log, "llm_retry "));
        for (int chunk : List.of(3, 6, 9)) {
            one(log, "llm_retry ", "chunk=" + chunk + " pass=1", "transport_attempt=1");
            one(log, "llm_retry_started", "chunk=" + chunk + " pass=1", "transport_attempt=2");
            one(log, "llm_retry_succeeded", "chunk=" + chunk + " pass=1", "transport_attempt=2");
        }
        assertEquals(3, ctx.usage().snapshot().failedProviderAttempts());
        assertTrue(ctx.progress().snapshot().failure().recovered());
        assertEquals(14, ctx.progress().snapshot().chunksCompleted());
    }

    /** A chunk rate-limited on every attempt: six attempts, the exhaustion named, and the request survives. */
    @Test
    void aRateLimitRepeatedUntilItsRetriesAreExhaustedIsReportedNotSilent() {
        FlakyLlm llm = new FlakyLlm().script(marker(5), rateLimited(0L));
        RunContext ctx = RunContext.start(300);
        List<String> log;
        try (LogCapture logs = new LogCapture()) {
            run(llm, ctx, millis -> { }, 4); // returns: discovery failures are absorbed, never fatal
            log = logs.lines();
        }
        assertEquals(6, llm.attempts(marker(5)));
        assertEquals(5, count(log, "llm_retry "));
        one(log, "llm_retry_exhausted", "chunk=5 pass=1", "attempts=6", "error=rate_limited", "will_retry=no");
        one(log, "pass1_discovery_degraded", "chunk=5 pass=1");
        RequestProgress.Snapshot progress = ctx.progress().snapshot();
        assertEquals(14, progress.chunksCompleted());
        assertEquals(5, progress.failure().chunk());
        assertFalse(progress.failure().recovered(), "the failure was never recovered from");
    }

    /** A worker's own exception during a retry: named where it happened and why the run stopped; it still propagates. */
    @Test
    void aWorkerExceptionDuringARetryIsNamedAndStillPropagates() {
        FlakyLlm llm = new FlakyLlm().script(marker(4), rateLimited(0L),
                new IllegalStateException("synthetic failure inside the client"));
        List<String> log;
        try (LogCapture logs = new LogCapture()) {
            assertThrows(IllegalStateException.class, () -> run(llm, RunContext.start(300), millis -> { }, 4));
            log = logs.lines();
        }
        one(log, "llm_call_failed_unexpectedly", "chunk=4 pass=1", "transport_attempt=2",
                "error=IllegalStateException");
        one(log, "llm_run_aborted", "cause=IllegalStateException");
    }

    /**
     * The document's deadline passes during a retry's wait: with one worker the chunks run in order, so
     * the wait is the only thing in flight, and the retry is logged as aborted, not as a retry that ran.
     */
    @Test
    void theDocumentDeadlineExpiringDuringABackoffIsLoggedAsAborted() {
        FakeClock clock = new FakeClock();
        RunContext ctx = clock.context(3.5);
        FlakyLlm llm = new FlakyLlm().script(marker(2), rateLimited(2000L));
        List<String> log;
        try (LogCapture logs = new LogCapture()) {
            assertThrows(DocumentTimeoutError.class, () -> run(llm, ctx, millis -> clock.advance(3.0), 1));
            log = logs.lines();
        }
        one(log, "llm_retry ", "chunk=2 pass=1", "delay_ms=2000", "will_retry=yes");
        one(log, "llm_retry_aborted", "chunk=2 pass=1", "transport_attempt=2", "reason=deadline", "waited_ms=2000");
        assertEquals(1, llm.attempts(marker(2)), "no attempt starts once the budget is spent");
    }

    /** A shutdown that interrupts the wait: named as interrupted, and the call is not made again. */
    @Test
    void anInterruptedRetryWaitIsLoggedAsInterrupted() {
        FlakyLlm llm = new FlakyLlm().script(marker(2), rateLimited(0L), ok());
        LlmDetector.Sleeper interrupted = millis -> {
            throw new InterruptedException("synthetic interrupt");
        };
        List<String> log;
        try (LogCapture logs = new LogCapture()) {
            assertThrows(AIProviderError.class, () -> run(llm, RunContext.start(300), interrupted, 1));
            log = logs.lines();
        }
        one(log, "llm_retry_interrupted", "chunk=2 pass=1", "transport_attempt=1", "waited_ms=0",
                "error=rate_limited");
        assertEquals(1, llm.attempts(marker(2)));
    }

    /** Five rate limits, then success on the sixth attempt: the request is a success, and the 429s are counted, not failures. */
    @Test
    void aSuccessfulRequestWithFiveRecoveredRateLimitsIsLoggedAsRecovered() {
        FlakyLlm llm = new FlakyLlm().script(marker(6), rateLimited(0L), rateLimited(0L), rateLimited(0L),
                rateLimited(0L), rateLimited(0L), ok());
        RunContext ctx = RunContext.start(300);
        List<String> log;
        try (LogCapture logs = new LogCapture()) {
            run(llm, ctx, millis -> { }, 4);
            log = logs.lines();
        }
        assertEquals(5, count(log, "llm_retry "));
        one(log, "llm_retry_succeeded", "chunk=6 pass=1", "transport_attempt=6");
        assertEquals(0, count(log, "llm_retry_exhausted"));
        assertEquals(6, llm.attempts(marker(6)));
        assertEquals(5, ctx.usage().snapshot().failedProviderAttempts());
        assertTrue(ctx.progress().snapshot().failure().recovered());
    }
}
