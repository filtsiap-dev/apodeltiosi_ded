package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.llm.LlmClient.Completion;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.TokenUsage;
import dev.filtsiap.ded.anonymizer.llm.LlmUsage.TruncatedCall;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread-safe accumulator for ONE document's provider calls (port of {@code llm/usage.UsageRecorder}).
 *
 * <p>One recorder per document, carried by its {@code RunContext} and reached by every provider
 * call that document makes: pass 1, pass-2 first attempts and corrective retries, and the
 * post-redaction remediation. Nothing is keyed by thread or document id, and there is no shared
 * state: the recorder IS the document's scope, so two documents cannot mix their totals however
 * they are run. Within a document chunks run concurrently, so every write is taken under one lock
 * and the numbers leave as an immutable {@link LlmUsage}.
 *
 * <p>NEVER FAILS A DOCUMENT: a response shaped unexpectedly is counted as missing usage, and a
 * bug in counting is logged by type and booked the same way. NEVER GUESSES: a count the provider
 * did not report is absent, not zero, and estimating one would mean tokenizing the document for
 * accounting.
 *
 * <p>Two deliberate differences from v2: a response counts as having usage only when it reports
 * BOTH its prompt and its completion tokens (v2 accepts either one, which understates a total
 * that is then priced); and cached and reasoning tokens are read, as subsets of the input and
 * output counts.
 */
public final class UsageRecorder {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.llm.usage");

    /** Above this, a reported count is not a count, and accepting it could break the sum. */
    static final long MAX_REPORTED_TOKENS = 1_000_000_000L;

    /**
     * How the document-wide pass 2 turned out: SKIPPED once when the whole queue was empty, otherwise
     * one EXECUTED or FAILED per batch (FAILED: pass 2 was unavailable for some of its candidates, which
     * got the documented fallback).
     */
    enum Pass2Outcome { SKIPPED, EXECUTED, FAILED }

    private final Object lock = new Object();
    private int calls;
    private int pass1Calls;
    private int pass2Calls;
    private int pass2RetryCalls;
    private int remediationCalls;
    private int remediationRetryCalls;
    private long input;
    private long cached;
    private boolean cachedReported;
    private long output;
    private long reasoning;
    private boolean reasoningReported;
    private long total;
    private int missing;
    private int failedAttempts;
    private long providerNanos;
    private final List<TruncatedCall> truncated = new ArrayList<>();
    private int pass1Success;
    private int pass1ParseFailure;
    private int pass1OutputTruncated;
    private int pass1ProviderFailure;
    private int pass2Skipped;
    private int pass2Executed;
    private int pass2Failed;
    private int pass2Retried;
    private int pass2Attempts;
    private int pass2Incomplete;

    /** What one response adds, worked out before the lock is taken so applying it cannot throw. */
    private record Entry(Long prompt, Long completion, long total, Long cached, Long reasoning, TruncatedCall cut) {
        boolean usable() {
            return prompt != null && completion != null;
        }
    }

    /**
     * Books one provider response. Reads only its usage report and finish reason; the completion
     * text is not touched. Never raises.
     */
    void record(Completion completion, int chunkIndex, CallKind kind, int limit, long elapsedNanos) {
        Entry entry;
        try {
            entry = entry(completion, chunkIndex, kind, limit);
        } catch (RuntimeException e) {
            // A last-resort net: the readers are total, so reaching this is a bug, and a bug in
            // COUNTING must not fail a document that was otherwise produced correctly.
            LOG.warn("usage_accounting_failed chunk={} call={} error={}", chunkIndex + 1, kind.wire(),
                    e.getClass().getSimpleName());
            entry = new Entry(null, null, 0, null, null, null);
        }
        synchronized (lock) {
            calls++;
            switch (kind) {
                case PASS1 -> pass1Calls++;
                case PASS2 -> pass2Calls++;
                case PASS2_RETRY -> {
                    pass2Calls++;
                    pass2RetryCalls++;
                }
                case REMEDIATION -> remediationCalls++;
                case REMEDIATION_RETRY -> {
                    remediationCalls++;
                    remediationRetryCalls++;
                }
            }
            providerNanos += Math.max(0, elapsedNanos);
            if (entry.usable()) {
                input += entry.prompt();
                output += entry.completion();
                total += entry.total();
                if (entry.cached() != null) {
                    cached += entry.cached();
                    cachedReported = true;
                }
                if (entry.reasoning() != null) {
                    reasoning += entry.reasoning();
                    reasoningReported = true;
                }
            } else {
                missing++;
            }
            if (entry.cut() != null) {
                truncated.add(entry.cut());
            }
        }
    }

    private static Entry entry(Completion completion, int chunkIndex, CallKind kind, int limit) {
        TokenUsage usage = completion.usage();
        Long prompt = usage == null ? null : count(usage.promptTokens());
        Long out = usage == null ? null : count(usage.completionTokens());
        TruncatedCall cut = completion.truncated() ? new TruncatedCall(chunkIndex, kind, out, limit) : null;
        if (prompt == null || out == null) {
            return new Entry(null, null, 0, null, null, cut);
        }
        // The provider's own total when it gave a sane one; the parts otherwise.
        Long reported = count(usage.totalTokens());
        long sum = reported != null && reported >= prompt + out ? reported : prompt + out;
        // Subsets, so a subset larger than its whole is nonsense and is not believed.
        Long cachedPart = count(usage.cachedPromptTokens());
        Long reasoningPart = count(usage.reasoningTokens());
        return new Entry(prompt, out, sum, cachedPart != null && cachedPart <= prompt ? cachedPart : null,
                reasoningPart != null && reasoningPart <= out ? reasoningPart : null, cut);
    }

    /** A reported count, or null when it is not usable as one: NULL IS NOT ZERO. */
    static Long count(Long value) {
        if (value == null || value < 0 || value > MAX_REPORTED_TOKENS) {
            return null;
        }
        return value;
    }

    /** Books one transport attempt that returned no response: its time, and no tokens. */
    void recordFailedAttempt(long elapsedNanos) {
        synchronized (lock) {
            failedAttempts++;
            providerNanos += Math.max(0, elapsedNanos);
        }
    }

    /** Counts how one chunk's pass 1 turned out. */
    void recordPass1(LlmDetector.Pass1Outcome outcome) {
        synchronized (lock) {
            switch (outcome) {
                case SUCCESS -> pass1Success++;
                case PARSE_FAILURE -> pass1ParseFailure++;
                case OUTPUT_TRUNCATED -> pass1OutputTruncated++;
                case PROVIDER_FAILURE -> pass1ProviderFailure++;
            }
        }
    }

    /** Counts how one pass-2 batch (or the empty queue) turned out; {@code retried} when it needed its corrective retry. */
    void recordPass2(Pass2Outcome outcome, boolean retried) {
        synchronized (lock) {
            switch (outcome) {
                case SKIPPED -> pass2Skipped++;
                case EXECUTED -> pass2Executed++;
                case FAILED -> pass2Failed++;
            }
            if (retried) {
                pass2Retried++;
            }
        }
    }

    /** Counts one pass-2 response, and whether it was a usable READING at all. */
    void recordPass2Attempt(boolean complete) {
        synchronized (lock) {
            pass2Attempts++;
            if (!complete) {
                pass2Incomplete++;
            }
        }
    }

    /** Freezes the current totals. */
    public LlmUsage snapshot() {
        synchronized (lock) {
            return new LlmUsage(calls, pass1Calls, pass2Calls, pass2RetryCalls, remediationCalls,
                    remediationRetryCalls, input, cachedReported ? cached : null, output,
                    reasoningReported ? reasoning : null, total, missing, failedAttempts, providerNanos / 1_000_000,
                    truncated, pass1Success, pass1ParseFailure, pass1OutputTruncated, pass2Skipped, pass2Executed,
                    pass2Failed, pass2Retried, pass2Attempts, pass2Incomplete, pass1ProviderFailure);
        }
    }
}
