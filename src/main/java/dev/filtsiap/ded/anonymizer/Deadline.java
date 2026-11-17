package dev.filtsiap.ded.anonymizer;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/**
 * How much of a document's budget is left, and whether it has been spent (port of
 * {@code deadline.Deadline}).
 *
 * <p>Backed by a monotonic nanosecond clock ({@link System#nanoTime()}), so a wall-clock
 * adjustment mid-document can neither extend nor collapse the budget. The clock is injectable
 * because a test that really waited five minutes would prove nothing a fake one does not.
 *
 * <p>This is cooperative: a check cannot interrupt work already running, but it guarantees that
 * no NEW stage begins on a document that has run out of time, including the stage that would
 * have produced the output. A provider call already in flight ends at its own timeout, which is
 * itself cut to the remaining budget ({@link #budget}).
 */
public final class Deadline {

    /** Below this, there is no point starting a provider call: it would be cut off before answering. */
    public static final double MIN_ATTEMPT_BUDGET_S = 1.0;

    private final long expiresAtNanos;
    private final long startedAtNanos;
    private final LongSupplier clock;
    private final AtomicBoolean cancelled = new AtomicBoolean();

    private Deadline(long startedAtNanos, long expiresAtNanos, LongSupplier clock) {
        this.startedAtNanos = startedAtNanos;
        this.expiresAtNanos = expiresAtNanos;
        this.clock = clock;
    }

    /** A budget of {@code seconds} starting now, on {@code clock} (nanoseconds). */
    public static Deadline after(double seconds, LongSupplier clock) {
        long started = clock.getAsLong();
        return new Deadline(started, started + (long) (seconds * 1e9), clock);
    }

    /** Elapsed since the document began, including upload/input reading before the pipeline. */
    public long elapsedMillis() {
        return Math.max(0L, clock.getAsLong() - startedAtNanos) / 1_000_000;
    }

    /** Seconds left, never negative. */
    public double remaining() {
        return Math.max(0.0, (expiresAtNanos - clock.getAsLong()) / 1e9);
    }

    public boolean expired() {
        return remaining() <= 0.0;
    }

    /**
     * The last stage name a boundary or a provider attempt gave this document: where processing was
     * when it stopped, for the document's final log line. A name from this code, never document text.
     */
    private volatile String lastStage = "accept";

    /** Raises {@link DocumentTimeoutError} if the budget is gone. Called at every stage boundary. */
    public void check(String stage) {
        lastStage = stage;
        if (expired()) {
            throw new DocumentTimeoutError(stage);
        }
    }

    /** The stage most recently begun on this document (see {@link #check} and {@link #budget}). */
    public String lastStage() {
        return lastStage;
    }

    /**
     * The timeout to give one blocking operation: {@code cap}, or less. Raises when no more than
     * {@link #MIN_ATTEMPT_BUDGET_S} remains, since starting a call that cannot finish spends a
     * round trip to learn what the clock already knew.
     */
    public double budget(double cap, String stage) {
        lastStage = stage;
        double left = remaining();
        if (left <= MIN_ATTEMPT_BUDGET_S) {
            throw new DocumentTimeoutError(stage);
        }
        return Math.min(cap, left);
    }

    /** Tells every worker to stop at its next checkpoint. */
    public void cancel() {
        cancelled.set(true);
    }

    public boolean cancelled() {
        return cancelled.get();
    }

    /** Out of time or told to stop: what a worker actually asks. */
    public boolean done() {
        return cancelled() || expired();
    }
}
