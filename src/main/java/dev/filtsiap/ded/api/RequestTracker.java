package dev.filtsiap.ded.api;

import dev.filtsiap.ded.anonymizer.RunContext;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * The requests inside the application handler, and the switch that stops admitting more. This
 * is what shutdown waits for: idle keep-alive connections, and exchanges still queued for a
 * worker or still sending their request headers, are not document work and are never waited for.
 *
 * <p>Admission, completion and the start of shutdown share one lock, so a request either entered
 * before shutdown counted it or is refused: none can slip in after the count.
 */
final class RequestTracker {

    private int active;
    private volatile boolean closed;
    private volatile boolean cancelling;
    private int refused;
    /** The threads running the admitted requests: the only ones a cancellation interrupts. */
    private final Set<Thread> inside = new HashSet<>();
    /** The document each admitted request is working on, by its thread: what shutdown reports by request id. */
    private final Map<Thread, RunContext> documents = new HashMap<>();

    /** Admits one request; false once shutdown has begun (the caller refuses it). */
    synchronized boolean enter() {
        if (closed) {
            refused++;
            return false;
        }
        active++;
        inside.add(Thread.currentThread());
        return true;
    }

    /** One admitted request has left the handler, however it left. */
    synchronized void exit() {
        inside.remove(Thread.currentThread());
        active--;
        if (active == 0) {
            notifyAll();
        }
    }

    /** Stops admitting; returns how many requests are inside the handler at that moment. */
    synchronized int close() {
        closed = true;
        return active;
    }

    boolean closed() {
        return closed;
    }

    synchronized int active() {
        return active;
    }

    synchronized int refused() {
        return refused;
    }

    /** Waits until no request is inside the handler or {@code deadlineNanos} passes; true when idle. */
    synchronized boolean awaitIdle(long deadlineNanos) throws InterruptedException {
        while (active > 0) {
            long left = deadlineNanos - System.nanoTime();
            if (left <= 0) {
                return false;
            }
            TimeUnit.NANOSECONDS.timedWait(this, left);
        }
        return true;
    }

    /**
     * The drain window is over: whatever is still running is being cancelled, not failing. The
     * flag is set before the interrupts, so a request that sees one knows why; under the lock, so
     * a thread that has already left (and may be serving another connection) is never hit.
     */
    synchronized void cancel() {
        cancelling = true;
        inside.forEach(Thread::interrupt);
    }

    boolean cancelling() {
        return cancelling;
    }

    /** The calling request's document: from now until {@link #untrackDocument}, shutdown reports it by its ids. */
    synchronized void trackDocument(RunContext document) {
        documents.put(Thread.currentThread(), document);
    }

    /** The calling request's document has ended, however it ended. */
    synchronized void untrackDocument() {
        documents.remove(Thread.currentThread());
    }

    /** The documents still inside the handler right now. */
    synchronized List<RunContext> documentsInFlight() {
        return List.copyOf(documents.values());
    }
}
