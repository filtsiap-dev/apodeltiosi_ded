package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.llm.UsageRecorder;
import java.util.UUID;
import java.util.function.LongSupplier;

/**
 * Who is asking, how long they have, and what their document has cost (port of
 * {@code deadline.RunContext}). Threaded explicitly through the pipeline; the ids go into the
 * MESSAGE of each log line.
 *
 * <p>Both ids are generated, never derived from input: a filename is chosen by whoever sent the
 * document and can contain someone's name, and correlation ids end up in every log line.
 *
 * <p>{@code usage} is the document's own LLM ledger (v2 creates it in {@code anonymize_document};
 * here it is created with the context, which has exactly the same per-document scope). Living on
 * the context is what lets the caller that started the document read what it cost even when it
 * FAILED: a document that ran out of time after six provider calls still spent them.
 */
public record RunContext(Deadline deadline, String requestId, String documentId, UsageRecorder usage,
                         RequestProgress progress) {

    /** Begins a document's budget now on the monotonic clock, with fresh ids. */
    public static RunContext start(double seconds) {
        return start(seconds, null, System::nanoTime);
    }

    /** Begins a budget now; {@code documentId} null means a fresh one. */
    public static RunContext start(double seconds, String documentId, LongSupplier clock) {
        return new RunContext(Deadline.after(seconds, clock), hex(16), documentId != null ? documentId : hex(12),
                new UsageRecorder(), new RequestProgress());
    }

    private static String hex(int length) {
        return UUID.randomUUID().toString().replace("-", "").substring(0, length);
    }

    /** The correlation fields, ready to append to a log message. */
    public String tag() {
        return "request_id=" + requestId + " document_id=" + documentId;
    }

    /** The same, plus which chunk (counted from 1), pass and attempt. */
    public String chunkTag(int chunkIndex, int passNumber, String attempt) {
        return tag() + " chunk=" + (chunkIndex + 1) + " pass=" + passNumber + " attempt=" + attempt;
    }
}
