package dev.filtsiap.ded.anonymizer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * How far one document's LLM stage got, and which provider failure to name when it did not finish:
 * the pass-1 chunks completed out of the chunks it has, and the provider failures no later success
 * has answered. Chunks run on several workers, so every method is synchronized.
 *
 * <p>Counts, positions (1-based chunk and pass), and classification labels only. Never a provider
 * message, a response body or document text.
 */
public final class RequestProgress {

    /**
     * One provider failure: where it happened and how it was classified.
     *
     * @param label      the classification ({@code rate_limited}, {@code timeout}, {@code http_500} ...)
     * @param httpStatus the HTTP status, or null when the failure had none
     * @param recovered  whether a later attempt for the same chunk and pass succeeded
     */
    public record Failure(int chunk, int pass, String label, Integer httpStatus, boolean recovered) {
    }

    /**
     * The progress as the final log line reads it. {@code failure} is the most recent failure that
     * never recovered, else the most recent failure at all (recovered), else null.
     */
    public record Snapshot(int chunksCompleted, int chunksTotal, Failure failure) {
    }

    private int chunksTotal;
    private int chunksCompleted;
    private Failure last;
    /** Failures no later success has answered, oldest first: the key is {@code chunk/pass}. */
    private final Map<String, Failure> unrecovered = new LinkedHashMap<>();

    /** The number of pass-1 chunks the document was split into. */
    public synchronized void chunksStarted(int total) {
        chunksTotal = total;
    }

    /** One pass-1 chunk finished (its discovery and routing, whatever their outcome). */
    public synchronized void chunkCompleted() {
        chunksCompleted++;
    }

    /** One provider attempt failed. */
    public synchronized void providerFailed(int chunk, int pass, String label, Integer httpStatus) {
        Failure failure = new Failure(chunk, pass, label, httpStatus, false);
        last = failure;
        String key = key(chunk, pass);
        unrecovered.remove(key);
        unrecovered.put(key, failure); // moved to the end: most recent last
    }

    /** A provider call for this chunk and pass succeeded after one or more failed attempts. */
    public synchronized void providerRecovered(int chunk, int pass) {
        unrecovered.remove(key(chunk, pass));
        if (last != null && last.chunk() == chunk && last.pass() == pass) {
            last = new Failure(chunk, pass, last.label(), last.httpStatus(), true);
        }
    }

    public synchronized Snapshot snapshot() {
        Failure report = null;
        for (Failure f : unrecovered.values()) {
            report = f;
        }
        return new Snapshot(chunksCompleted, chunksTotal, report != null ? report : last);
    }

    private static String key(int chunk, int pass) {
        return chunk + "/" + pass;
    }
}
