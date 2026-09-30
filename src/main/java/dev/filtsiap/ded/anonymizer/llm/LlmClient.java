package dev.filtsiap.ded.anonymizer.llm;

/**
 * One chat-completion call (the only thing the detector needs from a provider).
 *
 * <p>This interface is the record/replay seam for differential verification: tests replay
 * recorded Python responses through it, keyed by (chunk index, pass, attempt), so the Java
 * detector can be diffed against Python without a live, non-deterministic model.
 * Implementations are thread-safe: chunks call it concurrently.
 */
public interface LlmClient extends AutoCloseable {

    /** A request, exactly as Python sends it: one system and one user message. */
    record ChatRequest(String model, String systemPrompt, String userMessage, int maxCompletionTokens) {
    }

    /**
     * Returns the first choice's message content, or null when the provider returned none.
     *
     * @throws LlmCallException for transport and provider failures, classified like the
     *                          Python SDK's exception types
     */
    String complete(ChatRequest request);

    /** Releases connections. No checked exception. */
    @Override
    void close();
}
