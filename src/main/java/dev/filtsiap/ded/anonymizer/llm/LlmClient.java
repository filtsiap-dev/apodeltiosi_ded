package dev.filtsiap.ded.anonymizer.llm;

import java.util.Set;

/**
 * One chat-completion call (the only thing the detector needs from a provider).
 *
 * <p>Makes exactly the call it is asked for: implementations do not retry. Retries belong to
 * {@link LlmDetector}, so every one is logged and counted and two layers cannot multiply.
 * Implementations are thread-safe: chunks call it concurrently.
 */
public interface LlmClient extends AutoCloseable {

    /**
     * A request, exactly as Python sends it: one system and one user message.
     *
     * @param timeoutSeconds the per-phase timeout for THIS call: the configured one, or less when
     *                       the document's remaining budget is shorter
     */
    record ChatRequest(String model, String systemPrompt, String userMessage, int maxCompletionTokens,
                       double timeoutSeconds) {
    }

    /**
     * The token counts a provider reported for one response, exactly as reported: each one null
     * when the response did not carry it. Counts only, never text. Validated where they are added
     * up ({@link UsageRecorder}), not here, so a nonsensical report is still visible as one.
     *
     * <p>OpenAI semantics: {@code cachedPromptTokens} is the part of {@code promptTokens} served
     * from the prompt cache, and {@code reasoningTokens} the part of {@code completionTokens} spent
     * reasoning. Both are SUBSETS, never additions.
     */
    record TokenUsage(Long promptTokens, Long completionTokens, Long totalTokens, Long cachedPromptTokens,
                      Long reasoningTokens) {
    }

    /**
     * One provider response, reduced to what a caller judges it by (port of {@code Completion}).
     * {@code finishReason} and {@code refused} are the difference between a short answer and a
     * truncated one, which nothing in the body can tell: a decision list cut off at the token
     * ceiling looks exactly like a complete list of fewer decisions.
     *
     * @param text         the first choice's content, or "" when there was none
     * @param finishReason the provider's own word for why it stopped, or null when it gave none
     * @param refused      whether the model returned an explicit refusal instead of an answer
     * @param usage        the provider's token report for this response, or null when it sent none
     */
    record Completion(String text, String finishReason, boolean refused, TokenUsage usage) {

        /** Reasons meaning the model said all it meant to. null counts as complete; an unknown one does not. */
        private static final Set<String> COMPLETE_FINISH_REASONS = Set.of("stop");

        public Completion {
            text = text == null ? "" : text;
        }

        /** A response that reported no token usage. */
        public Completion(String text, String finishReason, boolean refused) {
            this(text, finishReason, refused, null);
        }

        /** The provider stopped at the output-token ceiling. */
        public boolean truncated() {
            return "length".equals(finishReason);
        }

        /** A content filter or an explicit refusal cut the answer short. */
        public boolean filtered() {
            return refused || "content_filter".equals(finishReason);
        }

        /** Whether this body is the whole of what the model meant to say. */
        public boolean complete() {
            return !refused && (finishReason == null || COMPLETE_FINISH_REASONS.contains(finishReason));
        }

        /** A counts-only phrase naming why this is not a complete answer; null when it is one. */
        public String problem() {
            if (complete()) {
                return null;
            }
            if (truncated()) {
                return "the completion stopped at the output-token limit (finish_reason=length)";
            }
            if (refused) {
                return "the model returned a refusal instead of an answer";
            }
            if (filtered()) {
                return "the completion was cut short by a content filter (finish_reason=content_filter)";
            }
            return "the completion did not finish normally (finish_reason=" + finishReason + ")";
        }
    }

    /**
     * Makes one request.
     *
     * @throws LlmCallException for transport and provider failures, classified like the
     *                          Python SDK's exception types
     */
    Completion complete(ChatRequest request);

    /** Releases connections. No checked exception. */
    @Override
    void close();
}
