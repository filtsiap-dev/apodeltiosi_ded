package dev.filtsiap.ded.anonymizer.llm;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A simulated provider: no network. A request whose message contains a script's key answers that
 * script, one outcome per attempt: a {@link Completion}, or a {@link RuntimeException} to throw. The
 * last outcome repeats. Any other request answers pass 1 with an empty list. The empty key matches
 * every request.
 */
public final class FlakyLlm implements LlmClient {

    private final Map<String, List<Object>> scripts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> attempts = new ConcurrentHashMap<>();

    public FlakyLlm script(String key, Object... outcomes) {
        scripts.put(key, List.of(outcomes));
        return this;
    }

    /** How many attempts the script for {@code key} has answered so far. */
    public int attempts(String key) {
        AtomicInteger n = attempts.get(key);
        return n == null ? 0 : n.get();
    }

    /** A provider answer of HTTP 429 that asks for {@code retryAfterMs} before the next attempt. */
    public static LlmCallException rateLimited(long retryAfterMs) {
        return LlmCallException.status(429, retryAfterMs, null);
    }

    /** A normally finished, empty pass-1 answer. */
    public static Completion ok() {
        return new Completion("[]", "stop", false);
    }

    @Override
    public Completion complete(ChatRequest request) {
        for (Map.Entry<String, List<Object>> script : scripts.entrySet()) {
            if (request.userMessage().contains(script.getKey())) {
                List<Object> outcomes = script.getValue();
                int attempt = attempts.computeIfAbsent(script.getKey(), k -> new AtomicInteger()).getAndIncrement();
                Object outcome = outcomes.get(Math.min(attempt, outcomes.size() - 1));
                if (outcome instanceof RuntimeException failure) {
                    throw failure;
                }
                return (Completion) outcome;
            }
        }
        return ok();
    }

    @Override
    public void close() {
    }
}
