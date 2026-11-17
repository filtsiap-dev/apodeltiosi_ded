package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/** In-process stand-in for a model: answers are computed from the request. Records every request. */
public final class ScriptedLlm implements LlmClient {

    public final List<ChatRequest> requests = new CopyOnWriteArrayList<>();
    private final Function<ChatRequest, Completion> answer;

    /** A model whose every answer is a normally finished body. */
    public ScriptedLlm(Function<ChatRequest, String> text) {
        this(text, null);
    }

    private ScriptedLlm(Function<ChatRequest, String> text, Function<ChatRequest, Completion> full) {
        this.answer = full != null ? full : r -> finished(text.apply(r));
    }

    /** A body the provider finished normally. */
    public static Completion finished(String text) {
        return new Completion(text, "stop", false);
    }

    /** A body the provider finished normally, with the token usage it reported for it. */
    public static Completion finished(String text, TokenUsage usage) {
        return new Completion(text, "stop", false, usage);
    }

    /** A usage report of {@code prompt} input and {@code completion} output tokens, nothing cached or reasoned. */
    public static TokenUsage usage(long prompt, long completion) {
        return new TokenUsage(prompt, completion, prompt + completion, null, null);
    }

    /**
     * The same model, but every answer carries a synthetic usage report: {@code usage} decides it
     * from the request (pass 1, pass 2, retry, remediation all look different).
     */
    public static ScriptedLlm reporting(ScriptedLlm model, java.util.function.Function<ChatRequest, TokenUsage> usage) {
        return completions(r -> {
            Completion c = model.answer.apply(r);
            return new Completion(c.text(), c.finishReason(), c.refused(), usage.apply(r));
        });
    }

    /** A model that also controls finish reason and refusal (or throws a provider failure). */
    public static ScriptedLlm completions(Function<ChatRequest, Completion> answer) {
        return new ScriptedLlm(null, answer);
    }

    @Override
    public Completion complete(ChatRequest request) {
        requests.add(request);
        return answer.apply(request);
    }

    @Override
    public void close() {
    }

    public static boolean isPass1(ChatRequest r) {
        return r.systemPrompt().equals(Prompts.SYSTEM_PROMPT_PASS1);
    }

    /** A pass-2 call (first or retry) of the post-redaction remediation: its one instruction line. */
    public static boolean isRemediation(ChatRequest r) {
        return r.userMessage().contains("from a document that has ALREADY been redacted once");
    }

    public static boolean isRetry(ChatRequest r) {
        return r.userMessage().contains("\n\nYOUR PREVIOUS RESPONSE WAS REJECTED: ");
    }

    /** The CANDIDATES array sent in a pass-2 message. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> candidates(ChatRequest r) {
        String json = r.userMessage().split("\n\nCANDIDATES:\n", 2)[1];
        json = json.split("\n\nYOUR PREVIOUS RESPONSE WAS REJECTED", 2)[0];
        try {
            return (List<Map<String, Object>>) PyJson.loads(json);
        } catch (PyJson.JsonDecodeError e) {
            throw new IllegalStateException(e);
        }
    }

    /** The ids asked about in a pass-2 message, in order. */
    public static List<String> candidateIds(ChatRequest r) {
        return candidates(r).stream().map(c -> (String) c.get("id")).toList();
    }

    /** One pass-2 answer entry. */
    public static Map<String, Object> answer(String id, String action, String category) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("action", action);
        m.put("category", category);
        return m;
    }

    /** One pass-2 NEW finding. */
    public static Map<String, Object> newFinding(String text, String action, String category) {
        Map<String, Object> m = answer("NEW", action, category);
        m.put("text", text);
        return m;
    }

    /**
     * A cooperative model: nothing new in pass 1; pass 2 decides every candidate by id with its
     * first recommendation (REVIEW becoming REDACT, a missing category becoming POSSIBLE_PERSON).
     */
    public static ScriptedLlm cooperative() {
        return new ScriptedLlm(r -> isPass1(r) ? "[]" : PyJson.dumps(agreeWithEveryCandidate(r)));
    }

    @SuppressWarnings("unchecked")
    public static List<Object> agreeWithEveryCandidate(ChatRequest r) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> c : candidates(r)) {
            Map<String, Object> first = ((List<Map<String, Object>>) c.get("recommendations")).get(0);
            String action = first.get("action").equals("REVIEW") ? "REDACT" : (String) first.get("action");
            String category = first.get("category") == null ? "POSSIBLE_PERSON" : (String) first.get("category");
            out.add(answer((String) c.get("id"), action, category));
        }
        return out;
    }
}
