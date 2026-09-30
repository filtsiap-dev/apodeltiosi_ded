package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/** In-process stand-in for a model: answers are computed from the request. Records every request. */
public final class ScriptedLlm implements LlmClient {

    public final List<ChatRequest> requests = new CopyOnWriteArrayList<>();
    private final Function<ChatRequest, String> answer;

    public ScriptedLlm(Function<ChatRequest, String> answer) {
        this.answer = answer;
    }

    @Override
    public String complete(ChatRequest request) {
        requests.add(request);
        return answer.apply(request);
    }

    @Override
    public void close() {
    }

    public static boolean isPass1(ChatRequest r) {
        return r.systemPrompt().equals(Prompts.SYSTEM_PROMPT_PASS1);
    }

    /** The known spans sent in a pass-2 message. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> knownSpans(ChatRequest r) {
        String json = r.userMessage().split("emit a final decision for every entry\\):\n", 2)[1];
        json = json.split("\n\nYOUR PREVIOUS RESPONSE WAS REJECTED", 2)[0];
        try {
            return (List<Map<String, Object>>) PyJson.loads(json);
        } catch (PyJson.JsonDecodeError e) {
            throw new IllegalStateException(e);
        }
    }

    /** A cooperative model: nothing new in pass 1; pass 2 confirms every known span, REVIEW becoming REDACT. */
    public static ScriptedLlm cooperative() {
        return new ScriptedLlm(r -> {
            if (isPass1(r)) {
                return "[]";
            }
            List<Object> out = new ArrayList<>();
            for (Map<String, Object> ks : knownSpans(r)) {
                String action = ks.get("action").equals("REVIEW") ? "REDACT" : (String) ks.get("action");
                out.add(Map.of("text", ks.get("text"), "category", ks.get("category"), "action", action));
            }
            return PyJson.dumps(out);
        });
    }
}
