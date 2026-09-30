package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Prompt layer for the two-pass LLM stage (port of {@code llm/prompts.py}).
 *
 * <p>Pass 1 is blind: the raw excerpt only. Pass 2 is informed validation: the excerpt plus
 * every known span. Known spans are serialized with {@link PyJson#dumps}, which reproduces
 * Python's {@code json.dumps(..., ensure_ascii=False)} byte for byte, so the model receives the
 * same prompt from either implementation.
 */
public final class Prompts {

    /** Blind pass-1 system prompt. */
    public static final String SYSTEM_PROMPT_PASS1 = PromptText.SYSTEM_PROMPT_PASS1;
    /** Informed pass-2 system prompt. */
    public static final String SYSTEM_PROMPT_PASS2 = PromptText.SYSTEM_PROMPT_PASS2;

    /** Provenance: sha256 over the two system prompts. The retry builder does not change it. */
    public static final String PROMPTS_SHA256 = sha256Hex(SYSTEM_PROMPT_PASS1 + SYSTEM_PROMPT_PASS2);

    private Prompts() {
    }

    /** The pass-1 user message: the raw excerpt and nothing else. */
    public static String buildPass1Message(String chunkText) {
        return "DOCUMENT EXCERPT:\n" + chunkText;
    }

    /**
     * The pass-2 user message: the excerpt plus all known spans, each shaped
     * {@code {"text", "category", "action", "context"}}.
     */
    public static String buildPass2Message(String chunkText, List<Map<String, Object>> knownSpans) {
        return "DOCUMENT EXCERPT:\n" + chunkText + "\n\n"
                + "KNOWN SPANS (deterministic detections + your first-pass proposals; "
                + "context, not binding — emit a final decision for every entry):\n"
                + PyJson.dumps(knownSpans);
    }

    /**
     * The single pass-2 retry message: the original message, the rejection reason (a
     * machine-written phrase, never model text) and the verbatim texts still undecided.
     */
    public static String buildPass2RetryMessage(String chunkText, List<Map<String, Object>> knownSpans,
                                                List<String> unresolved, String reason) {
        List<String> lines = new ArrayList<>(List.of(
                buildPass2Message(chunkText, knownSpans),
                "",
                "YOUR PREVIOUS RESPONSE WAS REJECTED: " + reason + ".",
                "Return the complete JSON array again — valid JSON, no markdown, no prose."));
        if (!unresolved.isEmpty()) {
            lines.addAll(List.of(
                    "",
                    "These KNOWN SPANS entries still have NO final decision. Each one MUST",
                    "appear in your response with \"action\" set to REDACT or PRESERVE "
                            + "(REVIEW and SKIP are not decisions for these):",
                    PyJson.dumps(unresolved)));
        }
        return String.join("\n", lines);
    }

    static String sha256Hex(String text) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
