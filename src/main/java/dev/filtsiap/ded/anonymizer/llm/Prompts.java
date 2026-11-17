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
 * <p>Every excerpt and every context window is taken from the MASKED view: the rule engine's hard
 * redactions are already runs of dots in it. Pass 1 is discovery: the masked excerpt only. Pass 2
 * is final adjudication of a candidate queue and nothing else: one JSON array of candidates, each
 * with a transient id, its exact text, every source's recommendation and up to 40 code points of
 * context either side; never the excerpt. Payloads are serialized with {@link PyJson#dumps},
 * which reproduces Python's {@code json.dumps(..., ensure_ascii=False)} byte for byte.
 */
public final class Prompts {

    /** Pass-1 system prompt. */
    public static final String SYSTEM_PROMPT_PASS1 = PromptText.SYSTEM_PROMPT_PASS1;
    /** Adjudicating pass-2 system prompt. */
    public static final String SYSTEM_PROMPT_PASS2 = PromptText.SYSTEM_PROMPT_PASS2;

    /** Provenance: sha256 over the two system prompts. The retry builders do not change it. */
    public static final String PROMPTS_SHA256 = sha256Hex(SYSTEM_PROMPT_PASS1 + SYSTEM_PROMPT_PASS2);

    private Prompts() {
    }

    /** The pass-1 user message: the masked excerpt and nothing else. */
    public static String buildPass1Message(String chunkText) {
        return "DOCUMENT EXCERPT:\n" + chunkText;
    }

    /**
     * The single corrective pass-1 message, after a completed response that could not be used: the
     * same masked excerpt, and one machine-written line asking for a complete answer in the same
     * schema. {@code problem} is a machine-written phrase, never model or document text.
     */
    public static String buildPass1RetryMessage(String chunkText, String problem) {
        return buildPass1Message(chunkText) + "\n\nYOUR PREVIOUS RESPONSE COULD NOT BE USED: " + problem + ".\n"
                + "Return the complete JSON array in the schema above — valid JSON, no markdown, no prose.";
    }

    /**
     * The pass-2 user message: one instruction line, then the candidate queue, so the message ENDS
     * with the payload. There is no excerpt: the candidates and their context windows are all pass 2
     * is shown. It is never built for an empty queue.
     *
     * <p>{@code remediation} says this is the post-redaction re-ask: the candidates come from the
     * ALREADY-REDACTED document and are what its audit found still visible. Only the instruction
     * line changes (same system prompt, same payload, same rules); the one thing the model could
     * not work out for itself is that the runs of dots are earlier redactions.
     */
    public static String buildPass2Message(List<Map<String, Object>> candidates, boolean remediation) {
        String instruction;
        if (remediation) {
            instruction = "These candidates are from a document that has ALREADY been redacted once: every run "
                    + "of dots in their text or context is text that was removed, not text that is missing. They "
                    + "are what the post-redaction audit found still visible and thinks may be personal data that "
                    + "should have gone. Return one decision for every candidate id below, and no other entries.";
        } else {
            instruction = "Return one decision for every candidate id below, and no other entries.";
        }
        return instruction + "\n\nCANDIDATES:\n" + PyJson.dumps(candidates);
    }

    /**
     * The single pass-2 retry message. {@code candidates} is the re-asked subset (the whole queue
     * when {@code keptPrevious} is false). {@code reason} and {@code rejections} are machine-written
     * phrases, never model or document text. A correction to a remediation call is still a
     * remediation call.
     *
     * <p>It says what {@code Pass2Queue.validate} and the corrective retry really did, and nothing
     * stricter: with {@code keptPrevious}, each rejected entry cost only its own candidate (re-asked
     * here) and every usable answer was kept; without it, rejections are only ever present when an
     * entry showed the response was not tracking the list (an id not in CANDIDATES, no id, not an
     * object), which is the one thing that sets a whole response aside.
     */
    public static String buildPass2RetryMessage(List<Map<String, Object>> candidates, List<String> rejections,
                                                String reason, boolean keptPrevious, boolean remediation) {
        List<String> lines = new ArrayList<>(List.of(
                buildPass2Message(candidates, remediation),
                "",
                "YOUR PREVIOUS RESPONSE WAS REJECTED: " + reason + ".",
                ""));
        if (keptPrevious) {
            lines.addAll(List.of(
                    "This is a correction, not a fresh start. The candidates above are the ONLY",
                    "ones still outstanding — anything you already decided correctly has been kept",
                    "and must NOT be sent again. Decide every id listed above, and no others."));
        } else {
            lines.addAll(List.of(
                    "Nothing from your previous response could be kept, so the whole queue is",
                    "above again. Decide every id listed there, and no others."));
        }
        lines.add("Return a JSON array — valid JSON, no markdown, no prose.");
        if (!rejections.isEmpty()) {
            lines.add("");
            lines.add(keptPrevious
                    ? "These entries could not be used, so only the candidates they were about are asked again; do "
                    + "not repeat them:"
                    : "These entries could not be used. An id that is not in CANDIDATES, an entry with no id, or one "
                    + "that is not an object means the response was not tracking the list, so none of it was kept; do "
                    + "not repeat them:");
            lines.add(PyJson.dumps(rejections));
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
