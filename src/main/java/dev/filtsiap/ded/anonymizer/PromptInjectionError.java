package dev.filtsiap.ded.anonymizer;

/**
 * The document carries text shaped like an instruction to the model (port of
 * {@code PromptInjectionError}). Deterministic, pattern-based and deliberately narrow; see
 * {@link InjectionScreen}. The message names the rule that matched and where, never the text that
 * matched: echoing that back would hand the attempt straight into the logs.
 */
public class PromptInjectionError extends AnonymizerError {
    private static final long serialVersionUID = 1L;

    public PromptInjectionError(String message) {
        super(message, "PROMPT_INJECTION_DETECTED", null);
    }

    @Override
    public String publicDetail() {
        return "the document contains content matching a prompt-injection pattern and was refused";
    }

    @Override
    public String outcome() {
        return "prompt_injection";
    }
}
