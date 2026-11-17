package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.ProcessEnv;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;

/** Client factory (port of {@code llm/client.build_client}). */
public final class LlmClients {

    private LlmClients() {
    }

    /**
     * An OpenAI or Azure OpenAI client for those providers; in regex mode, one that refuses every call.
     * A configured context window is checked here, at startup ({@link LlmDetector#checkContextLimit}).
     */
    public static LlmClient build(RuntimeConfig cfg) {
        LlmDetector.checkContextLimit(cfg);
        return switch (cfg.provider()) {
            case OPENAI -> OpenAiLlmClient.openAi(cfg.openaiApiKey(), cfg.llmTimeoutS(),
                    ProcessEnv.get("OPENAI_BASE_URL"), ProcessEnv.get("OPENAI_ORG_ID"),
                    ProcessEnv.get("OPENAI_PROJECT_ID"));
            case AZURE -> OpenAiLlmClient.azure(cfg.azureApiKey(), cfg.azureEndpoint(), cfg.azureApiVersion(),
                    cfg.llmTimeoutS());
            case REGEX -> new RegexModeLlmClient();
        };
    }
}
