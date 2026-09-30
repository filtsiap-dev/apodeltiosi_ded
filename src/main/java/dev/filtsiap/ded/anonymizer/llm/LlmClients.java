package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.ProcessEnv;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;

/** Client factory (port of {@code llm/client.build_client}). */
public final class LlmClients {

    private LlmClients() {
    }

    /** An OpenAI client when the provider is openai, an Azure OpenAI client otherwise. */
    public static LlmClient build(RuntimeConfig cfg) {
        if (cfg.provider() == RuntimeConfig.Provider.OPENAI) {
            return OpenAiLlmClient.openAi(cfg.openaiApiKey(), cfg.llmTimeoutS(), ProcessEnv.get("OPENAI_BASE_URL"),
                    ProcessEnv.get("OPENAI_ORG_ID"), ProcessEnv.get("OPENAI_PROJECT_ID"));
        }
        return OpenAiLlmClient.azure(cfg.azureApiKey(), cfg.azureEndpoint(), cfg.azureApiVersion(), cfg.llmTimeoutS());
    }
}
