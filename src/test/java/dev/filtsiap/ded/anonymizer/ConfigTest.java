package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigTest {

    static Map<String, String> openAiEnv() {
        Map<String, String> env = new HashMap<>();
        env.put("ANON_PROVIDER", "openai");
        env.put("OPENAI_API_KEY", "sk-test");
        env.put("ANON_MODEL", "gpt-test");
        return env;
    }

    @Test
    void defaultsAndOverrides() {
        Map<String, String> env = openAiEnv();
        env.put("ANON_LLM_TIMEOUT_S", " 12.5 ");
        env.put("ANON_CHUNK_SIZE_CHARS", "1_500");
        RuntimeConfig cfg = Config.loadRuntimeConfig(env);
        assertEquals(12.5, cfg.llmTimeoutS());
        assertEquals(1500, cfg.chunkSizeChars());
        assertEquals(RuntimeConfig.DEFAULT_LLM_CONCURRENCY, cfg.llmConcurrency());
        assertEquals("gpt-test", cfg.modelHandle());
    }

    @Test
    void blankApiKeyCountsAsUnset() {
        Map<String, String> env = openAiEnv();
        env.put("ANON_API_KEY", "  \u00a0");
        assertNull(Config.loadRuntimeConfig(env).anonApiKey());
    }

    @Test
    void errorsNameTheVariableNotTheSecret() {
        Map<String, String> env = openAiEnv();
        env.put("ANON_PROVIDER", "gemini");
        assertEquals("ANON_PROVIDER must be 'openai' or 'azure', got 'gemini'",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(env)).getMessage());
        Map<String, String> azure = Map.of("ANON_PROVIDER", "azure");
        assertEquals("AZURE_OPENAI_API_KEY is required when ANON_PROVIDER=azure",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(azure)).getMessage());
        Map<String, String> bad = openAiEnv();
        bad.put("ANON_CHUNK_SIZE_CHARS", "3.5");
        assertEquals("ANON_CHUNK_SIZE_CHARS must be a number, got '3.5'",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(bad)).getMessage());
    }

    @Test
    void repositoryConfigLoads() {
        FileConfig files = Config.loadFileConfig(Path.of("config"));
        assertEquals(0.8, files.policy().preserveHighConfidenceThreshold());
        assertTrue(files.policy().hardRedactCategories().contains("AFM"));
        assertTrue(files.rules().preserveEmailDomains().contains("aade.gr"));
        assertTrue(files.configSha256().matches("[0-9a-f]{64}"));
    }

    @Test
    void missingPolicyIsAConfigurationError(@TempDir Path dir) {
        assertThrows(ConfigurationError.class, () -> Config.loadFileConfig(dir));
    }

    @Test
    void envFileFillsOnlyMissingNames(@TempDir Path dir) throws Exception {
        Path env = dir.resolve(".env");
        Files.writeString(env, "# comment\nexport ANON_TEST_ONLY_A='quoted value'\nANON_TEST_ONLY_B = b\nPATH=/nope\n");
        Config.loadEnvFile(env);
        assertEquals("quoted value", ProcessEnv.get("ANON_TEST_ONLY_A"));
        assertEquals("b", ProcessEnv.get("ANON_TEST_ONLY_B"));
        assertTrue(!"/nope".equals(ProcessEnv.get("PATH"))); // real environment wins
    }
}
