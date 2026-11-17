package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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
    void tokenPricesAreOptionalDecimalsReadAtRuntimeNeverBuiltIn() {
        // Nothing configured: no price, and the currency defaults to USD.
        assertEquals(LlmPricing.UNSET, Config.loadRuntimeConfig(openAiEnv()).pricing());
        assertTrue(!LlmPricing.UNSET.configured());

        Map<String, String> env = openAiEnv();
        env.put("ANON_INPUT_COST_PER_1M_TOKENS", " 0.15 ");
        env.put("ANON_OUTPUT_COST_PER_1M_TOKENS", "0.6");
        env.put("ANON_CACHED_INPUT_COST_PER_1M_TOKENS", "0.075");
        env.put("ANON_COST_CURRENCY", "eur");
        LlmPricing p = Config.loadRuntimeConfig(env).pricing();
        assertEquals(new java.math.BigDecimal("0.15"), p.inputPerMillion()); // decimal, as written
        assertEquals(new java.math.BigDecimal("0.075"), p.cachedInputPerMillion());
        assertEquals("EUR", p.currency());
        assertTrue(p.configured());

        env.remove("ANON_CACHED_INPUT_COST_PER_1M_TOKENS");
        env.put("ANON_INPUT_COST_PER_1M_TOKENS", "0"); // a free model is a price, not an absent one
        assertTrue(Config.loadRuntimeConfig(env).pricing().configured());
    }

    @Test
    void aHalfOrMalformedPriceIsAConfigurationError() {
        Map<String, String> onlyInput = openAiEnv();
        onlyInput.put("ANON_INPUT_COST_PER_1M_TOKENS", "0.15");
        assertEquals("ANON_INPUT_COST_PER_1M_TOKENS and ANON_OUTPUT_COST_PER_1M_TOKENS must be set together (one of "
                + "them alone prices only part of every call)",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(onlyInput)).getMessage());
        Map<String, String> onlyCached = openAiEnv();
        onlyCached.put("ANON_CACHED_INPUT_COST_PER_1M_TOKENS", "0.01");
        assertTrue(assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(onlyCached)).getMessage()
                .startsWith("ANON_CACHED_INPUT_COST_PER_1M_TOKENS needs "));
        for (Map.Entry<String, String> bad : Map.of("abc", "ANON_INPUT_COST_PER_1M_TOKENS must be a decimal number, "
                + "got 'abc'", "NaN", "ANON_INPUT_COST_PER_1M_TOKENS must be a decimal number, got 'NaN'", "-1",
                "ANON_INPUT_COST_PER_1M_TOKENS must not be negative, got '-1'", "1e7",
                "ANON_INPUT_COST_PER_1M_TOKENS must be at most 1000000 (a price per 1M tokens), got '1e7'").entrySet()) {
            Map<String, String> env = openAiEnv();
            env.put("ANON_INPUT_COST_PER_1M_TOKENS", bad.getKey());
            env.put("ANON_OUTPUT_COST_PER_1M_TOKENS", "1");
            assertEquals(bad.getValue(), assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(env))
                    .getMessage());
        }
        Map<String, String> currency = openAiEnv();
        currency.put("ANON_COST_CURRENCY", "dollars");
        assertEquals("ANON_COST_CURRENCY must be a three-letter ISO 4217 code such as USD or EUR, got 'dollars'",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(currency)).getMessage());
    }

    @Test
    void regexModeNeedsNoModelSettings() {
        RuntimeConfig cfg = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "regex"));
        assertEquals(RuntimeConfig.Provider.REGEX, cfg.provider());
        assertNull(cfg.modelHandle());
        assertNull(cfg.openaiApiKey());
        assertNull(cfg.azureApiKey());
        assertEquals("RuntimeConfig[provider=regex, model=null]", cfg.toString());
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
        assertEquals("ANON_PROVIDER must be 'openai', 'azure' or 'regex', got 'gemini'",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(env)).getMessage());
        Map<String, String> azure = Map.of("ANON_PROVIDER", "azure");
        assertEquals("AZURE_OPENAI_API_KEY is required when ANON_PROVIDER=azure (it is unset or contains only whitespace)",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(azure)).getMessage());
        Map<String, String> bad = openAiEnv();
        bad.put("ANON_CHUNK_SIZE_CHARS", "3.5");
        assertEquals("ANON_CHUNK_SIZE_CHARS must be a number, got '3.5'",
                assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(bad)).getMessage());
    }

    static Map<String, String> with(String... pairs) {
        Map<String, String> env = openAiEnv();
        for (int i = 0; i < pairs.length; i += 2) {
            env.put(pairs[i], pairs[i + 1]);
        }
        return env;
    }

    static String refused(Map<String, String> env) {
        return assertThrows(ConfigurationError.class, () -> Config.loadRuntimeConfig(env)).getMessage();
    }

    @Test
    void secretsAreStrippedAndAWhitespaceSecretIsUnset() {
        assertEquals("OPENAI_API_KEY is required when ANON_PROVIDER=openai (it is unset or contains only whitespace)",
                refused(with("OPENAI_API_KEY", " \t ")));
        assertEquals("sk-test", Config.loadRuntimeConfig(with("OPENAI_API_KEY", "  sk-test\n")).openaiApiKey());
    }

    @Test
    void numbersMustBeFinitePositiveAndBounded() {
        assertEquals("ANON_LLM_TIMEOUT_S must be greater than zero, got 0.0", refused(with("ANON_LLM_TIMEOUT_S", "0")));
        assertEquals("ANON_LLM_TIMEOUT_S must be greater than zero, got -5.0", refused(with("ANON_LLM_TIMEOUT_S", "-5")));
        assertEquals("ANON_LLM_TIMEOUT_S must be a finite number, got nan", refused(with("ANON_LLM_TIMEOUT_S", "NaN")));
        assertEquals("ANON_LLM_TIMEOUT_S must be a finite number, got inf", refused(with("ANON_LLM_TIMEOUT_S", "inf")));
        assertEquals("ANON_LLM_TIMEOUT_S must be a finite number, got inf", refused(with("ANON_LLM_TIMEOUT_S", "1e400")));
        assertEquals("ANON_LLM_TIMEOUT_S must be at most 3600, got 3600.5", refused(with("ANON_LLM_TIMEOUT_S", "3600.5")));
        assertEquals(3600.0, Config.loadRuntimeConfig(with("ANON_LLM_TIMEOUT_S", "3600")).llmTimeoutS());
        assertEquals("ANON_LLM_CONCURRENCY must be greater than zero, got -1", refused(with("ANON_LLM_CONCURRENCY", "-1")));
        assertEquals("ANON_LLM_CONCURRENCY must be greater than zero, got 0", refused(with("ANON_LLM_CONCURRENCY", "0")));
        assertEquals("ANON_LLM_CONCURRENCY must be at most 64, got 65", refused(with("ANON_LLM_CONCURRENCY", "65")));
        assertEquals(64, Config.loadRuntimeConfig(with("ANON_LLM_CONCURRENCY", "64")).llmConcurrency());
        assertEquals("ANON_CHUNK_SIZE_CHARS must be at most 200000, got 200001",
                refused(with("ANON_CHUNK_SIZE_CHARS", "200001")));
        assertEquals("ANON_MAX_COMPLETION_TOKENS must be at most 1e+06, got 1000001",
                refused(with("ANON_MAX_COMPLETION_TOKENS", "1000001")));
    }

    @Test
    void theDocumentDeadlineDefaultsToFiveMinutesAndIsBounded() {
        assertEquals(300.0, Config.loadRuntimeConfig(openAiEnv()).documentDeadlineS());
        assertEquals(12.5, Config.loadRuntimeConfig(with("ANON_DOCUMENT_DEADLINE_S", "12.5")).documentDeadlineS());
        assertEquals("ANON_DOCUMENT_DEADLINE_S must be greater than zero, got 0.0",
                refused(with("ANON_DOCUMENT_DEADLINE_S", "0")));
        assertEquals("ANON_DOCUMENT_DEADLINE_S must be at most 86400, got 86401.0",
                refused(with("ANON_DOCUMENT_DEADLINE_S", "86401")));
    }

    @Test
    void theResourceLimitsDefaultToV2sValues() {
        assertEquals(new ResourceLimits(20_000_000L, 500L, 25_000_000L, 60_000_000L, 50.0, 1_000_000L, 400_000L, 150L, 10_000_000L, 0L),
                Config.loadRuntimeConfig(openAiEnv()).limits());
        assertEquals(1_048_576L, Config.loadRuntimeConfig(with("ANON_MAX_UPLOAD_BYTES", "1048576")).limits()
                .maxUploadBytes());
        // The retired name is not read, as in v2: an upload limit is bytes, not mebibytes.
        assertEquals(20_000_000L, Config.loadRuntimeConfig(with("ANON_MAX_UPLOAD_MB", "1")).limits().maxUploadBytes());
    }

    @Test
    void limitsMustBePositiveAndCoherent() {
        assertEquals("ANON_MAX_ZIP_MEMBERS must be greater than zero, got 0", refused(with("ANON_MAX_ZIP_MEMBERS", "0")));
        assertEquals("ANON_MAX_TEXT_CHARS must be greater than zero, got -1", refused(with("ANON_MAX_TEXT_CHARS", "-1")));
        assertEquals("ANON_MAX_UPLOAD_BYTES must be a number, got '1.5e6'",
                refused(with("ANON_MAX_UPLOAD_BYTES", "1.5e6")));
        assertEquals("ANON_MAX_COMPRESSION_RATIO must be a finite number greater than 1, got 1.0",
                refused(with("ANON_MAX_COMPRESSION_RATIO", "1")));
        assertEquals("ANON_MAX_COMPRESSION_RATIO must be a finite number greater than 1, got nan",
                refused(with("ANON_MAX_COMPRESSION_RATIO", "nan")));
        assertEquals("ANON_COMPRESSION_RATIO_FLOOR_BYTES must not be negative, got -1",
                refused(with("ANON_COMPRESSION_RATIO_FLOOR_BYTES", "-1")));
        assertEquals(0L, Config.loadRuntimeConfig(with("ANON_COMPRESSION_RATIO_FLOOR_BYTES", "0")).limits()
                .compressionRatioFloorBytes()); // zero means every member is ratio-checked
        assertEquals("ANON_MAX_ZIP_MEMBER_BYTES must not exceed ANON_MAX_ZIP_TOTAL_BYTES",
                refused(with("ANON_MAX_ZIP_MEMBER_BYTES", "60000001")));
        assertEquals("ANON_MAX_UPLOAD_BYTES must not exceed ANON_MAX_ZIP_TOTAL_BYTES",
                refused(with("ANON_MAX_ZIP_TOTAL_BYTES", "19999999", "ANON_MAX_ZIP_MEMBER_BYTES", "1000000")));
        assertEquals("ANON_COMPRESSION_RATIO_FLOOR_BYTES must not exceed ANON_MAX_ZIP_MEMBER_BYTES, or no member is "
                + "ever ratio-checked", refused(with("ANON_COMPRESSION_RATIO_FLOOR_BYTES", "25000001")));
    }

    @Test
    void logLevelsAreNormalizedAndCheckedAtLoad() {
        assertEquals("INFO", Config.loadRuntimeConfig(openAiEnv()).logLevel());
        assertEquals("WARNING", Config.loadRuntimeConfig(with("ANON_LOG_LEVEL", " warning ")).logLevel());
        assertEquals("ANON_LOG_LEVEL must be one of CRITICAL, DEBUG, ERROR, INFO, NOTSET, WARNING, got 'WARN'",
                refused(with("ANON_LOG_LEVEL", "WARN")));
    }

    @Test
    void theAzureEndpointMustBeAnAbsoluteHttpUrl() {
        Map<String, String> azure = new HashMap<>(Map.of("ANON_PROVIDER", "azure", "AZURE_OPENAI_API_KEY", "k",
                "ANON_AZURE_DEPLOYMENT", "dep", "ANON_AZURE_API_VERSION", "2024-10-21"));
        for (String endpoint : new String[] {"example-tenant.openai.azure.com", "ftp://example-tenant.openai.azure.com",
                "https://", "https:///path"}) {
            azure.put("AZURE_OPENAI_ENDPOINT", endpoint);
            assertEquals("AZURE_OPENAI_ENDPOINT must be an absolute http(s) URL", refused(azure), endpoint);
        }
        azure.put("AZURE_OPENAI_ENDPOINT", " https://example-tenant.openai.azure.com/ ");
        assertEquals("https://example-tenant.openai.azure.com/", Config.loadRuntimeConfig(azure).azureEndpoint());
    }

    static void writeConfig(Path dir, String policy, String patterns) throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), policy);
        Files.writeString(dir.resolve("regex_patterns.yaml"), patterns);
        Files.copy(Path.of("config", "prompt_injection.yaml"), dir.resolve("prompt_injection.yaml"),
                StandardCopyOption.REPLACE_EXISTING);
    }

    static String refusedFiles(Path dir) {
        return assertThrows(ConfigurationError.class, () -> Config.loadFileConfig(dir)).getMessage();
    }

    @Test
    void regexOverridesMustCompileWhereTheDetectorsUseThem(@TempDir Path dir) throws Exception {
        String policy = policyYaml("[DOU]", "[AFM]");
        writeConfig(dir, policy, "afm:\n  body: '(\\d{9}'\n");
        String message = refusedFiles(dir);
        assertTrue(message.startsWith(dir.resolve("regex_patterns.yaml") + ": pattern 'afm' body does not compile "
                + "in context: "), message);
        writeConfig(dir, policy, "amka:\n  prefix: '(?:ΑΜΚΑ'\n");
        assertTrue(refusedFiles(dir).contains(": pattern 'amka' prefix does not compile in context: "));
        // A valid override loads; a name no detector reads is only a warning, and is not compiled.
        writeConfig(dir, policy, "afm:\n  body: '(\\d{9})'\nnot_a_detector:\n  body: '('\n");
        assertEquals("(\\d{9})", Config.loadFileConfig(dir).rules().patterns().get("afm").get("body"));
    }

    @Test
    void policyThresholdsAreConfidences(@TempDir Path dir) throws Exception {
        String head = "policy:\n  preserve_high_confidence_threshold: 0.8\n  redact_high_confidence_threshold: 0.9\n";
        writeConfig(dir, head + "  redact_threshold: 1.5\n", "");
        assertEquals("policy.yaml: 'redact_threshold' must be a confidence between 0 and 1, got 1.5", refusedFiles(dir));
        writeConfig(dir, head + "  redact_threshold: .nan\n", "");
        assertEquals("policy.yaml: 'redact_threshold' must be a confidence between 0 and 1, got nan", refusedFiles(dir));
        writeConfig(dir, head + "  redact_threshold: -0.1\n", "");
        assertEquals("policy.yaml: 'redact_threshold' must be a confidence between 0 and 1, got -0.1", refusedFiles(dir));
        writeConfig(dir, head + "  redact_threshold: 0.95\n", "");
        assertEquals("policy.yaml: redact_threshold must not exceed redact_high_confidence_threshold", refusedFiles(dir));
        writeConfig(dir, head + "  redact_threshold: 0.9\n", "");
        assertEquals(0.9, Config.loadFileConfig(dir).policy().redactThreshold()); // equal is coherent
    }

    @Test
    void aBrokenYamlFileIsAConfigurationErrorWithAPosition(@TempDir Path dir) throws Exception {
        writeConfig(dir, "policy:\n\tredact_threshold: 0.7\n", "");
        String message = refusedFiles(dir);
        assertTrue(message.startsWith("policy.yaml is not valid YAML: "), message);
        assertTrue(message.endsWith(" at line 2, column 1"), message);
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

    static String policyYaml(String hardPreserve, String hardRedact) {
        return "policy:\n  preserve_high_confidence_threshold: 0.8\n  redact_high_confidence_threshold: 0.9\n"
                + "  redact_threshold: 0.7\n  hard_preserve_categories: " + hardPreserve + "\n"
                + "  hard_redact_categories: " + hardRedact + "\n";
    }

    @Test
    void hardPolicyCategoriesMustExistAndBeDisjoint(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), policyYaml("[FIELD_LABEL, NOPE, AAA]", "[AFM]"));
        assertEquals("policy.yaml: hard_preserve_categories names categories that do not exist: AAA, NOPE",
                assertThrows(ConfigurationError.class, () -> Config.loadFileConfig(dir)).getMessage());
        Files.writeString(dir.resolve("policy.yaml"), policyYaml("[AFM, DOU]", "[AFM]"));
        assertEquals("policy.yaml: AFM is listed as both hard-preserve and hard-redact",
                assertThrows(ConfigurationError.class, () -> Config.loadFileConfig(dir)).getMessage());
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
