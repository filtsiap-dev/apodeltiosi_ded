package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyNumber;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Configuration loaders (port of {@code config.py}).
 *
 * <p>Runtime config comes from the environment ({@link #loadRuntimeConfig}); file config from
 * a {@code config/} directory ({@link #loadFileConfig}). Nothing is read at class load: every
 * read happens in a loader call, with an injectable {@code env} map for tests.
 */
public final class Config {

    /** Lazy, so reading config never initialises logging before the server has chosen its level. */
    private static final class Log {
        static final Logger LOG = LoggerFactory.getLogger("anonymizer.config");
    }

    private Config() {
    }

    // ------------------------------------------------------------------ .env

    /**
     * Fills {@link ProcessEnv} from a simple KEY=VALUE {@code .env} file (dependency-free, like
     * the Python loader). Blank and {@code #} lines are skipped, a leading {@code export } is
     * stripped, key and value are trimmed, matching surrounding quotes are removed. A variable
     * already present is left untouched. Missing file: no-op. Never logs values.
     */
    public static void loadEnvFile(Path path) {
        if (!Files.isRegularFile(path)) {
            return;
        }
        for (String rawLine : PyStr.splitlines(readUtf8(path))) {
            String line = PyStr.strip(rawLine);
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("export ")) {
                line = PyStr.lstrip(line.substring("export ".length()));
            }
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = PyStr.strip(line.substring(0, eq));
            String value = PyStr.strip(line.substring(eq + 1));
            if (PyStr.len(value) >= 2) {
                String first = PyStr.charAt(value, 0);
                String last = PyStr.sliceFrom(value, -1);
                if (first.equals(last) && (first.equals("\"") || first.equals("'"))) {
                    value = PyStr.slice(value, 1, -1);
                }
            }
            if (!key.isEmpty() && !ProcessEnv.contains(key)) {
                ProcessEnv.put(key, value);
            }
        }
    }

    // ------------------------------------------------------------------ runtime config

    /** Loads {@code ./.env} into the process environment, then reads the environment. */
    public static RuntimeConfig loadRuntimeConfig() {
        loadEnvFile(Path.of("").toAbsolutePath().resolve(".env"));
        return loadRuntimeConfig(ProcessEnv.snapshot());
    }

    /** Builds a RuntimeConfig from an explicit environment map (tests stay hermetic). */
    public static RuntimeConfig loadRuntimeConfig(Map<String, String> env) {
        String providerRaw = env.getOrDefault("ANON_PROVIDER", "openai");
        RuntimeConfig.Provider provider;
        if (providerRaw.equals("openai")) {
            provider = RuntimeConfig.Provider.OPENAI;
        } else if (providerRaw.equals("azure")) {
            provider = RuntimeConfig.Provider.AZURE;
        } else {
            throw new ConfigurationError(
                    "ANON_PROVIDER must be 'openai' or 'azure', got " + PyRepr.repr(providerRaw));
        }

        String openaiApiKey = null;
        String openaiModel = null;
        String azureApiKey = null;
        String azureEndpoint = null;
        String azureDeployment = null;
        String azureApiVersion = null;
        if (provider == RuntimeConfig.Provider.OPENAI) {
            openaiApiKey = require(env, "OPENAI_API_KEY", providerRaw);
            openaiModel = require(env, "ANON_MODEL", providerRaw);
        } else {
            azureApiKey = require(env, "AZURE_OPENAI_API_KEY", providerRaw);
            azureEndpoint = require(env, "AZURE_OPENAI_ENDPOINT", providerRaw);
            azureDeployment = require(env, "ANON_AZURE_DEPLOYMENT", providerRaw);
            azureApiVersion = require(env, "ANON_AZURE_API_VERSION", providerRaw);
        }

        // An all-whitespace key counts as unset: a blank .env line never becomes a credential.
        String apiKey = PyStr.strip(env.getOrDefault("ANON_API_KEY", ""));
        if (apiKey.isEmpty()) {
            apiKey = null;
        }

        Double timeout = optionalNumber(env, "ANON_LLM_TIMEOUT_S", s -> PyNumber.parseFloat(s).orElse(null));
        Integer chunkSize = optionalInt(env, "ANON_CHUNK_SIZE_CHARS");
        Integer maxTokens = optionalInt(env, "ANON_MAX_COMPLETION_TOKENS");
        Integer concurrency = optionalInt(env, "ANON_LLM_CONCURRENCY");
        Integer maxUpload = optionalInt(env, "ANON_MAX_UPLOAD_MB");
        String logLevel = env.get("ANON_LOG_LEVEL");

        return new RuntimeConfig(
                provider, openaiApiKey, openaiModel, azureApiKey, azureEndpoint, azureDeployment,
                azureApiVersion, apiKey,
                timeout != null ? timeout : RuntimeConfig.DEFAULT_LLM_TIMEOUT_S,
                chunkSize != null ? chunkSize : RuntimeConfig.DEFAULT_CHUNK_SIZE_CHARS,
                maxTokens != null ? maxTokens : RuntimeConfig.DEFAULT_MAX_COMPLETION_TOKENS,
                concurrency != null ? concurrency : RuntimeConfig.DEFAULT_LLM_CONCURRENCY,
                logLevel != null ? logLevel : RuntimeConfig.DEFAULT_LOG_LEVEL,
                maxUpload != null ? maxUpload : RuntimeConfig.DEFAULT_MAX_UPLOAD_MB);
    }

    private static String require(Map<String, String> env, String name, String provider) {
        String value = env.get(name);
        if (value == null || value.isEmpty()) {
            throw new ConfigurationError(name + " is required when ANON_PROVIDER=" + provider);
        }
        return value;
    }

    private static <T> T optionalNumber(Map<String, String> env, String name, Function<String, T> caster) {
        String raw = env.get(name);
        if (raw == null) {
            return null;
        }
        T value = caster.apply(raw);
        if (value == null) {
            throw new ConfigurationError(name + " must be a number, got " + PyRepr.repr(raw));
        }
        return value;
    }

    private static Integer optionalInt(Map<String, String> env, String name) {
        return optionalNumber(env, name, s -> PyNumber.parseInt(s)
                .filter(v -> v.bitLength() < 32)
                .map(v -> v.intValue())
                .orElse(null));
    }

    // ------------------------------------------------------------------ file config

    /**
     * Loads policy thresholds, regex overrides and the allowlists from {@code configDir}, and
     * hashes every config file for provenance.
     */
    public static FileConfig loadFileConfig(Path configDir) {
        Map<?, ?> policyData = loadYamlMapping(configDir.resolve("policy.yaml"),
                "policy.yaml not found in " + configDir);
        Map<?, ?> policyMap = asMapOrEmpty(policyData.get("policy"), "policy.yaml 'policy:'");

        PolicySettings policy = new PolicySettings(
                policyThreshold(policyMap, "preserve_high_confidence_threshold"),
                policyThreshold(policyMap, "redact_high_confidence_threshold"),
                policyThreshold(policyMap, "redact_threshold"),
                new HashSet<>(stringItems(policyMap.get("hard_preserve_categories"))),
                new HashSet<>(stringItems(policyMap.get("hard_redact_categories"))));

        Set<String> preserveEmailDomains = new HashSet<>();
        for (String domain : stringItems(policyMap.get("preserve_email_domains"))) {
            String stripped = PyStr.strip(domain);
            if (!stripped.isEmpty()) {
                preserveEmailDomains.add(PyStr.casefold(stripped));
            }
        }

        Map<?, ?> patternsData = loadYamlMapping(configDir.resolve("regex_patterns.yaml"),
                "regex_patterns.yaml not found in " + configDir);
        Map<String, Map<String, String>> patterns = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : patternsData.entrySet()) {
            // Python keeps non-str names too, but no str lookup can ever hit them.
            if (e.getKey() instanceof String name && e.getValue() instanceof Map<?, ?> spec) {
                Map<String, String> converted = new LinkedHashMap<>();
                spec.forEach((k, v) -> converted.put(PyRepr.str(k), PyRepr.str(v)));
                patterns.put(name, converted);
            }
        }

        Path allowlistDir = configDir.resolve("allowlists");
        DetectorRules rules = new DetectorRules(
                patterns,
                loadAllowlist(allowlistDir.resolve("dou.txt")),
                loadAllowlist(allowlistDir.resolve("public_services.txt")),
                loadAllowlist(allowlistDir.resolve("legal_refs.txt")),
                preserveEmailDomains);

        // Provenance: one hash over every config file's raw bytes, in a fixed order; a missing
        // allowlist contributes only its name (matching the warn-and-continue loader).
        MessageDigest digest = sha256();
        for (String name : List.of("policy.yaml", "regex_patterns.yaml", "allowlists/dou.txt",
                "allowlists/public_services.txt", "allowlists/legal_refs.txt")) {
            digest.update(name.getBytes(StandardCharsets.UTF_8));
            Path path = configDir.resolve(name);
            if (Files.exists(path)) {
                try {
                    digest.update(Files.readAllBytes(path));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
        }
        return new FileConfig(policy, rules, HexFormat.of().formatHex(digest.digest()));
    }

    private static double policyThreshold(Map<?, ?> policyMap, String key) {
        if (!policyMap.containsKey(key)) {
            throw new ConfigurationError("policy.yaml is missing required key " + PyRepr.repr(key)
                    + " under 'policy:'");
        }
        return PyNumber.toFloat(policyMap.get(key)).orElseThrow(() -> new ConfigurationError(
                "policy.yaml key " + PyRepr.repr(key) + " must be a number"));
    }

    /** Python {@code [str(c) for c in value]} for a YAML value (a string iterates its characters). */
    private static List<String> stringItems(Object value) {
        List<String> items = new ArrayList<>();
        if (value == null) {
            return items;
        }
        if (value instanceof List<?> list) {
            list.forEach(v -> items.add(PyRepr.str(v)));
        } else if (value instanceof Map<?, ?> map) {
            map.keySet().forEach(k -> items.add(PyRepr.str(k)));
        } else if (value instanceof String s) {
            s.codePoints().forEach(cp -> items.add(new String(Character.toChars(cp))));
        } else {
            throw new ConfigurationError("expected a list in policy.yaml, got " + PyRepr.repr(value));
        }
        return items;
    }

    private static Map<?, ?> asMapOrEmpty(Object value, String what) {
        if (value == null || value instanceof Map<?, ?> m && m.isEmpty()) {
            return Map.of();
        }
        if (value instanceof Map<?, ?> m) {
            return m;
        }
        throw new ConfigurationError(what + " must be a mapping");
    }

    private static Map<?, ?> loadYamlMapping(Path path, String missingMessage) {
        if (!Files.exists(path)) {
            throw new ConfigurationError(missingMessage);
        }
        Object data = new Yaml(new SafeConstructor(new LoaderOptions())).load(readUtf8(path));
        if (data == null || Boolean.FALSE.equals(data) || "".equals(data)
                || (data instanceof Map<?, ?> m && m.isEmpty()) || (data instanceof List<?> l && l.isEmpty())
                || (data instanceof Number n && n.doubleValue() == 0.0)) {
            return Map.of(); // Python: yaml.safe_load(f) or {}
        }
        if (!(data instanceof Map<?, ?> map)) {
            throw new ConfigurationError(path.getFileName() + " must contain a mapping");
        }
        return map;
    }

    private static Set<String> loadAllowlist(Path path) {
        if (!Files.exists(path)) {
            Log.LOG.warn("Allowlist file not found: {} (using empty allowlist)", path);
            return Set.of();
        }
        Set<String> entries = new HashSet<>();
        for (String line : PyStr.splitlines(readUtf8(path))) {
            String stripped = PyStr.strip(line);
            if (stripped.isEmpty() || stripped.startsWith("#")) {
                continue;
            }
            entries.add(stripped);
        }
        return entries;
    }

    /** Strict UTF-8 read with Python's universal-newline translation. */
    static String readUtf8(Path path) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(Files.readAllBytes(path)))
                    .toString();
            return text.replace("\r\n", "\n").replace('\r', '\n');
        } catch (CharacterCodingException e) {
            throw new ConfigurationError(path.getFileName() + " is not valid UTF-8", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
