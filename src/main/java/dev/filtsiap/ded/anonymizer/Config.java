package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyNumber;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.math.MathContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.Mark;
import org.yaml.snakeyaml.error.MarkedYAMLException;
import org.yaml.snakeyaml.error.YAMLException;

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
        } else if (providerRaw.equals("regex")) {
            provider = RuntimeConfig.Provider.REGEX;
        } else {
            throw new ConfigurationError(
                    "ANON_PROVIDER must be 'openai', 'azure' or 'regex', got " + PyRepr.repr(providerRaw));
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
        } else if (provider == RuntimeConfig.Provider.AZURE) {
            azureApiKey = require(env, "AZURE_OPENAI_API_KEY", providerRaw);
            azureEndpoint = require(env, "AZURE_OPENAI_ENDPOINT", providerRaw);
            azureDeployment = require(env, "ANON_AZURE_DEPLOYMENT", providerRaw);
            azureApiVersion = require(env, "ANON_AZURE_API_VERSION", providerRaw);
            validateAzureEndpoint(azureEndpoint);
        }

        // An all-whitespace key counts as unset: a blank .env line never becomes a credential.
        String apiKey = PyStr.strip(env.getOrDefault("ANON_API_KEY", ""));
        if (apiKey.isEmpty()) {
            apiKey = null;
        }

        // Optional knobs: absent keeps the default; present must be finite, positive and bounded.
        Double timeout = optionalFloat(env, "ANON_LLM_TIMEOUT_S");
        Long chunkSize = optionalLong(env, "ANON_CHUNK_SIZE_CHARS");
        Long maxTokens = optionalLong(env, "ANON_MAX_COMPLETION_TOKENS");
        Long contextTokens = optionalLong(env, "ANON_LLM_CONTEXT_TOKENS");
        Long concurrency = optionalLong(env, "ANON_LLM_CONCURRENCY");
        double llmTimeoutS = timeout == null ? RuntimeConfig.DEFAULT_LLM_TIMEOUT_S
                : number("ANON_LLM_TIMEOUT_S", timeout, 3600);
        int chunkSizeChars = chunkSize == null ? RuntimeConfig.DEFAULT_CHUNK_SIZE_CHARS
                : (int) number("ANON_CHUNK_SIZE_CHARS", chunkSize, 200_000);
        int maxCompletionTokens = maxTokens == null ? RuntimeConfig.DEFAULT_MAX_COMPLETION_TOKENS
                : (int) number("ANON_MAX_COMPLETION_TOKENS", maxTokens, 1_000_000);
        // No default: unset means the window is unknown and no whole-request check is made.
        int llmContextTokens = contextTokens == null ? 0
                : (int) number("ANON_LLM_CONTEXT_TOKENS", contextTokens, 100_000_000);
        int llmConcurrency = concurrency == null ? RuntimeConfig.DEFAULT_LLM_CONCURRENCY
                : (int) number("ANON_LLM_CONCURRENCY", concurrency, 64);
        ResourceLimits limits = validateLimits(readLimits(env));
        Double deadline = optionalFloat(env, "ANON_DOCUMENT_DEADLINE_S");
        double documentDeadlineS = deadline == null ? RuntimeConfig.DEFAULT_DOCUMENT_DEADLINE_S
                : number("ANON_DOCUMENT_DEADLINE_S", deadline, 86_400);

        return new RuntimeConfig(
                provider, openaiApiKey, openaiModel, azureApiKey, azureEndpoint, azureDeployment,
                azureApiVersion, apiKey, llmTimeoutS, chunkSizeChars, maxCompletionTokens, llmContextTokens,
                llmConcurrency,
                logLevel(env.get("ANON_LOG_LEVEL")), documentDeadlineS, limits, readPricing(env));
    }

    /** A price above this per 1M tokens is a unit mistake (per token, per 1K), not a price. */
    private static final BigDecimal MAX_PRICE_PER_MILLION = BigDecimal.valueOf(1_000_000);
    private static final PyRegex.PyPattern CURRENCY_CODE = PyRegex.compile("[A-Z]{3}");

    /**
     * The token prices, all optional. Absent, cost is reported as unavailable. Present, each is
     * a non-negative decimal (read as {@link BigDecimal}, never as a float). The input and output
     * rates come as a pair, since a cost from one of them would be a fraction of a cost presented
     * as the whole; the cached-input rate refines a pair and means nothing without one.
     */
    static LlmPricing readPricing(Map<String, String> env) {
        BigDecimal input = price(env, "ANON_INPUT_COST_PER_1M_TOKENS");
        BigDecimal output = price(env, "ANON_OUTPUT_COST_PER_1M_TOKENS");
        BigDecimal cachedInput = price(env, "ANON_CACHED_INPUT_COST_PER_1M_TOKENS");
        if ((input == null) != (output == null)) {
            throw new ConfigurationError("ANON_INPUT_COST_PER_1M_TOKENS and ANON_OUTPUT_COST_PER_1M_TOKENS must be "
                    + "set together (one of them alone prices only part of every call)");
        }
        if (cachedInput != null && input == null) {
            throw new ConfigurationError("ANON_CACHED_INPUT_COST_PER_1M_TOKENS needs ANON_INPUT_COST_PER_1M_TOKENS "
                    + "and ANON_OUTPUT_COST_PER_1M_TOKENS");
        }
        String rawCurrency = env.get("ANON_COST_CURRENCY");
        String currency = rawCurrency == null ? LlmPricing.DEFAULT_CURRENCY : PyStr.upper(PyStr.strip(rawCurrency));
        if (CURRENCY_CODE.fullmatch(currency) == null) {
            throw new ConfigurationError("ANON_COST_CURRENCY must be a three-letter ISO 4217 code such as USD or EUR, "
                    + "got " + PyRepr.repr(rawCurrency));
        }
        return new LlmPricing(input, cachedInput, output, currency);
    }

    private static BigDecimal price(Map<String, String> env, String name) {
        String raw = env.get(name);
        if (raw == null) {
            return null;
        }
        BigDecimal value;
        try {
            value = new BigDecimal(PyStr.strip(raw));
        } catch (NumberFormatException e) {
            throw new ConfigurationError(name + " must be a decimal number, got " + PyRepr.repr(raw));
        }
        if (value.signum() < 0) {
            throw new ConfigurationError(name + " must not be negative, got " + PyRepr.repr(raw));
        }
        if (value.compareTo(MAX_PRICE_PER_MILLION) > 0) {
            throw new ConfigurationError(name + " must be at most 1000000 (a price per 1M tokens), got "
                    + PyRepr.repr(raw));
        }
        return value;
    }

    /**
     * The value of {@code name}, stripped, or an error naming the variable. Stripped because a
     * credential of three spaces is not a credential: it would reach the provider and fail there,
     * on somebody's document. The value never appears in the message.
     */
    private static String require(Map<String, String> env, String name, String provider) {
        String value = PyStr.strip(env.getOrDefault(name, ""));
        if (value.isEmpty()) {
            throw new ConfigurationError(name + " is required when ANON_PROVIDER=" + provider
                    + " (it is unset or contains only whitespace)");
        }
        return value;
    }

    /** An absolute http(s) URL. The value is not echoed: an endpoint can carry a tenant name. */
    private static void validateAzureEndpoint(String endpoint) {
        URI uri;
        try {
            uri = new URI(endpoint);
        } catch (URISyntaxException e) {
            throw new ConfigurationError("AZURE_OPENAI_ENDPOINT must be an absolute http(s) URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!(scheme.equals("http") || scheme.equals("https")) || uri.getRawAuthority() == null
                || uri.getRawAuthority().isEmpty()) {
            throw new ConfigurationError("AZURE_OPENAI_ENDPOINT must be an absolute http(s) URL");
        }
        if (scheme.equals("http")) {
            Log.LOG.warn("AZURE_OPENAI_ENDPOINT is not https; document text will cross the network in the clear");
        }
    }

    /** Level names Python's logging accepts, so an unknown one is a typed error at load time. */
    private static final Set<String> LOG_LEVELS = new TreeSet<>(
            List.of("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"));

    private static String logLevel(String raw) {
        if (raw == null) {
            return RuntimeConfig.DEFAULT_LOG_LEVEL;
        }
        String level = PyStr.upper(PyStr.strip(raw));
        if (!LOG_LEVELS.contains(level)) {
            throw new ConfigurationError("ANON_LOG_LEVEL must be one of " + String.join(", ", LOG_LEVELS)
                    + ", got " + PyRepr.repr(raw));
        }
        return level;
    }

    /**
     * A configuration number that has to be finite and strictly positive, and at most
     * {@code maximum} when one is given. Zero is rejected as firmly as a negative (a timeout of
     * zero is a call that cannot be made, a limit of zero refuses everything), and NaN because
     * every comparison against it is false, so a NaN limit silently disables its own check.
     */
    private static double number(String name, double value, double maximum) {
        String shown = PyFloat.repr(value);
        return checkNumber(name, value, shown, maximum);
    }

    private static long number(String name, long value, double maximum) {
        return (long) checkNumber(name, value, Long.toString(value), maximum);
    }

    private static double checkNumber(String name, double value, String shown, double maximum) {
        if (!Double.isFinite(value)) {
            throw new ConfigurationError(name + " must be a finite number, got " + shown);
        }
        if (value <= 0) {
            throw new ConfigurationError(name + " must be greater than zero, got " + shown);
        }
        if (!Double.isNaN(maximum) && value > maximum) {
            throw new ConfigurationError(name + " must be at most " + pyG(maximum) + ", got " + shown);
        }
        return value;
    }

    /** Python's {@code format(x, "g")} for the whole-number maxima above ("3600", "1e+06"). */
    private static String pyG(double x) {
        if (Math.abs(x) >= 1e6) {
            int exponent = (int) Math.floor(Math.log10(Math.abs(x)));
            String mantissa = new BigDecimal(x / Math.pow(10, exponent)).round(new MathContext(6))
                    .stripTrailingZeros().toPlainString();
            return mantissa + "e+" + (exponent < 10 ? "0" : "") + exponent;
        }
        return new BigDecimal(x).round(new MathContext(6)).stripTrailingZeros().toPlainString();
    }

    /** Reads every limit, overriding only what the environment sets: absent keeps the calibrated default. */
    private static ResourceLimits readLimits(Map<String, String> env) {
        ResourceLimits d = ResourceLimits.DEFAULTS;
        Double ratio = optionalFloat(env, "ANON_MAX_COMPRESSION_RATIO");
        return new ResourceLimits(
                longOr(env, "ANON_MAX_UPLOAD_BYTES", d.maxUploadBytes()),
                longOr(env, "ANON_MAX_ZIP_MEMBERS", d.maxZipMembers()),
                longOr(env, "ANON_MAX_ZIP_MEMBER_BYTES", d.maxZipMemberBytes()),
                longOr(env, "ANON_MAX_ZIP_TOTAL_BYTES", d.maxZipTotalBytes()),
                ratio == null ? d.maxCompressionRatio() : ratio,
                longOr(env, "ANON_COMPRESSION_RATIO_FLOOR_BYTES", d.compressionRatioFloorBytes()),
                longOr(env, "ANON_MAX_TEXT_CHARS", d.maxTextChars()),
                longOr(env, "ANON_MAX_CHUNKS", d.maxChunks()),
                longOr(env, "ANON_MAX_XML_BYTES", d.maxXmlBytes()),
                longOr(env, "ANON_MEMORY_BUDGET_BYTES", d.memoryBudgetBytes()));
    }

    /** Every bound finite and positive, and coherent with the others. */
    static ResourceLimits validateLimits(ResourceLimits limits) {
        number("ANON_MAX_UPLOAD_BYTES", limits.maxUploadBytes(), Double.NaN);
        number("ANON_MAX_ZIP_MEMBERS", limits.maxZipMembers(), Double.NaN);
        number("ANON_MAX_ZIP_MEMBER_BYTES", limits.maxZipMemberBytes(), Double.NaN);
        number("ANON_MAX_ZIP_TOTAL_BYTES", limits.maxZipTotalBytes(), Double.NaN);
        number("ANON_MAX_TEXT_CHARS", limits.maxTextChars(), Double.NaN);
        number("ANON_MAX_CHUNKS", limits.maxChunks(), Double.NaN);
        number("ANON_MAX_XML_BYTES", limits.maxXmlBytes(), Double.NaN);
        if (limits.memoryBudgetBytes() < 0) {
            throw new ConfigurationError("ANON_MEMORY_BUDGET_BYTES must not be negative (0 = 60% of the maximum "
                    + "heap), got " + limits.memoryBudgetBytes());
        }
        if (!Double.isFinite(limits.maxCompressionRatio()) || limits.maxCompressionRatio() <= 1.0) {
            throw new ConfigurationError("ANON_MAX_COMPRESSION_RATIO must be a finite number greater than 1, got "
                    + PyFloat.repr(limits.maxCompressionRatio()));
        }
        if (limits.compressionRatioFloorBytes() < 0) {
            throw new ConfigurationError("ANON_COMPRESSION_RATIO_FLOOR_BYTES must not be negative, got "
                    + limits.compressionRatioFloorBytes());
        }
        // Coherence: each of these describes a limit that can never be reached, so the one behind
        // it does all the work while the operator believes otherwise.
        if (limits.maxZipMemberBytes() > limits.maxZipTotalBytes()) {
            throw new ConfigurationError("ANON_MAX_ZIP_MEMBER_BYTES must not exceed ANON_MAX_ZIP_TOTAL_BYTES");
        }
        if (limits.maxUploadBytes() > limits.maxZipTotalBytes()) {
            throw new ConfigurationError("ANON_MAX_UPLOAD_BYTES must not exceed ANON_MAX_ZIP_TOTAL_BYTES");
        }
        if (limits.maxXmlBytes() > limits.maxZipTotalBytes()) {
            throw new ConfigurationError("ANON_MAX_XML_BYTES must not exceed ANON_MAX_ZIP_TOTAL_BYTES");
        }
        if (limits.compressionRatioFloorBytes() > limits.maxZipMemberBytes()) {
            throw new ConfigurationError("ANON_COMPRESSION_RATIO_FLOOR_BYTES must not exceed "
                    + "ANON_MAX_ZIP_MEMBER_BYTES, or no member is ever ratio-checked");
        }
        return limits;
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

    /** Python {@code float(raw)}: "nan" and "inf" parse, and are then refused by {@link #number}. */
    private static Double optionalFloat(Map<String, String> env, String name) {
        return optionalNumber(env, name, s -> PyNumber.parseFloat(s).orElse(null));
    }

    /** Python {@code int(raw)}; a value that does not fit a long is refused rather than wrapped. */
    private static Long optionalLong(Map<String, String> env, String name) {
        return optionalNumber(env, name, s -> PyNumber.parseInt(s)
                .filter(v -> v.bitLength() < 64)
                .map(v -> v.longValue())
                .orElse(null));
    }

    private static long longOr(Map<String, String> env, String name, long fallback) {
        Long value = optionalLong(env, name);
        return value == null ? fallback : value;
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
        // The one ordering the resolver's semantics require: the structured-redact tier is gated on
        // the high threshold and the ordinary one on the low, so inverting them makes it unreachable.
        if (policy.redactThreshold() > policy.redactHighConfidenceThreshold()) {
            throw new ConfigurationError(
                    "policy.yaml: redact_threshold must not exceed redact_high_confidence_threshold");
        }
        validateHardCategories(policy);

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
            if (e.getKey() instanceof String name && !PRESERVE_FAMILIES_KEY.equals(name)
                    && e.getValue() instanceof Map<?, ?> spec) {
                Map<String, String> converted = new LinkedHashMap<>();
                spec.forEach((k, v) -> converted.put(PyRepr.str(k), PyRepr.str(v)));
                patterns.put(name, converted);
            }
        }
        validatePatterns(patterns, configDir.resolve("regex_patterns.yaml"));
        List<DetectorRules.PreserveFamily> families = loadPreserveFamilies(patternsData.get(PRESERVE_FAMILIES_KEY),
                policy, configDir.resolve("regex_patterns.yaml"));

        // Prompt-injection rules. REQUIRED: a security control that silently disables itself when
        // its file is missing is worse than one that refuses to start, because nothing downstream
        // can tell "no rule matched" from "no rule was loaded".
        Path injectionPath = configDir.resolve("prompt_injection.yaml");
        List<InjectionScreen.Rule> injectionRules = InjectionScreen.compileRules(
                loadYamlMapping(injectionPath, "prompt_injection.yaml not found in " + configDir),
                injectionPath.toString());

        Path allowlistDir = configDir.resolve("allowlists");
        DetectorRules rules = new DetectorRules(
                patterns,
                loadAllowlist(allowlistDir.resolve("dou.txt")),
                loadAllowlist(allowlistDir.resolve("public_services.txt")),
                loadAllowlist(allowlistDir.resolve("legal_refs.txt")),
                preserveEmailDomains,
                loadAllowlist(allowlistDir.resolve("regions.txt")),
                families,
                // The chat name lists, shared: POSITIVE evidence of a person's name for the DOCX
                // detectors. Optional here like the allowlists (warn and continue); the chat
                // service still requires them when it loads its own lists.
                loadAllowlist(configDir.resolve(NAME_LISTS.get(0))),
                loadAllowlist(configDir.resolve(NAME_LISTS.get(1))));

        // Provenance: one hash over every config file's raw bytes, in a fixed order; a missing
        // allowlist contributes only its name (matching the warn-and-continue loader).
        MessageDigest digest = sha256();
        for (String name : List.of("policy.yaml", "regex_patterns.yaml", "prompt_injection.yaml", "allowlists/dou.txt",
                "allowlists/public_services.txt", "allowlists/legal_refs.txt", "allowlists/regions.txt",
                NAME_LISTS.get(0), NAME_LISTS.get(1))) {
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
        return new FileConfig(policy, rules, injectionRules, HexFormat.of().formatHex(digest.digest()));
    }

    /** The {@code regex_patterns.yaml} key holding the hard-preserve phrase families. */
    static final String PRESERVE_FAMILIES_KEY = "preserve_families";
    /** The chat name lists the DOCX detectors also read, relative to the config directory. */
    static final List<String> NAME_LISTS = List.of("chat/given_names.txt", "chat/surnames.txt");

    /**
     * Compiles {@code preserve_families}: per family a category, a scope ({@code any} or
     * {@code label}) and its folded patterns. A family's plain patterns are compiled as one
     * alternation, longest first; a composite pattern (one with its variable part in group 1) is
     * compiled on its own.
     *
     * <p>A family is a hard decision, never a recommendation, so its category must be a configured
     * HARD PRESERVE category. A family whose category is unknown, or known but not hard, is DISABLED
     * with a warning and the service starts without it: it is never mapped to another category and
     * never promoted, and the other families are unaffected. Its structure is still checked first,
     * so anything malformed (not a mapping, a bad scope, no patterns, a pattern that does not compile
     * or has more than one group) stops the service starting, whatever the category.
     */
    private static List<DetectorRules.PreserveFamily> loadPreserveFamilies(Object data, PolicySettings policy,
                                                                           Path source) {
        List<DetectorRules.PreserveFamily> families = new ArrayList<>();
        if (data == null) {
            return families;
        }
        if (!(data instanceof Map<?, ?> byName)) {
            throw new ConfigurationError(source + ": " + PRESERVE_FAMILIES_KEY + " must be a mapping");
        }
        for (Map.Entry<?, ?> e : byName.entrySet()) {
            String name = PyRepr.str(e.getKey());
            String where = source + ": preserve family " + PyRepr.repr(name);
            if (!(e.getValue() instanceof Map<?, ?> spec)) {
                throw new ConfigurationError(where + " must be a mapping");
            }
            String categoryName = PyRepr.str(spec.get("category"));
            // Null when unknown: the family is still validated in full, then disabled.
            SpanCategory category = SpanCategory.fromWire(categoryName).orElse(null);
            String disabled = category == null ? "unknown category " + PyRepr.repr(categoryName)
                    : !policy.hardPreserveCategories().contains(category.wire())
                    ? "category " + category.wire() + " is not a hard_preserve_categories entry in policy.yaml"
                    : null;
            List<DetectorRules.PreserveFamily> compiled = compilePreserveFamily(spec, name, where, category);
            if (disabled != null) {
                // Nothing compiled for a disabled family is kept, so it can never produce a span.
                Log.LOG.warn("{}: {}; the family is disabled (not hard-preserved, not used) and the service "
                        + "continues without it", where, disabled);
                continue;
            }
            families.addAll(compiled);
        }
        return families;
    }

    /**
     * One family, fully validated and compiled: its composite patterns, then its plain alternation.
     * Raises {@link ConfigurationError} for anything malformed, whatever the category.
     */
    private static List<DetectorRules.PreserveFamily> compilePreserveFamily(Map<?, ?> spec, String name, String where,
                                                                            SpanCategory category) {
        DetectorRules.Scope scope = switch (PyRepr.str(spec.get("scope"))) {
            case "any" -> DetectorRules.Scope.ANY;
            case "label" -> DetectorRules.Scope.LABEL;
            default -> throw new ConfigurationError(where + ": scope must be 'any' or 'label'");
        };
        List<DetectorRules.PreserveFamily> families = new ArrayList<>();
        List<String> plain = new ArrayList<>();
        for (String pattern : stringItems(spec.get("patterns"))) {
            Map.Entry<PyRegex.PyPattern, Integer> compiled;
            try {
                compiled = DetectorSupport.compileFamilyPattern(pattern);
            } catch (IllegalArgumentException ex) {
                throw new ConfigurationError(where + ": pattern " + PyRepr.repr(pattern) + " is invalid: "
                        + ex.getMessage());
            }
            if (compiled.getValue() > 1) {
                throw new ConfigurationError(where + ": pattern " + PyRepr.repr(pattern)
                        + " has more than one capturing group");
            }
            if (compiled.getValue() == 1) {
                families.add(new DetectorRules.PreserveFamily(name, category, scope, compiled.getKey(), true));
            } else {
                plain.add(pattern);
            }
        }
        if (plain.isEmpty() && families.isEmpty()) {
            throw new ConfigurationError(where + " has no patterns");
        }
        if (!plain.isEmpty()) {
            // Longest first, so a shorter alternative never shadows a longer one at the same place.
            plain.sort(Comparator.comparingInt(String::length).reversed().thenComparing(PyStr.CODE_POINT_ORDER));
            families.add(new DetectorRules.PreserveFamily(name, category, scope,
                    DetectorSupport.compileFamilyPattern(String.join("|", plain.stream()
                            .map(p -> "(?:" + p + ")").toList())).getKey(), false));
        }
        return families;
    }

    private static double policyThreshold(Map<?, ?> policyMap, String key) {
        if (!policyMap.containsKey(key)) {
            throw new ConfigurationError("policy.yaml is missing required key " + PyRepr.repr(key)
                    + " under 'policy:'");
        }
        double value = PyNumber.toFloat(policyMap.get(key)).orElseThrow(() -> new ConfigurationError(
                "policy.yaml: " + PyRepr.repr(key) + " must be a number, got " + PyRepr.repr(policyMap.get(key))));
        if (!Double.isFinite(value) || value < 0.0 || value > 1.0) {
            throw new ConfigurationError("policy.yaml: " + PyRepr.repr(key)
                    + " must be a confidence between 0 and 1, got " + PyFloat.repr(value));
        }
        return value;
    }

    /**
     * Every shape a pattern fragment is interpolated into by {@link Detectors}. A fragment is
     * compiled in ALL of them: compiling it alone proves neither that it works in context (a body
     * may rely on a wrapper's group) nor that it is safe there (a trailing alternation compiles
     * alone and changes meaning once wrapped).
     */
    private static final List<String> BODY_CONTEXTS = List.of("@@", "\\b@@\\b", "(?<!\\d)@@(?!\\d)");
    private static final List<String> PREFIX_CONTEXTS = List.of("(?:@@)?x", "@@x");

    /**
     * Compiles every override the way the detectors will use it, so an invalid one stops the
     * service starting instead of surfacing as a failure on somebody's document.
     */
    private static void validatePatterns(Map<String, Map<String, String>> patterns, Path source) {
        Set<String> names = new TreeSet<>(PyStr.CODE_POINT_ORDER);
        names.addAll(patterns.keySet());
        for (String name : names) {
            if (!DetectorPatterns.DEFAULT_PATTERNS.containsKey(name)) {
                // Harmless but useless: the operator believes they changed a rule, and did not.
                Log.LOG.warn("{} defines pattern {}, which no detector uses", source, PyRepr.repr(name));
                continue;
            }
            for (Map.Entry<String, List<String>> kind : List.of(Map.entry("body", BODY_CONTEXTS),
                    Map.entry("prefix", PREFIX_CONTEXTS))) {
                String fragment = patterns.get(name).get(kind.getKey());
                if (fragment == null) {
                    continue;
                }
                for (String context : kind.getValue()) {
                    try {
                        PyRegex.compile(context.replace("@@", fragment));
                    } catch (RuntimeException e) {
                        throw new ConfigurationError(source + ": pattern " + PyRepr.repr(name) + " " + kind.getKey()
                                + " does not compile in context: " + e.getMessage());
                    }
                }
            }
        }
    }

    /**
     * Rejects a hard-policy category that does not exist (a policy line that protects nothing
     * while the operator believes it does) and one listed as both hard-preserve and hard-redact.
     */
    private static void validateHardCategories(PolicySettings policy) {
        for (Map.Entry<String, Set<String>> field : List.of(
                Map.entry("hard_preserve_categories", policy.hardPreserveCategories()),
                Map.entry("hard_redact_categories", policy.hardRedactCategories()))) {
            Set<String> unknown = new TreeSet<>(PyStr.CODE_POINT_ORDER);
            field.getValue().stream().filter(c -> SpanCategory.fromWire(c).isEmpty()).forEach(unknown::add);
            if (!unknown.isEmpty()) {
                throw new ConfigurationError("policy.yaml: " + field.getKey()
                        + " names categories that do not exist: " + String.join(", ", unknown));
            }
        }
        Set<String> both = new TreeSet<>(PyStr.CODE_POINT_ORDER);
        policy.hardPreserveCategories().stream().filter(policy.hardRedactCategories()::contains).forEach(both::add);
        if (!both.isEmpty()) {
            throw new ConfigurationError("policy.yaml: " + String.join(", ", both)
                    + " is listed as both hard-preserve and hard-redact");
        }
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
        Object data;
        try {
            data = new Yaml(new SafeConstructor(new LoaderOptions())).load(readUtf8(path));
        } catch (MarkedYAMLException e) {
            // The parser's own problem and position only, never the offending source line.
            Mark mark = e.getProblemMark();
            String where = mark == null ? "" : " at line " + (mark.getLine() + 1) + ", column " + (mark.getColumn() + 1);
            throw new ConfigurationError(path.getFileName() + " is not valid YAML: "
                    + (e.getProblem() == null ? "parse error" : e.getProblem()) + where);
        } catch (YAMLException e) {
            throw new ConfigurationError(path.getFileName() + " is not valid YAML (" + e.getClass().getSimpleName() + ")");
        }
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
