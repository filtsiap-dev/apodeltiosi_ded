package dev.filtsiap.ded.anonymizer.chat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import dev.filtsiap.ded.anonymizer.ConfigurationError;

/** config/chat/chat.yaml. A missing file means {@link #DEFAULTS}: NER off. */
public record ChatSettings(boolean nerEnabled, String nerProvider, double nerMinConfidence, int nerTimeoutMs) {

    /** The settings used when chat.yaml is absent. */
    public static final ChatSettings DEFAULTS = new ChatSettings(false, "none", 0.6, 2000);

    /**
     * Reads {@code chat.yaml} from {@code chatDir}; a missing file gives {@link #DEFAULTS}.
     *
     * @param chatDir the config/chat directory
     * @return the settings
     * @throws ConfigurationError when the file is unreadable or invalid, or asks for NER (v1 has none)
     */
    public static ChatSettings load(Path chatDir) {
        Path path = chatDir.resolve("chat.yaml");
        if (!Files.isRegularFile(path)) {
            return DEFAULTS;
        }
        Object data;
        try {
            String yaml = Files.readString(path, StandardCharsets.UTF_8);
            data = new Yaml(new SafeConstructor(new LoaderOptions())).load(yaml);
        } catch (IOException | RuntimeException e) {
            throw new ConfigurationError("cannot read " + path + ": " + e.getMessage(), e);
        }
        Map<?, ?> root = data instanceof Map<?, ?> m ? m : Map.of();
        Map<?, ?> ner = root.get("ner") instanceof Map<?, ?> m ? m : Map.of();
        boolean enabled = Boolean.TRUE.equals(ner.get("enabled"));
        String provider = String.valueOf(ner.containsKey("provider") ? ner.get("provider") : DEFAULTS.nerProvider());
        double minConfidence = ner.get("min_confidence") instanceof Number n ? n.doubleValue()
                : DEFAULTS.nerMinConfidence();
        int timeoutMs = ner.get("timeout_ms") instanceof Number n ? n.intValue() : DEFAULTS.nerTimeoutMs();
        if (minConfidence < 0 || minConfidence > 1) {
            throw new ConfigurationError(path + ": ner.min_confidence must be between 0 and 1");
        }
        if (enabled) {
            // v1 ships the slot, not a model: refusing to start beats silently running without NER.
            throw new ConfigurationError(path + ": ner.enabled is true but this build has no NER provider ('"
                    + provider + "'); see the spec's \"When NER is switched on\"");
        }
        return new ChatSettings(false, provider, minConfidence, timeoutMs);
    }
}
