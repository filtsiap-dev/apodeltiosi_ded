package dev.filtsiap.ded.anonymizer;

import java.util.List;

/**
 * Configuration read from the {@code config/} directory (port of {@code config.FileConfig}).
 *
 * @param injectionRules the prompt-injection screening rules, compiled at load time so a broken
 *                       one stops startup instead of a request
 * @param configSha256 sha256 over every config file's raw bytes: the "which rules produced
 *                     this output?" half of the provenance stamp
 */
public record FileConfig(PolicySettings policy, DetectorRules rules, List<InjectionScreen.Rule> injectionRules,
                         String configSha256) {
    public FileConfig {
        injectionRules = List.copyOf(injectionRules);
    }
}
