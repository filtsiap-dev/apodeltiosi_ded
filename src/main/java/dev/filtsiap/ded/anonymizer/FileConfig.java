package dev.filtsiap.ded.anonymizer;

/**
 * Configuration read from the {@code config/} directory (port of {@code config.FileConfig}).
 *
 * @param configSha256 sha256 over every config file's raw bytes: the "which rules produced
 *                     this output?" half of the provenance stamp
 */
public record FileConfig(PolicySettings policy, DetectorRules rules, String configSha256) {
}
