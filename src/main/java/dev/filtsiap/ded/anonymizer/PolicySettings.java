package dev.filtsiap.ded.anonymizer;

import java.util.Set;

/**
 * Resolver policy from {@code config/policy.yaml} (port of {@code config.PolicySettings}).
 * Category sets hold the raw YAML strings, as in Python, and are compared against
 * {@link SpanCategory#wire()}.
 */
public record PolicySettings(
        double preserveHighConfidenceThreshold,
        double redactHighConfidenceThreshold,
        double redactThreshold,
        Set<String> hardPreserveCategories,
        Set<String> hardRedactCategories) {
    public PolicySettings {
        hardPreserveCategories = Set.copyOf(hardPreserveCategories);
        hardRedactCategories = Set.copyOf(hardRedactCategories);
    }
}
