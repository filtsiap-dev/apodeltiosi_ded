package dev.filtsiap.ded.anonymizer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Data-driven detector inputs (port of {@code config.DetectorRules}): regex overrides from
 * {@code regex_patterns.yaml} and the allowlists. Sets are for membership only; detectors that
 * iterate them sort first, so iteration order never reaches output.
 */
public record DetectorRules(
        Map<String, Map<String, String>> patterns,
        Set<String> douAllowlist,
        Set<String> publicServices,
        Set<String> legalRefs,
        Set<String> preserveEmailDomains) {
    public DetectorRules {
        Map<String, Map<String, String>> copy = new LinkedHashMap<>();
        patterns.forEach((k, v) -> copy.put(k, Collections.unmodifiableMap(new LinkedHashMap<>(v))));
        patterns = Collections.unmodifiableMap(copy);
        douAllowlist = Set.copyOf(douAllowlist);
        publicServices = Set.copyOf(publicServices);
        legalRefs = Set.copyOf(legalRefs);
        preserveEmailDomains = Set.copyOf(preserveEmailDomains);
    }
}
