package dev.filtsiap.ded.anonymizer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pipeline result (port of {@code AnonymizeResult}). Exists only for documents that passed the
 * mandatory scan; {@code postcheck} carries the non-blocking findings. Provenance keys:
 * provider, model, config_sha256, prompts_sha256, package_version.
 */
public record AnonymizeResult(
        String documentId,
        byte[] redactedDocx,
        PlanSummary summary,
        List<String> warnings,
        String model,
        Map<String, Double> timings,
        PostcheckSummary postcheck,
        Map<String, String> provenance) {

    public AnonymizeResult {
        warnings = List.copyOf(warnings);
        timings = Collections.unmodifiableMap(new LinkedHashMap<>(timings));
        provenance = Collections.unmodifiableMap(new LinkedHashMap<>(provenance));
    }
}
