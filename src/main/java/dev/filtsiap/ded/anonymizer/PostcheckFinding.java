package dev.filtsiap.ded.anonymizer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One finding of the post-redaction scan (port of {@code postcheck.PostcheckFinding}; lives in
 * the models package, which breaks Python's type-only models/postcheck cycle).
 */
public record PostcheckFinding(Severity severity, String kind, String location, String detail) {

    /** Finding severity. HIGH blocks the document. */
    public enum Severity { HIGH, MEDIUM }

    /** Python {@code dataclasses.asdict(finding)}. */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("severity", severity.name());
        m.put("kind", kind);
        m.put("location", location);
        m.put("detail", detail);
        return m;
    }
}
