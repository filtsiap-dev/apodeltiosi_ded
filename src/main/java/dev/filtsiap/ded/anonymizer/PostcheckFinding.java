package dev.filtsiap.ded.anonymizer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One finding of the post-redaction scan (port of {@code postcheck.PostcheckFinding}; lives in
 * the models package, which breaks Python's type-only models/postcheck cycle).
 *
 * <p>{@code span} is the exact slice this finding names, when it names one: null for every
 * package-level finding and for the over-redaction reports (see
 * {@link Postcheck#REMEDIABLE_CATEGORIES}). A finding WITH a span is one the pipeline puts back to
 * pass 2; a HIGH finding without one still stops the document.
 */
public record PostcheckFinding(Severity severity, String kind, String location, String detail, ResidualSpan span) {

    /** Finding severity. A HIGH that names no text slice blocks the document. */
    public enum Severity { HIGH, MEDIUM }

    /** A finding that names no slice of text. */
    public PostcheckFinding(Severity severity, String kind, String location, String detail) {
        this(severity, kind, location, detail, null);
    }

    /**
     * Python {@code dataclasses.asdict(finding)} WITHOUT the span: this map reaches the CLI's
     * {@code --qa} output and the API's summary JSON, and the span carries the residual text.
     */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("severity", severity.name());
        m.put("kind", kind);
        m.put("location", location);
        m.put("detail", detail);
        return m;
    }
}
