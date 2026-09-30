package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.LlmDetector;
import dev.filtsiap.ded.anonymizer.llm.Prompts;
import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transport-neutral pipeline: parse, detect, LLM, resolve, apply, scan (port of
 * {@code pipeline.py}).
 *
 * <p>The final scan is mandatory, with no flag to skip it. A HIGH finding raises
 * {@link ResidualPIIError}, so an {@link AnonymizeResult} can only exist for a document that
 * passed. Nothing is caught here; every callee exception propagates.
 */
public final class Pipeline {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.pipeline");

    private Pipeline() {
    }

    /** {@link #anonymizeDocument(byte[], RuntimeConfig, FileConfig, LlmClient, String)} with a fresh id. */
    public static AnonymizeResult anonymizeDocument(byte[] docxBytes, RuntimeConfig config, FileConfig files,
                                                    LlmClient client) {
        return anonymizeDocument(docxBytes, config, files, client, null);
    }

    public static AnonymizeResult anonymizeDocument(byte[] docxBytes, RuntimeConfig config, FileConfig files,
                                                    LlmClient client, String documentId) {
        if (documentId == null) {
            documentId = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        }
        Map<String, Double> timings = new LinkedHashMap<>();
        long tTotal = System.nanoTime();

        long t0 = System.nanoTime();
        DocxEngine.validateDocxBytes(docxBytes);
        DocumentData document = DocxEngine.parseDocx(docxBytes, documentId);
        timings.put("parse", seconds(t0));
        LOG.info("stage=parse document_id={} units={} elapsed={}s", documentId, document.textUnits().size(),
                fixed3(timings.get("parse")));

        t0 = System.nanoTime();
        Detectors.DetectionResult detection = Detectors.detectAll(document, files.rules());
        timings.put("detect", seconds(t0));
        LOG.info("stage=detect document_id={} candidate_spans={} review_hints={} elapsed={}s", documentId,
                detection.resolverSpans().size(), detection.reviewHints().size(), fixed3(timings.get("detect")));

        t0 = System.nanoTime();
        List<Span> llmSpans = LlmDetector.runLlmDetection(document, detection.resolverSpans(),
                detection.reviewHints(), client, config);
        timings.put("llm", seconds(t0));
        LOG.info("stage=llm document_id={} llm_spans={} elapsed={}s", documentId, llmSpans.size(),
                fixed3(timings.get("llm")));

        // Review hints are LLM input only and never reach the resolver.
        t0 = System.nanoTime();
        List<Span> candidates = new ArrayList<>(llmSpans);
        candidates.addAll(detection.resolverSpans());
        RedactionPlan plan = Resolver.resolveRedactions(document, candidates, files.policy());
        timings.put("resolve", seconds(t0));
        if (plan.spans().stream().anyMatch(s -> s.action() != SpanAction.REDACT && s.action() != SpanAction.PRESERVE)) {
            throw new IllegalStateException("plan contains a non-final action — programming bug");
        }
        LOG.info("stage=resolve document_id={} plan_spans={} elapsed={}s", documentId, plan.spans().size(),
                fixed3(timings.get("resolve")));

        t0 = System.nanoTime();
        byte[] redacted = DocxEngine.writeRedactedDocx(docxBytes, document, plan);
        DocxEngine.validateDocxBytes(redacted);
        timings.put("apply", seconds(t0));
        LOG.info("stage=apply document_id={} redacted_bytes={} elapsed={}s", documentId, redacted.length,
                fixed3(timings.get("apply")));

        // Mandatory audit of exactly the bytes about to be handed back.
        t0 = System.nanoTime();
        PostcheckSummary postcheck = Postcheck.scanRedactedDocxBytes(redacted, files);
        timings.put("scan", seconds(t0));
        int high = postcheck.bySeverity().getOrDefault("HIGH", 0);
        LOG.info("stage=scan document_id={} findings={} high={} by_kind={} elapsed={}s", documentId,
                postcheck.findingsTotal(), high, PyRepr.repr(postcheck.byKind()), fixed3(timings.get("scan")));

        if (high > 0) {
            // Fail closed: kinds and locations only, never finding details or document text.
            String locations = postcheck.findings().stream()
                    .filter(f -> f.severity() == PostcheckFinding.Severity.HIGH)
                    .map(f -> f.kind() + "@" + f.location())
                    .collect(Collectors.joining(", "));
            throw new ResidualPIIError("post-redaction scan found " + high + " HIGH-severity finding(s); "
                    + "the document needs manual review (" + locations + ")");
        }

        List<String> warnings = new ArrayList<>(plan.warnings());
        if (postcheck.findingsTotal() > 0) {
            warnings.add("post-redaction scan: " + postcheck.findingsTotal() + " non-blocking finding(s) "
                    + PyRepr.repr(postcheck.byKind()));
        }
        timings.put("total", seconds(tTotal));

        Map<String, String> provenance = new LinkedHashMap<>();
        provenance.put("provider", config.provider().wire());
        provenance.put("model", config.modelHandle());
        provenance.put("config_sha256", files.configSha256());
        provenance.put("prompts_sha256", Prompts.PROMPTS_SHA256);
        provenance.put("package_version", packageVersion());

        return new AnonymizeResult(documentId, redacted, Summary.buildSummary(plan), warnings, config.modelHandle(),
                timings, postcheck, provenance);
    }

    /** JAR manifest {@code Implementation-Version} (equals pyproject's version), else "unknown". */
    static String packageVersion() {
        String v = Pipeline.class.getPackage().getImplementationVersion();
        return v == null ? "unknown" : v;
    }

    private static double seconds(long startNanos) {
        return (System.nanoTime() - startNanos) / 1e9;
    }

    private static String fixed3(double d) {
        return PyFloat.fixed(d, 3);
    }
}
