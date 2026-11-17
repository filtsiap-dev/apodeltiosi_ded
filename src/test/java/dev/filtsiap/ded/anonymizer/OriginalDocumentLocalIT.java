package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.*;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.api.ApiServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Explicit local acceptance: mvn -o -Dtest=OriginalDocumentLocalIT -DargLine=-Xmx768m test.
 * The private fixture is never copied into test resources, changed, printed, or committed.
 * This verifies control flow and deterministic policy only, not real-model semantic accuracy. */
class OriginalDocumentLocalIT {
    static final String SHA256 = "cc6b38864d13a5976edb3791a3366ebf2d0121fd1a90317eadb0dc5cdf1e8e29";
    static final String MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "offline", "ANON_MODEL", "offline", "ANON_API_KEY", "offline"));
    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));

    static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    @Test void unchangedOriginalReachesRemediationAndReturnsAuditedDocxOverHttp() throws Exception {
        Path path;
        try (var paths = Files.walk(Path.of("."), 2)) {
            path = paths.filter(p -> p.getFileName().toString().equals("Test_big_doc.docx"))
                    .findFirst().orElseThrow(() -> new IllegalStateException("original local fixture required"));
        }
        byte[] input = Files.readAllBytes(path);
        assertEquals(SHA256, hash(input), "fixture must be the unchanged original, including source markers");
        assertEquals(192665, input.length);
        long estimate = MemoryGate.estimateBytes(ZipPackage.declaredSizes(input));
        assertTrue(MemoryGate.budgetBytes(CFG.limits()) >= estimate, "use the documented local test heap; do not bypass admission");
        ScriptedLlm fake = ScriptedLlm.cooperative();
        var result = Pipeline.anonymizeDocument(input, CFG, FILES, fake, RunContext.start(CFG.documentDeadlineS()));
        assertTrue(fake.requests.stream().anyMatch(ScriptedLlm::isRemediation));
        assertTrue(result.timings().containsKey("final_scan"));
        DocumentData source = DocxEngine.parseDocx(input, "original", CFG.limits());
        DocumentData returned = DocxEngine.parseDocx(result.redactedDocx(), "original", CFG.limits());
        assertTrue(source.sameUnitGeometry(returned), "supported text geometry must survive in this original fixture");
        assertTrue(result.postcheck().blocking().isEmpty());
        assertFalse(result.postcheck().byKind().containsKey("wrong_placeholder"));
        assertFalse(result.postcheck().byKind().containsKey("ellipsis_residue"));

        // Validate every hard policy character, not just that a valid ZIP was returned.
        List<Span> rules = Detectors.detectAll(source, FILES.rules()).resolverSpans();
        Map<String, TextUnit> outputUnits = returned.textUnits().stream()
                .collect(java.util.stream.Collectors.toMap(TextUnit::unitId, u -> u));
        long protectedPoints = 0, redactedPoints = 0;
        for (Span s : rules) {
            TextUnit output = outputUnits.get(s.unitId());
            if (Resolver.isHardRedact(s, FILES.policy())) {
                for (int i = s.start(); i < s.end(); i++) {
                    assertEquals('.', PyStr.codePointAt(output.normalizedText(), i), "hard redaction incomplete at " + s.unitId());
                    redactedPoints++;
                }
            } else if (Resolver.isHardPreserve(s, FILES.policy())) {
                for (int i = s.start(); i < s.end(); i++) {
                    int at = i;
                    if (rules.stream().anyMatch(r -> Resolver.isHardRedact(r, FILES.policy()) && r.unitId().equals(s.unitId())
                            && r.start() <= at && r.end() > at)) continue;
                    assertTrue(PyStr.codePointAt(s.text(), i - s.start()) == PyStr.codePointAt(output.normalizedText(), i),
                            "hard preserve changed at " + s.unitId());
                    protectedPoints++;
                }
            }
        }
        assertTrue(protectedPoints > 0 && redactedPoints > 0);
        for (PostcheckFinding f : result.postcheck().findings()) {
            if (f.severity() == PostcheckFinding.Severity.HIGH) {
                assertNotNull(f.span());
                assertTrue(result.unresolved().stream().anyMatch(u -> u.audit().stream().anyMatch(a -> a.kind().equals(f.kind()))
                        && u.locations().stream().anyMatch(l -> l.unitId().equals(f.span().unitId())
                        && l.start() <= f.span().start() && l.end() >= f.span().end())), "HIGH lacks complete review provenance");
            }
        }
        assertEquals(result.unresolvedCount() == 0 ? "processed" : "needs-review", result.status());

        ScriptedLlm httpFake = ScriptedLlm.cooperative();
        ApiServer server = ApiServer.start(CFG, FILES, httpFake, new InetSocketAddress("127.0.0.1", 0), 1);
        try (HttpClient http = HttpClient.newHttpClient()) {
            var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/anonymize"))
                    .header("Authorization", "Bearer offline").header("Content-Type", MIME)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(input)).build();
            var response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, response.statusCode());
            assertEquals(MIME, response.headers().firstValue("Content-Type").orElseThrow());
            assertEquals(result.status(), response.headers().firstValue("X-Anonymization-Status").orElseThrow());
            assertEquals(Integer.toString(result.unresolvedCount()), response.headers().firstValue("X-Unresolved-Count").orElseThrow());
            assertEquals(Integer.toString(result.postcheck().findingsTotal()), response.headers().firstValue("X-Postcheck-Findings").orElseThrow());
            assertTrue(response.headers().firstValue("Content-Disposition").orElseThrow()
                    .matches("attachment; filename=\"[a-zA-Z0-9_-]+_redacted\\.docx\""));
            DocumentData httpOutput = DocxEngine.parseDocx(response.body(), "http", CFG.limits());
            assertTrue(returned.textUnits().stream().map(TextUnit::normalizedText).toList()
                    .equals(httpOutput.textUnits().stream().map(TextUnit::normalizedText).toList()), "HTTP output text differs from audited pipeline output");
        } finally {
            server.stop(0);
        }
        assertEquals(SHA256, hash(Files.readAllBytes(path)), "original file was changed");
        System.out.println("ORIGINAL_ACCEPTANCE status=" + result.status() + " units=" + returned.textUnits().size()
                + " hard_preserved_points=" + protectedPoints + " hard_redacted_points=" + redactedPoints
                + " findings=" + result.postcheck().findingsTotal() + " unresolved=" + result.unresolvedCount()
                + " heap_max=" + Runtime.getRuntime().maxMemory() + " admission_estimate=" + estimate
                + " provider=offline_fake semantic_accuracy=unverified");
    }
}
