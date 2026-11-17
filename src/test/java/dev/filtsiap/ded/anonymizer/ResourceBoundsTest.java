package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * R-1 (memory) and R-2 (depth): what a small hostile upload can make the process allocate or
 * recurse into is bounded before it is allocated, and refused with a 413-class error, never an
 * OutOfMemoryError or StackOverflowError.
 */
class ResourceBoundsTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));

    static RuntimeConfig config(String... overrides) {
        Map<String, String> env = new HashMap<>(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test"));
        for (int i = 0; i < overrides.length; i += 2) {
            env.put(overrides[i], overrides[i + 1]);
        }
        return Config.loadRuntimeConfig(env);
    }

    static AnonymizeResult run(byte[] docx, RuntimeConfig cfg) {
        return Pipeline.anonymizeDocument(docx, cfg, FILES, ScriptedLlm.cooperative(), RunContext.start(60));
    }

    static ResourceLimitExceededError refused(byte[] docx, RuntimeConfig cfg) {
        return assertThrows(ResourceLimitExceededError.class, () -> run(docx, cfg));
    }

    static String nested(String open, String close, int depth) {
        return open.repeat(depth) + close.repeat(depth);
    }

    // ------------------------------------------------------------------ R-2: depth

    @Test
    void aMainDocumentNestedDeeperThanTheLimitIsRefusedNotOverflowed() {
        byte[] docx = TestDocx.paragraphs("κείμενο").document(TestDocx.p("κείμενο")
                + "<w:p>" + nested("<w:sdt>", "</w:sdt>", 20_000) + "</w:p>").bytes();
        assertEquals("XML_TOO_DEEP", refused(docx, config()).code());
    }

    @Test
    void aMalformedSidePartNestedDeeperThanTheLimitIsRefusedByTheRecoveringParserToo() {
        // Unclosed, so the strict parse fails and the lenient one (jsoup, any depth) takes over:
        // before the bound, converting its tree recursed once per level and overflowed the stack.
        byte[] docx = TestDocx.paragraphs("κείμενο").put("customXml/item1.xml", "<r>" + "<a>".repeat(100_000))
                .bytes();
        assertEquals("XML_TOO_DEEP", refused(docx, config()).code());
    }

    @Test
    void aWellFormedSidePartNestedDeeperThanTheLimitIsRefused() {
        byte[] docx = TestDocx.paragraphs("κείμενο").put("customXml/item1.xml", nested("<a>", "</a>", 5_000))
                .bytes();
        assertEquals("XML_TOO_DEEP", refused(docx, config()).code());
    }

    @Test
    void nestingWithinTheLimitIsProcessedOnEveryJdk() {
        // 200 levels: under lxml's (and so v2's) 256, above the JDK 24+ default of 100.
        byte[] docx = TestDocx.paragraphs("κείμενο").put("customXml/item1.xml", nested("<a>", "</a>", 200))
                .bytes();
        assertNotNull(run(docx, config()).redactedDocx());
    }

    // ------------------------------------------------------------------ R-1: memory

    @Test
    void xmlPartsOverTheirLimitAreRefusedFromTheCentralDirectory() {
        byte[] docx = TestDocx.paragraphs("κείμενο").put("customXml/item1.xml", "<r>" + "<a/>".repeat(1_000) + "</r>")
                .bytes();
        RuntimeConfig small = config("ANON_MAX_XML_BYTES", "2000");
        assertEquals("XML_TOTAL_TOO_LARGE", refused(docx, small).code());
        // The same answer from the package reader itself, whoever calls it.
        ResourceLimitExceededError e = assertThrows(ResourceLimitExceededError.class,
                () -> DocxEngine.validateDocxBytes(docx, small.limits()));
        assertEquals("XML_TOTAL_TOO_LARGE", e.code());
        assertNotNull(run(docx, config()).redactedDocx()); // under the default
    }

    @Test
    void aDocumentWhoseEstimateExceedsTheWholeBudgetIsRefusedRatherThanLeftWaiting() {
        byte[] docx = TestDocx.paragraphs("κείμενο").put("customXml/item1.xml", "<r>" + "<a/>".repeat(30_000) + "</r>")
                .bytes();
        ZipPackage.DeclaredSizes sizes = ZipPackage.declaredSizes(docx);
        long estimate = MemoryGate.estimateBytes(sizes);
        assertTrue(estimate > MemoryGate.BASE_BYTES + sizes.xmlBytes() * 99, "estimate " + estimate);
        RuntimeConfig tight = config("ANON_MEMORY_BUDGET_BYTES", Long.toString(estimate - 1));
        assertEquals("MEMORY_BUDGET_EXCEEDED", refused(docx, tight).code());
        assertNotNull(run(docx, config("ANON_MEMORY_BUDGET_BYTES", Long.toString(estimate))).redactedDocx());
    }

    @Test
    void aDocumentWaitsForRoomAndIsAdmittedWhenItFrees() throws Exception {
        byte[] docx = TestDocx.paragraphs("κείμενο").put("customXml/item1.xml", "<r>" + "<a/>".repeat(30_000) + "</r>")
                .bytes();
        long estimate = MemoryGate.estimateBytes(ZipPackage.declaredSizes(docx));
        // Room for one such document, not two; a budget no other test uses, so its own gate.
        ResourceLimits limits = config("ANON_MEMORY_BUDGET_BYTES", Long.toString(estimate + 7_777)).limits();
        MemoryGate.Permit first = MemoryGate.admit(docx, limits, RunContext.start(60).deadline(), "t");
        CompletableFuture<MemoryGate.Permit> second = CompletableFuture.supplyAsync(
                () -> MemoryGate.admit(docx, limits, RunContext.start(60).deadline(), "t"));
        Thread.sleep(300);
        assertFalse(second.isDone(), "admitted while the budget was held");
        first.close();
        second.get(5, TimeUnit.SECONDS).close();
        // With no room until its deadline, a document times out instead of waiting forever.
        MemoryGate.Permit held = MemoryGate.admit(docx, limits, RunContext.start(60).deadline(), "t");
        try {
            assertThrows(DocumentTimeoutError.class,
                    () -> MemoryGate.admit(docx, limits, RunContext.start(0.3).deadline(), "t"));
        } finally {
            held.close();
        }
    }

    @Test
    void theTextLimitStopsExtractionInsideOneHugeParagraph() {
        RuntimeConfig ten = config("ANON_MAX_TEXT_CHARS", "1000");
        ResourceLimitExceededError e = assertThrows(ResourceLimitExceededError.class,
                () -> DocxEngine.parseDocx(TestDocx.paragraphs("α".repeat(200_000)).bytes(), "d", ten.limits()));
        assertEquals("TEXT_TOO_LARGE", e.code());
        assertEquals("document holds more than 1000 characters of text; the limit is 1000", e.getMessage());
    }
}
