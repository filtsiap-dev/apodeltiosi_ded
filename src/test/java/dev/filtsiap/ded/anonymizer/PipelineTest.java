package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.llm.Prompts;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PipelineTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));

    @Test
    void redactsAndStampsProvenance() {
        String afm = TestDocx.validAfm("24681357");
        byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος με ΑΦΜ " + afm + ".").bytes();
        AnonymizeResult r = Pipeline.anonymizeDocument(docx, CFG, FILES, ScriptedLlm.cooperative(), "doc1");
        String xml = TestDocx.part(r.redactedDocx(), "word/document.xml");
        assertFalse(xml.contains(afm));
        assertFalse(xml.contains("Παπαδόπουλος"));
        assertTrue(xml.contains("........."));
        assertEquals("doc1", r.documentId());
        assertEquals(Prompts.PROMPTS_SHA256, r.provenance().get("prompts_sha256"));
        assertEquals(FILES.configSha256(), r.provenance().get("config_sha256"));
        assertEquals("openai", r.provenance().get("provider"));
        assertTrue(r.timings().keySet().containsAll(java.util.List.of("parse", "detect", "llm", "resolve", "apply", "scan", "total")));
    }

    @Test
    void residualHighFindingBlocksTheDocument() {
        // 31/02 is not a date, so the detector gives this AMKA only a soft REDACT (0.75); a model that calls
        // it a DATE out-ranks that, the number survives, and the mandatory scan must block the document.
        // (The scan's AMKA rule reads the digits as YYMMDD; this value matches either reading. CLAUDE.md O7.)
        byte[] docx = TestDocx.paragraphs("ΑΜΚΑ 31021512345").bytes();
        ScriptedLlm wrong = new ScriptedLlm(req -> ScriptedLlm.isPass1(req) ? "[]"
                : "[{\"text\": \"31021512345\", \"category\": \"DATE\", \"action\": \"PRESERVE\"}]");
        ResidualPIIError e = assertThrows(ResidualPIIError.class,
                () -> Pipeline.anonymizeDocument(docx, CFG, FILES, wrong, "doc2"));
        assertTrue(e.getMessage().startsWith("post-redaction scan found 1 HIGH-severity finding(s); "
                + "the document needs manual review (residual_amka@word/document.xml:u0"), e.getMessage());
        assertFalse(e.getMessage().contains("31021512345"));
    }

    @Test
    void invalidInputNeverReachesTheModel() {
        ScriptedLlm llm = ScriptedLlm.cooperative();
        assertThrows(InvalidDocumentError.class,
                () -> Pipeline.anonymizeDocument("not a docx".getBytes(), CFG, FILES, llm, "d"));
        assertEquals(0, llm.requests.size());
    }
}
