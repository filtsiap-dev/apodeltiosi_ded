package dev.filtsiap.ded.anonymizer.llm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.AITimeoutError;
import dev.filtsiap.ded.anonymizer.AIUnavailableError;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitType;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class LlmDetectorTest {

    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test", "ANON_CHUNK_SIZE_CHARS", "20"));

    static TextUnit para(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static TextUnit cell(String id, int row, int col, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.TABLE_CELL, text, text, List.of(),
                new TextUnit.TableCellLocation(0, row, col, "", row == 0));
    }

    @Test
    void tablesFirstThenParagraphsWithinTheLimit() {
        DocumentData doc = new DocumentData("d", List.of(para("u0", "0123456789"), cell("u1", 0, 1, "B"),
                cell("u2", 0, 0, "A"), para("u3", "abcdefghi"), para("u4", "long paragraph here!")), List.of(), List.of());
        List<LlmDetector.Chunk> chunks = LlmDetector.splitIntoChunks(doc, 20);
        assertEquals("TABLE:\nA | B", chunks.get(0).text());
        assertEquals("0123456789\nabcdefghi", chunks.get(1).text());
        assertEquals("long paragraph here!", chunks.get(2).text());
    }

    @Test
    void jsonArrayExtractionFallsBackToBrackets() {
        assertEquals(1, LlmDetector.extractJsonArray("Sure:\n```json\n[{\"a\": 1}]\n```").size());
        assertNull(LlmDetector.extractJsonArray("{\"not\": \"a list\"}"));
        assertNull(LlmDetector.extractJsonArray("no json"));
    }

    @Test
    void pass2ValidationDropsBadItemsAndCoercesReview() {
        List<LlmDetector.Pass2Decision> d = LlmDetector.validatePass2Entries(
                "[{\"text\": \"Νίκος\", \"category\": \"PERSON\", \"action\": \"review\"}, 7,"
                        + " {\"text\": \" \"}, {\"text\": \"x\", \"category\": \"NOPE\", \"action\": \"REDACT\"}]");
        assertEquals(1, d.size());
        assertEquals("POSSIBLE_PERSON", d.get(0).category());
        assertEquals("REDACT", d.get(0).action());
        assertTrue(d.get(0).coerced());
        assertEquals("pass-2 output could not be parsed as a JSON array",
                assertThrows(AIProviderError.class, () -> LlmDetector.validatePass2Entries("{oops")).getMessage());
    }

    @Test
    void skipDoesNotResolveAReviewHint() {
        Span hint = new Span("u0", 0, 5, "Νίκος", SpanCategory.POSSIBLE_PERSON, "t", 0.45, SpanAction.REVIEW, "");
        assertEquals(List.of("Νίκος"), LlmDetector.unresolvedReviewHints(
                List.of(new LlmDetector.Pass2Decision("νίκος", "POSSIBLE_PERSON", "SKIP", false)), List.of(hint)));
        assertEquals(List.of(), LlmDetector.unresolvedReviewHints(
                List.of(new LlmDetector.Pass2Decision("ο  ΝΙΚΟΣ", "POSSIBLE_PERSON", "REDACT", false)),
                List.of(new Span("u0", 0, 5, "Νικος", SpanCategory.POSSIBLE_PERSON, "t", 0.45, SpanAction.REVIEW, ""))));
    }

    @Test
    void shortRedactTextsOnlyMatchStandaloneTokens() {
        LlmDetector.Chunk chunk = new LlmDetector.Chunk(List.of(para("u0", "ΑΦΜ ΑΦΜΑ ΑΦΜ")), false, null);
        List<Span> spans = LlmDetector.locatePass2Decisions(
                List.of(new LlmDetector.Pass2Decision("ΑΦΜ", "AFM", "REDACT", false)), chunk);
        assertEquals(List.of(0, 9), spans.stream().map(Span::start).toList());
    }

    @Test
    void incompletePass2IsRetriedOnceThenFails() {
        DocumentData doc = new DocumentData("d", List.of(para("u0", "Νίκος")), List.of(), List.of());
        Span hint = new Span("u0", 0, 5, "Νίκος", SpanCategory.POSSIBLE_PERSON, "t", 0.45, SpanAction.REVIEW, "");
        ScriptedLlm silent = new ScriptedLlm(r -> "[]");
        AIProviderError e = assertThrows(AIProviderError.class,
                () -> LlmDetector.runLlmDetection(doc, List.of(), List.of(hint), silent, CFG));
        assertEquals("pass 2 still incomplete after one retry (chunk 0): 1 rule-flagged REVIEW entry/entries "
                + "received no REDACT or PRESERVE decision", e.getMessage());
        assertEquals(3, silent.requests.size()); // pass 1, pass 2, one retry
        assertTrue(silent.requests.get(2).userMessage().contains("YOUR PREVIOUS RESPONSE WAS REJECTED"));
    }

    @Test
    void providerFailuresMapToTypedErrors() {
        DocumentData doc = new DocumentData("d", List.of(para("u0", "κείμενο")), List.of(), List.of());
        assertEquals("LLM call timed out after 60.0s (chunk 0, pass 1)", assertThrows(AITimeoutError.class,
                () -> LlmDetector.runLlmDetection(doc, List.of(), List.of(),
                        new ScriptedLlm(r -> { throw LlmCallException.timeout(null); }), CFG)).getMessage());
        assertThrows(AIUnavailableError.class, () -> LlmDetector.runLlmDetection(doc, List.of(), List.of(),
                new ScriptedLlm(r -> { throw LlmCallException.connection(null); }), CFG));
        assertEquals("provider returned HTTP 429 (chunk 0, pass 1)", assertThrows(AIProviderError.class,
                () -> LlmDetector.runLlmDetection(doc, List.of(), List.of(),
                        new ScriptedLlm(r -> { throw LlmCallException.status(429, null); }), CFG)).getMessage());
        assertEquals("empty completion (possible content filter) (chunk 0, pass 1)", assertThrows(AIProviderError.class,
                () -> LlmDetector.runLlmDetection(doc, List.of(), List.of(), new ScriptedLlm(r -> ""), CFG)).getMessage());
    }

    @Test
    void generatedPromptTextIsExactlyPythons() throws Exception {
        var f = PromptText.class.getDeclaredField("PYTHON_PROMPTS_SHA256");
        f.setAccessible(true);
        assertEquals(f.get(null), Prompts.PROMPTS_SHA256);
    }
}
