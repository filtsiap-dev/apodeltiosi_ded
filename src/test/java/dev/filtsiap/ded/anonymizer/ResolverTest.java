package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class ResolverTest {

    static final PolicySettings POLICY = Config.loadFileConfig(Path.of("config")).policy();

    static TextUnit unit(String id, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    static Span span(String unit, int s, int e, SpanCategory c, double conf, SpanAction a) {
        return new Span(unit, s, e, "", c, "test", conf, a, "");
    }

    @Test
    void hardRedactBeatsHardPreserve() {
        DocumentData doc = new DocumentData("d", List.of(unit("u0", "0123456789")), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, List.of(
                span("u0", 0, 10, SpanCategory.DATE, 0.95, SpanAction.PRESERVE),
                span("u0", 2, 5, SpanCategory.AFM, 1.0, SpanAction.REDACT)), POLICY);
        assertEquals(3, plan.spans().size());
        assertEquals(SpanAction.REDACT, plan.spans().get(1).action());
        assertEquals("234", plan.spans().get(1).text());
    }

    @Test
    void hardPreserveBeatsSoftRedact() {
        DocumentData doc = new DocumentData("d", List.of(unit("u0", "0123456789")), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, List.of(
                span("u0", 0, 10, SpanCategory.DATE, 0.95, SpanAction.PRESERVE),
                span("u0", 2, 5, SpanCategory.POSSIBLE_PERSON, 0.75, SpanAction.REDACT)), POLICY);
        assertEquals(1, plan.spans().size());
        assertEquals(SpanAction.PRESERVE, plan.spans().get(0).action());
    }

    @Test
    void outputIsOrderedLikePythonStrings() {
        DocumentData doc = new DocumentData("d", List.of(unit("u2", "abc"), unit("u10", "abc")), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, List.of(
                span("u2", 0, 3, SpanCategory.EMAIL, 0.95, SpanAction.REDACT),
                span("u10", 0, 3, SpanCategory.EMAIL, 0.95, SpanAction.REDACT)), POLICY);
        assertEquals(List.of("u10", "u2"), plan.spans().stream().map(Span::unitId).toList());
    }

    @Test
    void inconsistencyWarningNeverQuotesText() {
        DocumentData doc = new DocumentData("d", List.of(unit("u0", "Νίκος"), unit("u1", "νίκος")), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, List.of(
                new Span("u0", 0, 5, "Νίκος", SpanCategory.POSSIBLE_PERSON, "t", 0.9, SpanAction.REDACT, ""),
                new Span("u1", 0, 5, "νίκος", SpanCategory.DATE, "t", 0.95, SpanAction.PRESERVE, "")), POLICY);
        assertEquals(1, plan.warnings().size());
        assertEquals(false, plan.warnings().get(0).contains("ίκος"));
    }

    @Test
    void reviewSpansAreAProgrammingError() {
        DocumentData doc = new DocumentData("d", List.of(unit("u0", "x")), List.of(), List.of());
        assertThrows(IllegalStateException.class, () -> Resolver.resolveRedactions(doc,
                List.of(span("u0", 0, 1, SpanCategory.PHONE, 0.9, SpanAction.REVIEW)), POLICY));
    }
}
