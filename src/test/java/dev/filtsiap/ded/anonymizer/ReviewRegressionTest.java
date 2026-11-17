package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.*;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.HashSet;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Synthetic, public test data only. End-to-end checks for the independent review findings. */
class ReviewRegressionTest {
    static final FileConfig FILES = PipelineTest.FILES;
    static final ResourceLimits LIMITS = ResourceLimits.DEFAULTS;

    static DocumentData parse(byte[] bytes) { return DocxEngine.parseDocx(bytes, "review-test", LIMITS); }
    static AnonymizeResult run(byte[] bytes, ScriptedLlm fake) {
        return PipelineTest.run(bytes, PipelineTest.CFG, FILES, fake, "review-test");
    }
    static String hidden(String text) {
        return "<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>" + text + "</w:t></w:r></w:p>";
    }
    static Span span(String unit, int start, int end, String text, SpanCategory category, SpanAction action) {
        return new Span(unit, start, end, text, category, "test", 1, action, "", SpanOrigin.DETERMINISTIC);
    }
    static RedactionPlan plan(List<Span> spans) { return new RedactionPlan("review-test", spans, List.of()); }

    @Test void sourceMarkersSurviveButNewExtendedAndUnlocatedMarkersBlock() {
        byte[] input = TestDocx.paragraphs("😀 ***** [NAME] ……", "elsewhere *****").bytes();
        AnonymizeResult result = run(input, ScriptedLlm.cooperative());
        assertTrue(result.postcheck().blocking().isEmpty());
        assertTrue(parse(result.redactedDocx()).textUnits().getFirst().normalizedText().contains("***** [NAME] ……"));
        assertFalse(Postcheck.scanRedactedDocxBytes(result.redactedDocx(), FILES, null, LIMITS).blocking().isEmpty());
        for (String changed : List.of("😀 ****** [NAME] ……", "😀 ***** [AFM] ……", "😀 ***** [NAME] ………")) {
            byte[] out = TestDocx.paragraphs(changed, "elsewhere *****").bytes();
            assertFalse(Postcheck.scanRedactedDocxBytes(out, FILES, parse(input), LIMITS).blocking().isEmpty());
        }
        byte[] elsewhere = TestDocx.paragraphs("*****", "normal").bytes();
        assertFalse(Postcheck.scanRedactedDocxBytes(TestDocx.paragraphs("normal", "*****").bytes(), FILES,
                parse(elsewhere), LIMITS).blocking().isEmpty());
    }

    @Test void sourceDigitMasksAreLocatedHighQuestionsWithoutDiagnosticText() {
        byte[] bytes = TestDocx.paragraphs("😀 *****12345").bytes();
        PostcheckSummary audit = Postcheck.scanRedactedDocxBytes(bytes, FILES, parse(bytes), LIMITS);
        PostcheckFinding finding = audit.findings().stream().filter(f -> f.kind().equals("source_mask_identifier"))
                .findFirst().orElseThrow();
        assertEquals(2, finding.span().start());
        assertEquals(12, finding.span().end());
        assertEquals(PostcheckFinding.Severity.HIGH, finding.severity());
        assertTrue(audit.blocking().isEmpty());
        assertFalse(finding.toString().contains("12345"));
        assertFalse(PyJson.dumps(audit.asMap()).contains("12345"));
        AnonymizeResult redacted = run(bytes, ScriptedLlm.cooperative());
        assertFalse(TestDocx.part(redacted.redactedDocx(), "word/document.xml").contains("12345"));
    }

    @Test void writerTraceSurvivesRemovedUnitsRepeatedTextDifferentPartsAndASecondWrite() {
        byte[] bytes = TestDocx.paragraphs().document(hidden("same …… *****")
                + "<w:del>" + TestDocx.p("deleted") + "</w:del>"
                + TestDocx.p("same …… *****") + TestDocx.p("same …… *****")
                + "<w:ins>" + TestDocx.p("😀 visible …… *****") + "</w:ins>")
                .put("word/header1.xml", "<w:hdr xmlns:w=\"" + DocxEngine.W_NS + "\">"
                        + TestDocx.p("same …… *****") + "</w:hdr>").bytes();
        DocumentData source = parse(bytes);
        DocxEngine.WriteResult first = DocxEngine.writeRedactedDocxWithTrace(bytes, source, plan(List.of()), LIMITS);
        assertEquals(4, first.document().textUnits().size());
        assertEquals(List.of(new UnitSlice("u0", 0, 4)), first.correspondence().translate(new UnitSlice("u2", 0, 4)));
        assertTrue(first.correspondence().translate(new UnitSlice("u0", 0, 4)).isEmpty());
        Span redact = span("u2", 2, 9, "visible", SpanCategory.APPELLANT_NAME, SpanAction.REDACT);
        DocxEngine.WriteResult second = DocxEngine.writeRedactedDocxWithTrace(first.bytes(), first.document(),
                plan(List.of(redact)), LIMITS);
        PostcheckSummary audit = Postcheck.scanRedactedDocxBytes(second.bytes(), FILES, source, plan(List.of()), LIMITS,
                first.correspondence().then(second.correspondence()));
        assertTrue(audit.blocking().isEmpty());
        assertTrue(run(bytes, ScriptedLlm.cooperative()).postcheck().blocking().isEmpty());
    }

    @Test void resizedUnitsKeepOnlyTheirActualSurvivingPolicyLocations() {
        byte[] bytes = TestDocx.paragraphs().document("<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>hidden</w:t></w:r>"
                + "<w:r><w:t>οδός 😀 …… *****</w:t><w:tab/><w:t>end</w:t></w:r></w:p>").bytes();
        DocumentData source = parse(bytes);
        DocxEngine.WriteResult written = DocxEngine.writeRedactedDocxWithTrace(bytes, source, plan(List.of()), LIMITS);
        Span label = span("u0", 6, 10, "οδός", SpanCategory.FIELD_LABEL, SpanAction.PRESERVE);
        List<Span> kept = written.correspondence().translateSpans(List.of(label), false);
        assertEquals(1, kept.size());
        assertEquals(0, kept.getFirst().start());
        assertEquals("οδός", kept.getFirst().text());
        assertTrue(written.correspondence().translateSpans(List.of(label), true).isEmpty());
        assertTrue(Postcheck.scanRedactedDocxBytes(written.bytes(), FILES, source, plan(List.of()), LIMITS,
                written.correspondence()).blocking().isEmpty());
        // Removing text BETWEEN stars must not prove that the newly joined run existed in the source.
        byte[] joined = TestDocx.paragraphs().document("<w:p><w:r><w:t>***</w:t></w:r><w:r><w:rPr><w:vanish/>"
                + "</w:rPr><w:t>x</w:t></w:r><w:r><w:t>***</w:t></w:r></w:p>").bytes();
        assertThrows(ResidualPIIError.class, () -> run(joined, ScriptedLlm.cooperative()));
    }

    @Test void nestedTablesAndTextboxesHaveUniquePhysicalOwnershipAndPreserveAllText() {
        String inner = "<w:tbl><w:tr><w:tc>" + TestDocx.p("inner😀") + "</w:tc></w:tr></w:tbl>";
        String textbox = "<w:p><w:r><w:t>outer</w:t><w:pict><w:txbxContent>" + TestDocx.p("box😀")
                + "</w:txbxContent></w:pict><w:t>tail</w:t></w:r></w:p>";
        byte[] bytes = TestDocx.paragraphs().document("<w:tbl><w:tr><w:tc>" + TestDocx.p("before") + inner
                + TestDocx.p("after") + "</w:tc></w:tr></w:tbl>" + textbox).bytes();
        DocumentData doc = parse(bytes);
        var refs = doc.textUnits().stream().flatMap(u -> u.charMap().stream()).toList();
        assertEquals(refs.size(), new HashSet<>(refs).size());
        assertEquals("beforeinner😀afteroutertailbox😀", doc.textUnits().stream().map(TextUnit::normalizedText)
                .collect(java.util.stream.Collectors.joining()));
        TextUnit cell = doc.textUnits().getFirst();
        Span keep = span(cell.unitId(), 6, 12, "inner😀", SpanCategory.MONEY, SpanAction.PRESERVE);
        Span remove = new Span(cell.unitId(), 6, 12, "inner😀", SpanCategory.POSSIBLE_PERSON, "test", 1,
                SpanAction.REDACT, "", SpanOrigin.LLM_PASS2);
        byte[] output = DocxEngine.writeRedactedDocx(bytes, doc, Resolver.resolveRedactions(doc,
                List.of(keep, remove), FILES.policy()), LIMITS);
        assertTrue(TestDocx.part(output, "word/document.xml").contains("inner😀"));
    }

    @Test void allowlistsRespectUnicodeTokensAndDottedAbbreviations() {
        for (String text : List.of("ΝΙΚΑΣ", "ΙΚΑ2", "2ΙΚΑ", "ΙΚΑ\u0301", "\u0301ΙΚΑ", "xΙΚΑ")) {
            assertTrue(DetectorSupport.allowlistMatches(text, List.of("ΙΚΑ")).isEmpty());
        }
        for (String text : List.of("ΙΚΑ", "(ΙΚΑ)", "ΙΚΑ,", "ΙΚΑ. 2")) {
            assertEquals(1, DetectorSupport.allowlistMatches(text, List.of("ΙΚΑ")).size());
        }
        assertEquals(1, DetectorSupport.allowlistMatches("(Δ.Ο.Υ.)", List.of("Δ.Ο.Υ.")).size());
        assertEquals(1, DetectorSupport.allowlistMatches("ν.1234/2020", List.of("ν."), true).size());
        assertEquals(1, DetectorSupport.allowlistMatches("Π.Δ.12", List.of("Π.Δ."), true).size());
        assertTrue(DetectorSupport.allowlistMatches("νόμος1234", List.of("νόμος"), true).isEmpty());
        assertTrue(DetectorSupport.allowlistMatches("Ν.ΙΚΑΣ", List.of("Ν."), true).isEmpty());
        assertEquals("ν.", Detectors.detectLegalRefs(parse(TestDocx.paragraphs("ν.1234/2020").bytes())
                .textUnits().getFirst(), FILES.rules()).stream().filter(s -> s.text().equals("ν.")).findFirst().orElseThrow().text());
        byte[] bytes = TestDocx.paragraphs("Η ενδικοφανή προσφυγή του ΓΕΩΡΓΙΟΣ ΝΙΚΑΣ.", "ΙΚΑ").bytes();
        var result = parse(run(bytes, ScriptedLlm.cooperative()).redactedDocx());
        assertFalse(result.textUnits().getFirst().normalizedText().contains("ΙΚΑ"));
        assertEquals("ΙΚΑ", result.textUnits().get(1).normalizedText());
    }

    @Test void privateLabeledPhonesAreReaskedAndPublicContactsStayVisible() {
        String number = "6912345678";
        String table = "<w:tbl><w:tr><w:tc>" + TestDocx.p("Τηλέφωνο προσφεύγοντος: " + number)
                + "</w:tc></w:tr></w:tbl>";
        byte[] bytes = TestDocx.paragraphs().document(TestDocx.p("ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ")
                + TestDocx.p("Τηλέφωνο: " + number) + TestDocx.p("ΑΠΟΦΑΣΗ") + table).bytes();
        ScriptedLlm fake = new ScriptedLlm(r -> ScriptedLlm.isPass1(r) ? "[]" : PyJson.dumps(ScriptedLlm.candidates(r)
                .stream().map(c -> ScriptedLlm.answer((String)c.get("id"), ScriptedLlm.isRemediation(r)
                        ? "REDACT" : "PRESERVE", "PHONE")).toList()));
        AnonymizeResult result = run(bytes, fake);
        String xml = TestDocx.part(result.redactedDocx(), "word/document.xml");
        assertTrue(xml.contains("Τηλέφωνο: " + number));
        assertTrue(xml.contains("Τηλέφωνο προσφεύγοντος: .........."));
        assertEquals(1, fake.requests.stream().filter(ScriptedLlm::isRemediation).count());
        assertFalse(PostcheckSupport.looksLikeOfficialContactPhone("ΑΑΔΕ\nΤηλέφωνο προσφεύγοντος: " + number, 30));
        assertFalse(PostcheckSupport.looksLikeOfficialContactPhone("Τηλέφωνο: " + number, 10));
        for (String context : List.of("ΑΑΔΕ\nπροσφεύγοντος\nΤηλέφωνο: ", "ΔΕΔΟΜΕΝΑ\nΤηλέφωνο: ")) {
            assertFalse(PostcheckSupport.looksLikeOfficialContactPhone(context + number, PyStr.len(context)));
        }
    }

    @Test void lostDiscoveryNeedsReviewButValidEmptyAndSkipReadingsDoNot() {
        byte[] bytes = TestDocx.paragraphs("John Smith").bytes();
        for (String response : List.of("not json", "[{}]", "[{\"text\":\"John Smith\",\"action\":\"REDACT\","
                + "\"category\":\"PERSON\"},{}]")) {
            ScriptedLlm fake = new ScriptedLlm(r -> ScriptedLlm.isPass1(r) ? response
                    : PyJson.dumps(ScriptedLlm.agreeWithEveryCandidate(r)));
            AnonymizeResult result = run(bytes, fake);
            assertEquals("needs-review", result.status());
            assertTrue(result.unresolved().stream().anyMatch(f -> f.kind() == UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE));
            assertEquals(2, fake.requests.stream().filter(ScriptedLlm::isPass1).count());
        }
        for (String response : List.of("[]", "[{\"action\":\"SKIP\"}]")) {
            ScriptedLlm fake = new ScriptedLlm(r -> response);
            assertEquals("processed", run(bytes, fake).status());
            assertEquals(1, fake.requests.size());
        }
    }

    @Test void phonesAtUnitBoundariesAreIndependentAuditOccurrences() {
        byte[] bytes = TestDocx.paragraphs("6912345678", "6912345678", "tail").bytes();
        PostcheckSummary scan = Postcheck.scanRedactedDocxBytes(bytes, FILES, null, LIMITS);
        assertEquals(2, scan.byKind().get("phone_shape"));
        assertEquals(List.of("u0", "u1"), scan.findings().stream().filter(f -> f.kind().equals("phone_shape"))
                .map(f -> f.span().unitId()).toList());
    }

    /**
     * A large document-wide queue (450 questions: pass 1 could not decide any of them) is sent in batches
     * of at most 30; a batch the provider reports cut at the length limit is split into smaller requests
     * with the ORIGINAL ids; every id is answered exactly once, and every answer is written back.
     */
    @Test void largeTableAdjudicationSplitsOnlyAfterReportedLengthAndRetainsEveryId() {
        StringBuilder rows = new StringBuilder("<w:tbl><w:tr><w:tc>" + TestDocx.p("ΠΑΡΑΣΤΑΤΙΚΟ") + "</w:tc></w:tr>");
        List<Object> review = new java.util.ArrayList<>();
        for (int i = 0; i < 450; i++) {
            rows.append("<w:tr><w:tc>").append(TestDocx.p("INV-" + (1000 + i))).append("</w:tc></w:tr>");
            review.add(java.util.Map.of("text", "INV-" + (1000 + i), "action", "REVIEW", "category", "INVOICE_TABLE_ID"));
        }
        byte[] bytes = TestDocx.paragraphs().document(rows.append("</w:tbl>").toString()).bytes();
        java.util.Set<String> answered = java.util.concurrent.ConcurrentHashMap.newKeySet();
        java.util.List<Integer> sizes = new java.util.concurrent.CopyOnWriteArrayList<>();
        ScriptedLlm fake = ScriptedLlm.completions(r -> {
            if (ScriptedLlm.isPass1(r)) return ScriptedLlm.finished(PyJson.dumps(review));
            var candidates = ScriptedLlm.candidates(r);
            sizes.add(candidates.size());
            if (candidates.size() > 5) return new dev.filtsiap.ded.anonymizer.llm.LlmClient.Completion("[]", "length", false);
            candidates.forEach(c -> assertTrue(answered.add((String)c.get("id")), "candidate was answered twice across batches"));
            return ScriptedLlm.finished(PyJson.dumps(ScriptedLlm.agreeWithEveryCandidate(r)));
        });
        AnonymizeResult result = run(bytes, fake);
        assertEquals(450, answered.size());
        java.util.Set<String> expected = new HashSet<>();
        for (int i = 1; i <= 450; i++) expected.add("C" + i);
        assertEquals(expected, answered); // the document-wide ids, each once
        assertTrue(sizes.stream().allMatch(n -> n <= 30), sizes.toString()); // never one oversized call
        assertEquals(15, sizes.stream().filter(n -> n == 30).count()); // 15 batches, each cut and split once
        assertTrue(result.unresolved().isEmpty(), result.unresolved().toString());
        assertFalse(TestDocx.part(result.redactedDocx(), "word/document.xml").contains("INV-"));
    }

    @Test void shallowMalformedXmlIsNotAResourceViolationAndDepthBoundariesHold() throws Exception {
        assertThrows(LxmlDom.XmlSyntaxError.class, () -> LxmlDom.parseStrict("<r><x></r>".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertNotNull(LxmlDom.parseStrict(("<x>".repeat(256) + "</x>".repeat(256)).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals("XML_TOO_DEEP", assertThrows(ResourceLimitExceededError.class,
                () -> LxmlDom.parseStrict(("<x>".repeat(257) + "</x>".repeat(257)).getBytes(java.nio.charset.StandardCharsets.UTF_8))).code());
        assertFalse(LxmlDom.isDepthLimitDiagnostic("malformed shallow XML"));
        assertThrows(LxmlDom.XmlSyntaxError.class, () -> LxmlDom.parseStrict(
                "<jdk.xml.maxElementDepth></wrong>".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }
}
