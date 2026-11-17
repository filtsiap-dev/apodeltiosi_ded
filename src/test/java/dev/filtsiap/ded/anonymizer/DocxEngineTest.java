package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class DocxEngineTest {

    private static final ResourceLimits LIMITS = ResourceLimits.DEFAULTS;

    @Test
    void parsesParagraphsAndTablesWithCodePointCharMaps() {
        String table = "<w:tbl><w:tr><w:tc>" + TestDocx.p("ΑΦΜ") + "</w:tc></w:tr><w:tr><w:tc>" + TestDocx.p("123")
                + "</w:tc></w:tr></w:tbl>";
        byte[] docx = TestDocx.paragraphs().document(table + TestDocx.p("a😀b")).bytes();
        DocumentData doc = DocxEngine.parseDocx(docx, "d", LIMITS);
        assertEquals(3, doc.textUnits().size());
        TextUnit cell = doc.textUnits().get(1);
        assertEquals(UnitType.TABLE_CELL, cell.unitType());
        assertEquals("ΑΦΜ", cell.location().columnHeader());
        TextUnit para = doc.textUnits().get(2);
        assertEquals(3, para.charMap().size()); // the emoji is one code point, one ref
        assertEquals(2, para.charMap().get(2).charIndex());
    }

    /** One table row; {@code marker} is the row's {@code w:tblHeader} element, or null for none. */
    static String row(String marker, String... cells) {
        StringBuilder s = new StringBuilder("<w:tr>");
        if (marker != null) {
            s.append("<w:trPr>").append(marker).append("</w:trPr>");
        }
        for (String c : cells) {
            s.append("<w:tc>").append(c.isEmpty() ? "<w:p/>" : TestDocx.p(c)).append("</w:tc>");
        }
        return s.append("</w:tr>").toString();
    }

    static List<TextUnit> tableCells(String... rows) {
        byte[] docx = TestDocx.paragraphs().document("<w:tbl>" + String.join("", rows) + "</w:tbl>").bytes();
        return DocxEngine.parseDocx(docx, "d", LIMITS).textUnits().stream()
                .filter(u -> u.unitType() == UnitType.TABLE_CELL).toList();
    }

    /** "header text" per cell, "*" for a header-row cell: the whole table's header classification at a glance. */
    static List<String> headers(List<TextUnit> cells) {
        return cells.stream().map(u -> ((TextUnit.TableCellLocation) u.location()).isHeaderRow() ? "*"
                : u.location().columnHeader()).toList();
    }

    @Test
    void explicitWordHeaderRowsAreHeadersIncludingSeveral() {
        List<TextUnit> cells = tableCells(row("<w:tblHeader/>", "Στοιχεία", ""), row("<w:tblHeader/>", "ΑΦΜ", "Ποσό"),
                row(null, "Γεώργιος", "100"));
        assertEquals(List.of("*", "*", "*", "ΑΦΜ", "Ποσό"), headers(cells));
        // Switched off, the marker is no header; and that first row of free text is data.
        assertEquals(List.of("", "", "", ""), headers(tableCells(row("<w:tblHeader w:val=\"0\"/>", "Περιγραφή", "Τιμή"),
                row(null, "x", "y"))));
    }

    @Test
    void anUnmarkedFirstRowIsAHeaderOnlyWhenItIsPositivelyARowOfLabels() {
        // Strong evidence: a majority of known labels, at least two, no digits.
        assertEquals(List.of("*", "*", "*", "ΑΦΜ", "Ονοματεπώνυμο", "Ποσό"),
                headers(tableCells(row(null, "ΑΦΜ", "Ονοματεπώνυμο", "Ποσό"), row(null, "1", "Γεώργιος", "5"))));
        // A one-column table whose only cell is a known label.
        assertEquals(List.of("*", "ΑΦΜ"), headers(tableCells(row(null, "ΑΦΜ"), row(null, "123"))));
        // Data, or ambiguous: no header at all, so no column header reaches any cell.
        for (String[] first : List.of(new String[] {"ΑΦΜ", "123456789"}, new String[] {"ΣΥΝΟΛΟ", "1.250,00", "24"},
                new String[] {"Γεώργιος Παπαδόπουλος", "Λαμία"}, new String[] {"ΣΥΝΟΛΟ", "Παρατηρήσεις"},
                new String[] {"ΑΦΜ", "Περιγραφή", "Σχόλια"})) {
            String[] second = new String[first.length];
            java.util.Arrays.fill(second, "τιμή");
            List<TextUnit> cells = tableCells(row(null, first), row(null, second));
            assertTrue(headers(cells).stream().allMatch(String::isEmpty), String.join(" | ", first) + " -> "
                    + headers(cells));
        }
        // A single-row table has no header to give.
        assertEquals(List.of("", ""), headers(tableCells(row(null, "ΑΦΜ", "Ονοματεπώνυμο"))));
    }

    /** A first row that is not positively a header can never make the column map hard-preserve the cells below it. */
    @Test
    void anAmbiguousFirstRowNeverDrivesTheColumnRules() {
        List<TextUnit> cells = tableCells(row(null, "ΣΥΝΟΛΟ", "Γεώργιος Παπαδόπουλος"),
                row(null, "Νικόλαος Ιωάννου", "οδός Ερμού 5"));
        DocumentData doc = new DocumentData("d", cells, List.of(), List.of());
        List<Span> spans = Detectors.detectAll(doc, Config.loadFileConfig(java.nio.file.Path.of("config")).rules())
                .resolverSpans();
        assertTrue(spans.stream().noneMatch(s -> s.detector().equals("table_cell_header")), spans.toString());
        // With the same row as a real Word header, the column map applies as before.
        List<TextUnit> marked = tableCells(row("<w:tblHeader/>", "ΣΥΝΟΛΟ", "Όνομα"), row(null, "1.250,00", "Γεώργιος"));
        List<Span> markedSpans = Detectors.detectAll(new DocumentData("d", marked, List.of(), List.of()),
                Config.loadFileConfig(java.nio.file.Path.of("config")).rules()).resolverSpans();
        assertTrue(markedSpans.stream().anyMatch(s -> s.detector().equals("table_cell_header")
                && s.category() == SpanCategory.MONEY && s.text().equals("1.250,00")), markedSpans.toString());
    }

    @Test
    void redactionIsOneGlyphPerCodePoint() {
        byte[] docx = TestDocx.paragraphs("x😀y").bytes();
        DocumentData doc = DocxEngine.parseDocx(docx, "d", LIMITS);
        RedactionPlan plan = new RedactionPlan("d", List.of(
                new Span("u0", 1, 2, "😀", SpanCategory.POSSIBLE_PERSON, "t", 1, SpanAction.REDACT, "",
                        SpanOrigin.DETERMINISTIC)), List.of());
        String xml = TestDocx.part(DocxEngine.writeRedactedDocx(docx, doc, plan, LIMITS), "word/document.xml");
        assertTrue(xml.contains(">x.y<"), xml);
    }

    @Test
    void metadataCommentsTrackedChangesAndHiddenTextAreCleaned() {
        String body = "<w:p><w:ins><w:r><w:t>kept</w:t></w:r></w:ins><w:del><w:r><w:delText>gone</w:delText></w:r></w:del>"
                + "<w:r><w:rPr><w:vanish/></w:rPr><w:t>hidden</w:t></w:r><w:commentReference w:id=\"0\"/></w:p>";
        byte[] docx = TestDocx.paragraphs().document(body)
                .put("docProps/core.xml", "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" "
                        + "xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:creator>Συγγραφέας</dc:creator></cp:coreProperties>")
                .put("word/comments.xml", "<w:comments " + TestDocx.W + "><w:comment w:id=\"0\">" + TestDocx.p("σχόλιο") + "</w:comment></w:comments>")
                .put("docProps/custom.xml", "<Properties/>")
                .bytes();
        byte[] out = DocxEngine.writeRedactedDocx(docx, DocxEngine.parseDocx(docx, "d", LIMITS), new RedactionPlan("d", List.of(), List.of()), LIMITS);
        String doc = TestDocx.part(out, "word/document.xml");
        assertTrue(doc.contains("kept"));
        assertFalse(doc.contains("gone") || doc.contains("hidden") || doc.contains("commentReference"));
        assertFalse(TestDocx.part(out, "docProps/core.xml").contains("Συγγραφέας"));
        assertFalse(TestDocx.part(out, "word/comments.xml").contains("σχόλιο"));
        assertEquals(null, TestDocx.part(out, "docProps/custom.xml"));
    }

    @Test
    void strictMainDocumentContract() {
        assertEquals("Not a valid DOCX package", assertThrows(InvalidDocumentError.class,
                () -> DocxEngine.validateDocxBytes("hello".getBytes(StandardCharsets.UTF_8), LIMITS)).getMessage());
        assertEquals("Not a valid DOCX package: missing _rels/.rels", assertThrows(InvalidDocumentError.class,
                () -> DocxEngine.validateDocxBytes(TestDocx.paragraphs("x").remove("_rels/.rels").bytes(), LIMITS)).getMessage());
        assertTrue(assertThrows(InvalidDocumentError.class, () -> DocxEngine.validateDocxBytes(
                TestDocx.paragraphs().put("word/document.xml", "<w:document " + TestDocx.W + "><w:body>").bytes(), LIMITS))
                .getMessage().startsWith("word/document.xml is not valid XML: "));
        assertEquals("word/document.xml has no w:body element", assertThrows(InvalidDocumentError.class,
                () -> DocxEngine.validateDocxBytes(TestDocx.paragraphs().put("word/document.xml",
                        "<w:document " + TestDocx.W + "/>").bytes(), LIMITS)).getMessage());
    }

    static final String RELS_NS = "xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"";

    static String rels(String... targets) {
        StringBuilder out = new StringBuilder("<Relationships " + RELS_NS + ">");
        for (int i = 0; i < targets.length; i++) {
            out.append("<Relationship Id=\"rId").append(i + 1).append("\" Type=\"").append(TestDocx.OFFICE_DOCUMENT_REL)
                    .append("\" Target=\"").append(targets[i]).append("\"/>");
        }
        return out.append("</Relationships>").toString();
    }

    static AnonymizerError refusal(TestDocx docx) {
        return assertThrows(AnonymizerError.class, () -> DocxEngine.validateDocxBytes(docx.bytes(), LIMITS));
    }

    static void refused(Class<? extends AnonymizerError> type, String code, String message, TestDocx docx) {
        AnonymizerError e = refusal(docx);
        assertEquals(type, e.getClass(), e.getMessage());
        assertEquals(code, e.code());
        if (message != null) {
            assertEquals(message, e.getMessage());
        }
    }

    /** v2's validate_docx_package, check by check: the package must say what it is, once, coherently. */
    @Test
    void thePackageStructureIsValidatedStrictly() {
        String ct = "[Content_Types].xml";
        refused(InvalidDocumentError.class, "MALFORMED_PACKAGE_XML", null, TestDocx.paragraphs("x").put(ct, "not XML"));
        assertTrue(refusal(TestDocx.paragraphs("x").put(ct, "not XML")).getMessage()
                .startsWith("[Content_Types].xml is not valid XML: "));
        refused(InvalidDocumentError.class, "MALFORMED_PACKAGE_XML", "[Content_Types].xml has an unexpected root element",
                TestDocx.paragraphs("x").put(ct, "<Types/>"));
        refused(InvalidDocumentError.class, "MALFORMED_PACKAGE_XML", null,
                TestDocx.paragraphs("x").put("_rels/.rels", "<Relationships " + RELS_NS + ">"));
        refused(InvalidDocumentError.class, "MALFORMED_PACKAGE_XML", "_rels/.rels has an unexpected root element",
                TestDocx.paragraphs("x").put("_rels/.rels", "<Relationships/>"));
        refused(InvalidDocumentError.class, "INVALID_ROOT_RELATIONSHIP", "package has no officeDocument relationship",
                TestDocx.paragraphs("x").put("_rels/.rels", rels()));
        refused(InvalidDocumentError.class, "INVALID_ROOT_RELATIONSHIP",
                "package declares more than one officeDocument relationship",
                TestDocx.paragraphs("x").put("_rels/.rels", rels("word/document.xml", "word/document.xml")));
        refused(InvalidDocumentError.class, "INVALID_ROOT_RELATIONSHIP",
                "the officeDocument relationship points at a part that is not in the package",
                TestDocx.paragraphs("x").put("_rels/.rels", rels("word/elsewhere.xml")));
        refused(InvalidDocumentError.class, "MALFORMED_PACKAGE_XML",
                "[Content_Types].xml declares no content type for word/document.xml", TestDocx.paragraphs("x").put(ct,
                        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                                + "<Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>"));
        refused(InvalidDocumentError.class, "UNSUPPORTED_MAIN_PART_NAME", "the main document part must be word/document.xml",
                TestDocx.paragraphs("x").put("word/main.xml", "<w:document " + TestDocx.W + "><w:body/></w:document>")
                        .put("_rels/.rels", rels("word/main.xml")).put(ct, TestDocx.contentTypes(TestDocx.MAIN_CONTENT_TYPE)
                                .replace("/word/document.xml", "/word/main.xml")));
        // A leading slash on the target names the same part.
        DocxEngine.validateDocxBytes(TestDocx.paragraphs("x").put("_rels/.rels", rels("/word/document.xml")).bytes(), LIMITS);
    }

    @Test
    void aWellFormedPackageThatIsNotAPlainDocumentIsAnUnsupportedFormat() {
        for (String type : new String[] {"application/vnd.ms-word.document.macroEnabled.main+xml",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
                "application/vnd.ms-word.template.macroEnabledTemplate.main+xml"}) {
            refused(UnsupportedDocumentFormatError.class, "UNSUPPORTED_DOCUMENT_FORMAT", "macro-enabled and template Word "
                    + "packages (.docm/.dotx/.dotm) are not supported; save the file as .docx and send it again",
                    TestDocx.paragraphs("x").put("[Content_Types].xml", TestDocx.contentTypes(type)));
        }
        refused(UnsupportedDocumentFormatError.class, "UNSUPPORTED_DOCUMENT_FORMAT", "the package is not a Word document",
                TestDocx.paragraphs("x").put("[Content_Types].xml", TestDocx.contentTypes(
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")));
        byte[] ole2 = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1, 0, 0};
        UnsupportedDocumentFormatError legacy = assertThrows(UnsupportedDocumentFormatError.class,
                () -> DocxEngine.validateDocxBytes(ole2, LIMITS));
        assertEquals("UNSUPPORTED_LEGACY_WORD_FORMAT", legacy.code());
        // Bytes that are not a document at all stay a 400, as in v2.
        byte[] prefixed = ("junk" + new String(TestDocx.paragraphs("x").bytes(), StandardCharsets.ISO_8859_1))
                .getBytes(StandardCharsets.ISO_8859_1);
        assertEquals("Not a valid DOCX package", assertThrows(InvalidDocumentError.class,
                () -> DocxEngine.validateDocxBytes(prefixed, LIMITS)).getMessage());
    }

    @Test
    void damagedHeaderIsRecoveredAndRedacted() {
        String header = "<w:hdr " + TestDocx.W + ">" + TestDocx.p("Κεφαλίδα ΑΦΜ 123") + "<w:p><w:r><w:t>tail";
        byte[] docx = TestDocx.paragraphs("σώμα").put("word/header1.xml", header).bytes();
        DocumentData doc = DocxEngine.parseDocx(docx, "d", LIMITS);
        assertTrue(doc.textUnits().stream().anyMatch(u -> u.partName().equals("word/header1.xml")
                && u.text().equals("Κεφαλίδα ΑΦΜ 123")));
    }

    @Test
    void unparseableMustParsePartFailsClosed() {
        // Nothing element-like survives recovery: the part must not be copied through verbatim.
        byte[] docx = TestDocx.paragraphs("σώμα").put("word/header1.xml", "ΑΦΜ 123456789 no markup at all").bytes();
        assertEquals("part could not be parsed and cannot be safely redacted: word/header1.xml",
                assertThrows(InvalidDocumentError.class, () -> DocxEngine.parseDocx(docx, "d", LIMITS)).getMessage());
    }
}
