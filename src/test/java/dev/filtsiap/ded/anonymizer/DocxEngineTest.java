package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class DocxEngineTest {

    @Test
    void parsesParagraphsAndTablesWithCodePointCharMaps() {
        String table = "<w:tbl><w:tr><w:tc>" + TestDocx.p("ΑΦΜ") + "</w:tc></w:tr><w:tr><w:tc>" + TestDocx.p("123")
                + "</w:tc></w:tr></w:tbl>";
        byte[] docx = TestDocx.paragraphs().document(table + TestDocx.p("a😀b")).bytes();
        DocumentData doc = DocxEngine.parseDocx(docx, "d");
        assertEquals(3, doc.textUnits().size());
        TextUnit cell = doc.textUnits().get(1);
        assertEquals(UnitType.TABLE_CELL, cell.unitType());
        assertEquals("ΑΦΜ", cell.location().columnHeader());
        TextUnit para = doc.textUnits().get(2);
        assertEquals(3, para.charMap().size()); // the emoji is one code point, one ref
        assertEquals(2, para.charMap().get(2).charIndex());
    }

    @Test
    void redactionIsOneGlyphPerCodePoint() {
        byte[] docx = TestDocx.paragraphs("x😀y").bytes();
        DocumentData doc = DocxEngine.parseDocx(docx, "d");
        RedactionPlan plan = new RedactionPlan("d", List.of(
                new Span("u0", 1, 2, "😀", SpanCategory.POSSIBLE_PERSON, "t", 1, SpanAction.REDACT, "")), List.of());
        String xml = TestDocx.part(DocxEngine.writeRedactedDocx(docx, doc, plan), "word/document.xml");
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
        byte[] out = DocxEngine.writeRedactedDocx(docx, DocxEngine.parseDocx(docx, "d"), new RedactionPlan("d", List.of(), List.of()));
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
                () -> DocxEngine.validateDocxBytes("hello".getBytes(StandardCharsets.UTF_8))).getMessage());
        assertEquals("Not a valid DOCX package: missing _rels/.rels", assertThrows(InvalidDocumentError.class,
                () -> DocxEngine.validateDocxBytes(TestDocx.paragraphs("x").remove("_rels/.rels").bytes())).getMessage());
        assertTrue(assertThrows(InvalidDocumentError.class, () -> DocxEngine.validateDocxBytes(
                TestDocx.paragraphs().put("word/document.xml", "<w:document " + TestDocx.W + "><w:body>").bytes()))
                .getMessage().startsWith("word/document.xml is not valid XML: "));
        assertEquals("word/document.xml has no w:body element", assertThrows(InvalidDocumentError.class,
                () -> DocxEngine.validateDocxBytes(TestDocx.paragraphs().put("word/document.xml",
                        "<w:document " + TestDocx.W + "/>").bytes())).getMessage());
    }

    @Test
    void damagedHeaderIsRecoveredAndRedacted() {
        String header = "<w:hdr " + TestDocx.W + ">" + TestDocx.p("Κεφαλίδα ΑΦΜ 123") + "<w:p><w:r><w:t>tail";
        byte[] docx = TestDocx.paragraphs("σώμα").put("word/header1.xml", header).bytes();
        DocumentData doc = DocxEngine.parseDocx(docx, "d");
        assertTrue(doc.textUnits().stream().anyMatch(u -> u.partName().equals("word/header1.xml")
                && u.text().equals("Κεφαλίδα ΑΦΜ 123")));
    }

    @Test
    void unparseableMustParsePartFailsClosed() {
        // Nothing element-like survives recovery: the part must not be copied through verbatim.
        byte[] docx = TestDocx.paragraphs("σώμα").put("word/header1.xml", "ΑΦΜ 123456789 no markup at all").bytes();
        assertEquals("part could not be parsed and cannot be safely redacted: word/header1.xml",
                assertThrows(InvalidDocumentError.class, () -> DocxEngine.parseDocx(docx, "d")).getMessage());
    }
}
