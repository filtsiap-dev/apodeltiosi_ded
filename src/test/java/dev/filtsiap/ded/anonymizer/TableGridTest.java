package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.llm.Chunk;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * Word tables on their LOGICAL grid: every cell under the header of the columns it really covers,
 * whatever {@code w:gridSpan}, {@code w:vMerge}, {@code w:hMerge}, {@code w:gridBefore}/{@code w:gridAfter},
 * content controls or border slivers do to the cells' positions in their rows. Each fixture is checked
 * for its cells' columns and headers, its source coordinates and its text, and the privacy cases also
 * for the detector spans, the resolver and the written document. All content is invented.
 */
class TableGridTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final ResourceLimits LIMITS = ResourceLimits.DEFAULTS;
    static final String NAME = "Γεώργιος Παπαδόπουλος";

    // ------------------------------------------------------------------ fixture builders

    /** A cell: its text ("" for an empty one) and its {@code w:tcPr} children. */
    static String tc(String text, String... props) {
        String pr = props.length == 0 ? "" : "<w:tcPr>" + String.join("", props) + "</w:tcPr>";
        return "<w:tc>" + pr + (text.isEmpty() ? "<w:p/>" : TestDocx.p(text)) + "</w:tc>";
    }

    static String span(int n) {
        return "<w:gridSpan w:val=\"" + n + "\"/>";
    }

    static final String V_RESTART = "<w:vMerge w:val=\"restart\"/>";
    static final String V_CONTINUE = "<w:vMerge/>";
    static final String HEADER = "<w:tblHeader/>";

    /** A row: its {@code w:trPr} children ("" for none) and its cells. */
    static String tr(String props, String... cells) {
        return "<w:tr>" + (props.isEmpty() ? "" : "<w:trPr>" + props + "</w:trPr>") + String.join("", cells) + "</w:tr>";
    }

    /** A table with a {@code w:tblGrid} of these column widths (twips). */
    static String tbl(int[] widths, String... rows) {
        StringBuilder grid = new StringBuilder("<w:tblGrid>");
        for (int w : widths) {
            grid.append("<w:gridCol w:w=\"").append(w).append("\"/>");
        }
        return "<w:tbl>" + grid.append("</w:tblGrid>") + String.join("", rows) + "</w:tbl>";
    }

    static int[] columns(int n) {
        int[] w = new int[n];
        java.util.Arrays.fill(w, 2000);
        return w;
    }

    static byte[] docx(String tableXml) {
        return TestDocx.paragraphs().document(TestDocx.p("Πίνακας στοιχείων") + tableXml).bytes();
    }

    static DocumentData parse(byte[] docx) {
        DocumentData doc = DocxEngine.parseDocx(docx, "d", LIMITS);
        assertSourceCoordinates(docx, doc);
        return doc;
    }

    static List<TextUnit> cells(DocumentData doc) {
        return doc.textUnits().stream().filter(u -> u.unitType() == UnitType.TABLE_CELL).toList();
    }

    static TextUnit.TableCellLocation at(TextUnit u) {
        return (TextUnit.TableCellLocation) u.location();
    }

    /** "text@row:col=header" per cell; "*" for a header-row cell, "~" after a header that is not aligned. */
    static List<String> layout(DocumentData doc) {
        return cells(doc).stream().map(u -> u.text() + "@" + at(u).rowIndex() + ":" + at(u).colIndex() + "="
                + (at(u).isHeaderRow() ? "*" : at(u).columnHeader() + (at(u).headerAligned() ? "" : "~"))).toList();
    }

    /**
     * Every character of every unit is the character its char map points at, in the document's own XML; and
     * every character of the document's text nodes is in exactly one unit. Source coordinates stay valid
     * and no text is lost or duplicated, whatever the grid did.
     */
    static void assertSourceCoordinates(byte[] docx, DocumentData doc) {
        Element root = LxmlDom.parseRecover(TestDocx.part(docx, "word/document.xml").getBytes(StandardCharsets.UTF_8));
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (TextUnit u : doc.textUnits()) {
            int[] cps = u.normalizedText().codePoints().toArray();
            assertEquals(cps.length, u.charMap().size(), u.unitId());
            for (int i = 0; i < cps.length; i++) {
                XmlCharRef ref = u.charMap().get(i);
                Element node = LxmlDom.findByElementPath(root, ref.textNodePath());
                if (LxmlDom.is(node, DocxEngine.W_NS, "t")) {
                    int[] source = LxmlDom.text(node).codePoints().toArray();
                    assertEquals(source[ref.charIndex()], cps[i], u.unitId() + "@" + i);
                    assertTrue(seen.add(ref.textNodePath() + "#" + ref.charIndex()), "duplicated " + ref);
                }
            }
        }
        int total = LxmlDom.descendants(root, DocxEngine.W_NS, "t").stream()
                .mapToInt(t -> (int) LxmlDom.text(t).codePoints().count()).sum();
        assertEquals(total, seen.size(), "every text character is in exactly one unit");
    }

    /** Every rule span: the resolver's (REDACT, PRESERVE) and the review hints (REVIEW). */
    static List<Span> detect(DocumentData doc) {
        Detectors.DetectionResult r = Detectors.detectAll(doc, FILES.rules());
        List<Span> all = new ArrayList<>(r.resolverSpans());
        all.addAll(r.reviewHints());
        return all;
    }

    /** The column map's spans, "text:CATEGORY/ACTION" ("!" when hard-preserved), in document order. */
    static List<String> columnSpans(DocumentData doc) {
        List<String> order = doc.textUnits().stream().map(TextUnit::unitId).toList();
        return detect(doc).stream().filter(s -> s.detector().equals("table_cell_header"))
                .sorted(java.util.Comparator.comparingInt(s -> order.indexOf(s.unitId())))
                .map(s -> s.text() + ":" + s.category().wire() + "/" + s.action().wire()
                        + (Resolver.isHardPreserve(s, FILES.policy()) ? "!" : "")).toList();
    }

    /** The table rendered as the model reads it, from the real chunker. */
    static String rendered(DocumentData doc) {
        List<TextUnit> table = cells(doc);
        return new Chunk(table, true, 0).render().text();
    }

    // ------------------------------------------------------------------ the privacy case

    /**
     * THE DEFECT: a cell spanning two grid columns shifted the name after it under "ΣΥΝΟΛΟ", whose column
     * rule is a whole-cell MONEY PRESERVE, a HARD one: nothing could redact the name. On the grid it is under
     * "Όνομα", the merged cell spans two different labels and has none, and the name is redacted.
     */
    static final String NAME_AFTER_MERGE = tbl(columns(3),
            tr("", tc("ΑΦΜ"), tc("ΣΥΝΟΛΟ"), tc("Όνομα")),
            tr("", tc("Στοιχεία οφειλέτη", span(2)), tc(NAME)),
            tr("", tc("Λοιπά"), tc("1.250,00"), tc("Νικόλαος Ιωάννου")));

    @Test
    void aNameAfterAMergedCellIsUnderItsOwnHeaderAndNeverHardPreserved() {
        DocumentData doc = parse(docx(NAME_AFTER_MERGE));
        assertEquals(List.of("ΑΦΜ@0:0=*", "ΣΥΝΟΛΟ@0:1=*", "Όνομα@0:2=*",
                "Στοιχεία οφειλέτη@1:0=~", NAME + "@1:2=Όνομα",
                "Λοιπά@2:0=ΑΦΜ", "1.250,00@2:1=ΣΥΝΟΛΟ", "Νικόλαος Ιωάννου@2:2=Όνομα"), layout(doc));
        // The column rules: the name is a person question, the amount a hard money preserve.
        List<String> spans = columnSpans(doc);
        assertTrue(spans.contains(NAME + ":POSSIBLE_PERSON/REVIEW"), spans.toString());
        assertTrue(spans.contains("1.250,00:MONEY/PRESERVE!"), spans.toString());
        assertTrue(detect(doc).stream().noneMatch(s -> s.text().contains("Γεώργιος")
                && Resolver.isHardPreserve(s, FILES.policy())), detect(doc).toString());
        // The model reads the name in the "Όνομα" column, the merged cell in the first.
        assertTrue(rendered(doc).contains("\nΣτοιχεία οφειλέτη |  | " + NAME + "\n"), rendered(doc));
    }

    @Test
    void endToEndTheNameAfterAMergedCellIsRedactedAndTheAmountKept() {
        AnonymizeResult r = anonymize(docx(NAME_AFTER_MERGE));
        String body = TestDocx.part(r.redactedDocx(), "word/document.xml");
        assertFalse(body.contains("Γεώργιος") || body.contains("Παπαδόπουλος"), body);
        assertFalse(body.contains("Νικόλαος"), body);
        assertTrue(body.contains(">1.250,00<"), body);
        assertTrue(body.contains(">ΣΥΝΟΛΟ<") && body.contains(">Όνομα<"), body);
    }

    static AnonymizeResult anonymize(byte[] docx) {
        RuntimeConfig cfg = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test"));
        return Pipeline.anonymizeDocument(docx, cfg, FILES, ScriptedLlm.cooperative(),
                RunContext.start(300, "grid", System::nanoTime));
    }

    // ------------------------------------------------------------------ horizontal merges

    @Test
    void gridSpansOfTwoAndThreeKeepEveryLaterCellInItsColumn() {
        DocumentData doc = parse(docx(tbl(columns(5),
                tr(HEADER, tc("Α/Α"), tc("ΑΦΜ"), tc("Όνομα"), tc("Διεύθυνση"), tc("ΣΥΝΟΛΟ")),
                tr("", tc("Σύνολο", span(3)), tc("οδός Ερμού 5"), tc("2.000,00")),
                tr("", tc("1"), tc("Α", span(2)), tc("Β"), tc("3,00")),
                tr("", tc("2"), tc("3"), tc(NAME), tc("Λαμία"), tc("4,00")))));
        assertEquals(List.of("Α/Α@0:0=*", "ΑΦΜ@0:1=*", "Όνομα@0:2=*", "Διεύθυνση@0:3=*", "ΣΥΝΟΛΟ@0:4=*",
                "Σύνολο@1:0=~", "οδός Ερμού 5@1:3=Διεύθυνση", "2.000,00@1:4=ΣΥΝΟΛΟ",
                "1@2:0=Α/Α", "Α@2:1=~", "Β@2:3=Διεύθυνση", "3,00@2:4=ΣΥΝΟΛΟ",
                "2@3:0=Α/Α", "3@3:1=ΑΦΜ", NAME + "@3:2=Όνομα", "Λαμία@3:3=Διεύθυνση", "4,00@3:4=ΣΥΝΟΛΟ"), layout(doc));
        // A merged cell before a sensitive column (row 1) and after one (row 2): neither shifts its neighbours.
        assertEquals(List.of("οδός Ερμού 5:POSSIBLE_PRIVATE_LOCATION/REVIEW", "2.000,00:MONEY/PRESERVE!",
                "Β:POSSIBLE_PRIVATE_LOCATION/REVIEW", "3,00:MONEY/PRESERVE!", "3:AFM/REDACT",
                NAME + ":POSSIBLE_PERSON/REVIEW", "Λαμία:POSSIBLE_PRIVATE_LOCATION/REVIEW", "4,00:MONEY/PRESERVE!"),
                columnSpans(doc));
    }

    /** The legacy horizontal merge: physical cells that continue the one before them, one visible cell. */
    @Test
    void aLegacyHorizontalMergeIsOneCellOverItsColumns() {
        String restart = "<w:hMerge w:val=\"restart\"/>";
        String cont = "<w:hMerge/>";
        DocumentData doc = parse(docx(tbl(columns(3),
                tr(HEADER, tc("ΣΥΝΟΛΟ"), tc("Όνομα"), tc("ΑΦΜ")),
                tr("", tc(NAME, restart), tc("", cont), tc("123")))));
        assertEquals(List.of("ΣΥΝΟΛΟ@0:0=*", "Όνομα@0:1=*", "ΑΦΜ@0:2=*", NAME + "@1:0=~", "123@1:2=ΑΦΜ"), layout(doc));
        assertTrue(columnSpans(doc).stream().noneMatch(s -> s.startsWith(NAME)), columnSpans(doc).toString());
    }

    // ------------------------------------------------------------------ vertical merges

    @Test
    void aVerticalMergeNeitherDuplicatesNorInventsText() {
        String table = tbl(columns(3),
                tr(HEADER, tc("Όνομα"), tc("ΑΦΜ"), tc("ΣΥΝΟΛΟ")),
                tr("", tc(NAME, V_RESTART), tc("111"), tc("10,00")),
                tr("", tc("", V_CONTINUE), tc("222"), tc("20,00")),
                // Text in a continuation cell is malformed but real: it is its own cell's text, read once.
                tr("", tc("Ιωάννου", V_CONTINUE), tc("333"), tc("30,00")));
        DocumentData doc = parse(docx(table));
        assertEquals(List.of("Όνομα@0:0=*", "ΑΦΜ@0:1=*", "ΣΥΝΟΛΟ@0:2=*",
                NAME + "@1:0=Όνομα", "111@1:1=ΑΦΜ", "10,00@1:2=ΣΥΝΟΛΟ",
                "222@2:1=ΑΦΜ", "20,00@2:2=ΣΥΝΟΛΟ",
                "Ιωάννου@3:0=Όνομα", "333@3:1=ΑΦΜ", "30,00@3:2=ΣΥΝΟΛΟ"), layout(doc));
        assertEquals(1, cells(doc).stream().filter(u -> u.text().equals(NAME)).count());
    }

    /** Two marked header rows: a group label over two columns, sub-labels below, a header merged down. */
    @Test
    void aMultiRowHeaderWithHorizontalAndVerticalMergesLabelsEachColumn() {
        DocumentData doc = parse(docx(tbl(columns(4),
                tr(HEADER, tc("Στοιχεία προσώπου", span(2)), tc("ΣΥΝΟΛΟ", V_RESTART), tc("Παρατηρήσεις", V_RESTART)),
                tr(HEADER, tc("Όνομα"), tc("ΑΦΜ"), tc("", V_CONTINUE), tc("", V_CONTINUE)),
                tr("", tc(NAME), tc("123"), tc("1.000,00"), tc("Λοιπά")),
                tr("", tc("Νικόλαος Ιωάννου", span(2)), tc("2.000,00", V_RESTART), tc("Άλλα")),
                tr("", tc("Σύνολο", span(2)), tc("", V_CONTINUE), tc("")))));
        assertEquals(List.of("Στοιχεία προσώπου@0:0=*", "ΣΥΝΟΛΟ@0:2=*", "Παρατηρήσεις@0:3=*", "Όνομα@1:0=*",
                "ΑΦΜ@1:1=*", NAME + "@2:0=Όνομα", "123@2:1=ΑΦΜ", "1.000,00@2:2=ΣΥΝΟΛΟ", "Λοιπά@2:3=Παρατηρήσεις",
                // spans "Όνομα" and "ΑΦΜ": two labels, so neither
                "Νικόλαος Ιωάννου@3:0=~", "2.000,00@3:2=ΣΥΝΟΛΟ", "Άλλα@3:3=Παρατηρήσεις", "Σύνολο@4:0=~"), layout(doc));
    }

    // ------------------------------------------------------------------ omitted positions, slivers, wrappers

    @Test
    void gridBeforeAndAfterAndEmptyCellsKeepTheColumns() {
        String before = "<w:gridBefore w:val=\"1\"/>";
        String after = "<w:gridAfter w:val=\"1\"/>";
        DocumentData doc = parse(docx(tbl(columns(4),
                tr(HEADER, tc("Α/Α"), tc("Όνομα"), tc("ΑΦΜ"), tc("ΣΥΝΟΛΟ")),
                tr(before, tc(NAME), tc(""), tc("5,00")),
                tr(after, tc("3"), tc(""), tc("Νικόλαος Ιωάννου")))));
        assertEquals(List.of("Α/Α@0:0=*", "Όνομα@0:1=*", "ΑΦΜ@0:2=*", "ΣΥΝΟΛΟ@0:3=*",
                NAME + "@1:1=Όνομα", "5,00@1:3=ΣΥΝΟΛΟ", "3@2:0=Α/Α", "Νικόλαος Ιωάννου@2:2=ΑΦΜ"), layout(doc));
    }

    /**
     * Word's 10-twip slivers, where two rows' borders miss each other by a hair (as in a real invoice table):
     * the total under "ΣΥΝΟΛΟ" covers a sliver and the next real column; without the slivers both are one.
     */
    @Test
    void borderSliversAreNotColumns() {
        DocumentData doc = parse(docx(tbl(new int[] {600, 2000, 10, 1800, 10, 1800, 10},
                tr(HEADER, tc("Α/Α"), tc("Όνομα"), tc("ΑΦΜ", span(2)), tc("ΣΥΝΟΛΟ", span(2))),
                tr("", tc("1"), tc(NAME), tc("111", span(2)), tc("1,00", span(2))),
                tr("", tc("Σύνολο", span(3)), tc("", span(2)), tc("2,00", span(2))))));
        assertEquals(List.of("Α/Α@0:0=*", "Όνομα@0:1=*", "ΑΦΜ@0:2=*", "ΣΥΝΟΛΟ@0:3=*",
                "1@1:0=Α/Α", NAME + "@1:1=Όνομα", "111@1:2=ΑΦΜ", "1,00@1:3=ΣΥΝΟΛΟ",
                "Σύνολο@2:0=~", "2,00@2:3=ΣΥΝΟΛΟ"), layout(doc));
        assertTrue(columnSpans(doc).contains("2,00:MONEY/PRESERVE!"), columnSpans(doc).toString());
        assertTrue(rendered(doc).contains("\nΣύνολο |  |  | 2,00"), rendered(doc));
    }

    /** Rows and cells inside content controls are the table's own, in their places. */
    @Test
    void rowsAndCellsInsideContentControlsKeepTheirColumns() {
        String sdtCell = "<w:sdt><w:sdtPr/><w:sdtContent>" + tc(NAME) + "</w:sdtContent></w:sdt>";
        String sdtRow = "<w:sdt><w:sdtPr/><w:sdtContent>" + tr("", tc("4"), tc("Νικόλαος Ιωάννου"), tc("7,00"))
                + "</w:sdtContent></w:sdt>";
        DocumentData doc = parse(docx("<w:tbl><w:tblGrid/>" + tr(HEADER, tc("ΑΦΜ"), tc("Όνομα"), tc("ΣΥΝΟΛΟ"))
                + tr("", tc("3"), sdtCell, tc("5,00")) + sdtRow + "</w:tbl>"));
        assertEquals(List.of("ΑΦΜ@0:0=*", "Όνομα@0:1=*", "ΣΥΝΟΛΟ@0:2=*", "3@1:0=ΑΦΜ", NAME + "@1:1=Όνομα",
                "5,00@1:2=ΣΥΝΟΛΟ", "4@2:0=ΑΦΜ", "Νικόλαος Ιωάννου@2:1=Όνομα", "7,00@2:2=ΣΥΝΟΛΟ"), layout(doc));
    }

    /** A nested table's text belongs to its outer cell, which keeps its column. */
    @Test
    void aNestedTableStaysInsideItsOuterCell() {
        String inner = "<w:tbl>" + tr("", tc("εσωτερικό"), tc("κελί")) + "</w:tbl>";
        DocumentData doc = parse(docx(tbl(columns(3), tr(HEADER, tc("ΑΦΜ"), tc("Όνομα"), tc("ΣΥΝΟΛΟ")),
                tr("", tc("1", span(2)), "<w:tc>" + inner + TestDocx.p("9,00") + "</w:tc>"))));
        assertEquals(List.of("ΑΦΜ@0:0=*", "Όνομα@0:1=*", "ΣΥΝΟΛΟ@0:2=*", "1@1:0=~", "εσωτερικόκελί9,00@1:2=ΣΥΝΟΛΟ"),
                layout(doc));
    }

    /**
     * A grid that cannot be Word's (a span past 63 columns, or one that would overflow an int): the cells keep
     * their row positions, NO cell has a header, and nothing is lost. Unknown alignment never preserves.
     */
    @Test
    void anUnreadableGridFallsBackToNoHeaders() {
        for (String hostile : List.of("64", "2147483647", "99999999999")) {
            DocumentData doc = parse(docx(tbl(columns(3), tr(HEADER, tc("ΑΦΜ"), tc("ΣΥΝΟΛΟ"), tc("Όνομα")),
                    tr("", tc("x", "<w:gridSpan w:val=\"" + hostile + "\"/>"), tc(NAME)))));
            assertEquals(List.of("ΑΦΜ@0:0=*", "ΣΥΝΟΛΟ@0:1=*", "Όνομα@0:2=*", "x@1:0=~", NAME + "@1:1=~"), layout(doc),
                    hostile);
            assertEquals(List.of(), columnSpans(doc), hostile);
        }
    }

    // ------------------------------------------------------------------ group labels

    /**
     * A header cell over two sub-columns is a group label: it names the group, not the column. Its REDACT and
     * REVIEW rules still reach the sub-columns (the safe direction); its PRESERVE never does.
     */
    @Test
    void aGroupLabelNeverPreservesButStillRedactsAndAsks() {
        DocumentData doc = parse(docx(tbl(columns(4),
                tr(HEADER, tc("Όνομα", span(2)), tc("ΣΥΝΟΛΟ", span(2))),
                tr("", tc("Παπαδόπουλος"), tc("Γεώργιος"), tc("Νικόλαος Ιωάννου"), tc("€")),
                tr("", tc(NAME, span(2)), tc("1.000,00", span(2))))));
        assertEquals(List.of("Όνομα@0:0=*", "ΣΥΝΟΛΟ@0:2=*", "Παπαδόπουλος@1:0=Όνομα~", "Γεώργιος@1:1=Όνομα~",
                "Νικόλαος Ιωάννου@1:2=ΣΥΝΟΛΟ~", "€@1:3=ΣΥΝΟΛΟ~", NAME + "@2:0=Όνομα", "1.000,00@2:2=ΣΥΝΟΛΟ"), layout(doc));
        assertEquals(List.of("Παπαδόπουλος:POSSIBLE_PERSON/REVIEW", "Γεώργιος:POSSIBLE_PERSON/REVIEW",
                NAME + ":POSSIBLE_PERSON/REVIEW", "1.000,00:MONEY/PRESERVE!"), columnSpans(doc));
    }

    // ------------------------------------------------------------------ Problem B: one label is not a header

    @Test
    void aSparseFirstRowWithOneLabelIsNotAHeader() {
        // "ΣΥΝΟΛΟ | | ": one label in a three-column table is a title or a sparse data row.
        DocumentData sparse = parse(docx(tbl(columns(3), tr("", tc("ΣΥΝΟΛΟ"), tc(""), tc("")),
                tr("", tc(NAME), tc("x"), tc("y")))));
        assertEquals(List.of("ΣΥΝΟΛΟ@0:0=~", NAME + "@1:0=~", "x@1:1=~", "y@1:2=~"), layout(sparse));
        assertEquals(List.of(), columnSpans(sparse));
        // The same lone label spanning the whole row is a title, not a header either.
        DocumentData title = parse(docx(tbl(columns(3), tr("", tc("ΣΥΝΟΛΟ", span(3))),
                tr("", tc(NAME), tc("x"), tc("y")))));
        assertEquals(List.of(), columnSpans(title));
        assertTrue(cells(title).stream().noneMatch(u -> at(u).isHeaderRow()));
    }

    @Test
    void aGenuineSingleColumnTableKeepsItsOneLabelHeader() {
        DocumentData one = parse(docx(tbl(columns(1), tr("", tc("ΣΥΝΟΛΟ")), tr("", tc("1.250,00")))));
        assertEquals(List.of("ΣΥΝΟΛΟ@0:0=*", "1.250,00@1:0=ΣΥΝΟΛΟ"), layout(one));
        // A row of two labels beside an empty cell is still a header row.
        DocumentData two = parse(docx(tbl(columns(3), tr("", tc("ΑΦΜ"), tc("Όνομα"), tc("")),
                tr("", tc("123"), tc(NAME), tc("σημείωση")))));
        assertEquals(List.of("ΑΦΜ@0:0=*", "Όνομα@0:1=*", "123@1:0=ΑΦΜ", NAME + "@1:1=Όνομα", "σημείωση@1:2=~"),
                layout(two));
    }

    /** Word's own header mark is the author's statement and keeps its meaning, even on a sparse row. */
    @Test
    void anExplicitWordHeaderStillCountsWhenSparse() {
        DocumentData doc = parse(docx(tbl(columns(3), tr(HEADER, tc("ΣΥΝΟΛΟ"), tc(""), tc("")),
                tr("", tc("1.250,00"), tc(NAME), tc("y")))));
        assertEquals(List.of("ΣΥΝΟΛΟ@0:0=*", "1.250,00@1:0=ΣΥΝΟΛΟ", NAME + "@1:1=~", "y@1:2=~"), layout(doc));
    }

    // ------------------------------------------------------------------ write-back through the grid

    /** A redaction of a cell after a merge lands in that cell's own text node, character for character. */
    @Test
    void aRedactionAfterAMergedCellIsWrittenToThatCell() {
        byte[] input = docx(NAME_AFTER_MERGE);
        DocumentData doc = parse(input);
        TextUnit name = cells(doc).stream().filter(u -> u.text().equals(NAME)).findFirst().orElseThrow();
        RedactionPlan plan = new RedactionPlan("d", List.of(new Span(name.unitId(), 0, NAME.length(), NAME,
                SpanCategory.POSSIBLE_PERSON, "t", 1, SpanAction.REDACT, "", SpanOrigin.LLM_PASS2)), List.of());
        byte[] out = DocxEngine.writeRedactedDocx(input, doc, plan, LIMITS);
        String xml = TestDocx.part(out, "word/document.xml");
        assertFalse(xml.contains(NAME), xml);
        assertTrue(xml.contains(">" + ".".repeat(NAME.length()) + "<"), xml);
        DocumentData reparsed = parse(out);
        assertEquals(layout(doc).stream().map(l -> l.replace(NAME, ".".repeat(NAME.length()))).toList(),
                layout(reparsed));
        assertEquals(cells(doc).stream().map(TextUnit::unitId).toList(),
                cells(reparsed).stream().map(TextUnit::unitId).toList());
    }
}
