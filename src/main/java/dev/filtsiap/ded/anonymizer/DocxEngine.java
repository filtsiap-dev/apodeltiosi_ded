package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.text.Normalizer;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.w3c.dom.Element;

/**
 * DOCX parsing, byte-verbatim write-back and metadata cleanup (port of {@code docx_engine.py}).
 *
 * <p>{@code word/document.xml} is parsed strictly; every other part uses the recovering
 * parser, so a damaged header does not fail an otherwise readable document. Redaction is a
 * 1:1 substitution: one {@code "."} per code point, so every offset stays valid.
 */
public final class DocxEngine {

    static final String W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    static final String CP_NS = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties";
    static final String DC_NS = "http://purl.org/dc/elements/1.1/";
    static final String DCTERMS_NS = "http://purl.org/dc/terms/";
    static final String CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types";
    static final String RELATIONSHIPS_NS = "http://schemas.openxmlformats.org/package/2006/relationships";
    static final String OFFICE_DOCUMENT_REL_TYPE =
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";
    static final String CONTENT_TYPES_PART = "[Content_Types].xml";
    static final String ROOT_RELS_PART = "_rels/.rels";
    static final String MAIN_DOCUMENT_PART = "word/document.xml";
    static final String DOCX_MAIN_CONTENT_TYPE =
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";

    /**
     * The other three Word main-part types. v2 accepts them and normalizes the package to a plain
     * .docx first; this pipeline has no normalization stage, so they are refused as unsupported.
     */
    static final Set<String> OTHER_WORD_MAIN_CONTENT_TYPES = Set.of(
            "application/vnd.ms-word.document.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
            "application/vnd.ms-word.template.macroEnabledTemplate.main+xml");

    /** Compound File Binary signature: every legacy .doc and .dot begins with it. */
    private static final byte[] OLE2_MAGIC = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1,
        0x1A, (byte) 0xE1};
    /** Local file header: an OOXML package is a ZIP, so it begins with one. */
    private static final byte[] ZIP_MAGIC = {'P', 'K', 3, 4};

    private DocxEngine() {
    }

    // ------------------------------------------------------------------ validation

    /** Strictly parses {@code word/document.xml}: valid XML, root {@code w:document}, has {@code w:body}. */
    static void validateMainDocumentXml(byte[] blob) {
        Element root;
        try {
            root = LxmlDom.parseStrict(blob);
        } catch (LxmlDom.XmlSyntaxError e) {
            throw new InvalidDocumentError("word/document.xml is not valid XML: " + e.getMessage(), e);
        }
        if (!LxmlDom.is(root, W_NS, "document")) {
            throw new InvalidDocumentError("word/document.xml is not a WordprocessingML document "
                    + "(root element is " + PyRepr.repr(LxmlDom.tag(root)) + ", expected w:document)");
        }
        if (LxmlDom.childElements(root, W_NS, "body").isEmpty()) {
            throw new InvalidDocumentError("word/document.xml has no w:body element");
        }
    }

    /**
     * Validates a DOCX package strictly within {@code limits} (v2's {@code sniff_format} and
     * {@code validate_docx_package}), in v2's order: the bytes are a ZIP and not a legacy binary
     * Word file; the archive passes preflight with intact members; the three required parts exist;
     * {@code [Content_Types].xml} and {@code _rels/.rels} parse strictly with the right roots; exactly
     * one officeDocument relationship names a part that is present; that part's declared content
     * type is a plain Word document; it is {@code word/document.xml}; and that part parses strictly.
     * Throws {@link InvalidDocumentError}, {@link UnsupportedDocumentFormatError} or
     * {@link ResourceLimitExceededError}.
     */
    public static void validateDocxBytes(byte[] data, ResourceLimits limits) {
        if (startsWith(data, OLE2_MAGIC)) {
            throw new UnsupportedDocumentFormatError("legacy binary Word documents (.doc/.dot) are not supported; "
                    + "save the file as .docx and send it again", "UNSUPPORTED_LEGACY_WORD_FORMAT");
        }
        if (!startsWith(data, ZIP_MAGIC)) {
            // Bytes that are not a document at all are malformed input (400), not a format we declined.
            throw new InvalidDocumentError("Not a valid DOCX package");
        }
        ZipPackage pkg = open(data, limits);
        Set<String> names = new HashSet<>(pkg.names());
        List<String> missing = new ArrayList<>();
        for (String required : List.of(CONTENT_TYPES_PART, ROOT_RELS_PART, MAIN_DOCUMENT_PART)) {
            if (!names.contains(required)) {
                missing.add(required);
            }
        }
        if (!missing.isEmpty()) {
            throw new InvalidDocumentError("Not a valid DOCX package: missing " + String.join(", ", missing));
        }
        Map<String, byte[]> members = pkg.packageData();
        Element contentTypes = strictRoot(members.get(CONTENT_TYPES_PART), CONTENT_TYPES_PART, CONTENT_TYPES_NS, "Types");
        Element rels = strictRoot(members.get(ROOT_RELS_PART), ROOT_RELS_PART, RELATIONSHIPS_NS, "Relationships");

        String mainPart = mainDocumentTarget(rels);
        if (!names.contains(mainPart)) {
            throw new InvalidDocumentError("the officeDocument relationship points at a part that is not in the package",
                    "INVALID_ROOT_RELATIONSHIP");
        }
        String contentType = overrideContentType(contentTypes, mainPart);
        if (OTHER_WORD_MAIN_CONTENT_TYPES.contains(contentType)) {
            throw new UnsupportedDocumentFormatError("macro-enabled and template Word packages (.docm/.dotx/.dotm) "
                    + "are not supported; save the file as .docx and send it again");
        }
        if (!contentType.equals(DOCX_MAIN_CONTENT_TYPE)) {
            // A well-formed OPC package that is not a Word document: nothing is wrong with it, so this
            // is an unsupported format rather than a malformed one.
            throw new UnsupportedDocumentFormatError("the package is not a Word document");
        }
        if (!mainPart.equals(MAIN_DOCUMENT_PART)) {
            // Word always writes word/document.xml, and every stage here addresses it by that name.
            throw new InvalidDocumentError("the main document part must be " + MAIN_DOCUMENT_PART,
                    "UNSUPPORTED_MAIN_PART_NAME");
        }
        validateMainDocumentXml(members.get(MAIN_DOCUMENT_PART));
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        return data.length >= prefix.length && Arrays.equals(data, 0, prefix.length, prefix, 0, prefix.length);
    }

    /**
     * Strictly parses a required package part and confirms its root element. The recovering parser
     * would turn rubbish into an empty tree, and an empty {@code [Content_Types].xml} would mean
     * "this package declares nothing" rather than "this package is broken".
     */
    private static Element strictRoot(byte[] blob, String partName, String ns, String local) {
        Element root;
        try {
            root = LxmlDom.parseStrict(blob);
        } catch (LxmlDom.XmlSyntaxError e) {
            throw new InvalidDocumentError(partName + " is not valid XML: " + e.getMessage(), "MALFORMED_PACKAGE_XML");
        }
        if (root == null || !LxmlDom.is(root, ns, local)) {
            throw new InvalidDocumentError(partName + " has an unexpected root element", "MALFORMED_PACKAGE_XML");
        }
        return root;
    }

    /**
     * The part the root relationships name as the office document. Exactly one is required: none
     * means the package never says which part is the document, several mean it says so twice and
     * this would be choosing.
     */
    private static String mainDocumentTarget(Element rels) {
        List<String> targets = new ArrayList<>();
        for (Element relationship : LxmlDom.childElements(rels)) {
            if (!OFFICE_DOCUMENT_REL_TYPE.equals(LxmlDom.attr(relationship, "Type"))) {
                continue;
            }
            String target = PyStr.strip(Objects.requireNonNullElse(LxmlDom.attr(relationship, "Target"), ""));
            if (!target.isEmpty()) {
                targets.add(target.replaceFirst("^/+", ""));
            }
        }
        if (targets.isEmpty()) {
            throw new InvalidDocumentError("package has no officeDocument relationship", "INVALID_ROOT_RELATIONSHIP");
        }
        if (targets.size() > 1) {
            throw new InvalidDocumentError("package declares more than one officeDocument relationship",
                    "INVALID_ROOT_RELATIONSHIP");
        }
        return targets.get(0);
    }

    /** The content type {@code [Content_Types].xml} declares for one part, through its Override. */
    private static String overrideContentType(Element contentTypes, String partName) {
        String wanted = "/" + partName;
        for (Element override : LxmlDom.childElements(contentTypes)) {
            if (LxmlDom.localName(override).equals("Override") && PyStr.strip(
                    Objects.requireNonNullElse(LxmlDom.attr(override, "PartName"), "")).equals(wanted)) {
                return PyStr.strip(Objects.requireNonNullElse(LxmlDom.attr(override, "ContentType"), ""));
            }
        }
        throw new InvalidDocumentError(CONTENT_TYPES_PART + " declares no content type for " + partName,
                "MALFORMED_PACKAGE_XML");
    }

    private static ZipPackage open(byte[] data, ResourceLimits limits) {
        try {
            return ZipPackage.read(data, limits);
        } catch (ZipPackage.BadZipFile e) {
            throw new InvalidDocumentError("Not a valid DOCX package", e);
        } catch (ZipPackage.CorruptMember e) {
            // The member name is document-derived: it stays in the message, never in a response.
            throw new InvalidDocumentError("package member " + PyRepr.repr(e.memberName()) + " could not be read",
                    "CORRUPT_ZIP_MEMBER");
        }
    }

    // ------------------------------------------------------------------ part parsing

    /** Parses every .xml/.rels member with the recovering parser; unparseable parts are skipped. */
    static Map<String, Element> parseXmlParts(Map<String, byte[]> packageData) {
        Map<String, Element> parsed = new LinkedHashMap<>();
        packageData.forEach((name, blob) -> {
            if (!ZipPackage.isXmlPart(name)) {
                return;
            }
            Element root = LxmlDom.parseRecover(blob);
            if (root != null) {
                parsed.put(name, root);
            }
        });
        return parsed;
    }

    /**
     * Parts that redaction or metadata cleanup must rewrite. If one is present but cannot be
     * parsed even by the recovering parser, the document is rejected: copying it verbatim would
     * pass its text (or metadata) through unredacted, and the post-redaction scan could not read
     * it either. Python silently copies such a part; lxml rarely fails to recover one, so this
     * is a deliberate fail-closed tightening, not a behaviour change on real documents.
     */
    static boolean mustParse(String partName) {
        return isWordTextPart(partName) || partName.equals("word/comments.xml")
                || partName.equals("docProps/core.xml") || partName.equals("docProps/app.xml");
    }

    static void requireParsed(Map<String, byte[]> packageData, Map<String, Element> parsed) {
        for (String name : packageData.keySet()) {
            if (mustParse(name) && !parsed.containsKey(name)) {
                throw new InvalidDocumentError("part could not be parsed and cannot be safely redacted: " + name);
            }
        }
    }

    static boolean isWordTextPart(String partName) {
        return partName.equals("word/document.xml")
                || (partName.startsWith("word/header") && partName.endsWith(".xml"))
                || (partName.startsWith("word/footer") && partName.endsWith(".xml"))
                || partName.equals("word/footnotes.xml") || partName.equals("word/endnotes.xml");
    }

    // ------------------------------------------------------------------ character extraction

    private record ParaChars(List<String> chars, List<XmlCharRef> charMap) {
    }

    /**
     * {@code ANON_MAX_TEXT_CHARS}, enforced while the text is extracted: every character costs a
     * String and an {@link XmlCharRef} (about 100 bytes), so a document is stopped at the limit,
     * not after building a map for all of its text (25 million characters would need 2.5 GB).
     * Counts exactly what the units will hold: each extracted character lands in one unit.
     */
    static final class CharBudget {
        private final long limit;
        private long used;

        CharBudget(long limit) {
            this.limit = limit;
        }

        void take() {
            if (++used > limit) {
                throw new ResourceLimitExceededError("document holds more than " + limit + " characters of text; "
                        + "the limit is " + limit, "TEXT_TOO_LARGE");
            }
        }
    }

    /**
     * Visible characters of a paragraph (per-character NFC, tabs, breaks) with a parallel map
     * into the XML. Per-character NFC never changes the count, which keeps offsets aligned.
     */
    private static ParaChars extractParaChars(Element root, Element paragraph, String partName, CharBudget budget) {
        List<String> chars = new ArrayList<>();
        List<XmlCharRef> map = new ArrayList<>();
        for (Element node : LxmlDom.iterElements(paragraph)) {
            if (ancestor(node, "p") != paragraph) {
                continue; // a textbox's inner paragraph owns its own characters
            }
            if (LxmlDom.is(node, W_NS, "t")) {
                String text = LxmlDom.text(node);
                if (text == null) {
                    text = "";
                }
                String path = LxmlDom.elementPath(root, node);
                int idx = 0;
                for (int i = 0; i < text.length(); ) {
                    int cp = text.codePointAt(i);
                    i += Character.charCount(cp);
                    budget.take();
                    String ch = new String(Character.toChars(cp));
                    String norm = Normalizer.normalize(ch, Normalizer.Form.NFC);
                    if (PyStr.len(norm) != 1) {
                        norm = ch; // 1 char : 1 ref outranks normalization
                    }
                    chars.add(norm);
                    map.add(new XmlCharRef(partName, path, idx));
                    idx++;
                }
            } else if (LxmlDom.is(node, W_NS, "tab")) {
                budget.take();
                chars.add("\t");
                map.add(new XmlCharRef(partName, LxmlDom.elementPath(root, node), 0));
            } else if (LxmlDom.is(node, W_NS, "br")) {
                budget.take();
                chars.add("\n");
                map.add(new XmlCharRef(partName, LxmlDom.elementPath(root, node), 0));
            } else if (LxmlDom.is(node, W_NS, "cr")) {
                budget.take();
                chars.add("\n");
                map.add(new XmlCharRef(partName, LxmlDom.elementPath(root, node), 0));
            }
        }
        if (chars.size() != map.size()) {
            throw new IllegalStateException("char/char_map desynchronized");
        }
        return new ParaChars(chars, map);
    }

    // ------------------------------------------------------------------ parsing

    private static Element ancestor(Element node, String local) {
        for (Element p = LxmlDom.parent(node); p != null; p = LxmlDom.parent(p)) {
            if (LxmlDom.is(p, W_NS, local)) {
                return p;
            }
        }
        return null;
    }

    /** The stripped text of a cell's {@code w:t} nodes, as the header map reads it. */
    private static String cellText(Element cell) {
        StringBuilder text = new StringBuilder();
        for (Element node : LxmlDom.iterElements(cell)) {
            if (LxmlDom.is(node, W_NS, "t")) {
                String t = LxmlDom.text(node);
                text.append(t == null ? "" : t);
            }
        }
        return PyStr.strip(text.toString());
    }

    /** Whether Word repeats this row as the table's header ({@code w:trPr/w:tblHeader}, not switched off). */
    private static boolean repeatsAsHeader(Element row) {
        for (Element trPr : LxmlDom.childElements(row, W_NS, "trPr")) {
            for (Element header : LxmlDom.childElements(trPr, W_NS, "tblHeader")) {
                String val = header.getAttributeNS(W_NS, "val");
                return val == null || val.isEmpty() || !(val.equals("0") || val.equals("false") || val.equals("off"));
            }
        }
        return false;
    }

    /** The longest cell text an unmarked header row may hold, in code points: a label is short. */
    static final int HEADER_LABEL_MAX = 40;

    /**
     * Whether an unmarked first row is positively a row of column labels: no cell holds a digit or more
     * than {@link #HEADER_LABEL_MAX} code points, a strict majority of its non-empty cells are labels the
     * rules already know ({@link Detectors#isKnownColumnLabel}), and there are at least two of them. One
     * label is enough only in a table of ONE column ({@code singleColumn}: no row holds two cells side by
     * side); elsewhere "ΣΥΝΟΛΟ | | " or a lone label spanning the row is a title or a sparse data row, not
     * a header. Anything less is ambiguous, and ambiguous is data.
     */
    static boolean labelRow(List<GridCell> row, boolean singleColumn) {
        int nonEmpty = 0;
        int labels = 0;
        for (GridCell cell : row) {
            String text = cellText(cell.element());
            if (text.isEmpty()) {
                continue;
            }
            if (text.codePoints().anyMatch(Character::isDigit) || PyStr.len(text) > HEADER_LABEL_MAX) {
                return false;
            }
            nonEmpty++;
            if (Detectors.isKnownColumnLabel(text)) {
                labels++;
            }
        }
        return 2 * labels > nonEmpty && (labels >= 2 || (labels == 1 && nonEmpty == 1 && singleColumn));
    }

    // ------------------------------------------------------------------ the table grid

    /**
     * Word's own limit on a table's columns. A row whose grid positions run past it is not laid out on
     * Word's grid (or its metadata is hostile), so the table's columns cannot be established.
     */
    static final int MAX_GRID_COLUMNS = 63;

    /**
     * One {@code w:tc} at its place in the table's LOGICAL grid, counted in the grid's real columns (its
     * {@link #SLIVER_TWIPS slivers} taken out). The grid position comes from the row's
     * {@code w:gridBefore} plus the {@code w:gridSpan} of every cell before it, never from the cell's
     * position among the row's cells; {@code column} is its first column. {@code [coverStart, coverEnd)}
     * are the columns the visible cell covers: its own span, widened over a legacy {@code w:hMerge} group
     * (each member keeps its own {@code column}, and all of them the group's cover). A vertical merge
     * ({@code w:vMerge}) changes no position: the continuation cell is a cell of its own row, usually
     * empty, and is never given the text of the cell above it.
     */
    record GridCell(Element element, int column, int coverStart, int coverEnd) {
    }

    /** The text of one header cell, over the grid columns {@code [start, end)} it covers. */
    private record HeaderLabel(String text, int start, int end) {
    }

    /**
     * The row's {@code w:tc}, in order, including those a content control ({@code w:sdt}) or custom XML
     * wraps; never a nested table's. Likewise {@link #rowsOf} for a table's {@code w:tr}.
     */
    private static List<Element> cellsOf(Element row) {
        return structural(row, "tc", new ArrayList<>());
    }

    private static List<Element> rowsOf(Element table) {
        return structural(table, "tr", new ArrayList<>());
    }

    private static List<Element> structural(Element parent, String wanted, List<Element> out) {
        for (Element child : LxmlDom.childElements(parent)) {
            if (LxmlDom.is(child, W_NS, wanted)) {
                out.add(child);
            } else if (!LxmlDom.is(child, W_NS, "tbl") && !LxmlDom.is(child, W_NS, "tr")
                    && !LxmlDom.is(child, W_NS, "tc") && !LxmlDom.is(child, W_NS, "p")) {
                structural(child, wanted, out); // a wrapper (w:sdt, w:sdtContent, w:customXml)
            }
        }
        return out;
    }

    /**
     * {@code pr/<local> @w:val} as a count: {@code fallback} when the element is absent, capped at one past
     * {@link #MAX_GRID_COLUMNS}, and one past it as well when present but unreadable, so a value the grid
     * cannot be built from makes the grid unreadable instead of being guessed.
     */
    private static int gridValue(Element owner, String pr, String local, int fallback) {
        for (Element props : LxmlDom.childElements(owner, W_NS, pr)) {
            for (Element e : LxmlDom.childElements(props, W_NS, local)) {
                String val = e.getAttributeNS(W_NS, "val");
                return val != null && val.matches("\\d{1,9}") ? Math.min(Integer.parseInt(val), MAX_GRID_COLUMNS + 1)
                        : MAX_GRID_COLUMNS + 1;
            }
        }
        return fallback;
    }

    /** The legacy horizontal merge mark on a cell: "restart", "continue", or null. */
    private static String hMerge(Element cell) {
        for (Element props : LxmlDom.childElements(cell, W_NS, "tcPr")) {
            for (Element e : LxmlDom.childElements(props, W_NS, "hMerge")) {
                String val = e.getAttributeNS(W_NS, "val");
                return "restart".equals(val) ? "restart" : "continue";
            }
        }
        return null;
    }

    /**
     * A grid column narrower than this, in twips, is a SLIVER: narrower than one default cell margin
     * (108 twips), so it cannot hold a column of text. Word inserts one wherever two rows' borders miss
     * each other by a hair (a header cell over grid columns 3-4 and a total under 4-5, column 3 being 10
     * twips wide); it is layout, not a column, and the columns are read with the slivers taken out.
     */
    static final int SLIVER_TWIPS = 100;

    /** Which grid columns the table's {@code w:tblGrid} declares as slivers; none without readable widths. */
    private static boolean[] slivers(Element table) {
        List<Element> columns = new ArrayList<>();
        for (Element grid : LxmlDom.childElements(table, W_NS, "tblGrid")) {
            columns.addAll(LxmlDom.childElements(grid, W_NS, "gridCol"));
        }
        boolean[] sliver = new boolean[Math.min(columns.size(), MAX_GRID_COLUMNS + 1)];
        for (int i = 0; i < sliver.length; i++) {
            String width = columns.get(i).getAttributeNS(W_NS, "w");
            sliver[i] = width != null && width.matches("\\d{1,9}") && Integer.parseInt(width) < SLIVER_TWIPS;
        }
        return sliver;
    }

    /**
     * One row's cells on the grid, slivers taken out, or null when its positions (with
     * {@code w:gridAfter}) run past {@link #MAX_GRID_COLUMNS}. Integer arithmetic only, on capped values:
     * a hostile span cannot overflow. A cell covering only slivers covers no column (an empty cover).
     * Columns strictly increase along the row, so no two cells ever share a place.
     */
    private static List<GridCell> gridRow(Element row, boolean[] sliver) {
        List<Element> cells = cellsOf(row);
        int n = cells.size();
        int[] start = new int[n];
        int[] end = new int[n];
        boolean[] continues = new boolean[n];
        int column = gridValue(row, "trPr", "gridBefore", 0);
        for (int i = 0; i < n; i++) {
            int span = Math.max(1, gridValue(cells.get(i), "tcPr", "gridSpan", 1));
            start[i] = column;
            end[i] = column + span;
            column = end[i];
            if (column > MAX_GRID_COLUMNS) {
                return null;
            }
            String merge = hMerge(cells.get(i));
            continues[i] = "continue".equals(merge) && i > 0
                    && ("restart".equals(hMerge(cells.get(i - 1))) || continues[i - 1]);
        }
        if (column + gridValue(row, "trPr", "gridAfter", 0) > MAX_GRID_COLUMNS) {
            return null;
        }
        // rank[c]: the columns before grid column c, slivers not counted.
        int[] rank = new int[column + 1];
        for (int c = 0; c < column; c++) {
            rank[c + 1] = rank[c] + (isSliver(sliver, c) ? 0 : 1);
        }
        List<GridCell> out = new ArrayList<>(n);
        int previous = -1;
        for (int first = 0; first < n; ) {
            int last = first;
            while (last + 1 < n && continues[last + 1]) {
                last++;
            }
            int[] cover = collapse(start[first], end[last], sliver, rank);
            for (int i = first; i <= last; i++) {
                int own = collapse(start[i], end[i], sliver, rank)[0];
                previous = Math.max(own, previous + 1);
                out.add(new GridCell(cells.get(i), previous, cover[0], cover[1]));
            }
            first = last + 1;
        }
        return out;
    }

    private static boolean isSliver(boolean[] sliver, int column) {
        return column < sliver.length && sliver[column];
    }

    /** Grid columns {@code [start, end)} without their slivers, as {start, end}; {rank, rank} when all are slivers. */
    private static int[] collapse(int start, int end, boolean[] sliver, int[] rank) {
        int low = start;
        while (low < end && isSliver(sliver, low)) {
            low++;
        }
        int high = end;
        while (high > low && isSliver(sliver, high - 1)) {
            high--;
        }
        return new int[] {rank[low], rank[high]};
    }

    /** The table's rows on its grid, or null when any row's grid cannot be read (see {@link #gridRow}). */
    static List<List<GridCell>> grid(Element table, List<Element> rows) {
        boolean[] sliver = slivers(table);
        List<List<GridCell>> grid = new ArrayList<>(rows.size());
        for (Element row : rows) {
            List<GridCell> cells = gridRow(row, sliver);
            if (cells == null) {
                return null;
            }
            grid.add(cells);
        }
        return grid;
    }

    /**
     * The safe fallback for a table whose grid cannot be read: every cell at its position among its row's
     * cells, as before the grid was read. No column header is ever derived from it (see {@link #parseDocx}).
     */
    private static List<List<GridCell>> physical(List<Element> rows) {
        List<List<GridCell>> grid = new ArrayList<>(rows.size());
        for (Element row : rows) {
            List<Element> cells = cellsOf(row);
            List<GridCell> out = new ArrayList<>(cells.size());
            for (int i = 0; i < cells.size(); i++) {
                out.add(new GridCell(cells.get(i), i, i, i + 1));
            }
            grid.add(out);
        }
        return grid;
    }

    /**
     * Each grid column's header label: the last header row with text in that column. A header cell
     * spanning several columns labels each of them, as one label over its whole cover.
     */
    private static Map<Integer, HeaderLabel> headerLabels(List<List<GridCell>> grid, List<Integer> headerRows) {
        Map<Integer, HeaderLabel> labels = new java.util.HashMap<>();
        for (int headerRow : headerRows) {
            for (GridCell cell : grid.get(headerRow)) {
                String text = cellText(cell.element());
                if (text.isEmpty()) {
                    continue;
                }
                HeaderLabel label = new HeaderLabel(text, cell.coverStart(), cell.coverEnd());
                for (int c = cell.coverStart(); c < cell.coverEnd(); c++) {
                    labels.put(c, label);
                }
            }
        }
        return labels;
    }

    /** A body cell's column header, and whether that header names exactly the columns the cell covers. */
    private record ColumnHeader(String text, boolean aligned) {
        static final ColumnHeader NONE = new ColumnHeader("", false);
    }

    /**
     * The header over a body cell: the one label every column it covers carries. A cell spanning columns
     * with different labels, or a labelled and an unlabelled one, has no header: which column it holds is
     * the very thing the grid does not say. {@code aligned} when that label's own cell covers exactly the
     * cell's columns; a wider header cell (a group label over several sub-columns) names the group, not
     * the column, and {@link Detectors#detectTableSensitiveValues} never preserves on it.
     */
    private static ColumnHeader headerOf(GridCell cell, Map<Integer, HeaderLabel> labels) {
        HeaderLabel first = cell.coverEnd() > cell.coverStart() ? labels.get(cell.coverStart()) : null;
        if (first == null) {
            return ColumnHeader.NONE;
        }
        boolean one = true;
        for (int c = cell.coverStart() + 1; c < cell.coverEnd(); c++) {
            HeaderLabel label = labels.get(c);
            if (label == null || !label.text().equals(first.text())) {
                return ColumnHeader.NONE;
            }
            one &= label.equals(first);
        }
        return new ColumnHeader(first.text(), one && first.start() == cell.coverStart() && first.end() == cell.coverEnd());
    }

    /** Parses DOCX bytes into table-cell and paragraph TextUnits for every Word text part. */
    public static DocumentData parseDocx(byte[] data, String documentId, ResourceLimits limits) {
        validateDocxBytes(data, limits);
        Map<String, byte[]> packageData = open(data, limits).packageData();
        Map<String, Element> parsedParts = parseXmlParts(packageData);
        if (!parsedParts.containsKey("word/document.xml")) {
            throw new InvalidDocumentError("word/document.xml could not be parsed");
        }
        requireParsed(packageData, parsedParts);

        List<TextUnit> units = new ArrayList<>();
        CharBudget budget = new CharBudget(limits.maxTextChars());
        int unitCounter = 0;
        Map<String, Element> sortedParts = new TreeMap<>(PyStr.CODE_POINT_ORDER);
        sortedParts.putAll(parsedParts);

        for (Map.Entry<String, Element> part : sortedParts.entrySet()) {
            String partName = part.getKey();
            if (!isWordTextPart(partName)) {
                continue;
            }
            Element root = part.getValue();
            Set<Element> tableCellParagraphs = Collections.newSetFromMap(new IdentityHashMap<>());
            int tableIndex = 0;
            // Each table's cells (their positions in `units`) and the paragraphs just before it, nearest
            // first: the table's title is named once the paragraphs have their unit ids.
            Map<Integer, List<Integer>> cellsOfTable = new LinkedHashMap<>();
            Map<Integer, List<Element>> titleCandidates = new LinkedHashMap<>();
            Map<Element, String> paragraphUnits = new IdentityHashMap<>();

            for (Element table : LxmlDom.descendants(root, W_NS, "tbl")) {
                if (ancestor(table, "tbl") != null) {
                    continue; // nested content is already owned by its outer cell
                }
                // The table's own rows (also inside a content control); a nested table's paragraphs are
                // absorbed into the outer cell.
                List<Element> rows = rowsOf(table);
                if (rows.isEmpty()) {
                    continue;
                }
                // Every cell at its LOGICAL grid column, so a merged cell never shifts the cells after it
                // against the header. A grid that cannot be read falls back to cell positions, with no
                // column header at all: unknown alignment never drives the column rules.
                List<List<GridCell>> grid = grid(table, rows);
                boolean aligned = grid != null;
                if (!aligned) {
                    grid = physical(rows);
                }
                // Header rows: the leading rows Word repeats as headers; else the first row, but only when
                // it is positively a row of column labels. Otherwise the table has NO header: an unmarked
                // first row is data, so it can never steer the column rules over the cells below it.
                List<Integer> headerRows = new ArrayList<>();
                while (headerRows.size() < rows.size() && repeatsAsHeader(rows.get(headerRows.size()))) {
                    headerRows.add(headerRows.size());
                }
                boolean singleColumn = grid.stream().allMatch(r -> r.size() <= 1);
                if (headerRows.isEmpty() && aligned && rows.size() >= 2 && labelRow(grid.get(0), singleColumn)) {
                    headerRows.add(0);
                }
                Map<Integer, HeaderLabel> labels = aligned ? headerLabels(grid, headerRows) : Map.of();
                List<Element> before = new ArrayList<>();
                for (org.w3c.dom.Node n = table.getPreviousSibling(); n != null && before.size() < 3;
                     n = n.getPreviousSibling()) {
                    if (LxmlDom.is(n, W_NS, "tbl")) {
                        break;
                    }
                    if (LxmlDom.is(n, W_NS, "p")) {
                        before.add((Element) n);
                    }
                }
                titleCandidates.put(tableIndex, before);
                for (int rowIdx = 0; rowIdx < rows.size(); rowIdx++) {
                    boolean isHeaderRow = headerRows.contains(rowIdx);
                    for (GridCell cell : grid.get(rowIdx)) {
                        ColumnHeader header = isHeaderRow ? ColumnHeader.NONE : headerOf(cell, labels);
                        List<String> chars = new ArrayList<>();
                        List<XmlCharRef> charMap = new ArrayList<>();
                        for (Element para : LxmlDom.descendants(cell.element(), W_NS, "p")) {
                            tableCellParagraphs.add(para);
                            ParaChars pc = extractParaChars(root, para, partName, budget);
                            chars.addAll(pc.chars());
                            charMap.addAll(pc.charMap());
                        }
                        if (!chars.isEmpty()) {
                            String joined = String.join("", chars);
                            cellsOfTable.computeIfAbsent(tableIndex, k -> new ArrayList<>()).add(units.size());
                            units.add(new TextUnit("u" + unitCounter, partName, UnitType.TABLE_CELL, joined, joined,
                                    charMap, new TextUnit.TableCellLocation(tableIndex, rowIdx, cell.column(),
                                            header.text(), isHeaderRow, null, header.aligned())));
                            unitCounter++;
                        }
                    }
                }
                tableIndex++;
            }

            for (Element paragraph : LxmlDom.descendants(root, W_NS, "p")) {
                if (tableCellParagraphs.contains(paragraph)) {
                    continue;
                }
                ParaChars pc = extractParaChars(root, paragraph, partName, budget);
                if (!pc.chars().isEmpty()) {
                    String joined = String.join("", pc.chars());
                    paragraphUnits.put(paragraph, "u" + unitCounter);
                    // Global counter that also counted table cells: downstream relies on order only.
                    units.add(new TextUnit("u" + unitCounter, partName, UnitType.PARAGRAPH, joined, joined,
                            pc.charMap(), new TextUnit.ParagraphLocation(unitCounter)));
                    unitCounter++;
                }
            }
            // Each table's title: the nearest paragraph with text just before it (no table between).
            cellsOfTable.forEach((index, positions) -> {
                String title = titleCandidates.getOrDefault(index, List.of()).stream().map(paragraphUnits::get)
                        .filter(java.util.Objects::nonNull).findFirst().orElse(null);
                if (title != null) {
                    for (int position : positions) {
                        TextUnit cell = units.get(position);
                        units.set(position, new TextUnit(cell.unitId(), cell.partName(), cell.unitType(), cell.text(),
                                cell.normalizedText(), cell.charMap(),
                                ((TextUnit.TableCellLocation) cell.location()).withTitle(title)));
                    }
                }
            });
        }
        List<String> inventory = new ArrayList<>(packageData.keySet());
        inventory.sort(PyStr.CODE_POINT_ORDER);
        return new DocumentData(documentId, units, inventory, List.of());
    }

    // ------------------------------------------------------------------ applying a plan

    private record Edit(String path, int charIndex, String replacement) {
    }

    private static void applyNodeEdits(Element root, List<Edit> edits) {
        Map<String, List<Edit>> grouped = new LinkedHashMap<>();
        for (Edit e : edits) {
            if (e.path().startsWith("<")) {
                continue;
            }
            grouped.computeIfAbsent(e.path(), k -> new ArrayList<>()).add(e);
        }
        grouped.forEach((path, nodeEdits) -> {
            Element node = LxmlDom.findByElementPath(root, path);
            if (node == null || !LxmlDom.is(node, W_NS, "t")) {
                return;
            }
            String text = LxmlDom.text(node);
            int[] cps = (text == null ? "" : text).codePoints().toArray();
            List<Edit> ordered = new ArrayList<>(nodeEdits);
            ordered.sort(Comparator.comparingInt(Edit::charIndex).reversed());
            String[] chars = new String[cps.length];
            for (int i = 0; i < cps.length; i++) {
                chars[i] = new String(Character.toChars(cps[i]));
            }
            for (Edit e : ordered) {
                if (0 <= e.charIndex() && e.charIndex() < chars.length) {
                    chars[e.charIndex()] = e.replacement();
                }
            }
            LxmlDom.setText(node, String.join("", chars));
        });
    }

    /** Replaces every code point of every REDACT span with {@link Models#REDACTION_GLYPH}. */
    static void applyPlan(Map<String, Element> parsedParts, DocumentData document, RedactionPlan plan) {
        Map<String, List<Span>> spansByUnit = new LinkedHashMap<>();
        plan.spans().forEach(s -> spansByUnit.computeIfAbsent(s.unitId(), k -> new ArrayList<>()).add(s));
        for (TextUnit unit : document.textUnits()) {
            Element partRoot = parsedParts.get(unit.partName());
            if (partRoot == null) {
                continue;
            }
            int mapLen = unit.charMap().size();
            List<Span> spans = new ArrayList<>(spansByUnit.getOrDefault(unit.unitId(), List.of()));
            spans.sort(Comparator.comparingInt(Span::start).reversed());
            for (Span span : spans) {
                if (span.action() != SpanAction.REDACT) {
                    continue;
                }
                int start = Math.min(Math.max(0, span.start()), mapLen);
                int end = Math.min(Math.max(0, span.end()), mapLen);
                List<Edit> edits = new ArrayList<>();
                for (int i = start; i < end; i++) {
                    XmlCharRef ref = unit.charMap().get(i);
                    if (ref.textNodePath().startsWith("<")) {
                        continue;
                    }
                    edits.add(new Edit(ref.textNodePath(), ref.charIndex(), Models.REDACTION_GLYPH));
                }
                if (!edits.isEmpty()) {
                    applyNodeEdits(partRoot, edits);
                }
            }
        }
    }

    // ------------------------------------------------------------------ metadata cleanup

    private static Element firstChild(Element root, String ns, String local) {
        for (Element child : LxmlDom.childElements(root)) {
            if (LxmlDom.is(child, ns, local)) {
                return child;
            }
        }
        return null;
    }

    private static void setChildText(Element root, String ns, String local, String text) {
        Element child = firstChild(root, ns, local);
        if (child != null) {
            LxmlDom.replaceContentWithText(child, text);
        }
    }

    private static void cleanupCoreProperties(Map<String, Element> parts) {
        Element root = parts.get("docProps/core.xml");
        if (root == null) {
            return;
        }
        setChildText(root, DC_NS, "creator", "");
        setChildText(root, CP_NS, "lastModifiedBy", "");
        setChildText(root, DC_NS, "title", "");
        setChildText(root, CP_NS, "keywords", "");
        setChildText(root, CP_NS, "category", "");
        setChildText(root, DCTERMS_NS, "created", "2000-01-01T00:00:00Z");
        setChildText(root, DCTERMS_NS, "modified", "2000-01-01T00:00:00Z");
    }

    private static void cleanupAppProperties(Map<String, Element> parts) {
        Element root = parts.get("docProps/app.xml");
        if (root == null) {
            return;
        }
        for (Element e : LxmlDom.iterElements(root)) {
            String local = LxmlDom.localName(e);
            if (local.equals("Company") || local.equals("Manager") || local.equals("Template")) {
                LxmlDom.replaceContentWithText(e, "");
            }
        }
    }

    private static void removeCustomProperties(Map<String, Element> parts, Set<String> removedParts) {
        removedParts.add("docProps/custom.xml");
        parts.remove("docProps/custom.xml");
        Element rels = parts.get("_rels/.rels");
        if (rels != null) {
            for (Element rel : LxmlDom.childElements(rels)) {
                String target = LxmlDom.attr(rel, "Target");
                String type = LxmlDom.attr(rel, "Type");
                target = target == null ? "" : target;
                type = type == null ? "" : type;
                if (target.equals("docProps/custom.xml") || target.equals("/docProps/custom.xml")
                        || type.endsWith("/custom-properties")) {
                    LxmlDom.removeWithTail(rel);
                }
            }
        }
        Element contentTypes = parts.get("[Content_Types].xml");
        if (contentTypes != null) {
            for (Element override : LxmlDom.childElements(contentTypes)) {
                if ("/docProps/custom.xml".equals(LxmlDom.attr(override, "PartName"))) {
                    LxmlDom.removeWithTail(override);
                }
            }
        }
    }

    private static void removeElements(Element root, Set<String> locals) {
        for (Element e : LxmlDom.iterElements(root)) {
            if (W_NS.equals(e.getNamespaceURI()) && locals.contains(e.getLocalName()) && LxmlDom.parent(e) != null) {
                LxmlDom.removeWithTail(e);
            }
        }
    }

    private static void cleanupComments(Map<String, Element> parts) {
        if (parts.containsKey("word/comments.xml")) {
            parts.put("word/comments.xml", LxmlDom.newRoot(W_NS, "w", "comments"));
        }
        Element document = parts.get("word/document.xml");
        if (document != null) {
            removeElements(document, Set.of("commentRangeStart", "commentRangeEnd", "commentReference"));
        }
    }

    /** Accepts all tracked changes: unwraps insertions/move-tos, drops deletions/move-froms. */
    private static void cleanupTrackedChanges(Element root) {
        List<Element> wrappers = new ArrayList<>();
        for (Element e : LxmlDom.iterElements(root)) {
            if (W_NS.equals(e.getNamespaceURI()) && Set.of("ins", "del", "moveFrom", "moveTo").contains(e.getLocalName())) {
                wrappers.add(e);
            }
        }
        // Reverse document order keeps nested wrappers consistent while splicing.
        for (int i = wrappers.size() - 1; i >= 0; i--) {
            Element e = wrappers.get(i);
            if (LxmlDom.parent(e) == null) {
                continue;
            }
            if (e.getLocalName().equals("ins") || e.getLocalName().equals("moveTo")) {
                LxmlDom.unwrap(e);
            } else {
                LxmlDom.dropKeepingTail(e);
            }
        }
    }

    /** Removes runs marked hidden via {@code w:rPr/w:vanish}. */
    private static void cleanupHiddenText(Element root) {
        List<Element> runs = new ArrayList<>();
        for (Element run : LxmlDom.iterElements(root)) {
            if (!LxmlDom.is(run, W_NS, "r")) {
                continue;
            }
            boolean vanish = LxmlDom.childElements(run, W_NS, "rPr").stream()
                    .anyMatch(rPr -> !LxmlDom.childElements(rPr, W_NS, "vanish").isEmpty());
            if (vanish) {
                runs.add(run);
            }
        }
        for (Element run : runs) {
            if (LxmlDom.parent(run) != null) {
                LxmlDom.dropKeepingTail(run);
            }
        }
    }

    /** Scrubs metadata, custom properties, comments, tracked changes and hidden text. Returns removed part names. */
    static Set<String> cleanSensitiveParts(Map<String, Element> parts) {
        Set<String> removed = new HashSet<>();
        cleanupCoreProperties(parts);
        cleanupAppProperties(parts);
        removeCustomProperties(parts, removed);
        cleanupComments(parts);
        for (Map.Entry<String, Element> e : new ArrayList<>(parts.entrySet())) {
            if (isWordTextPart(e.getKey())) {
                cleanupTrackedChanges(e.getValue());
                cleanupHiddenText(e.getValue());
            }
        }
        return removed;
    }

    // ------------------------------------------------------------------ write-back

    /**
     * Produces the redacted package: applies the plan, cleans sensitive parts, re-serializes
     * parsed XML parts and copies every other member verbatim with its original metadata.
     */
    public static byte[] writeRedactedDocx(byte[] inputBytes, DocumentData document, RedactionPlan plan,
                                           ResourceLimits limits) {
        return writeRedactedDocxWithTrace(inputBytes, document, plan, limits).bytes();
    }

    record WriteResult(byte[] bytes, DocumentData document, SourceCorrespondence correspondence) { }

    static WriteResult writeRedactedDocxWithTrace(byte[] inputBytes, DocumentData document, RedactionPlan plan,
                                                  ResourceLimits limits) {
        validateDocxBytes(inputBytes, limits);
        String stage = "read";
        try {
            ZipPackage pkg = open(inputBytes, limits);
            Map<String, byte[]> packageData = pkg.packageData();

            stage = "parse";
            Map<String, Element> parsedParts = parseXmlParts(packageData);
            requireParsed(packageData, parsedParts);
            SourceCorrespondence.Capture capture = new SourceCorrespondence.Capture(document, parsedParts);

            stage = "apply_plan";
            applyPlan(parsedParts, document, plan);

            stage = "clean_sensitive_parts";
            Set<String> removed = cleanSensitiveParts(parsedParts);

            stage = "write";
            Set<String> written = new HashSet<>();
            List<Map.Entry<ZipArchiveEntry, byte[]>> items = new ArrayList<>();
            for (ZipPackage.Member m : pkg.members()) {
                String name = m.name();
                if (written.contains(name) || removed.contains(name)) {
                    continue;
                }
                written.add(name);
                byte[] payload = parsedParts.containsKey(name)
                        ? LxmlDom.serialize(parsedParts.get(name))
                        : packageData.get(name);
                items.add(new AbstractMap.SimpleEntry<>(m.info(), payload));
            }
            byte[] bytes = ZipPackage.write(items);
            DocumentData output;
            try {
                output = parseDocx(bytes, document.documentId(), limits);
            } catch (AnonymizerError e) {
                throw new DocumentProcessingError("the redacted document is not a valid output package",
                        "INVALID_OUTPUT_PACKAGE", e);
            }
            return new WriteResult(bytes, output, capture.finish(output));
        } catch (InvalidDocumentError | DocumentProcessingError | ResourceLimitExceededError e) {
            throw e;
        } catch (Exception e) {
            throw new DocumentProcessingError("failed during " + stage, e);
        }
    }
}
