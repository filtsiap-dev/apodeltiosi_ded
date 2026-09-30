package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.text.Normalizer;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
     * Validates a DOCX package: a readable ZIP with intact members, the required parts, and a
     * strictly parsing {@code word/document.xml}. Throws {@link InvalidDocumentError}.
     */
    public static void validateDocxBytes(byte[] data) {
        ZipPackage pkg = open(data);
        Set<String> names = new HashSet<>(pkg.names());
        List<String> missing = new ArrayList<>();
        for (String required : List.of("[Content_Types].xml", "_rels/.rels", "word/document.xml")) {
            if (!names.contains(required)) {
                missing.add(required);
            }
        }
        if (!missing.isEmpty()) {
            throw new InvalidDocumentError("Not a valid DOCX package: missing " + String.join(", ", missing));
        }
        validateMainDocumentXml(pkg.packageData().get("word/document.xml"));
    }

    private static ZipPackage open(byte[] data) {
        try {
            return ZipPackage.read(data);
        } catch (ZipPackage.BadZipFile e) {
            throw new InvalidDocumentError("Not a valid DOCX package", e);
        } catch (ZipPackage.CorruptMember e) {
            throw new InvalidDocumentError("Not a valid DOCX package: corrupt member " + e.memberName(), e);
        }
    }

    // ------------------------------------------------------------------ part parsing

    /** Parses every .xml/.rels member with the recovering parser; unparseable parts are skipped. */
    static Map<String, Element> parseXmlParts(Map<String, byte[]> packageData) {
        Map<String, Element> parsed = new LinkedHashMap<>();
        packageData.forEach((name, blob) -> {
            if (!(name.endsWith(".xml") || name.endsWith(".rels"))) {
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
     * Visible characters of a paragraph (per-character NFC, tabs, breaks) with a parallel map
     * into the XML. Per-character NFC never changes the count, which keeps offsets aligned.
     */
    private static ParaChars extractParaChars(Element root, Element paragraph, String partName) {
        List<String> chars = new ArrayList<>();
        List<XmlCharRef> map = new ArrayList<>();
        for (Element node : LxmlDom.iterElements(paragraph)) {
            if (LxmlDom.is(node, W_NS, "t")) {
                String text = LxmlDom.text(node);
                if (text == null) {
                    text = "";
                }
                String path = LxmlDom.elementPath(root, node);
                int idx = 0;
                for (int cp : text.codePoints().toArray()) {
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
                chars.add("\t");
                map.add(new XmlCharRef(partName, "<w:tab/>", 0));
            } else if (LxmlDom.is(node, W_NS, "br")) {
                chars.add("\n");
                map.add(new XmlCharRef(partName, "<w:br/>", 0));
            } else if (LxmlDom.is(node, W_NS, "cr")) {
                chars.add("\n");
                map.add(new XmlCharRef(partName, "<w:cr/>", 0));
            }
        }
        if (chars.size() != map.size()) {
            throw new IllegalStateException("char/char_map desynchronized");
        }
        return new ParaChars(chars, map);
    }

    // ------------------------------------------------------------------ parsing

    /** Parses DOCX bytes into table-cell and paragraph TextUnits for every Word text part. */
    public static DocumentData parseDocx(byte[] data, String documentId) {
        validateDocxBytes(data);
        Map<String, byte[]> packageData = open(data).packageData();
        Map<String, Element> parsedParts = parseXmlParts(packageData);
        if (!parsedParts.containsKey("word/document.xml")) {
            throw new InvalidDocumentError("word/document.xml could not be parsed");
        }
        requireParsed(packageData, parsedParts);

        List<TextUnit> units = new ArrayList<>();
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

            for (Element table : LxmlDom.descendants(root, W_NS, "tbl")) {
                // Direct-child rows only; a nested table's paragraphs are absorbed into the outer cell.
                List<Element> rows = LxmlDom.childElements(table, W_NS, "tr");
                if (rows.isEmpty()) {
                    continue;
                }
                List<String> headerTexts = new ArrayList<>();
                for (Element cell : LxmlDom.childElements(rows.get(0), W_NS, "tc")) {
                    StringBuilder cellText = new StringBuilder();
                    for (Element node : LxmlDom.iterElements(cell)) {
                        if (LxmlDom.is(node, W_NS, "t")) {
                            String t = LxmlDom.text(node);
                            cellText.append(t == null ? "" : t);
                        }
                    }
                    headerTexts.add(PyStr.strip(cellText.toString()));
                }
                for (int rowIdx = 0; rowIdx < rows.size(); rowIdx++) {
                    boolean isHeaderRow = rowIdx == 0;
                    List<Element> cells = LxmlDom.childElements(rows.get(rowIdx), W_NS, "tc");
                    for (int colIdx = 0; colIdx < cells.size(); colIdx++) {
                        String colHeader = colIdx < headerTexts.size() ? headerTexts.get(colIdx) : "";
                        List<String> chars = new ArrayList<>();
                        List<XmlCharRef> charMap = new ArrayList<>();
                        for (Element para : LxmlDom.descendants(cells.get(colIdx), W_NS, "p")) {
                            tableCellParagraphs.add(para);
                            ParaChars pc = extractParaChars(root, para, partName);
                            chars.addAll(pc.chars());
                            charMap.addAll(pc.charMap());
                        }
                        if (!chars.isEmpty()) {
                            String joined = String.join("", chars);
                            units.add(new TextUnit("u" + unitCounter, partName, UnitType.TABLE_CELL, joined, joined,
                                    charMap, new TextUnit.TableCellLocation(tableIndex, rowIdx, colIdx,
                                            isHeaderRow ? "" : colHeader, isHeaderRow)));
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
                ParaChars pc = extractParaChars(root, paragraph, partName);
                if (!pc.chars().isEmpty()) {
                    String joined = String.join("", pc.chars());
                    // Global counter that also counted table cells: downstream relies on order only.
                    units.add(new TextUnit("u" + unitCounter, partName, UnitType.PARAGRAPH, joined, joined,
                            pc.charMap(), new TextUnit.ParagraphLocation(unitCounter)));
                    unitCounter++;
                }
            }
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
            if (node == null) {
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
    public static byte[] writeRedactedDocx(byte[] inputBytes, DocumentData document, RedactionPlan plan) {
        validateDocxBytes(inputBytes);
        String stage = "read";
        try {
            ZipPackage pkg = open(inputBytes);
            Map<String, byte[]> packageData = pkg.packageData();

            stage = "parse";
            Map<String, Element> parsedParts = parseXmlParts(packageData);
            requireParsed(packageData, parsedParts);

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
            return ZipPackage.write(items);
        } catch (InvalidDocumentError | DocumentProcessingError e) {
            throw e;
        } catch (Exception e) {
            throw new DocumentProcessingError("failed during " + stage, e);
        }
    }
}
