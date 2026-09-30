package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.PostcheckFinding.Severity.HIGH;
import static dev.filtsiap.ded.anonymizer.PostcheckFinding.Severity.MEDIUM;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.w3c.dom.Element;

/**
 * Mandatory post-redaction audit (port of {@code postcheck.py}). Scans the redacted output for
 * residual leaks; the pipeline blocks on any HIGH finding. {@code detail} never echoes matched
 * document text, except for {@code wrong_placeholder} and {@code over_redaction}, whose matches
 * cannot be PII by construction. No network, no writes, no logging.
 */
public final class Postcheck {

    private static final String W = DocxEngine.W_NS;
    /** Alphanumeric token longer than 12 characters (Unicode word characters, no underscore). */
    private static final PyPattern LONG_TOKEN_RE = PyRegex.compile("[^\\W_]{13,}");

    private Postcheck() {
    }

    private record Range(int start, int end) {
    }

    private static boolean overlaps(Range span, List<Range> ranges) {
        for (Range r : ranges) {
            if (span.start() < r.end() && r.start() < span.end()) {
                return true;
            }
        }
        return false;
    }

    static boolean isTextPart(String name) {
        return DocxEngine.isWordTextPart(name);
    }

    static boolean isHeaderFooterPart(String name) {
        return (name.startsWith("word/header") || name.startsWith("word/footer")) && name.endsWith(".xml");
    }

    /** Audits redacted DOCX bytes; returns severity- and kind-bucketed findings. */
    public static PostcheckSummary scanRedactedDocxBytes(byte[] redactedBytes, FileConfig files) {
        DocxEngine.validateDocxBytes(redactedBytes);
        DocumentData document = DocxEngine.parseDocx(redactedBytes, "postcheck");
        List<PostcheckFinding> findings = new ArrayList<>();
        List<TextUnit> units = document.textUnits();

        // Joined text plus the code-point offset where each unit starts.
        List<String> parts = new ArrayList<>();
        int[] offsets = new int[units.size()];
        int cursor = 0;
        for (int i = 0; i < units.size(); i++) {
            offsets[i] = cursor;
            parts.add(units.get(i).normalizedText());
            cursor += PyStr.len(units.get(i).normalizedText()) + 1;
        }
        String text = String.join("\n", parts);

        java.util.function.IntFunction<String> locate = pos -> {
            if (units.isEmpty()) {
                return "unknown";
            }
            int idx = bisectRight(offsets, pos) - 1;
            idx = Math.max(0, Math.min(idx, units.size() - 1));
            TextUnit u = units.get(idx);
            return u.partName() + ":" + u.unitId();
        };

        List<Range> amkaRanges = new ArrayList<>();
        List<Range> phoneRanges = new ArrayList<>();
        Map<String, PyPattern> qa = PostcheckPatterns.QA_PATTERNS;

        for (PyMatch m : qa.get("AFM").finditer(text)) {
            if (PostcheckSupport.afmChecksumOk(m.group(1))) {
                findings.add(new PostcheckFinding(HIGH, "residual_afm", locate.apply(m.start(1)),
                        "valid-checksum 9-digit AFM survives"));
            } else {
                findings.add(new PostcheckFinding(MEDIUM, "afm_shape", locate.apply(m.start(1)),
                        "9-digit AFM-shaped run survives"));
            }
        }
        for (PyMatch m : qa.get("AMKA").finditer(text)) {
            amkaRanges.add(new Range(m.start(1), m.end(1)));
            findings.add(new PostcheckFinding(HIGH, "residual_amka", locate.apply(m.start(1)),
                    "11-digit AMKA-shaped value survives"));
        }
        for (PyMatch m : qa.get("IBAN_GR").finditer(text)) {
            if (PostcheckSupport.ibanChecksumOk(m.group())) {
                findings.add(new PostcheckFinding(HIGH, "residual_iban", locate.apply(m.start()),
                        "valid Greek IBAN survives"));
            }
        }
        for (PyMatch m : qa.get("EMAIL").finditer(text)) {
            String domain = PyStr.casefold(PyStr.afterLast(m.group(), "@"));
            if (files.rules().preserveEmailDomains().contains(domain)) {
                continue;
            }
            findings.add(new PostcheckFinding(HIGH, "residual_email", locate.apply(m.start()),
                    "email address survives"));
        }
        for (PyMatch m : qa.get("PHONE").finditer(text)) {
            if (PostcheckSupport.normalizedGreekPhone(m.group()).isEmpty()) {
                continue;
            }
            phoneRanges.add(new Range(m.start(), m.end()));
            if (PostcheckSupport.looksLikeOfficialContactPhone(text, m.start())) {
                continue;
            }
            findings.add(new PostcheckFinding(MEDIUM, "phone_shape", locate.apply(m.start()),
                    "Greek phone-shaped number survives"));
        }
        for (PyMatch m : qa.get("DIGIT_RUN").finditer(text)) {
            String run = m.group();
            if (PyStr.len(run) == 9) {
                continue; // the AFM checks own that length
            }
            Range span = new Range(m.start(), m.end());
            if (overlaps(span, amkaRanges) || overlaps(span, phoneRanges)) {
                continue;
            }
            if (PostcheckSupport.normalizedGreekPhone(run).isPresent()) {
                continue;
            }
            findings.add(new PostcheckFinding(MEDIUM, "digit_run", locate.apply(m.start()),
                    "suspicious " + PyStr.len(run) + "-digit run survives"));
        }
        for (PyMatch m : PostcheckPatterns.WRONG_PLACEHOLDER_RE.finditer(text)) {
            findings.add(new PostcheckFinding(HIGH, "wrong_placeholder", locate.apply(m.start()),
                    "placeholder residue survives: " + m.group()));
        }
        for (PyMatch m : PostcheckPatterns.ELLIPSIS_RUN_RE.finditer(text)) {
            int n = PyStr.len(m.group());
            findings.add(new PostcheckFinding(n >= 2 ? HIGH : MEDIUM, "ellipsis_residue", locate.apply(m.start()),
                    "run of " + n + " U+2026 ellipsis chars — old glyph applied char-by-char"));
        }
        for (PyMatch m : PostcheckPatterns.CASE_REF_LEAK_RE.finditer(text)) {
            if (m.group(1).contains(".")) {
                continue;
            }
            findings.add(new PostcheckFinding(MEDIUM, "case_ref_leak", locate.apply(m.start()),
                    "case reference value survives after its label"));
        }
        for (PyMatch m : PostcheckPatterns.BENEFICIARY_LEAK_RE.finditer(text)) {
            findings.add(new PostcheckFinding(MEDIUM, "beneficiary_leak", locate.apply(m.start()),
                    "beneficiary name survives after δικαιούχο"));
        }
        for (PyMatch m : PostcheckPatterns.PARTIAL_STAR_RESIDUE_RE.finditer(text)) {
            findings.add(new PostcheckFinding(MEDIUM, "partial_star_residue", locate.apply(m.start()),
                    "partial-star masked identifier survives"));
        }
        for (PyMatch m : PostcheckPatterns.PERSON_LEAK_RE.finditer(text)) {
            findings.add(new PostcheckFinding(MEDIUM, "person_name_leak", locate.apply(m.start()),
                    "capitalized person name survives after identity context"));
        }
        for (PyMatch m : PostcheckPatterns.OVER_REDACT_RE.finditer(text)) {
            findings.add(new PostcheckFinding(MEDIUM, "over_redaction", locate.apply(m.start()),
                    "over-redacted preserved metadata: " + m.group()));
        }

        // --- table check
        for (TextUnit u : units) {
            if (u.unitType() != UnitType.TABLE_CELL || !(u.location() instanceof TextUnit.TableCellLocation loc)) {
                continue;
            }
            String header = PyStr.casefold(PyStr.collapseWhitespace(loc.columnHeader()));
            if (!PostcheckPatterns.INVOICE_COLUMN_HEADERS.contains(header)) {
                continue;
            }
            if (!PyStr.anyDigit(u.normalizedText())) {
                continue;
            }
            findings.add(new PostcheckFinding(MEDIUM, "table_invoice_leak",
                    "table " + loc.tableIndex() + " row " + loc.rowIndex() + " col " + loc.colIndex(),
                    "digits survive under an invoice column header"));
        }

        // --- ZIP-level checks
        ZipPackage pkg;
        try {
            pkg = ZipPackage.read(redactedBytes);
        } catch (ZipPackage.BadZipFile | ZipPackage.CorruptMember e) {
            throw new InvalidDocumentError("Not a valid DOCX package", e); // unreachable: validated above
        }
        List<String> names = pkg.names();
        Map<String, byte[]> data = pkg.packageData();

        if (names.contains("word/comments.xml")) {
            Element root = LxmlDom.parseRecover(data.get("word/comments.xml"));
            if (root != null && !LxmlDom.descendants(root, W, "comment").isEmpty()) {
                findings.add(new PostcheckFinding(HIGH, "nonempty_comments", "word/comments.xml",
                        "comments part still contains comment elements"));
            }
        }
        for (String name : names) {
            if (!isTextPart(name)) {
                continue;
            }
            Element root = LxmlDom.parseRecover(data.get(name));
            if (root == null) {
                continue;
            }
            if (!LxmlDom.descendants(root, W, "ins").isEmpty() || !LxmlDom.descendants(root, W, "del").isEmpty()) {
                findings.add(new PostcheckFinding(HIGH, "tracked_change", name, "tracked-change markup survives"));
            }
            boolean vanish = LxmlDom.descendants(root, W, "rPr").stream()
                    .anyMatch(rPr -> !LxmlDom.childElements(rPr, W, "vanish").isEmpty());
            if (vanish) {
                findings.add(new PostcheckFinding(MEDIUM, "hidden_text", name, "hidden (vanish) run survives"));
            }
        }
        if (names.contains("docProps/core.xml")) {
            Element root = LxmlDom.parseRecover(data.get("docProps/core.xml"));
            if (root != null) {
                Element creator = firstChild(root, DocxEngine.DC_NS, "creator");
                if (creator != null && !PyStr.strip(textOrEmpty(creator)).isEmpty()) {
                    findings.add(new PostcheckFinding(HIGH, "metadata_creator", "docProps/core.xml",
                            "dc:creator is non-blank"));
                }
                Element lmb = firstChild(root, DocxEngine.CP_NS, "lastModifiedBy");
                if (lmb != null && !PyStr.strip(textOrEmpty(lmb)).isEmpty()) {
                    findings.add(new PostcheckFinding(HIGH, "metadata_last_modified_by", "docProps/core.xml",
                            "cp:lastModifiedBy is non-blank"));
                }
            }
        }
        for (String name : names) {
            boolean isOle = name.startsWith("word/embeddings/oleObject") && PyStr.lower(name).endsWith(".bin");
            if (isOle || name.startsWith("word/media/")) {
                findings.add(new PostcheckFinding(MEDIUM, "embedded_object", name, "embedded object present in package"));
            }
        }
        for (String name : names) {
            if (!isHeaderFooterPart(name)) {
                continue;
            }
            Element root = LxmlDom.parseRecover(data.get(name));
            if (root == null) {
                continue;
            }
            for (String token : LONG_TOKEN_RE.findallStrings(LxmlDom.itertext(root))) {
                findings.add(new PostcheckFinding(MEDIUM, "long_token_header_footer", name,
                        "alphanumeric token of length " + PyStr.len(token) + " survives"));
            }
        }

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        Map<String, Integer> byKind = new LinkedHashMap<>();
        for (PostcheckFinding f : findings) {
            bySeverity.merge(f.severity().name(), 1, Integer::sum);
            byKind.merge(f.kind(), 1, Integer::sum);
        }
        return new PostcheckSummary(findings.isEmpty(), findings.size(), bySeverity, byKind, findings);
    }

    private static String textOrEmpty(Element e) {
        String t = LxmlDom.text(e);
        return t == null ? "" : t;
    }

    private static Element firstChild(Element root, String ns, String local) {
        for (Element child : LxmlDom.childElements(root)) {
            if (LxmlDom.is(child, ns, local)) {
                return child;
            }
        }
        return null;
    }

    /** Python {@code bisect.bisect_right}. */
    static int bisectRight(int[] sorted, int x) {
        int lo = 0;
        int hi = sorted.length;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (x < sorted[mid]) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        return lo;
    }
}
