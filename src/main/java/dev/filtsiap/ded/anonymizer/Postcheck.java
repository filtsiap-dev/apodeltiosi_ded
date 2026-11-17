package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.PostcheckFinding.Severity.HIGH;
import static dev.filtsiap.ded.anonymizer.PostcheckFinding.Severity.MEDIUM;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.w3c.dom.Element;

/**
 * Mandatory post-redaction audit (port of {@code postcheck.py}). Scans the redacted output for
 * residual leaks: once after the first redaction, and once more on the returned bytes when the
 * remediation rewrote them. No network, no writes, no logging, never a call to a model.
 *
 * <p>WHAT THE PIPELINE DOES WITH A FINDING depends on whether it points at document TEXT. A
 * finding that does carries a {@link ResidualSpan}, the exact slice of the scanned output it was
 * found at, and the pipeline puts that slice to LLM pass 2 instead of failing the document. A
 * finding with no span (package- and structure-level problems, our own write-path residue, the
 * over-redaction reports) keeps the old handling: a HIGH one still aborts the document.
 *
 * <p>THE SPAN IS COMPUTED HERE, WHERE THE MATCH IS, never re-derived later by searching for the
 * matched string: two identical values in two places are two residuals.
 *
 * <p>{@code detail} never echoes matched document text, except for {@code over_redaction}, whose matches are structural markers. The matched text DOES live
 * on {@link ResidualSpan#text()}, which is kept out of every {@code toString} and every map.
 */
public final class Postcheck {

    private static final String W = DocxEngine.W_NS;
    /** Alphanumeric token longer than 12 characters (Unicode word characters, no underscore). */
    private static final PyPattern LONG_TOKEN_RE = PyRegex.compile("[^\\W_]{13,}");

    /**
     * The parts that carry macro code. Named here rather than shared with the write path on
     * purpose: an auditor that imports its expectations from the code it audits cannot catch that
     * code being wrong about them.
     */
    private static final Set<String> MACRO_PARTS = Set.of("word/vbaProject.bin", "word/vbaData.xml");

    /**
     * WHICH FINDING KINDS CAN BE PUT BACK TO PASS 2, and the category each one is recorded under
     * ({@code REMEDIABLE_CATEGORIES}). Every kind not listed keeps its old handling, deliberately:
     * {@code wrong_placeholder} and {@code ellipsis_residue} are residue of our own write path (bug
     * signatures, not judgements; ellipses the input itself had, at the same coordinates, are not
     * reported as residue when source correspondence proves their origin); {@code over_redaction} and {@code label_removed} report text
     * that is MISSING, which nothing can restore; the package-level kinds name a PART, not a
     * slice; and {@code table_invoice_leak} names a CELL, which is not a value.
     */
    public static final Map<String, SpanCategory> REMEDIABLE_CATEGORIES;

    static {
        Map<String, SpanCategory> m = new LinkedHashMap<>();
        m.put("residual_afm", SpanCategory.AFM);
        m.put("afm_shape", SpanCategory.AFM);
        m.put("residual_amka", SpanCategory.AMKA);
        m.put("residual_iban", SpanCategory.IBAN);
        m.put("residual_email", SpanCategory.EMAIL);
        m.put("phone_shape", SpanCategory.PHONE);
        m.put("digit_run", SpanCategory.TRANSACTION_ID);
        m.put("case_ref_leak", SpanCategory.CASE_REF_NUMBER);
        m.put("beneficiary_leak", SpanCategory.PRIVATE_BENEFICIARY);
        m.put("partial_star_residue", SpanCategory.FISCAL_DEVICE_ID);
        m.put("source_mask_identifier", SpanCategory.TRANSACTION_ID);
        m.put("person_name_leak", SpanCategory.POSSIBLE_PERSON);
        m.put("residual_property_id", SpanCategory.PROPERTY_ID);
        // Java-only kinds. "inconsistent_redaction" is remediable too, under the category the plan
        // redacted its value with, so it is not in this fixed map.
        m.put("company_name_leak", SpanCategory.PRIVATE_COMPANY_NAME);
        m.put("account_leak", SpanCategory.BANK_ACCOUNT);
        m.put("street_leak", SpanCategory.PRIVATE_ADDRESS);
        m.put("registry_leak", SpanCategory.CASE_REF_NUMBER);
        REMEDIABLE_CATEGORIES = Collections.unmodifiableMap(m);
    }

    /**
     * The categories whose redacted values the consistency check looks for elsewhere in the same
     * document: identities and identifiers, where the same text means the same thing. Reference
     * numbers, dates and places are not here: there the same digits or words can mean other things.
     */
    private static final Set<SpanCategory> CONSISTENCY_CATEGORIES = Set.of(SpanCategory.AFM, SpanCategory.AMKA,
            SpanCategory.IBAN, SpanCategory.EMAIL, SpanCategory.BANK_ACCOUNT, SpanCategory.PROPERTY_ID,
            SpanCategory.APPELLANT_NAME, SpanCategory.FATHER_NAME, SpanCategory.POSSIBLE_PERSON,
            SpanCategory.PRIVATE_BENEFICIARY, SpanCategory.PRIVATE_COMPANY_NAME, SpanCategory.POSSIBLE_COMPANY,
            SpanCategory.PRIVATE_ADDRESS, SpanCategory.BUSINESS_SEAT);
    private static final Set<SpanCategory> IDENTIFIER_CATEGORIES = Set.of(SpanCategory.AFM, SpanCategory.AMKA,
            SpanCategory.IBAN, SpanCategory.EMAIL, SpanCategory.BANK_ACCOUNT, SpanCategory.PROPERTY_ID);
    private static final Set<SpanCategory> ADDRESS_CATEGORIES = Set.of(SpanCategory.PRIVATE_ADDRESS,
            SpanCategory.BUSINESS_SEAT);
    private static final PyPattern LEADING_ARTICLE_RE = PyRegex.compile("^(?:του|της|των)\\s+", PyRegex.IGNORECASE);

    /** One case-insensitive literal pattern per structural label, in vocabulary order. */
    private static final List<PyPattern> LABEL_PATTERNS = PostcheckPatterns.LABEL_VOCABULARY.stream()
            .map(label -> PyRegex.compile(PyRegex.escape(label), PyRegex.IGNORECASE)).toList();

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

    /**
     * Audits redacted DOCX bytes within {@code limits} (the same limits the input was read under,
     * so a document accepted under raised limits is not refused at its own scan).
     *
     * @param sourceDocument the PARSED INPUT, or null: with it the scan also reports structural
     *                       labels that went in and did not come out (over-redaction), and tells the
     *                       input's own ellipses from write-path residue
     */
    public static PostcheckSummary scanRedactedDocxBytes(byte[] redactedBytes, FileConfig files,
                                                         DocumentData sourceDocument, ResourceLimits limits) {
        return scanRedactedDocxBytes(redactedBytes, files, sourceDocument, null, limits);
    }

    /**
     * The same scan, also reporting {@code inconsistent_redaction}: a value {@code plan} redacted in one
     * place that is still visible in another. Needs the parsed input whose coordinates {@code plan}
     * uses; skipped when the scanned parse no longer lines up with it unit for unit.
     */
    public static PostcheckSummary scanRedactedDocxBytes(byte[] redactedBytes, FileConfig files,
                                                         DocumentData sourceDocument, RedactionPlan plan,
                                                         ResourceLimits limits) {
        return scanRedactedDocxBytes(redactedBytes, files, sourceDocument, plan, limits, null);
    }

    static PostcheckSummary scanRedactedDocxBytes(byte[] redactedBytes, FileConfig files,
                                                  DocumentData sourceDocument, RedactionPlan plan,
                                                  ResourceLimits limits, SourceCorrespondence trace) {
        DocxEngine.validateDocxBytes(redactedBytes, limits);
        DocumentData document = DocxEngine.parseDocx(redactedBytes, "postcheck", limits);
        List<PostcheckFinding> findings = new ArrayList<>();
        List<TextUnit> units = document.textUnits();
        SourceCorrespondence correspondence = trace == null
                ? SourceCorrespondence.sameLocations(sourceDocument, document) : trace;

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

        // The exact text-unit slice a match sits in, or null: for a kind nothing downstream can act
        // on, and for a match that runs past its unit into the "\n" joining it to the next one
        // (it belongs to no single unit, so there is nowhere exact to write a decision).
        // Surrounding whitespace belongs to the sentence, not the value: this is a write boundary.
        Slicer sliceAt = (category, start, end) -> {
            if (category == null || units.isEmpty() || end <= start) {
                return null;
            }
            int index = bisectRight(offsets, start) - 1;
            if (index < 0 || index >= units.size()) {
                return null;
            }
            TextUnit unit = units.get(index);
            String unitText = unit.normalizedText();
            int localStart = start - offsets[index];
            int localEnd = end - offsets[index];
            if (localStart < 0 || localEnd > PyStr.len(unitText)) {
                return null;
            }
            while (localStart < localEnd && PyUnicode.isSpace(PyStr.codePointAt(unitText, localStart))) {
                localStart++;
            }
            while (localEnd > localStart && PyUnicode.isSpace(PyStr.codePointAt(unitText, localEnd - 1))) {
                localEnd--;
            }
            if (localStart >= localEnd) {
                return null;
            }
            return new ResidualSpan(unit.unitId(), localStart, localEnd, PyStr.slice(unitText, localStart, localEnd),
                    category);
        };
        // A finding for the value at [start, end), carrying that slice; located at `at` (the cue,
        // for the checks that match a label and capture what follows it).
        Residual residual = (severity, kind, start, end, detail, at) -> new PostcheckFinding(severity, kind,
                locate.apply(at), detail, sliceAt.at(REMEDIABLE_CATEGORIES.get(kind), start, end));

        List<Range> amkaRanges = new ArrayList<>();
        List<Range> phoneRanges = new ArrayList<>();
        Map<String, PyPattern> qa = PostcheckPatterns.QA_PATTERNS;

        for (PyMatch m : qa.get("AFM").finditer(text)) {
            if (PostcheckSupport.afmChecksumOk(m.group(1))) {
                findings.add(residual.of(HIGH, "residual_afm", m.start(1), m.end(1),
                        "valid-checksum 9-digit AFM survives", m.start(1)));
            } else {
                findings.add(residual.of(MEDIUM, "afm_shape", m.start(1), m.end(1),
                        "9-digit AFM-shaped run survives", m.start(1)));
            }
        }
        for (PyMatch m : qa.get("AMKA").finditer(text)) {
            amkaRanges.add(new Range(m.start(1), m.end(1)));
            findings.add(residual.of(HIGH, "residual_amka", m.start(1), m.end(1),
                    "11-digit AMKA-shaped value survives", m.start(1)));
        }
        for (PyMatch m : qa.get("IBAN_GR").finditer(text)) {
            if (PostcheckSupport.ibanChecksumOk(m.group())) {
                findings.add(residual.of(HIGH, "residual_iban", m.start(), m.end(), "valid Greek IBAN survives",
                        m.start()));
            }
        }
        for (PyMatch m : qa.get("EMAIL").finditer(text)) {
            String domain = PyStr.casefold(PyStr.afterLast(m.group(), "@"));
            if (files.rules().preserveEmailDomains().contains(domain)) {
                continue;
            }
            findings.add(residual.of(HIGH, "residual_email", m.start(), m.end(), "email address survives",
                    m.start()));
        }
        for (PyMatch m : qa.get("PHONE").finditer(text)) {
            if (PostcheckSupport.normalizedGreekPhone(m.group()).isEmpty()) {
                continue;
            }
            phoneRanges.add(new Range(m.start(), m.end()));
            int phoneUnit = bisectRight(offsets, m.start()) - 1;
            if (phoneUnit >= 0 && PostcheckSupport.looksLikeOfficialContactPhone(document,
                    units.get(phoneUnit), m.start() - offsets[phoneUnit])) {
                continue;
            }
            findings.add(residual.of(MEDIUM, "phone_shape", m.start(), m.end(), "Greek phone-shaped number survives",
                    m.start()));
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
            findings.add(residual.of(MEDIUM, "digit_run", m.start(), m.end(),
                    "suspicious " + PyStr.len(run) + "-digit run survives", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.WRONG_PLACEHOLDER_RE.finditer(text)) {
            int index = bisectRight(offsets, m.start()) - 1;
            if (index >= 0 && correspondence.unchanged(units.get(index).unitId(),
                    m.start() - offsets[index], m.end() - offsets[index])) {
                if (m.group().codePoints().anyMatch(Character::isDigit)) {
                    findings.add(residual.of(HIGH, "source_mask_identifier", m.start(), m.end(),
                            "source masking leaves identifier characters visible", m.start()));
                }
                continue;
            }
            findings.add(new PostcheckFinding(HIGH, "wrong_placeholder", locate.apply(m.start()),
                    "unattributed placeholder of " + PyStr.len(m.group()) + " code points survives"));
        }
        for (PyMatch m : PostcheckPatterns.ELLIPSIS_RUN_RE.finditer(text)) {
            int index = bisectRight(offsets, m.start()) - 1;
            if (index >= 0 && correspondence.unchanged(units.get(index).unitId(),
                    m.start() - offsets[index], m.end() - offsets[index])) {
                continue; // the input's own punctuation, exactly where the input had it: not our residue
            }
            int n = PyStr.len(m.group());
            findings.add(new PostcheckFinding(n >= 2 ? HIGH : MEDIUM, "ellipsis_residue", locate.apply(m.start()),
                    "run of " + n + " U+2026 ellipsis chars — old glyph applied char-by-char"));
        }
        for (PyMatch m : PostcheckPatterns.CASE_REF_LEAK_RE.finditer(text)) {
            if (m.group(1).contains(".")) {
                continue;
            }
            findings.add(residual.of(MEDIUM, "case_ref_leak", m.start(1), m.end(1),
                    "case reference value survives after its label", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.BENEFICIARY_LEAK_RE.finditer(text)) {
            findings.add(residual.of(MEDIUM, "beneficiary_leak", m.start(1), m.end(1),
                    "beneficiary name survives after δικαιούχο", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.PARTIAL_STAR_RESIDUE_RE.finditer(text)) {
            findings.add(residual.of(MEDIUM, "partial_star_residue", m.start(), m.end(),
                    "partial-star masked identifier survives", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.PERSON_LEAK_RE.finditer(text)) {
            findings.add(residual.of(MEDIUM, "person_name_leak", m.start(1), m.end(1),
                    "capitalized person name survives after identity context", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.COMPANY_NAME_LEAK_RE.finditer(text)) {
            findings.add(residual.of(MEDIUM, "company_name_leak", m.start(1), m.end(1),
                    "company name survives after its cue", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.ACCOUNT_LEAK_RE.finditer(text)) {
            findings.add(residual.of(MEDIUM, "account_leak", m.start(1), m.end(1),
                    "account identifier survives after its cue", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.STREET_LEAK_RE.finditer(text)) {
            int group = m.start(1) >= 0 ? 1 : 2;
            findings.add(residual.of(MEDIUM, "street_leak", m.start(group), m.end(group),
                    "street name survives after its cue", m.start()));
        }
        for (PyMatch m : PostcheckPatterns.REGISTRY_LEAK_RE.finditer(text)) {
            findings.add(residual.of(MEDIUM, "registry_leak", m.start(1), m.end(1),
                    "register or gazette-issue number survives after its cue", m.start()));
        }
        if (sourceDocument != null && plan != null) {
            inconsistentRedactions(correspondence, document, plan, offsets, locate, sliceAt, findings);
        }
        for (PyMatch m : PostcheckPatterns.OVER_REDACT_RE.finditer(text)) {
            findings.add(new PostcheckFinding(MEDIUM, "over_redaction", locate.apply(m.start()),
                    "over-redacted preserved metadata: " + m.group()));
        }

        // HIGH and list-aware: PROPERTY_ID is a hard-redact category, so a surviving value is a
        // miss by every stage at once. The whole comma/"και"-joined run after each cue is walked,
        // because the interesting failure is the SECOND value of a list surviving.
        for (PostcheckPatterns.PropertyIdPattern spec : PostcheckPatterns.PROPERTY_ID_PATTERNS) {
            for (PyMatch cue : spec.cue().finditer(text)) {
                String window = PyStr.slice(text, cue.end(), cue.end() + PostcheckPatterns.PROPERTY_LIST_BUDGET);
                int join = window.indexOf('\n'); // a list never spans a text unit
                if (join >= 0) {
                    window = window.substring(0, join);
                }
                PyMatch run = spec.list().match(window);
                if (run == null) {
                    continue;
                }
                for (PyMatch value : spec.value().finditer(run.group())) {
                    findings.add(residual.of(HIGH, "residual_property_id", cue.end() + value.start(),
                            cue.end() + value.end(), spec.name() + " value survives after its label",
                            cue.end() + value.start()));
                }
            }
        }

        // The over-redaction counterpart: a structural label that is in the input and gone from
        // the output was eaten by a span that reached too far. Counts only, no document text.
        if (sourceDocument != null) {
            String sourceText = String.join("\n", sourceDocument.textUnits().stream()
                    .map(TextUnit::normalizedText).toList());
            for (PyPattern label : LABEL_PATTERNS) {
                int before = label.countAll(sourceText);
                int after = label.countAll(text);
                if (before > after) {
                    findings.add(new PostcheckFinding(MEDIUM, "label_removed", "document", (before - after) + " of "
                            + before + " occurrence(s) of a structural label were redacted with their value"));
                }
            }
        }

        // --- table check
        for (int i = 0; i < units.size(); i++) {
            TextUnit u = units.get(i);
            if (u.unitType() != UnitType.TABLE_CELL || !(u.location() instanceof TextUnit.TableCellLocation loc)) {
                continue;
            }
            String header = PyStr.casefold(PyStr.collapseWhitespace(loc.columnHeader()));
            // A bank's name under a bank column is kept by policy: no finding.
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
            pkg = ZipPackage.read(redactedBytes, limits);
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
        // Java-only, deliberately kept: v2 no longer audits dc:creator/cp:lastModifiedBy because its
        // write path now preserves them; this write path still blanks them, so a non-blank one here
        // is that code failing, and it blocks.
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
            if (MACRO_PARTS.contains(name)) {
                // A surviving macro part means the output can still execute code: far worse to hand
                // back than any text leak.
                findings.add(new PostcheckFinding(HIGH, "macro_part_survived", name,
                        "macro project survived normalization"));
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

    /**
     * THE CONSISTENCY CHECK, Java-only: a value {@code plan} REDACTED in one place that is still
     * visible, wholly or in part, in another. Found by searching the SOURCE units (whitespace runs
     * may differ between occurrences) and judged on the scanned units at the same offsets, which line
     * up because redaction is one character for one. Only identities and identifiers, and only
     * values strong enough to mean the same thing everywhere; a finding is a question for pass 2,
     * never a redaction by itself.
     */
    private static void inconsistentRedactions(SourceCorrespondence correspondence, DocumentData scanned, RedactionPlan plan,
                                               int[] offsets, java.util.function.IntFunction<String> locate,
                                               Slicer sliceAt, List<PostcheckFinding> findings) {
        Map<String, SpanCategory> values = new LinkedHashMap<>();
        for (Span span : plan.spans()) {
            if (span.action() == SpanAction.REDACT && CONSISTENCY_CATEGORIES.contains(span.category())) {
                String value = PyStr.collapseWhitespace(LEADING_ARTICLE_RE.subLiteral("", span.text()));
                if (strongValue(value, span.category())) {
                    values.putIfAbsent(value, span.category());
                }
            }
        }
        List<TextUnit> scannedUnits = scanned.textUnits();
        for (Map.Entry<String, SpanCategory> value : values.entrySet()) {
            String[] words = value.getKey().split(" ");
            StringBuilder regex = new StringBuilder("(?<![\\w@.])");
            for (int w = 0; w < words.length; w++) {
                regex.append(w == 0 ? "" : "\\s+").append(PyRegex.escape(words[w]));
            }
            PyPattern occurrence = PyRegex.compile(regex.append("(?![\\w@])").toString());
            for (int i = 0; i < scannedUnits.size(); i++) {
                TextUnit sourceUnit = correspondence.alignedSource(scannedUnits.get(i));
                if (sourceUnit == null) {
                    continue;
                }
                String before = sourceUnit.normalizedText();
                String after = scannedUnits.get(i).normalizedText();
                for (PyMatch m : occurrence.finditer(before)) {
                    if (stillVisible(before, after, m.start(), m.end())) {
                        int at = offsets[i] + m.start();
                        findings.add(new PostcheckFinding(MEDIUM, "inconsistent_redaction", locate.apply(at),
                                "a value redacted elsewhere in this document is visible here",
                                sliceAt.at(value.getValue(), at, offsets[i] + m.end())));
                    }
                }
            }
        }
    }

    /** Long and specific enough that the same text is the same identity or identifier wherever it is. */
    private static boolean strongValue(String value, SpanCategory category) {
        long letters = value.codePoints().filter(Character::isLetter).count();
        long digits = value.codePoints().filter(Character::isDigit).count();
        if (IDENTIFIER_CATEGORIES.contains(category)) {
            return digits >= 6 || value.contains("@");
        }
        if (ADDRESS_CATEGORIES.contains(category)) {
            return letters >= 8 && value.contains(" ");
        }
        return letters >= 4 && !value.isEmpty() && Character.isUpperCase(value.codePointAt(0));
    }

    /**
     * Whether most of {@code [start, end)} came through unredacted: at least half its letters and
     * digits. A value whose identifying part was blanked and whose structural tail ("/2026") stays is
     * redacted there, not inconsistent; a name with only the gaps between its words dotted is not.
     */
    private static boolean stillVisible(String before, String after, int start, int end) {
        int total = 0;
        int visible = 0;
        for (int k = start; k < end; k++) {
            int cp = PyStr.codePointAt(before, k);
            if (Character.isLetterOrDigit(cp)) {
                total++;
                if (PyStr.codePointAt(after, k) == cp) {
                    visible++;
                }
            }
        }
        return total > 0 && 2 * visible >= total;
    }

    @FunctionalInterface
    private interface Slicer {
        ResidualSpan at(SpanCategory category, int start, int end);
    }

    @FunctionalInterface
    private interface Residual {
        PostcheckFinding of(PostcheckFinding.Severity severity, String kind, int start, int end, String detail, int at);
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
