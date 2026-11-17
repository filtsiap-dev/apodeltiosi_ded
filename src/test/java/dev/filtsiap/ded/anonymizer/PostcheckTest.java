package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class PostcheckTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));

    static PostcheckSummary scan(byte[] docx) {
        return Postcheck.scanRedactedDocxBytes(docx, FILES, null, ResourceLimits.DEFAULTS);
    }

    static PostcheckSummary scan(String... paragraphs) {
        return scan(TestDocx.paragraphs(paragraphs).bytes());
    }

    /** Each finding as kind@unit:start:end:text, "-" for one that names no slice. */
    static List<String> slices(PostcheckSummary s) {
        return s.findings().stream().map(f -> f.kind() + "@" + (f.span() == null ? "-" : f.span().unitId() + ":"
                + f.span().start() + ":" + f.span().end() + ":" + f.span().text())).toList();
    }

    /**
     * R-3: both email patterns run over whole texts of up to 400,000 characters. Unbounded, a long
     * run with no '@' cost O(n^2) (estimated at tens of minutes of CPU at this size); bounded to
     * RFC 5321's 64/253, each one is linear.
     */
    @Test
    void theEmailPatternsAreLinearOnLongRunsWithoutAnAt() {
        dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern qa = PostcheckPatterns.QA_PATTERNS.get("EMAIL");
        dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern detector = DetectorSupport.compile(
                "\\b" + DetectorSupport.body(FILES.rules(), "email") + "\\b",
                dev.filtsiap.ded.anonymizer.pycompat.PyRegex.IGNORECASE);
        for (String text : List.of("a".repeat(400_000), "a@" + "b".repeat(400_000), "x@" + "b.".repeat(200_000),
                "ab@".repeat(130_000))) {
            for (var pattern : List.of(qa, detector)) {
                org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(5),
                        () -> pattern.finditer(text));
            }
        }
    }

    @Test
    void theBoundedEmailPatternsStillFindOrdinaryAndOverlongAddresses() {
        dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern qa = PostcheckPatterns.QA_PATTERNS.get("EMAIL");
        assertEquals("g.papadopoulos@example.com",
                qa.finditer("email g.papadopoulos@example.com, τηλ.").get(0).group());
        // A local part past 64 characters still matches: its last 64 characters, never nothing.
        String overlong = "a".repeat(100) + "@example.gr";
        assertEquals("a".repeat(64) + "@example.gr", qa.finditer(overlong).get(0).group());
        PostcheckSummary s = scan("Επικοινωνία: g.papadopoulos@example.com");
        assertTrue(s.findings().stream().anyMatch(f -> f.kind().equals("residual_email")), slices(s).toString());
    }

    @Test
    void residualValidAfmIsHigh() {
        PostcheckSummary s = scan("ΑΦΜ " + TestDocx.validAfm("12345678"));
        assertEquals(1, s.bySeverity().get("HIGH"));
        assertEquals("residual_afm", s.findings().get(0).kind());
        assertEquals("word/document.xml:u0", s.findings().get(0).location());
    }

    @Test
    void residualAmkaIsHighWhateverTheBirthYear() {
        // DDMMYY: born 15/07/1985 and 03/11/1999. Before O7.3 the scan read YYMMDD and missed both.
        // (A deliberate difference from v2, whose QA pattern still reads YYMMDD.)
        for (String amka : new String[] {"15078512345", "03119912345", "20040512345"}) {
            assertEquals(1, scan("ΑΜΚΑ " + amka).byKind().get("residual_amka"), amka);
        }
    }

    @Test
    void detailsNeverEchoMatchedPii() {
        String afm = TestDocx.validAfm("87654321");
        PostcheckSummary s = scan("ΑΦΜ " + afm, "email x.y@example.com");
        assertTrue(s.findings().stream().noneMatch(f -> f.detail().contains(afm) || f.detail().contains("x.y@")));
    }

    @Test
    void cleanDocumentIsClean() {
        assertTrue(scan("Απόφαση χωρίς στοιχεία").clean());
    }

    // ------------------------------------------------------------------ the slice a finding names

    @Test
    void textualFindingsCarryTheExactSliceInTheirOwnUnit() {
        String afm = TestDocx.validAfm("09401420");
        PostcheckSummary s = scan("εισαγωγή", "😀 κωδικός " + afm + " και κινητό  6912345678  εδώ");
        // Code-point offsets (the emoji is one), in the second unit, the phone without the spaces it absorbed.
        assertEquals(List.of("residual_afm@u1:10:19:" + afm, "phone_shape@u1:32:42:6912345678"), slices(s));
        assertEquals(SpanCategory.AFM, s.findings().get(0).span().category());
        assertEquals(SpanCategory.PHONE, s.findings().get(1).span().category());
    }

    @Test
    void aNameIsTheNameAloneCaseSensitiveAndNeverAcrossAParagraph() {
        PostcheckSummary s = scan("ενδικοφανή προσφυγή του ΜΙΧΟΥ ΝΙΚΟΛΑΟΥ κατά της πράξης του Προϊσταμένου",
                "δικαιούχο τον Γεώργιο Παπαδόπουλο για το ποσό", "ενδικοφανή προσφυγή της Ελένης", "ΣΥΝΟΨΗ");
        // Scan order: every beneficiary check, then every person check.
        assertEquals(List.of("beneficiary_leak@u1:14:33:Γεώργιο Παπαδόπουλο",
                "person_name_leak@u0:24:38:ΜΙΧΟΥ ΝΙΚΟΛΑΟΥ", "person_name_leak@u2:24:30:Ελένης"), slices(s));
        // The location is the cue's, so it does not move when only the value is sliced.
        assertEquals("word/document.xml:u1", s.findings().get(0).location());
    }

    @Test
    void propertyListsAreWalkedSoTheSecondValueIsCaught() {
        PostcheckSummary s = scan("ΑΤΑΚ ..........., 00610643361 και ...........",
                "ΑΤΑΚ 00610643353, 00610643361 και 01188179990", "Ο.Τ. ...", "2019 ήταν το φορολογικό έτος");
        // Every surviving value of every list, each its own slice (offsets as v2 reports them).
        assertEquals(List.of("residual_property_id@u0:18:29:00610643361", "residual_property_id@u1:5:16:00610643353",
                "residual_property_id@u1:18:29:00610643361", "residual_property_id@u1:34:45:01188179990"),
                slices(s).stream().filter(x -> x.startsWith("residual_property_id")).toList());
        PostcheckFinding f = s.findings().stream().filter(x -> x.kind().equals("residual_property_id")).findFirst()
                .orElseThrow();
        assertEquals(PostcheckFinding.Severity.HIGH, f.severity());
        assertEquals("ΑΤΑΚ value survives after its label", f.detail());
        // The year in the next paragraph is not attributed to the "Ο.Τ." at the end of this one.
        assertEquals(4, s.byKind().get("residual_property_id"));
    }

    @Test
    void ownResidueAndPackageProblemsNameNoSliceAndHighOnesBlock() {
        byte[] docx = TestDocx.paragraphs().document(TestDocx.p("[NAME] και …… εδώ")
                        + "<w:p><w:ins w:id=\"1\"><w:r><w:t>προσθήκη</w:t></w:r></w:ins></w:p>")
                .put("word/vbaProject.bin", "synthetic macro payload").bytes();
        PostcheckSummary s = scan(docx);
        assertEquals(List.of("wrong_placeholder", "ellipsis_residue", "tracked_change", "macro_part_survived"),
                s.blocking().stream().map(PostcheckFinding::kind).toList());
        assertTrue(s.remediable().isEmpty());
        assertTrue(s.findings().stream().allMatch(f -> f.span() == null));
    }

    // ------------------------------------------------------------------ the input's ellipses vs our residue

    static DocumentData parse(byte[] docx) {
        return DocxEngine.parseDocx(docx, "s", ResourceLimits.DEFAULTS);
    }

    static List<String> ellipsisFindings(PostcheckSummary s) {
        return s.findings().stream().filter(f -> f.kind().equals("ellipsis_residue"))
                .map(f -> f.severity() + "@" + f.location()).toList();
    }

    /**
     * Ellipses the INPUT already had, at the same coordinates of a unit that is still its source unit
     * (only redaction dots changed it), are the document's punctuation, not write-path residue, however
     * long the run: they are not reported and they block nothing. The same bytes audited without the
     * source keep the conservative answer.
     */
    @Test
    void theInputsOwnEllipsesAreNotWriteBackResidue() {
        String afm = TestDocx.validAfm("09401420");
        String first = "Σύμφωνα με την … απόφαση και " + "…".repeat(24) + " με ΑΦΜ " + afm + ".";
        byte[] input = TestDocx.paragraphs(first, "Τέλος…").bytes();
        DocumentData source = parse(input);
        int start = first.indexOf(afm);
        RedactionPlan plan = new RedactionPlan("s", List.of(new Span("u0", start, start + 9, afm, SpanCategory.AFM, "t",
                0.95, SpanAction.REDACT, "", SpanOrigin.DETERMINISTIC)), List.of());
        byte[] output = DocxEngine.writeRedactedDocx(input, source, plan, ResourceLimits.DEFAULTS);
        assertTrue(TestDocx.part(output, "word/document.xml").contains("…".repeat(24) + " με ΑΦΜ ........."));

        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(output, FILES, source, plan, ResourceLimits.DEFAULTS);
        assertEquals(List.of(), ellipsisFindings(s));
        assertTrue(s.blocking().isEmpty(), slices(s).toString());

        assertEquals(List.of("MEDIUM@word/document.xml:u0", "HIGH@word/document.xml:u0", "MEDIUM@word/document.xml:u1"),
                ellipsisFindings(scan(output))); // no source: no correspondence, the old handling
    }

    /**
     * An ellipsis where the input had something else is ours: a character changed into U+2026, which no
     * redaction does, so the unit is not provably its source unit and the run is reported and blocks.
     * That includes a run that only GREW past an ellipsis the input had.
     */
    @Test
    void anEllipsisTheInputDidNotHaveIsResidueAndBlocks() {
        DocumentData source = parse(TestDocx.paragraphs("ο κωδικός ab12 εδώ", "ήδη … εδώ", "ήδη …x εδώ").bytes());
        byte[] output = TestDocx.paragraphs("ο κωδικός " + "…".repeat(4) + " εδώ", "ήδη … εδώ", "ήδη …… εδώ").bytes();
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(output, FILES, source, ResourceLimits.DEFAULTS);
        assertEquals(List.of("HIGH@word/document.xml:u0", "HIGH@word/document.xml:u2"), ellipsisFindings(s));
        assertEquals(List.of("ellipsis_residue", "ellipsis_residue"),
                s.blocking().stream().map(PostcheckFinding::kind).toList());
        assertTrue(s.findings().stream().allMatch(f -> f.span() == null)); // still nothing for pass 2 to settle
    }

    /**
     * Where the cleanup changed a unit (here a hidden run dropped from it), its coordinates no longer
     * mean the input's, so nothing in it can be shown to be the input's own: its ellipses keep the
     * conservative handling. A unit the cleanup did not touch is still judged against its source.
     */
    @Test
    void aUnitTheCleanupResizedKeepsTheConservativeHandling() {
        String hidden = "<w:p><w:r><w:t xml:space=\"preserve\">Δεύτερη …… </w:t></w:r><w:r><w:rPr><w:vanish/></w:rPr>"
                + "<w:t>κρυφό</w:t></w:r></w:p>";
        byte[] input = TestDocx.paragraphs().document(TestDocx.p("Πρώτη …… παράγραφος.") + hidden).bytes();
        DocumentData source = parse(input);
        RedactionPlan nothing = new RedactionPlan("s", List.of(), List.of());
        byte[] output = DocxEngine.writeRedactedDocx(input, source, nothing, ResourceLimits.DEFAULTS);
        assertFalse(source.sameUnitGeometry(parse(output)), "the cleanup must have resized the second unit");

        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(output, FILES, source, nothing, ResourceLimits.DEFAULTS);
        assertEquals(List.of("HIGH@word/document.xml:u1"), ellipsisFindings(s));
    }

    @Test
    void aHighTextualFindingIsRemediableNotBlocking() {
        PostcheckSummary s = scan("κωδικός " + TestDocx.validAfm("09401420"), "[NAME]");
        assertEquals(List.of("residual_afm"), s.remediable().stream().map(PostcheckFinding::kind).toList());
        assertEquals(List.of("wrong_placeholder"), s.blocking().stream().map(PostcheckFinding::kind).toList());
    }

    @Test
    void aStructuralLabelThatWentInAndDidNotComeOutIsReported() {
        DocumentData source = DocxEngine.parseDocx(TestDocx.paragraphs("Α.Φ.Μ. 123 κάτοικος Αθηνών").bytes(), "s",
                ResourceLimits.DEFAULTS);
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(TestDocx.paragraphs("...... ... κάτοικος ......").bytes(),
                FILES, source, ResourceLimits.DEFAULTS);
        assertEquals(List.of("label_removed@-"), slices(s));
        assertEquals("1 of 1 occurrence(s) of a structural label were redacted with their value",
                s.findings().get(0).detail());
    }

    // ------------------------------------------------------------------ Java-only residual checks

    @Test
    void companyBankAccountStreetAndRegistryValuesAreNamedByTheirExactSlice() {
        PostcheckSummary s = scan(
                "για την εταιρεία με την επωνυμία ΑΛΦΑ ΒΗΤΑ Α.Ε. και",
                "στην τράπεζα ΔΕΛΤΑ BANK, για τα έτη",
                "τον λογαριασμό 1234567890 της εταιρείας",
                "με έδρα επί της Αγίας Σοφίας Οδού 5, και οδός Ερμού αρ. 5",
                "Φ.Ε.Κ με αριθμό φύλλου 4321 της 21-3-2011",
                "με την επωνυμία ................ και δ.τ. ......... με ΑΦΜ .........",
                "η Τράπεζα της Ελλάδος");
        // A bank's name is kept by policy: no finding for "τράπεζα ΔΕΛΤΑ BANK".
        assertEquals(List.of("company_name_leak@u0:33:47:ΑΛΦΑ ΒΗΤΑ Α.Ε.", "account_leak@u2:15:25:1234567890", "street_leak@u3:16:33:Αγίας Σοφίας Οδού",
                        "street_leak@u3:46:51:Ερμού", "registry_leak@u4:23:27:4321"),
                slices(s).stream().filter(x -> !x.startsWith("digit_run") && !x.startsWith("case_ref_leak")).toList());
        assertEquals(SpanCategory.PRIVATE_COMPANY_NAME, s.findings().stream()
                .filter(f -> f.kind().equals("company_name_leak")).findFirst().orElseThrow().span().category());
        assertTrue(s.findings().stream().allMatch(f -> f.severity() == PostcheckFinding.Severity.MEDIUM));
    }

    @Test
    void aPartlyRedactedCompanyNameIsStillNamedWhole() {
        // What a PRESERVE on fragments used to leave: words visible, only the gaps between them dotted.
        assertEquals(List.of("company_name_leak@u0:16:36:ΑΛΦΑ ΒΗΤΑ.ΓΑΜΑ ΔΕΛΤΑ"), slices(scan(
                "με την επωνυμία ΑΛΦΑ ΒΗΤΑ.ΓΑΜΑ ΔΕΛΤΑ και")));
    }

    @Test
    void aCourtSerialAfterItsOtherCuesIsACaseRefQuestion() {
        assertEquals(List.of("case_ref_leak@u0:13:21:512/2019", "case_ref_leak@u1:10:18:512/2019"),
                slices(scan("τη με αριθμό 512/2019 απόφαση", "η υπ. αρ. 512/2019 δικαστική απόφαση")));
    }

    @Test
    void aBankColumnCellIsKeptByPolicyAndNoQuestion() {
        String table = "<w:tbl><w:tr><w:tc>" + TestDocx.p("ΠΙΣΤΩΤΙΚΟ ΙΔΡΥΜΑ") + "</w:tc></w:tr><w:tr><w:tc>"
                + TestDocx.p("ΚΑΠΑ BANK") + "</w:tc></w:tr><w:tr><w:tc>" + TestDocx.p("..........") + "</w:tc></w:tr></w:tbl>";
        PostcheckSummary s = scan(TestDocx.paragraphs().document(table).bytes());
        assertEquals(List.of(), slices(s));
    }

    // ------------------------------------------------------------------ the consistency check

    static DocumentData parse(String... paragraphs) {
        return DocxEngine.parseDocx(TestDocx.paragraphs(paragraphs).bytes(), "s", ResourceLimits.DEFAULTS);
    }

    static Span redacted(String unit, String text, String value, SpanCategory category) {
        int start = text.indexOf(value);
        return new Span(unit, start, start + value.length(), value, category, "t", 0.9, SpanAction.REDACT, "",
                SpanOrigin.LLM_PASS2);
    }

    @Test
    void aValueRedactedInOnePlaceAndVisibleInAnotherIsAQuestion() {
        String first = "η εταιρεία ΚΑΠΑ ΛΑΜΔΑ ΕΜΠΟΡΙΚΗ προσέφυγε";
        String second = "ο λογαριασμός της ΚΑΠΑ  ΛΑΜΔΑ ΕΜΠΟΡΙΚΗ στην τράπεζα";
        DocumentData source = parse(first, second);
        RedactionPlan plan = new RedactionPlan("s", List.of(redacted("u0", first, "ΚΑΠΑ ΛΑΜΔΑ ΕΜΠΟΡΙΚΗ",
                SpanCategory.PRIVATE_COMPANY_NAME)), List.of());
        byte[] output = TestDocx.paragraphs("η εταιρεία " + ".".repeat(19) + " προσέφυγε", second).bytes();
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(output, FILES, source, plan, ResourceLimits.DEFAULTS);
        // Found in the second paragraph although its spacing differs; recorded under the plan's category.
        PostcheckFinding f = s.findings().stream().filter(x -> x.kind().equals("inconsistent_redaction"))
                .findFirst().orElseThrow();
        assertEquals("u1:18:38:ΚΑΠΑ  ΛΑΜΔΑ ΕΜΠΟΡΙΚΗ", f.span().unitId() + ":" + f.span().start() + ":" + f.span().end()
                + ":" + f.span().text());
        assertEquals(SpanCategory.PRIVATE_COMPANY_NAME, f.span().category());
        assertEquals(PostcheckFinding.Severity.MEDIUM, f.severity());
        assertFalse(f.detail().contains("ΚΑΠΑ"));
    }

    @Test
    void theConsistencyCheckNeverPropagatesAGenericNumber() {
        // A reference serial, or a short identifier, is not an identity: the same digits elsewhere can be
        // an amount or another document, so redacting them once is no reason to ask about another place.
        String first = "αριθμό πρωτοκόλλου 4321 στο Ο.Τ. 1239 του σχεδίου";
        String second = "ποσό 4321 ευρώ και 1239 τετραγωνικά";
        DocumentData source = parse(first, second);
        RedactionPlan plan = new RedactionPlan("s", List.of(
                redacted("u0", first, "4321", SpanCategory.PROTOCOL_NUMBER),
                redacted("u0", first, "1239", SpanCategory.PROPERTY_ID)), List.of());
        byte[] output = TestDocx.paragraphs("αριθμό πρωτοκόλλου .... στο Ο.Τ. .... του σχεδίου", second).bytes();
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(output, FILES, source, plan, ResourceLimits.DEFAULTS);
        assertTrue(s.findings().stream().noneMatch(f -> f.kind().equals("inconsistent_redaction")), slices(s).toString());
    }

    @Test
    void anOccurrenceWhoseIdentifyingPartIsBlankedIsNotInconsistent() {
        // Redacted whole in one place, serial-only in another: the year left visible there is the
        // convention, not the value leaking. Fully visible elsewhere, it is a question.
        String first = "δήλωση (αριθ. ειδοποίησης 12345/2026, ...)";
        String second = "δήλωση (αριθ. ειδοποίησης 12345/2026, και 12345/2026 ξανά)";
        DocumentData source = parse(first, second);
        RedactionPlan plan = new RedactionPlan("s", List.of(redacted("u0", first, "12345/2026", SpanCategory.PROPERTY_ID)),
                List.of());
        byte[] output = TestDocx.paragraphs(first.replace("12345/2026", ".........."),
                second.replaceFirst("12345/2026", "...../2026")).bytes();
        PostcheckSummary s = Postcheck.scanRedactedDocxBytes(output, FILES, source, plan, ResourceLimits.DEFAULTS);
        List<String> found = s.findings().stream().filter(f -> f.kind().equals("inconsistent_redaction"))
                .map(f -> f.span().unitId() + ":" + f.span().start()).toList();
        assertEquals(List.of("u1:42"), found); // the second, fully visible occurrence only
    }

    @Test
    void theResidualTextStaysOutOfEveryRendering() {
        String name = "Γεώργιος Παπαδόπουλος";
        PostcheckSummary s = scan("με ΑΦΜ ......... " + name);
        PostcheckFinding f = s.findings().get(0);
        assertEquals(name, f.span().text());
        assertFalse(f.toString().contains("Γεώργιος") || s.toString().contains("Γεώργιος"), f.toString());
        assertFalse(s.asMap().toString().contains("Γεώργιος"));
        assertNull(f.asMap().get("span"));
    }
}
