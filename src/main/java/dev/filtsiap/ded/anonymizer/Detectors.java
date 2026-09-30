package dev.filtsiap.ded.anonymizer;

import static dev.filtsiap.ded.anonymizer.DetectorSupport.body;
import static dev.filtsiap.ded.anonymizer.DetectorSupport.captureSpans;
import static dev.filtsiap.ded.anonymizer.DetectorSupport.compile;
import static dev.filtsiap.ded.anonymizer.DetectorSupport.makeSpan;
import static dev.filtsiap.ded.anonymizer.DetectorSupport.normalizeHeader;
import static dev.filtsiap.ded.anonymizer.DetectorSupport.prefix;
import static dev.filtsiap.ded.anonymizer.DetectorSupport.regexSpans;
import static dev.filtsiap.ded.anonymizer.SpanAction.PRESERVE;
import static dev.filtsiap.ded.anonymizer.SpanAction.REDACT;
import static dev.filtsiap.ded.anonymizer.SpanAction.REVIEW;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The deterministic detectors (port of {@code detectors.py}). Every detector returns spans in
 * the same order as its Python counterpart.
 */
public final class Detectors {

    private static final PyPattern DOU_PREFIX_RE = PyRegex.compile("(?:Δ\\.Ο\\.Υ\\.|ΔΟΥ)\\s+", PyRegex.IGNORECASE);
    private static final PyPattern DOU_FALLBACK_RE = PyRegex.compile(
            DetectorPatterns.GREEK_CAPITALIZED + "(?:\\s+" + DetectorPatterns.GREEK_CAPITALIZED + ")*");
    private static final PyPattern SERIAL_COMPONENT_RE = PyRegex.compile("[^/&\\s]+");

    /** Whole-cell action for a table column, keyed by the normalized header. */
    private record HeaderAction(SpanCategory category, SpanAction action, double confidence, String reason) {
    }

    private static final Map<String, HeaderAction> TABLE_HEADER_ACTIONS = new LinkedHashMap<>();

    static {
        header("ΑΦΜ", SpanCategory.AFM, REDACT, 0.9, "AFM table column");
        header("Τηλέφωνο", SpanCategory.PHONE, REVIEW, 0.85,
                "Phone table column; AI must decide official vs private context");
        header("Email", SpanCategory.EMAIL, REDACT, 0.95, "Email table column");
        header("Όνομα", SpanCategory.POSSIBLE_PERSON, REVIEW, 0.6, "Name table column");
        header("Διεύθυνση", SpanCategory.POSSIBLE_PRIVATE_LOCATION, REVIEW, 0.6, "Address table column");
        header("ΠΑΡΑΣΤΑΤΙΚΟ", SpanCategory.INVOICE_TABLE_ID, REDACT, 0.9, "Invoice column");
        header("ΠΑΡΑ ΣΤΑΤΙΚΟ", SpanCategory.INVOICE_TABLE_ID, REDACT, 0.9, "Invoice column (split)");
        header("ΑΡ. ΠΑΡΑΣΤΑΤΙΚΟΥ", SpanCategory.INVOICE_TABLE_ID, REDACT, 0.9, "Invoice number column");
        header("ΤΙΜΟΛΟΓΙΟ", SpanCategory.INVOICE_TABLE_ID, REDACT, 0.9, "Invoice column");
        header("ΤΙΜ.", SpanCategory.INVOICE_TABLE_ID, REDACT, 0.9, "Invoice abbrev column");
        header("ΑΡΙΘΜΟΣ", SpanCategory.INVOICE_TABLE_ID, REDACT, 0.85, "Number column");
        header("ΣΤΟΙΧΕΙΟ", SpanCategory.INVOICE_TABLE_ID, REDACT, 0.85, "Document element column");
        header("ΚΑΘΑΡΗ ΑΞΙΑ", SpanCategory.MONEY, PRESERVE, 0.95, "Net value column");
        header("ΦΠΑ", SpanCategory.MONEY, PRESERVE, 0.95, "VAT column");
        header("ΣΥΝΟΛΟ", SpanCategory.MONEY, PRESERVE, 0.95, "Total column");
        header("ΗΜ/ΝΙΑ", SpanCategory.DATE, PRESERVE, 0.95, "Date column");
    }

    private static void header(String h, SpanCategory c, SpanAction a, double conf, String reason) {
        TABLE_HEADER_ACTIONS.put(normalizeHeader(h), new HeaderAction(c, a, conf, reason));
    }

    private Detectors() {
    }

    // ========================================================================= 1..6

    /** 1. AFM, AMKA and IBAN; confidence scaled by checksum/date validation and label presence. */
    public static List<Span> detectStructuredIds(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        String text = unit.normalizedText();

        String afmRe = "(?<!\\d)(?:" + prefix(rules, "afm") + ")?" + body(rules, "afm") + "(?!\\d)";
        for (PyMatch m : compile(afmRe, PyRegex.IGNORECASE).finditer(text)) {
            boolean valid = DetectorSupport.validAfm(m.group(1));
            boolean hasPrefix = m.start() < m.start(1);
            double confidence;
            String reason;
            if (valid) {
                confidence = 1.0;
                reason = "AFM checksum passed";
            } else if (hasPrefix) {
                confidence = 0.75;
                reason = "AFM label present but checksum failed";
            } else {
                confidence = 0.4;
                reason = "AFM shape matched but checksum failed";
            }
            spans.add(makeSpan(unit, m.start(), m.end(), SpanCategory.AFM, "afm_checksum", confidence, REDACT, reason));
        }

        String amkaRe = "(?<!\\d)(?:" + prefix(rules, "amka") + ")?" + body(rules, "amka") + "(?!\\d)";
        for (PyMatch m : compile(amkaRe, PyRegex.IGNORECASE).finditer(text)) {
            boolean valid = DetectorSupport.validAmkaBirthDate(m.group(1));
            boolean hasPrefix = m.start() < m.start(1);
            double confidence;
            String reason;
            if (valid) {
                confidence = 0.95;
                reason = "AMKA birth date is plausible";
            } else if (hasPrefix) {
                confidence = 0.75;
                reason = "AMKA label present but birth date invalid";
            } else {
                confidence = 0.5;
                reason = "AMKA shape matched";
            }
            spans.add(makeSpan(unit, m.start(), m.end(), SpanCategory.AMKA, "amka_date", confidence, REDACT, reason));
        }

        for (PyMatch m : compile("\\b" + body(rules, "iban") + "\\b", PyRegex.IGNORECASE).finditer(text)) {
            boolean valid = DetectorSupport.ibanIsValid(m.group());
            spans.add(makeSpan(unit, m.start(), m.end(), SpanCategory.IBAN, "iban_checksum",
                    valid ? 1.0 : 0.3, REDACT, valid ? "IBAN checksum passed" : "IBAN shape matched"));
        }
        return spans;
    }

    /** 2. Emails (PRESERVE for allowlisted public domains, else REDACT) and phones (REVIEW). */
    public static List<Span> detectContacts(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        PyPattern email = compile("\\b" + body(rules, "email") + "\\b", PyRegex.IGNORECASE);
        for (PyMatch m : email.finditer(unit.normalizedText())) {
            String value = m.group();
            String domain = value.contains("@") ? PyStr.casefold(PyStr.afterLast(value, "@")) : "";
            if (rules.preserveEmailDomains().contains(domain)) {
                spans.add(makeSpan(unit, m.start(), m.end(), SpanCategory.PUBLIC_SERVICE, "public_email_domain",
                        0.95, PRESERVE, "Public email domain allowlist"));
            } else {
                spans.add(makeSpan(unit, m.start(), m.end(), SpanCategory.EMAIL, "email_regex",
                        0.95, REDACT, "Email address matched"));
            }
        }
        record Phone(String name, double confidence) {
        }
        for (Phone p : List.of(new Phone("phone_intl", 0.9), new Phone("phone_00", 0.9),
                new Phone("phone_local", 0.7))) {
            spans.addAll(regexSpans(unit, "(?<!\\d)" + body(rules, p.name()) + "(?!\\d)", SpanCategory.PHONE,
                    p.name(), p.confidence(), REVIEW,
                    "Greek phone number matched; AI must decide official vs private context", 0));
        }
        return spans;
    }

    /**
     * 3. Protocol numbers, audit orders, act/invoice/transaction numbers. Prefixed patterns
     * redact only the captured value, keep a trailing date visible, and split "&"/"/" lists.
     */
    public static List<Span> detectProtocolsAndActs(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        record Named(String name, SpanCategory category) {
        }
        for (Named p : List.of(new Named("protocol_number", SpanCategory.PROTOCOL_NUMBER),
                new Named("audit_order", SpanCategory.AUDIT_ORDER))) {
            String regex = prefix(rules, p.name()) + body(rules, p.name());
            for (Span valueSpan : captureSpans(unit, regex, 1, p.category(), p.name(), 0.85, REDACT,
                    "Contextual identifier matched")) {
                DetectorSupport.SerialDate parts = DetectorSupport.splitSerialDate(valueSpan.text());
                String serial = parts != null ? parts.serial() : valueSpan.text();
                for (PyMatch c : SERIAL_COMPONENT_RE.finditer(serial)) {
                    spans.add(makeSpan(unit, valueSpan.start() + c.start(), valueSpan.start() + c.end(),
                            p.category(), p.name(), 0.85, REDACT, "Contextual identifier matched"));
                }
            }
        }
        for (Named p : List.of(new Named("act_number", SpanCategory.ACT_NUMBER),
                new Named("invoice_number", SpanCategory.INVOICE_NUMBER),
                new Named("transaction_id", SpanCategory.TRANSACTION_ID))) {
            String regex = prefix(rules, p.name()) + body(rules, p.name());
            spans.addAll(regexSpans(unit, regex, p.category(), p.name(), 0.85, REDACT,
                    "Contextual identifier matched"));
        }
        return spans;
    }

    /** 4. Challenged tax act numbers, requiring a tax-act cue within 100 characters after. */
    public static List<Span> detectChallengedActNumbers(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        String text = unit.normalizedText();
        for (PyMatch m : DetectorPatterns.CHALLENGED_ACT_RE.finditer(text)) {
            String window = PyStr.slice(text, m.end(), m.end() + 100);
            if (!DetectorPatterns.CHALLENGED_ACT_CONTEXT_RE.found(window)) {
                continue;
            }
            DetectorSupport.SerialDate parts = DetectorSupport.splitSerialDate(m.group(1));
            int gs;
            int ge;
            if (parts != null) {
                gs = m.start(1);
                ge = gs + PyStr.len(parts.serial());
            } else {
                gs = m.start(1);
                ge = m.end(1);
            }
            if (gs < ge) {
                spans.add(makeSpan(unit, gs, ge, SpanCategory.CHALLENGED_ACT_NUMBER, "challenged_act_ctx", 0.9,
                        REDACT, "Act number with tax-act context"));
            }
        }
        return spans;
    }

    static List<Span> detectDates(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(regexSpans(unit, body(rules, "date_numeric"), SpanCategory.DATE, "date_numeric", 0.95,
                PRESERVE, "Numeric date matched"));
        spans.addAll(regexSpans(unit, body(rules, "date_greek"), SpanCategory.DATE, "date_greek", 0.9,
                PRESERVE, "Greek textual date matched"));
        return spans;
    }

    static List<Span> detectDou(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        String text = unit.normalizedText();
        List<String> entries = new ArrayList<>(rules.douAllowlist());
        entries.sort(Comparator.comparingInt((String e) -> -PyStr.len(e)).thenComparing(PyStr.CODE_POINT_ORDER));
        for (PyMatch prefixMatch : DOU_PREFIX_RE.finditer(text)) {
            int valueStart = prefixMatch.end();
            String suffix = PyStr.sliceFrom(text, valueStart);
            String matchedEntry = null;
            for (String entry : entries) {
                if (compile(PyRegex.escape(entry) + "\\b", PyRegex.IGNORECASE).match(suffix) != null) {
                    matchedEntry = entry;
                    break;
                }
            }
            int end;
            double confidence;
            String reason;
            if (matchedEntry != null && !matchedEntry.isEmpty()) {
                end = valueStart + PyStr.len(matchedEntry);
                confidence = 0.95;
                reason = "DOU gazetteer match";
            } else {
                PyMatch fallback = DOU_FALLBACK_RE.match(suffix);
                if (fallback == null) {
                    continue;
                }
                end = valueStart + fallback.end();
                confidence = 0.7;
                reason = "DOU label with capitalized Greek words";
            }
            spans.add(makeSpan(unit, prefixMatch.start(), end, SpanCategory.DOU, "dou_gazetteer", confidence,
                    PRESERVE, reason));
        }
        return spans;
    }

    static List<Span> detectPublicServices(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        for (PyMatch m : DetectorSupport.allowlistMatches(unit.normalizedText(), rules.publicServices())) {
            spans.add(makeSpan(unit, m.start(), m.end(), SpanCategory.PUBLIC_SERVICE, "public_service_gazetteer",
                    0.9, PRESERVE, "Public service gazetteer match"));
        }
        return spans;
    }

    static List<Span> detectLegalRefs(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        record Legal(String name, SpanCategory category, double confidence) {
        }
        for (Legal p : List.of(
                new Legal("legal_ref_law", SpanCategory.LEGAL_REF, 0.95),
                new Legal("legal_ref_pd", SpanCategory.LEGAL_REF, 0.9),
                new Legal("legal_ref_short", SpanCategory.LEGAL_REF, 0.9),
                new Legal("legal_ref_fek", SpanCategory.LEGAL_REF, 0.95),
                new Legal("legal_ref_pol", SpanCategory.LEGAL_REF, 0.95),
                new Legal("legal_ref_ste", SpanCategory.LEGAL_REF, 0.95),
                new Legal("legal_ref_nsk", SpanCategory.LEGAL_REF, 0.95),
                new Legal("legal_ref_aade", SpanCategory.LEGAL_REF, 0.95),
                new Legal("article_ref", SpanCategory.ARTICLE_REF, 0.9),
                new Legal("court_decision", SpanCategory.COURT_DECISION, 0.85))) {
            spans.addAll(regexSpans(unit, body(rules, p.name()), p.category(), p.name(), p.confidence(), PRESERVE,
                    "Legal reference matched"));
        }
        for (PyMatch m : DetectorSupport.allowlistMatches(unit.normalizedText(), rules.legalRefs())) {
            spans.add(makeSpan(unit, m.start(), m.end(), SpanCategory.LEGAL_REF, "legal_ref_gazetteer", 0.9,
                    PRESERVE, "Legal abbreviation gazetteer match"));
        }
        return spans;
    }

    /** 5. All preserve-worthy content: dates, ΔΟΥ, public services, legal refs, money, years, %. */
    public static List<Span> detectPreserveSpans(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(detectDates(unit, rules));
        spans.addAll(detectDou(unit, rules));
        spans.addAll(detectPublicServices(unit, rules));
        spans.addAll(detectLegalRefs(unit, rules));
        spans.addAll(regexSpans(unit, body(rules, "money"), SpanCategory.MONEY, "money_amount", 0.95, PRESERVE,
                "Money amount matched"));
        spans.addAll(regexSpans(unit, body(rules, "tax_year"), SpanCategory.TAX_YEAR, "tax_year", 0.9, PRESERVE,
                "Tax year or fiscal period matched"));
        spans.addAll(regexSpans(unit, body(rules, "percentage"), SpanCategory.PERCENTAGE, "percentage", 0.95,
                PRESERVE, "Percentage matched"));
        spans.addAll(regexSpans(unit, body(rules, "fiscal_period"), SpanCategory.FISCAL_PERIOD, "fiscal_period",
                0.9, PRESERVE, "Fiscal period matched"));
        return spans;
    }

    /** 6. The decision's own number and place/date line. */
    public static List<Span> detectDecisionMetadata(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(regexSpans(unit, DetectorPatterns.DECISION_NUMBER_RE, SpanCategory.DECISION_METADATA,
                "decision_number", 0.98, PRESERVE, "Decision number matched"));
        spans.addAll(regexSpans(unit, DetectorPatterns.DECISION_PLACE_DATE_RE, SpanCategory.DECISION_METADATA,
                "decision_place_date", 0.98, PRESERVE, "Decision place/date matched"));
        return spans;
    }

    // ========================================================================= 7..14

    /** 7. Appellant name, father name, private address and business seat. */
    public static List<Span> detectAppellantIdentity(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(captureSpans(unit, DetectorPatterns.APPELLANT_NAME_RE, 1, SpanCategory.APPELLANT_NAME,
                "appellant_name_ctx", 0.9, REDACT, "Appellant name after ενδικοφανή προσφυγή"));
        spans.addAll(captureSpans(unit, DetectorPatterns.FATHER_NAME_RE, 1, SpanCategory.FATHER_NAME,
                "father_name_ctx", 0.85, REDACT, "Father name in genitive before ΑΦΜ/κάτοικ"));
        spans.addAll(captureSpans(unit, DetectorPatterns.PRIVATE_ADDRESS_RE, 1, SpanCategory.PRIVATE_ADDRESS,
                "private_address_ctx", 0.85, REDACT, "Private address after κάτοικος/οδός"));
        spans.addAll(captureSpans(unit, DetectorPatterns.BUSINESS_SEAT_RE, 1, SpanCategory.BUSINESS_SEAT,
                "business_seat_ctx", 0.85, REDACT, "Business seat after με έδρα"));
        return spans;
    }

    /** 8. Private company names after explicit cues, skipping public-service names. */
    public static List<Span> detectPrivateCompanies(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        Set<String> publicServicesCf = new HashSet<>();
        rules.publicServices().stream().filter(e -> !e.isEmpty()).forEach(e -> publicServicesCf.add(PyStr.casefold(e)));
        for (PyMatch m : DetectorPatterns.COMPANY_NAME_AFTER_CTX.finditer(unit.normalizedText())) {
            String name = PyStr.strip(m.group(1));
            if (name.isEmpty()) {
                continue;
            }
            String nameCf = PyStr.casefold(name);
            if (publicServicesCf.contains(nameCf)) {
                continue;
            }
            if (publicServicesCf.stream().anyMatch(e -> !e.isEmpty() && nameCf.contains(e))) {
                continue;
            }
            int gs = m.start(1);
            int ge = gs + PyStr.len(name);
            spans.add(makeSpan(unit, gs, ge, SpanCategory.PRIVATE_COMPANY_NAME, "company_ctx", 0.85, REDACT,
                    "Company name with explicit context cue"));
        }
        return spans;
    }

    /** 9. Bank accounts after λογ./λογαριασμό and beneficiaries after δικαιούχο. */
    public static List<Span> detectBankPaymentIds(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(captureSpans(unit, DetectorPatterns.BANK_ACCOUNT_RE, 1, SpanCategory.BANK_ACCOUNT,
                "bank_account_ctx", 0.85, REDACT, "Bank account after λογ./λογαριασμό"));
        spans.addAll(captureSpans(unit, DetectorPatterns.BENEFICIARY_RE, 1, SpanCategory.PRIVATE_BENEFICIARY,
                "beneficiary_ctx", 0.9, REDACT, "Beneficiary name after δικαιούχο"));
        return spans;
    }

    /** 10. Fiscal device identifiers with cues, and partial-star masked identifiers. */
    public static List<Span> detectFiscalDeviceIds(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(captureSpans(unit, DetectorPatterns.FISCAL_ID_RE, 1, SpanCategory.FISCAL_DEVICE_ID,
                "fiscal_device_ctx", 0.85, REDACT, "Fiscal device ID with context"));
        spans.addAll(regexSpans(unit, DetectorPatterns.PARTIAL_STAR_RE, SpanCategory.FISCAL_DEVICE_ID,
                "partial_star", 0.9, REDACT, "Partial-star masked identifier"));
        return spans;
    }

    /** 11. Table cells via the column-header map (invoice-shape fallback); inline invoices elsewhere. */
    public static List<Span> detectTableSensitiveValues(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        if (unit.unitType() != UnitType.TABLE_CELL) {
            for (PyMatch m : DetectorPatterns.INVOICE_PARAGRAPH_RE.finditer(unit.normalizedText())) {
                for (int group : new int[] {1, 2}) {
                    int gs = m.start(group);
                    int ge = m.end(group);
                    if (0 <= gs && gs < ge) {
                        spans.add(makeSpan(unit, gs, ge, SpanCategory.INVOICE_TABLE_ID, "invoice_inline", 0.85,
                                REDACT, "Invoice identifier in running text"));
                    }
                }
            }
            return spans;
        }
        if (PyStr.strip(unit.normalizedText()).isEmpty()) {
            return List.of();
        }
        HeaderAction mapped = TABLE_HEADER_ACTIONS.get(normalizeHeader(unit.location().columnHeader()));
        if (mapped != null) {
            return List.of(makeSpan(unit, 0, PyStr.len(unit.normalizedText()), mapped.category(),
                    "table_cell_header", mapped.confidence(), mapped.action(), mapped.reason()));
        }
        spans.addAll(regexSpans(unit, DetectorPatterns.INVOICE_CELL_RE, SpanCategory.INVOICE_TABLE_ID,
                "invoice_cell_shape", 0.85, REDACT, "Invoice-like value in table cell"));
        return spans;
    }

    /** 12. Low-confidence REVIEW candidates: name shapes, company suffixes, streets, medical terms. */
    public static List<Span> detectReviewCandidates(TextUnit unit) {
        String cap = DetectorPatterns.GREEK_CAPITALIZED;
        List<Span> spans = new ArrayList<>();
        // Case-sensitive: capitalization is the signal.
        spans.addAll(regexSpans(unit, "\\b" + cap + "\\s+" + cap + "\\b", SpanCategory.POSSIBLE_PERSON,
                "greek_name_shape", 0.45, REVIEW, "Two capitalized Greek words matched", 0));
        // (?!\w) rather than \b so dot-terminated suffixes (Α.Ε.) match before a space or the end.
        spans.addAll(regexSpans(unit, "\\b(?:" + cap + "(?:\\s+" + cap + ")*)\\s+"
                        + "(?:ΑΕ|Α\\.Ε\\.|ΕΠΕ|Ε\\.Π\\.Ε\\.|ΟΕ|Ο\\.Ε\\.|ΙΚΕ|Ι\\.Κ\\.Ε\\.)(?!\\w)",
                SpanCategory.POSSIBLE_COMPANY, "company_suffix", 0.65, REVIEW, "Company suffix matched", 0));
        spans.addAll(regexSpans(unit, "\\b(?:οδός|Οδός|Λεωφ\\.|Λεωφόρος)\\s+" + cap + "(?:\\s+" + cap + ")*"
                        + "(?:\\s+αρ\\.?\\s*\\d+|\\s+\\d+)?",
                SpanCategory.POSSIBLE_PRIVATE_LOCATION, "street_shape", 0.6, REVIEW, "Street-like address matched", 0));
        // Python iterates a set here (hash-seed order); MEDICAL_TERMS is sorted, so the order is stable.
        for (String term : DetectorPatterns.MEDICAL_TERMS) {
            spans.addAll(regexSpans(unit, PyRegex.escape(term), SpanCategory.MEDICAL_TERM, "medical_term_list",
                    0.5, REVIEW, "Medical term list match"));
        }
        return spans;
    }

    private static List<TextUnit> bodyParagraphs(DocumentData document) {
        return document.textUnits().stream()
                .filter(u -> u.unitType() == UnitType.PARAGRAPH && u.partName().equals("word/document.xml"))
                .toList();
    }

    /** 13. Issuing-authority header in the first 30 body paragraphs, stopping at the title. */
    public static List<Span> detectAuthorityHeader(DocumentData document) {
        List<TextUnit> paras = bodyParagraphs(document);
        List<Span> spans = new ArrayList<>();
        for (TextUnit unit : paras.subList(0, Math.min(30, paras.size()))) {
            if (DetectorPatterns.DECISION_TITLE_RE.match(PyStr.strip(unit.normalizedText())) != null) {
                break;
            }
            int cues = DetectorPatterns.AUTHORITY_HEADER_CUES.countAll(unit.normalizedText());
            double confidence;
            if (cues >= 2) {
                confidence = 1.0;
            } else if (cues == 1) {
                confidence = 0.7; // soft preserve: still wins over a soft REDACT
            } else {
                continue;
            }
            spans.add(makeSpan(unit, 0, PyStr.len(unit.normalizedText()), SpanCategory.PUBLIC_AUTHORITY_HEADER,
                    "authority_header", confidence, PRESERVE, "Authority header cue matched"));
        }
        return spans;
    }

    /** 14. Official signatory: isolated all-caps paragraph after a signature title, last 20%. */
    public static List<Span> detectFinalSignatory(DocumentData document) {
        List<TextUnit> paras = bodyParagraphs(document);
        if (paras.isEmpty()) {
            return List.of();
        }
        int thresholdIndex = (int) (paras.size() * 0.80);
        List<TextUnit> finalUnits = paras.subList(thresholdIndex, paras.size());
        List<Span> spans = new ArrayList<>();
        Set<String> preserved = new HashSet<>();
        for (int i = 0; i < finalUnits.size(); i++) {
            if (!DetectorPatterns.SIGNATURE_TITLE_RE.found(finalUnits.get(i).normalizedText())) {
                continue;
            }
            List<TextUnit> candidates = finalUnits.subList(Math.min(i + 1, finalUnits.size()),
                    Math.min(i + 6, finalUnits.size()));
            for (TextUnit cand : candidates) {
                String text = PyStr.strip(cand.normalizedText());
                if (DetectorPatterns.ISOLATED_ALLCAPS_NAME_RE.match(text) == null) {
                    continue;
                }
                if (preserved.contains(cand.unitId())) {
                    continue;
                }
                StringBuilder context = new StringBuilder();
                for (TextUnit u : finalUnits.subList(Math.max(0, i - 1), Math.min(i + 6, finalUnits.size()))) {
                    if (u != cand) { // identity, as Python's "is not"
                        context.append(u.normalizedText());
                    }
                }
                if (DetectorPatterns.PRIVATE_PARTY_CUE_RE.found(context.toString())) {
                    continue;
                }
                preserved.add(cand.unitId());
                spans.add(makeSpan(cand, 0, PyStr.len(cand.normalizedText()), SpanCategory.OFFICIAL_SIGNATORY,
                        "final_signatory", 0.95, PRESERVE, "Final signatory in signature block"));
                break;
            }
        }
        return spans;
    }

    // ========================================================================= aggregator

    /** Result split strictly by action. */
    public record DetectionResult(List<Span> resolverSpans, List<Span> reviewHints) {
        public DetectionResult {
            resolverSpans = List.copyOf(resolverSpans);
            reviewHints = List.copyOf(reviewHints);
        }
    }

    /** Runs every detector: document-level first, then per unit, in Python's order. */
    public static DetectionResult detectAll(DocumentData document, DetectorRules rules) {
        List<Span> all = new ArrayList<>();
        all.addAll(detectFinalSignatory(document));
        all.addAll(detectAuthorityHeader(document));
        for (TextUnit unit : document.textUnits()) {
            all.addAll(detectDecisionMetadata(unit));
            all.addAll(detectPreserveSpans(unit, rules));
            all.addAll(detectStructuredIds(unit, rules));
            all.addAll(detectContacts(unit, rules));
            all.addAll(detectChallengedActNumbers(unit));
            all.addAll(detectProtocolsAndActs(unit, rules));
            all.addAll(detectAppellantIdentity(unit));
            all.addAll(detectPrivateCompanies(unit, rules));
            all.addAll(detectBankPaymentIds(unit));
            all.addAll(detectFiscalDeviceIds(unit));
            all.addAll(detectTableSensitiveValues(unit));
            all.addAll(detectReviewCandidates(unit));
        }
        List<Span> review = all.stream().filter(s -> s.action() == REVIEW).toList();
        List<Span> resolver = all.stream().filter(s -> s.action() == REDACT || s.action() == PRESERVE).toList();
        return new DetectionResult(resolver, review);
    }
}
