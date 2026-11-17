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

import dev.filtsiap.ded.anonymizer.chat.GreekFold;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
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
    private static final PyPattern YEAR_ONLY_RE = PyRegex.compile("^(?:19|20)\\d{2}$");
    /** The outgoing-register code "ΕΞ" right before a value. */
    private static final PyPattern REGISTER_CODE_BEFORE_RE = PyRegex.compile("ΕΞ\\s+$");

    /** A property-identifier pattern and the shape of one value, to split a captured list per value. */
    private record PropertyPattern(String name, PyPattern value) {
    }

    private static final List<PropertyPattern> PROPERTY_PATTERNS = List.of(
            new PropertyPattern("atak", PyRegex.compile("\\d{11}")),
            new PropertyPattern("kaek", PyRegex.compile("\\d{12}(?:/\\d+)*")),
            // Suffix letter in both cases: the outer capture is case-insensitive.
            new PropertyPattern("ot", PyRegex.compile("\\d+[Α-ΩA-Zα-ωά-ώa-z]?")),
            new PropertyPattern("axk", PyRegex.compile("\\d+(?:/\\d+)+|\\d{3,}")),
            new PropertyPattern("notice_number", PyRegex.compile("\\d[\\d/\\-]*")));

    /** An all-zero ΚΑΕΚ subdivision suffix ("/0/0") names nothing and stays visible. */
    private static final PyPattern KAEK_ROOT_ZERO_SUFFIX_RE = PyRegex.compile("^(\\d{12})((?:/0+)+)$");

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
        // Java-only: a column the header says holds a party's account.
        // Headers compare casefolded but with their accents, so the lower-case spellings are listed too.
        header("ΛΟΓΑΡΙΑΣΜΟΣ", SpanCategory.BANK_ACCOUNT, REDACT, 0.9, "Account column");
        header("ΑΡ. ΛΟΓΑΡΙΑΣΜΟΥ", SpanCategory.BANK_ACCOUNT, REDACT, 0.9, "Account column");
        header("ΑΡΙΘΜΟΣ ΛΟΓΑΡΙΑΣΜΟΥ", SpanCategory.BANK_ACCOUNT, REDACT, 0.9, "Account column");
        header("ΑΡΙΘΜΟΣ ΛΟΓ/ΣΜΟΥ", SpanCategory.BANK_ACCOUNT, REDACT, 0.9, "Account column");
        header("IBAN", SpanCategory.BANK_ACCOUNT, REDACT, 0.9, "Account column");
    }

    /** Hints that only say "two capitalised words" or "a company suffix": the least specific evidence. */
    private static final Set<String> SHAPE_HINT_DETECTORS = Set.of("greek_name_shape", "company_suffix");

    /** REDACT proposals that already give a region a specific identity; a shape hint inside one adds nothing. */
    private static final Set<SpanCategory> SPECIFIC_IDENTITY_CATEGORIES = Set.of(SpanCategory.APPELLANT_NAME,
            SpanCategory.FATHER_NAME, SpanCategory.PRIVATE_COMPANY_NAME, SpanCategory.PRIVATE_BENEFICIARY,
            SpanCategory.PRIVATE_ADDRESS, SpanCategory.BUSINESS_SEAT, SpanCategory.BANK_ACCOUNT);

    private static void header(String h, SpanCategory c, SpanAction a, double conf, String reason) {
        TABLE_HEADER_ACTIONS.put(normalizeHeader(h), new HeaderAction(c, a, conf, reason));
    }

    /**
     * A bank column's labels: still known column labels, for header detection, but with no action on their
     * cells, since a bank's name is kept by policy (its account column is {@link #TABLE_HEADER_ACTIONS}').
     */
    private static final Set<String> BANK_COLUMN_LABELS = Set.of(normalizeHeader("ΤΡΑΠΕΖΑ"),
            normalizeHeader("Τράπεζα"), normalizeHeader("ΠΙΣΤΩΤΙΚΟ ΙΔΡΥΜΑ"), normalizeHeader("Πιστωτικό ίδρυμα"));

    /**
     * Whether a table cell's whole text is a column label the rules already know: a header the column
     * map acts on (which includes the invoice headers the post-check reads), a bank column's label, or a
     * name-column label ("Ονοματεπώνυμο", "Επώνυμο", "Όνομα"). Evidence for header detection only; no new
     * vocabulary.
     */
    static boolean isKnownColumnLabel(String cellText) {
        String text = PyStr.strip(PyStr.collapseWhitespace(cellText));
        return !text.isEmpty() && (TABLE_HEADER_ACTIONS.containsKey(normalizeHeader(text))
                || BANK_COLUMN_LABELS.contains(normalizeHeader(text))
                || DetectorPatterns.NAME_CONTEXT_RE.fullmatch(text) != null);
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
            // Group 1, not the whole match: the prefix is the "Α.Φ.Μ." label, which stays visible.
            // AFM is hard-redact, so a span over the label could never be won back by a preserve.
            spans.add(makeSpan(unit, m.start(1), m.end(1), SpanCategory.AFM, "afm_checksum", confidence, REDACT,
                    reason));
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
            // Group 1 for the same reason as AFM: the "ΑΜΚΑ" label stays.
            spans.add(makeSpan(unit, m.start(1), m.end(1), SpanCategory.AMKA, "amka_date", confidence, REDACT, reason));
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
                // Then a bare trailing "/YYYY": splitSerialDate only strips a FULL date, and the
                // component loop would redact the year as a number of its own. The gold keeps it.
                DetectorSupport.SerialDate year = DetectorSupport.splitYearSuffix(serial);
                if (year != null) {
                    serial = year.serial();
                }
                    if (p.category() == SpanCategory.AUDIT_ORDER && YEAR_ONLY_RE.match(serial) != null
                        && REGISTER_CODE_BEFORE_RE.found(PyStr.slice(unit.normalizedText(),
                                Math.max(0, valueSpan.start() - 4), valueSpan.start()))) {
                    continue; // "ΕΞ 2026" in a composite protocol is the register's year, not a serial
                }
                for (PyMatch c : SERIAL_COMPONENT_RE.finditer(serial)) {
                    spans.add(makeSpan(unit, valueSpan.start() + c.start(), valueSpan.start() + c.end(),
                            p.category(), p.name(), 0.85, REDACT, "Contextual identifier matched"));
                }
            }
        }
        for (Named p : List.of(new Named("act_number", SpanCategory.ACT_NUMBER),
                new Named("invoice_number", SpanCategory.INVOICE_NUMBER),
                new Named("transaction_id", SpanCategory.TRANSACTION_ID))) {
            // The trigger word sits inside `body`, but the value is still group 1 and the trigger is a
            // label the ΔΕΔ convention keeps ("Οριστική Πράξη", "Τιμολόγιο", "Α/Α", "Συναλλαγή").
            String regex = prefix(rules, p.name()) + body(rules, p.name());
            spans.addAll(captureSpans(unit, regex, 1, p.category(), p.name(), 0.85, REDACT,
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
            if (parts == null) {
                parts = DetectorSupport.splitYearSuffix(m.group(1));
            }
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
        // A tax assessment's triplicate number ("ΑΤΒ 25761/10.09.2024") is a taxpayer-file number: its digits only.
        spans.addAll(captureSpans(unit, DetectorPatterns.ATB_NUMBER_RE, 1, SpanCategory.CASE_REF_NUMBER, "atb_number",
                0.9, REDACT, "Assessment (ΑΤΒ) number: a taxpayer-file number"));
        return spans;
    }

    /** Whether a date at {@code start} is introduced by an explicit procedural cue ending just before it. */
    private static boolean proceduralCueBefore(String text, int start) {
        String window = PyStr.slice(text, Math.max(0, start - DetectorPatterns.PROCEDURAL_DATE_WINDOW), start);
        return DetectorPatterns.PROCEDURAL_DATE_CUE_RE.found(window);
    }

    /**
     * Numeric and Greek textual dates. One with a procedural cue in front is a hard-preserved
     * PROCEDURAL_DATE; every other date stays an ordinary DATE for pass 2, since it may be a date
     * of birth.
     */
    static List<Span> detectDates(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        String text = unit.normalizedText();
        record DatePattern(String name, double confidence, String reason) {
        }
        for (DatePattern p : List.of(new DatePattern("date_numeric", 0.95, "Numeric date matched"),
                new DatePattern("date_greek", 0.9, "Greek textual date matched"))) {
            for (PyMatch m : compile(body(rules, p.name()), PyRegex.IGNORECASE).finditer(text)) {
                boolean procedural = proceduralCueBefore(text, m.start());
                spans.add(makeSpan(unit, m.start(), m.end(),
                        procedural ? SpanCategory.PROCEDURAL_DATE : SpanCategory.DATE,
                        procedural ? "procedural_date" : p.name(), p.confidence(), PRESERVE,
                        procedural ? "Date introduced by a procedural cue" : p.reason()));
            }
        }
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
                new Legal("legal_ref_decision", SpanCategory.LEGAL_REF, 0.95),
                new Legal("article_ref", SpanCategory.ARTICLE_REF, 0.9))) {
            spans.addAll(regexSpans(unit, body(rules, p.name()), p.category(), p.name(), p.confidence(), PRESERVE,
                    "Legal reference matched"));
        }
        for (PyMatch m : DetectorSupport.allowlistMatches(unit.normalizedText(), rules.legalRefs(), true)) {
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

    /**
     * 7. Appellant name, father name, residence, private address and business seat.
     *
     * <p>A municipality WITH its administrative region after a residence cue ("κατοίκου Χ Αττικής")
     * is public geography: the new gold keeps both, so it is a hard PUBLIC_LOCALITY preserve (v2
     * blanks the municipality and keeps the region). A bare town after the cue ("κατοίκου Λαμίας") is
     * kept too (owner policy, as the prompts teach): HARD as well, but only as a whole run of one word, or
     * of a toponym modifier and one word, that no name list knows. Any other run after the cue gets an
     * ordinary private-address REDACT proposal, which pass 2 can overturn at exactly its slice and which
     * is the fallback when no usable decision exists.
     */
    public static List<Span> detectAppellantIdentity(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(captureSpans(unit, DetectorPatterns.APPELLANT_NAME_RE, 1, SpanCategory.APPELLANT_NAME,
                "appellant_name_ctx", 0.9, REDACT, "Appellant name after ενδικοφανή προσφυγή"));
        String text = unit.normalizedText();
        for (PyMatch m : DetectorPatterns.FATHER_NAME_RE.finditer(text)) {
            // A street word after a genitive is a street name ("επί της Χ Οδού") unless a person's name
            // stands right before the article: a patronymic needs person context, not just a cue.
            if (PyStr.casefold(m.group(2)).startsWith("οδ") && !DetectorPatterns.PERSON_NAME_BEFORE_RE.found(
                    PyStr.slice(text, Math.max(0, m.start(1) - 40), m.start(1)))) {
                continue;
            }
            int[] range = fatherNameSpan(text, m);
            if (range[0] < range[1]) {
                spans.add(makeSpan(unit, range[0], range[1], SpanCategory.FATHER_NAME, "father_name_ctx", 0.85, REDACT,
                        "Father name in genitive before ΑΦΜ/κάτοικ"));
            }
        }
        for (PyMatch m : DetectorPatterns.RESIDENCE_PLACE_RE.finditer(text)) {
            String run = m.group(1);
            int region = trailingRegion(run, rules.regions());
            // A bare town ("κατοίκου Λαμίας", "κάτοικος Νέας Σμύρνης"): policy keeps it. Only as the whole run,
            // ended by punctuation or the next address part (the pattern's lookahead), one word or a toponym
            // modifier and one word, and never a word the name lists know, so "η κάτοικος Μαρία ..." keeps no name.
            List<String> words = PyStr.split(run);
            boolean bareTown = region < 0 && (words.size() == 1
                    || words.size() == 2 && DetectorPatterns.isToponymModifier(words.get(0)))
                    && words.stream().map(GreekFold::fold).noneMatch(w -> rules.givenNames().contains(w)
                            || rules.surnames().contains(w));
            // The place and its region; at most two words before the region, so a run that is not
            // simply "municipality region" is not kept by policy.
            if (region >= 0 && PyStr.split(PyStr.slice(run, 0, region)).size() <= 2) {
                spans.add(makeSpan(unit, m.start(1), m.end(1), SpanCategory.PUBLIC_LOCALITY, "residence_locality",
                        0.95, PRESERVE, "Municipality and its region after a residence cue: public geography"));
            } else if (bareTown) {
                spans.add(makeSpan(unit, m.start(1), m.end(1), SpanCategory.PUBLIC_LOCALITY, "residence_locality",
                        0.95, PRESERVE, "Town after a residence cue: public geography"));
            } else {
                // Any other residence run is v2's private-address proposal, with a trailing region left visible:
                // an ordinary REDACT, the fallback to the LLM's decision.
                int end = m.start(1) + (region >= 0 ? PyStr.len(PyStr.rstrip(PyStr.slice(run, 0, region))) : PyStr.len(run));
                spans.add(makeSpan(unit, m.start(1), end, SpanCategory.PRIVATE_ADDRESS, "private_address_ctx", 0.85,
                        REDACT, "Private address after κάτοικος/οδός"));
            }
        }
        // v2's street capture, beside Java's original address rule, which stays: it also covers a street
        // written with its number and no "αρ." ("οδός Ερμού 5"), which v2's capture does not reach, and a
        // street after the residence with no street cue (group 2, its own span). A street span the original
        // rule already drew at the same place is not proposed twice.
        List<Span> original = new ArrayList<>();
        for (int group : new int[] {1, 2}) {
            original.addAll(captureSpans(unit, DetectorPatterns.PRIVATE_ADDRESS_RE, group,
                    SpanCategory.PRIVATE_ADDRESS, "private_address_ctx", 0.85, REDACT,
                    "Private address after κάτοικος/οδός"));
        }
        spans.addAll(original);
        for (Span street : captureSpans(unit, DetectorPatterns.STREET_ADDRESS_RE, 1, SpanCategory.PRIVATE_ADDRESS,
                "private_address_ctx", 0.85, REDACT, "Private address after κάτοικος/οδός")) {
            if (original.stream().noneMatch(o -> o.start() == street.start() && o.end() == street.end())) {
                spans.add(street);
            }
        }
        // The street number and the postal code, each its own value span, so "αρ." and "Τ.Κ." stay.
        for (PyMatch m : DetectorPatterns.ADDRESS_NUMBER_RE.finditer(text)) {
            if (DetectorPatterns.STREET_BEFORE_NUMBER_RE.found(PyStr.slice(text, Math.max(0, m.start() - 80), m.start()))) {
                spans.add(makeSpan(unit, m.start(1), m.end(1), SpanCategory.PRIVATE_ADDRESS, "address_number", 0.8,
                        REDACT, "Street number after αρ."));
            }
        }
        spans.addAll(captureSpans(unit, DetectorPatterns.POSTAL_CODE_RE, 1, SpanCategory.PRIVATE_ADDRESS,
                "postal_code", 0.9, REDACT, "Postal code after Τ.Κ."));
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
            // Aligned to the STRIPPED name at both ends: leading whitespace in the capture moves the start.
            int gs = m.start(1) + (PyStr.len(m.group(1)) - PyStr.len(PyStr.lstrip(m.group(1))));
            int ge = gs + PyStr.len(name);
            spans.add(makeSpan(unit, gs, ge, SpanCategory.PRIVATE_COMPANY_NAME, "company_ctx", 0.85, REDACT,
                    "Company name with explicit context cue"));
        }
        return spans;
    }

    /**
     * 9. Bank accounts after λογ./λογαριασμό/Τράπεζα and beneficiaries after δικαιούχο. A bank's NAME is
     * kept by policy ("ΕΤΕ", "Τράπεζα Πειραιώς"): no rule proposes it, in text or in a bank column.
     */
    public static List<Span> detectBankPaymentIds(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(captureSpans(unit, DetectorPatterns.BANK_ACCOUNT_RE, 1, SpanCategory.BANK_ACCOUNT,
                "bank_account_ctx", 0.85, REDACT, "Bank account after λογ./λογαριασμό"));
        spans.addAll(captureSpans(unit, DetectorPatterns.BENEFICIARY_RE, 1, SpanCategory.PRIVATE_BENEFICIARY,
                "beneficiary_ctx", 0.9, REDACT, "Beneficiary name after δικαιούχο"));
        return spans;
    }

    /**
     * 10. Fiscal device identifiers with cues, partial-star masked identifiers, and (Java-only, DOCX only) the
     * visible tail of an account the source masked with X: an ordinary proposal pass 2 decides, the masking
     * letters left visible.
     */
    public static List<Span> detectFiscalDeviceIds(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(captureSpans(unit, DetectorPatterns.FISCAL_ID_RE, 1, SpanCategory.FISCAL_DEVICE_ID,
                "fiscal_device_ctx", 0.85, REDACT, "Fiscal device ID with context"));
        spans.addAll(regexSpans(unit, DetectorPatterns.PARTIAL_STAR_RE, SpanCategory.FISCAL_DEVICE_ID,
                "partial_star", 0.9, REDACT, "Partial-star masked identifier"));
        spans.addAll(captureSpans(unit, DetectorPatterns.MASKED_ACCOUNT_TAIL_RE, 1, SpanCategory.BANK_ACCOUNT,
                "masked_account_tail", 0.85, REDACT, "Visible tail of an account the source masked with X"));
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
        // A whole-cell PRESERVE (a hard one, for the money columns) is taken only from a header whose own cell
        // covers exactly this cell's columns. Under a group label spanning several sub-columns the label does
        // not say which column this is; its REDACT and REVIEW actions still apply, being the safe direction.
        if (mapped != null && mapped.action() == PRESERVE
                && unit.location() instanceof TextUnit.TableCellLocation cell && !cell.headerAligned()) {
            mapped = null;
        }
        if (mapped != null) {
            return List.of(makeSpan(unit, 0, PyStr.len(unit.normalizedText()), mapped.category(),
                    "table_cell_header", mapped.confidence(), mapped.action(), mapped.reason()));
        }
        spans.addAll(regexSpans(unit, DetectorPatterns.INVOICE_CELL_RE, SpanCategory.INVOICE_TABLE_ID,
                "invoice_cell_shape", 0.85, REDACT, "Invoice-like value in table cell"));
        return spans;
    }

    /**
     * 12A. The structural label that introduces a value, never the value. Hard-preserved, so it
     * carves the label back out of any wider REDACT at the resolver, per character, whatever
     * produced that REDACT.
     */
    public static List<Span> detectFieldLabels(TextUnit unit, DetectorRules rules) {
        // Case-sensitive: the alternation spells out the forms it accepts.
        List<Span> spans = new ArrayList<>(regexSpans(unit, body(rules, "field_label"), SpanCategory.FIELD_LABEL,
                "field_label", 1.0, PRESERVE, "Structural field label; the value after it is what gets redacted", 0));
        spans.addAll(regexSpans(unit, DetectorPatterns.PARTY_ROLE_RE, SpanCategory.FIELD_LABEL, "party_role", 1.0,
                PRESERVE, "Generic party role; it names nobody"));
        return spans;
    }

    /**
     * 12B. Cadastral / property-register identifiers (ΑΤΑΚ, ΚΑΕΚ, Ο.Τ., Α.Χ.Κ., notice number),
     * one span per value of a listed capture. Hard-redact, which is safe only because every
     * pattern is cue-anchored and captures the value alone.
     */
    public static List<Span> detectPropertyIds(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        String reason = "Property/registry identifier after its label";
        for (PropertyPattern p : PROPERTY_PATTERNS) {
            String regex = prefix(rules, p.name()) + body(rules, p.name());
            for (Span valueSpan : captureSpans(unit, regex, 1, SpanCategory.PROPERTY_ID, p.name(), 1.0, REDACT,
                    reason)) {
                for (PyMatch c : p.value().finditer(valueSpan.text())) {
                    int start = valueSpan.start() + c.start();
                    int end = valueSpan.start() + c.end();
                    if (p.name().equals("kaek")) {
                        PyMatch zero = KAEK_ROOT_ZERO_SUFFIX_RE.match(c.group());
                        if (zero != null) {
                            end = start + PyStr.len(zero.group(1));
                            // Kept by policy, not only left out: a pass-2 span quoting the whole value
                            // would otherwise blank a suffix that names nothing. FIELD_LABEL is the hard
                            // preserve for structural text that can never itself be personal data.
                            spans.add(makeSpan(unit, end, start + PyStr.len(c.group()), SpanCategory.FIELD_LABEL,
                                    "kaek_zero_suffix", 1.0, PRESERVE, "All-zero ΚΑΕΚ subdivision suffix"));
                        }
                    }
                    if (p.name().equals("notice_number")) {
                        // A notice number keeps its trailing date or year, as a protocol number does.
                        String serial = c.group();
                        DetectorSupport.SerialDate dated = DetectorSupport.splitSerialDate(serial);
                        if (dated != null) {
                            serial = dated.serial();
                        }
                        DetectorSupport.SerialDate year = DetectorSupport.splitYearSuffix(serial);
                        if (year != null) {
                            serial = year.serial();
                        }
                        end = start + PyStr.len(serial);
                    }
                    if (start < end) {
                        spans.add(makeSpan(unit, start, end, SpanCategory.PROPERTY_ID, p.name(), 1.0, REDACT, reason));
                    }
                }
            }
        }
        return spans;
    }

    /**
     * 12C. A court reference. The serial of a decision that may belong to this case is a neutral
     * REVIEW question, so pass 2 decides own case vs precedent from the context; the shape alone
     * cannot tell, so the rule recommends neither (v2 proposes an ordinary PRESERVE, which leaves an
     * own-case serial visible whenever pass 2 follows the recommendation). The chamber ("Τμήμα 1ο
     * Τριμελές") is public court structure, not the case: a hard PUBLIC_SERVICE preserve under the new
     * gold (v2 leaves the number to pass 2, which redacts it).
     */
    public static List<Span> detectCaseCourtReferences(TextUnit unit) {
        List<Span> spans = new ArrayList<>();
        spans.addAll(captureSpans(unit, DetectorPatterns.CASE_COURT_SERIAL_RE, 1, SpanCategory.CASE_COURT_REFERENCE,
                "case_court_serial", 0.85, REVIEW,
                "Court serial: pass 2 decides own case (redact) vs precedent (keep)"));
        spans.addAll(captureSpans(unit, DetectorPatterns.COURT_CHAMBER_RE, 1, SpanCategory.PUBLIC_SERVICE,
                "court_chamber", 0.95, PRESERVE, "Court chamber number and composition: public court structure"));
        return spans;
    }

    /**
     * 12D. Place names after a locality cue. After an authority cue the toponym is part of a public
     * institution's name ("Δήμου Χ", "Διοικητικού Πρωτοδικείου Χ", "Εφετείο Χ") and the new gold
     * keeps it: a hard PUBLIC_SERVICE preserve over the cue and the toponym, so neither pass 2 nor a
     * name-shape proposal over the pair can blank either (v2 hard-redacts the toponym), and a hard
     * PUBLIC_LOCALITY preserve over a trailing administrative region. What follows the place is NOT
     * covered (see {@link #keptPlace}). After a district/area cue the place stays an ordinary 0.85
     * LOCALITY proposal for pass 2, as in v2.
     *
     * <p>The reason is the ROLE of the words, never the place: no place name appears in this code.
     */
    public static List<Span> detectLocalities(TextUnit unit, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        for (PyMatch m : DetectorPatterns.LOCALITY_AUTHORITY_RE.finditer(unit.normalizedText())) {
            List<int[]> kept = keptPlace(m.start(1), m.group(1), rules.regions());
            for (int i = 0; i < kept.size(); i++) {
                boolean name = i == 0; // the cue goes with the place; a separate region is geography
                spans.add(makeSpan(unit, name ? m.start() : kept.get(i)[0], kept.get(i)[1],
                        name ? SpanCategory.PUBLIC_SERVICE : SpanCategory.PUBLIC_LOCALITY,
                        name ? "authority_locality" : "authority_region", 0.95, PRESERVE,
                        "Public institution and its place after an authority cue"));
            }
        }
        spans.addAll(captureSpans(unit, DetectorPatterns.LOCALITY_CONTEXT_RE, 1, SpanCategory.LOCALITY,
                "locality_ctx", 0.85, REDACT, "Place name after a locality cue"));
        return spans;
    }

    /**
     * Where a patronymic span starts: the regex captures "τ(ου|ης) NAME" as one unit, because the
     * convention blanks the phrase whole. Right after the appeal cue the article is structural and
     * the gold keeps it ("προσφυγή του ………"), so there the span starts at the name.
     */
    static int[] fatherNameSpan(String text, PyMatch m) {
        int start = m.start(1);
        int end = m.end(1);
        if (DetectorPatterns.APPEAL_CUE_BEFORE_RE.found(PyStr.slice(text, Math.max(0, start - 24), start))) {
            String name = m.group(1);
            return new int[] {start + PyStr.len(name) - PyStr.len(DetectorPatterns.ARTICLE_STRIP.subLiteral("", name)), end};
        }
        return new int[] {start, end};
    }

    /**
     * Where a trailing administrative region from {@code regions} starts in {@code run} (longest
     * entry first, whole words, case-insensitive), or -1. A run that is nothing but a region has
     * none: "κατοίκου Θεσσαλονίκης" names the city a person lives in, not a municipality's region.
     */
    static int trailingRegion(String run, Set<String> regions) {
        String folded = PyStr.casefold(run);
        int runLen = PyStr.len(run);
        List<String> entries = new ArrayList<>(regions);
        entries.sort(Comparator.comparingInt(PyStr::len).reversed().thenComparing(PyStr.CODE_POINT_ORDER));
        for (String entry : entries) {
            int len = PyStr.len(entry);
            if (len > 0 && len < runLen && folded.endsWith(PyStr.casefold(entry))
                    && PyUnicode.isSpace(PyStr.codePointAt(run, runLen - len - 1))) {
                return runLen - len;
            }
        }
        return -1;
    }

    /**
     * The part of a place-name run after an authority cue that is kept: the place, and a trailing
     * region. The place is the run's first word, or its first TWO when the first is a toponym
     * modifier ({@link DetectorPatterns#TOPONYM_MODIFIERS}: "Νέας Σμύρνης", "Αγίας Παρασκευής"), a
     * word that cannot end a place name. One span when the run is exactly a place and its region,
     * two when other words sit between them; those are left to the ordinary layers.
     *
     * <p>BOUNDED ON PURPOSE. These are hard PRESERVES: a run that ran on into a personal name
     * ("Δήμου Νέας Σμύρνης Γεώργιος …") must not shield it, so no word is kept for merely being
     * capitalized after the place. Where the place's end cannot be told from the words alone (a
     * multi-word name with no modifier), only its first word is kept here, and the rest goes to pass
     * 2 as ordinary evidence, where the prompt teaches the institution-name reading.
     *
     * @return {@code [start, end)} code-point ranges in the unit
     */
    static List<int[]> keptPlace(int runStart, String run, Set<String> regions) {
        int runLen = PyStr.len(run);
        int placeEnd = wordEnd(run, 0);
        if (placeEnd < runLen && DetectorPatterns.isToponymModifier(PyStr.slice(run, 0, placeEnd))) {
            placeEnd = wordEnd(run, placeEnd + 1);
        }
        int region = trailingRegion(run, regions);
        if (region < 0) {
            return List.<int[]>of(new int[] {runStart, runStart + placeEnd});
        }
        if (PyStr.len(PyStr.rstrip(PyStr.slice(run, 0, region))) <= placeEnd) {
            return List.of(new int[] {runStart, runStart + runLen}); // the place and its region
        }
        return List.of(new int[] {runStart, runStart + placeEnd}, new int[] {runStart + region, runStart + runLen});
    }

    /** Where the word starting at {@code from} ends: the next whitespace, or the end of {@code run}. */
    private static int wordEnd(String run, int from) {
        int runLen = PyStr.len(run);
        while (from < runLen && PyUnicode.isSpace(PyStr.codePointAt(run, from))) {
            from++;
        }
        for (int i = from; i < runLen; i++) {
            if (PyUnicode.isSpace(PyStr.codePointAt(run, i))) {
                return i;
            }
        }
        return runLen;
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

    /**
     * 13. Issuing-authority header in the first 30 body paragraphs, stopping at the title. The header
     * comes before the body, so a paragraph that speaks of a private party (the appeal, a residence, an
     * ΑΦΜ, a seat: {@link DetectorPatterns#HEADER_END_CUE_RE}) also ends it. Without that stop, a short
     * document with no title line made the appellant's own paragraph, with its phone and e-mail cues, a
     * confident authority PRESERVE that outranked its address proposals at the resolver.
     */
    public static List<Span> detectAuthorityHeader(DocumentData document) {
        List<Span> spans = new ArrayList<>();
        for (TextUnit unit : headerParagraphs(document)) {
            int cues = DetectorPatterns.AUTHORITY_HEADER_CUES.countAll(unit.normalizedText());
            // PUBLIC_AUTHORITY_HEADER is not hard-preserved: both confidences are recommendations
            // that pass 2 adjudicates, and a REDACT can take either of them at the resolver.
            double confidence;
            if (cues >= 2) {
                confidence = 1.0;
            } else if (cues == 1) {
                confidence = 0.7;
            } else {
                continue;
            }
            spans.add(makeSpan(unit, 0, PyStr.len(unit.normalizedText()), SpanCategory.PUBLIC_AUTHORITY_HEADER,
                    "authority_header", confidence, PRESERVE, "Authority header cue matched"));
        }
        return spans;
    }

    /** The authority header's paragraphs: the first 30 body paragraphs, up to the title or a private-party cue. */
    static List<TextUnit> headerParagraphs(DocumentData document) {
        List<TextUnit> paras = bodyParagraphs(document);
        List<TextUnit> header = new ArrayList<>();
        for (TextUnit unit : paras.subList(0, Math.min(30, paras.size()))) {
            if (DetectorPatterns.DECISION_TITLE_RE.match(PyStr.strip(unit.normalizedText())) != null
                    || DetectorPatterns.HEADER_END_CUE_RE.found(unit.normalizedText())) {
                break;
            }
            header.add(unit);
        }
        return header;
    }

    /** The cells of every body table that names the issuing authority itself: its letterhead. */
    static List<TextUnit> letterheadCells(DocumentData document) {
        Set<Integer> tables = new HashSet<>();
        for (TextUnit unit : document.textUnits()) {
            if (unit.partName().equals("word/document.xml") && unit.location() instanceof TextUnit.TableCellLocation cell
                    && DetectorPatterns.STRONG_AUTHORITY_CUE_RE.found(unit.normalizedText())) {
                tables.add(cell.tableIndex());
            }
        }
        return document.textUnits().stream().filter(u -> u.partName().equals("word/document.xml")
                && u.location() instanceof TextUnit.TableCellLocation cell && tables.contains(cell.tableIndex())).toList();
    }

    /**
     * 13b. The issuing authority's own contact VALUES (its street, postal code and office lines), each a hard
     * PUBLIC_SERVICE preserve over the value alone (the labels are field labels already). Ownership is
     * established by structure, never by the value's shape: the lines stand in the authority's header (its
     * header paragraphs, or a cell of its letterhead table), the header names the authority itself
     * ({@link DetectorPatterns#STRONG_AUTHORITY_CUE_RE}), and the SAME block gives an e-mail on a public domain
     * ({@code policy.preserve_email_domains}). A block is one uninterrupted run of contact lines (any other
     * line ends it) or one letterhead table. A phone is kept only as a landline and a postal code only in its
     * own shape, so a private mobile or a stray value never inherits the exemption, and a private e-mail
     * stays a hard redact ({@link #detectContacts}).
     */
    public static List<Span> detectAuthorityContacts(DocumentData document, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        List<TextUnit> header = headerParagraphs(document);
        List<TextUnit> letterhead = letterheadCells(document);
        if (letterhead.isEmpty() && header.stream().noneMatch(
                u -> DetectorPatterns.STRONG_AUTHORITY_CUE_RE.found(u.normalizedText()))) {
            return spans;
        }
        List<TextUnit> block = new ArrayList<>();
        for (TextUnit unit : header) {
            if (PyStr.strip(unit.normalizedText()).isEmpty()) {
                continue;
            }
            if (DetectorPatterns.CONTACT_LINE_RE.match(unit.normalizedText()) != null) {
                block.add(unit);
                continue;
            }
            spans.addAll(authorityContactValues(block, rules));
            block = new ArrayList<>();
        }
        spans.addAll(authorityContactValues(block, rules));
        Map<Integer, List<TextUnit>> tables = new LinkedHashMap<>();
        for (TextUnit cell : letterhead) {
            tables.computeIfAbsent(((TextUnit.TableCellLocation) cell.location()).tableIndex(), k -> new ArrayList<>())
                    .add(cell);
        }
        tables.values().forEach(cells -> spans.addAll(authorityContactValues(cells, rules)));
        return spans;
    }

    /** A contact block's street, postal code and landline values, if the block gives a public e-mail; else none. */
    private static List<Span> authorityContactValues(List<TextUnit> block, DetectorRules rules) {
        List<Span> values = new ArrayList<>();
        boolean publicMail = false;
        for (TextUnit unit : block) {
            String text = unit.normalizedText();
            for (PyMatch m : DetectorPatterns.CONTACT_PAIR_RE.finditer(text)) {
                String label = PyStr.casefold(m.group(1));
                int start = m.start(2);
                int end = m.end(2);
                while (end > start && ".,;".indexOf(PyStr.codePointAt(text, end - 1)) >= 0) {
                    end--;
                }
                String value = PyStr.slice(text, start, end);
                boolean kept;
                if (label.startsWith("e")) {
                    publicMail |= value.contains("@")
                            && rules.preserveEmailDomains().contains(PyStr.casefold(PyStr.afterLast(value, "@")));
                    continue; // the e-mail itself is detectContacts' (a public domain is kept there)
                } else if (label.startsWith("ταχ") && label.contains("δ/νση")) {
                    kept = PyStr.len(value) <= 60 && !value.contains("@");
                } else if (label.startsWith("ταχ")) {
                    kept = DetectorPatterns.AUTHORITY_POSTCODE_VALUE_RE.fullmatch(value) != null;
                } else {
                    kept = DetectorPatterns.LANDLINE_VALUE_RE.fullmatch(value) != null;
                }
                if (kept && start < end) {
                    values.add(makeSpan(unit, start, end, SpanCategory.PUBLIC_SERVICE, "authority_contact", 1.0,
                            PRESERVE, "The issuing authority's own contact value, in its header"));
                }
            }
        }
        return publicMail ? values : List.of();
    }

    /** 14. Official signatory, without name lists: see {@link #detectFinalSignatory(DocumentData, DetectorRules)}. */
    public static List<Span> detectFinalSignatory(DocumentData document) {
        return detectFinalSignatory(document, new DetectorRules(Map.of(), Set.of(), Set.of(), Set.of(), Set.of(),
                Set.of()));
    }

    /** One line of a unit: a paragraph of it (a cell joins its paragraphs with nothing), cut at line breaks too. */
    private record Line(TextUnit unit, int start, int end) {
        String text() {
            return PyStr.slice(unit.normalizedText(), start, end);
        }
    }

    /**
     * 14. The final official signatory's NAME, hard-preserved (OFFICIAL_SIGNATORY is a
     * hard_preserve_categories entry): never redacted, never a pass-2 question.
     *
     * <p>POSITIVELY identified, never assumed. The signature block is the end of the document: body
     * paragraphs and table cells of {@code word/document.xml} from the last 20% of its paragraphs on
     * (a signature is usually a table: title and name in one cell, or the title in the cell above).
     * The lines are read in order down a paragraph run or a table column. A line holding a signing
     * official's TITLE ({@link DetectorPatterns#SIGNATORY_TITLE_RE}) opens a block; after the title's
     * own continuation lines (unit names, articles, abbreviations), the first line shaped like a name
     * of two to four capitalised words, on a line of its own, is the signatory. A name in capitals is
     * the block's convention; a name in mixed case needs one of its words in the name lists. The block
     * is skipped when it mentions a private party ({@link DetectorPatterns#PRIVATE_PARTY_CUE_RE}).
     *
     * <p>The span is the name only: the title, the unit, any other value in the same paragraph, row
     * or cell is not covered, so it stays with every other rule. No name is remembered: a later
     * occurrence of the same words elsewhere gets no protection from this one.
     */
    static List<Span> detectFinalSignatory(DocumentData document, DetectorRules rules) {
        List<TextUnit> paras = bodyParagraphs(document);
        if (paras.isEmpty()) {
            return List.of();
        }
        int threshold = bodyIndex(paras.get((int) (paras.size() * 0.80)));
        List<TextUnit> region = document.textUnits().stream()
                .filter(u -> u.partName().equals("word/document.xml") && bodyIndex(u) >= threshold)
                .toList();
        // Reading order: one run of the region's paragraphs, then each table's columns top to bottom.
        List<List<Line>> streams = new ArrayList<>();
        List<Line> paragraphLines = new ArrayList<>();
        region.stream().filter(u -> u.unitType() == UnitType.PARAGRAPH).forEach(u -> paragraphLines.addAll(lines(u)));
        streams.add(paragraphLines);
        Map<List<Integer>, List<TextUnit>> columns = new LinkedHashMap<>();
        for (TextUnit u : region) {
            if (u.unitType() == UnitType.TABLE_CELL) {
                TextUnit.TableCellLocation cell = (TextUnit.TableCellLocation) u.location();
                columns.computeIfAbsent(List.of(cell.tableIndex(), cell.colIndex()), k -> new ArrayList<>()).add(u);
            }
        }
        for (List<TextUnit> column : columns.values()) {
            List<Line> stream = new ArrayList<>();
            column.stream().sorted(Comparator.comparingInt(u -> ((TextUnit.TableCellLocation) u.location()).rowIndex()))
                    .forEach(u -> stream.addAll(lines(u)));
            streams.add(stream);
        }
        List<Span> spans = new ArrayList<>();
        Set<List<Object>> preserved = new HashSet<>();
        for (List<Line> stream : streams) {
            for (int i = 0; i < stream.size(); i++) {
                if (!DetectorPatterns.SIGNATORY_TITLE_RE.found(GreekFold.fold(stream.get(i).text()))) {
                    continue;
                }
                Line name = null;
                for (int j = i + 1; j < Math.min(stream.size(), i + 9); j++) {
                    Line candidate = stream.get(j);
                    String folded = GreekFold.fold(candidate.text());
                    if (DetectorPatterns.SIGNATORY_TITLE_RE.found(folded)
                            || DetectorPatterns.SIGNATORY_BLOCK_WORD_RE.found(folded)) {
                        continue; // the title's own continuation: its unit, its articles, its codes
                    }
                    if (DetectorPatterns.SIGNATORY_NAME_RE.match(candidate.text()) != null
                            && nameEvidence(candidate.text(), rules)) {
                        name = candidate;
                    }
                    break; // the first line that is not the title's is the name, or there is none
                }
                if (name == null) {
                    continue;
                }
                StringBuilder block = new StringBuilder();
                for (int k = Math.max(0, i - 1); k < stream.size() && stream.get(k) != name; k++) {
                    block.append(stream.get(k).text()).append('\n');
                }
                if (DetectorPatterns.PRIVATE_PARTY_CUE_RE.found(block.toString())
                        || !preserved.add(List.of(name.unit().unitId(), name.start(), name.end()))) {
                    continue;
                }
                spans.add(makeSpan(name.unit(), name.start(), name.end(), SpanCategory.OFFICIAL_SIGNATORY,
                        "final_signatory", 0.95, PRESERVE, "Final official signatory's name, after the signing title"));
            }
        }
        return spans;
    }

    /** A name in capitals is the signature block's convention; one in mixed case needs a listed word. */
    private static boolean nameEvidence(String name, DetectorRules rules) {
        if (PyStr.upper(name).equals(name)) {
            return true;
        }
        for (String word : PyStr.split(name)) {
            String folded = GreekFold.fold(PyStr.strip(word, ".,'’"));
            if (rules.givenNames().contains(folded) || rules.surnames().contains(folded)) {
                return true;
            }
        }
        return false;
    }

    /** Where {@code unit} stands among the body's children: the second step of its first character's XML path. */
    private static int bodyIndex(TextUnit unit) {
        if (unit.charMap().isEmpty()) {
            return -1;
        }
        String[] steps = unit.charMap().get(0).textNodePath().split("/");
        try {
            return steps.length > 2 ? Integer.parseInt(steps[2]) : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * The unit's lines, trimmed, empty ones dropped: a new line starts at a line break and wherever its
     * characters move to another paragraph (their XML path above the run changes), since a cell's
     * paragraphs are joined with nothing in its text.
     */
    private static List<Line> lines(TextUnit unit) {
        String text = unit.normalizedText();
        int n = PyStr.len(text);
        List<Line> out = new ArrayList<>();
        int start = 0;
        String paragraph = n > 0 && unit.charMap().size() == n ? DetectorSupport.paragraphOf(unit.charMap().get(0)) : null;
        for (int i = 0; i <= n; i++) {
            boolean breakHere = i == n || PyStr.codePointAt(text, i) == '\n';
            boolean newParagraph = false;
            if (!breakHere && paragraph != null) {
                String here = DetectorSupport.paragraphOf(unit.charMap().get(i));
                newParagraph = !here.equals(paragraph);
                paragraph = here;
            }
            if (breakHere || newParagraph) {
                int s = start;
                int e = i;
                while (s < e && PyUnicode.isSpace(PyStr.codePointAt(text, s))) {
                    s++;
                }
                while (e > s && PyUnicode.isSpace(PyStr.codePointAt(text, e - 1))) {
                    e--;
                }
                if (s < e) {
                    out.add(new Line(unit, s, e));
                }
                start = breakHere ? i + 1 : i;
            }
        }
        return out;
    }

    // ========================================================================= phrase families, names

    /**
     * 15. The hard-preserve phrase families of {@code regex_patterns.yaml} (headings, institutions,
     * departments, legal and procedural terms, labels, roles, the fixed parts of composite
     * references), on the unit's folded text, so case, accents and final sigma do not matter and every
     * offset is the unit's own. Hard by policy: each family's category is a hard-preserve category.
     */
    static List<Span> detectPreserveFamilies(TextUnit unit, DetectorSupport.MatchView view, DetectorRules rules) {
        List<Span> spans = new ArrayList<>();
        for (DetectorRules.PreserveFamily family : rules.preserveFamilies()) {
            spans.addAll(DetectorSupport.familySpans(unit, view, family));
        }
        return spans;
    }

    /** The name-evidence detector's name: its proposals take a shape hint's place. */
    static final String LISTED_NAME_DETECTOR = "listed_name";

    /**
     * 16. A person's full name the name lists vouch for: POSITIVE evidence only, an ordinary REDACT
     * proposal (never hard), which pass 1 confirms or pass 2 decides.
     *
     * <p>Two or three adjacent capitalised words on one line. Proposed when a given name and a
     * surname stand side by side, in either order (their inflected forms are in the lists); or when
     * one listed name stands beside an unlisted capitalised word and the context names a private
     * party (a party cue before it, or a name column). The span stops at the words: never across a
     * line, a tab, punctuation or a structural phrase, and never over a hard-preserved stretch (an
     * institution, a heading, the official signatory). Absence from the lists proves nothing: no
     * word is kept, and no hint is dropped, for not being listed.
     */
    static List<Span> detectListedNames(TextUnit unit, DetectorRules rules, List<Span> hardPreserved) {
        if (rules.givenNames().isEmpty() && rules.surnames().isEmpty()) {
            return List.of();
        }
        String text = unit.normalizedText();
        List<PyMatch> words = DetectorPatterns.CAPITALISED_WORD_RE.finditer(text);
        List<Span> spans = new ArrayList<>();
        int i = 0;
        while (i + 1 < words.size()) {
            int best = 0;
            for (int size = Math.min(3, words.size() - i); size >= 2; size--) {
                if (adjacent(text, words, i, size) && listedName(text, unit, words, i, size, rules)) {
                    best = size;
                    break;
                }
            }
            if (best == 0) {
                i++;
                continue;
            }
            int start = words.get(i).start();
            int end = words.get(i + best - 1).end();
            boolean shielded = hardPreserved.stream().anyMatch(s -> s.unitId().equals(unit.unitId())
                    && s.start() < end && start < s.end());
            if (!shielded) {
                spans.add(makeSpan(unit, start, end, SpanCategory.POSSIBLE_PERSON, LISTED_NAME_DETECTOR, 0.75, REDACT,
                        "Given name and surname from the name lists, or a listed name in a private-party context"));
            }
            i += best;
        }
        return spans;
    }

    /** Whether {@code size} words from {@code i} are separated by spaces only (no tab, break or punctuation). */
    private static boolean adjacent(String text, List<PyMatch> words, int i, int size) {
        for (int k = i; k < i + size - 1; k++) {
            String gap = PyStr.slice(text, words.get(k).end(), words.get(k + 1).start());
            if (gap.isEmpty() || gap.length() > 2 || !gap.chars().allMatch(c -> c == ' ' || c == ' ')) {
                return false;
            }
        }
        return true;
    }

    private static boolean listedName(String text, TextUnit unit, List<PyMatch> words, int i, int size,
                                      DetectorRules rules) {
        boolean given = false;
        boolean surname = false;
        int listed = 0;
        int givenOnly = 0;
        for (int k = i; k < i + size; k++) {
            String folded = GreekFold.fold(words.get(k).group());
            boolean g = rules.givenNames().contains(folded);
            boolean s = rules.surnames().contains(folded);
            if (g || s) {
                listed++;
            }
            if (g) {
                givenOnly++;
            }
            given |= g;
            surname |= s;
        }
        if (listed == size && given && surname) {
            return true; // a given name and a surname side by side (a word in both lists counts once)
        }
        // Otherwise only a listed GIVEN name may vouch for its unlisted neighbour as the surname (surnames are
        // an open class; given names are not), and only where the context names a private party.
        if (size != 2 || listed != 1 || givenOnly != 1) {
            return false;
        }
        int start = words.get(i).start();
        int end = words.get(i + 1).end();
        String before = PyStr.slice(text, Math.max(0, start - 60), start);
        String header = unit.location().columnHeader();
        return DetectorPatterns.PRIVATE_PARTY_CUE_RE.found(before)
                || DetectorPatterns.NAME_CONTEXT_RE.found(before)
                || DetectorPatterns.NAME_CONTEXT_RE.found(header)
                || DetectorPatterns.NAME_CONTEXT_RE.found(PyStr.slice(text, end, end + 40));
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
        List<Span> signatories = detectFinalSignatory(document, rules);
        all.addAll(signatories);
        all.addAll(detectAuthorityHeader(document));
        all.addAll(detectAuthorityContacts(document, rules));
        // The decision's own number and place/date line are the header's: its paragraphs and its letterhead.
        Set<String> header = new HashSet<>();
        headerParagraphs(document).forEach(u -> header.add(u.unitId()));
        letterheadCells(document).forEach(u -> header.add(u.unitId()));
        for (TextUnit unit : document.textUnits()) {
            // Hard and ordinary preserves alike; policy.hard_preserve_categories, not the detector,
            // decides which of the two a span is.
            if (header.contains(unit.unitId())) {
                all.addAll(detectDecisionMetadata(unit));
            }
            all.addAll(detectPreserveSpans(unit, rules));
            List<Span> labels = detectFieldLabels(unit, rules);
            all.addAll(labels);
            // A family span the field-label rule already drew at exactly the same place adds nothing.
            List<Span> families = new ArrayList<>(detectPreserveFamilies(unit, DetectorSupport.matchView(unit), rules));
            families.removeIf(f -> labels.stream().anyMatch(l -> l.start() == f.start() && l.end() == f.end()
                    && l.category() == f.category()));
            all.addAll(families);
            List<Span> shields = new ArrayList<>(families);
            signatories.stream().filter(s -> s.unitId().equals(unit.unitId())).forEach(shields::add);
            all.addAll(detectListedNames(unit, rules, shields));
            all.addAll(detectCaseCourtReferences(unit));
            all.addAll(detectStructuredIds(unit, rules));
            all.addAll(detectPropertyIds(unit, rules));
            all.addAll(detectContacts(unit, rules));
            all.addAll(detectChallengedActNumbers(unit));
            all.addAll(detectProtocolsAndActs(unit, rules));
            all.addAll(detectAppellantIdentity(unit, rules));
            all.addAll(detectLocalities(unit, rules));
            all.addAll(detectPrivateCompanies(unit, rules));
            all.addAll(detectBankPaymentIds(unit));
            all.addAll(detectFiscalDeviceIds(unit));
            all.addAll(detectTableSensitiveValues(unit));
            all.addAll(detectReviewCandidates(unit));
        }
        // A shape hint wholly inside a REDACT proposal that already names the region (a company, a
        // person, an address) is a weaker copy of that question: dropped, so pass 2 is not asked about
        // a fragment of a value on its own.
        List<Span> identities = all.stream()
                .filter(s -> s.action() == REDACT && (SPECIFIC_IDENTITY_CATEGORIES.contains(s.category())
                        || LISTED_NAME_DETECTOR.equals(s.detector()))).toList();
        List<Span> review = all.stream().filter(s -> s.action() == REVIEW)
                .filter(s -> !SHAPE_HINT_DETECTORS.contains(s.detector()) || identities.stream().noneMatch(
                        r -> r.unitId().equals(s.unitId()) && r.start() <= s.start() && s.end() <= r.end()))
                .toList();
        List<Span> resolver = all.stream().filter(s -> s.action() == REDACT || s.action() == PRESERVE).toList();
        return new DetectionResult(resolver, review);
    }
}
