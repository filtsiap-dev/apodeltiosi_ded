// Ported from v2 anonymizer/postcheck_support.py (constants); there is no generator on this branch.
// BENEFICIARY_LEAK_RE, PERSON_LEAK_RE, PROPERTY_ID_PATTERNS and LABEL_VOCABULARY regenerated from v2 (5f2b2cb).
// QA_PATTERNS.AMKA deliberately keeps the DDMMYY reading (v2 reads YYMMDD; see PostcheckTest).
package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Regex and data constants of the post-redaction audit (port of {@code postcheck_support.py}). */
public final class PostcheckPatterns {

    /** {@code qa_patterns}, insertion-ordered. */
    public static final Map<String, PyPattern> QA_PATTERNS;

    static {
        Map<String, PyPattern> qa = new LinkedHashMap<>();
        qa.put("AFM", PyRegex.compile("\\b(\\d{9})\\b", 0));
        qa.put("AMKA", PyRegex.compile("\\b((0[1-9]|[12]\\d|3[01])(0[1-9]|1[0-2])\\d{2}\\d{5})\\b", 0));
        qa.put("IBAN_GR", PyRegex.compile("\\bGR\\d{2}\\d{7}\\d{16}\\b", PyRegex.IGNORECASE));
        // Local part at most 64 and domain at most 253 (RFC 5321): unbounded, a long run with no
        // '@' costs O(n^2) (every start scans to the run's end), minutes of CPU on one document.
        // Bounded, a start scans at most 64 characters; a longer local part still matches its tail.
        qa.put("EMAIL", PyRegex.compile("[a-zA-Z0-9._%+\\-]{1,64}@[a-zA-Z0-9.\\-]{1,253}\\.[a-zA-Z]{2,}", 0));
        // Exactly ten local digits, horizontal separators only: never eat the unit-joining
        // newline and then lose a valid phone when the normalizer rejects cross-line matches.
        qa.put("PHONE", PyRegex.compile("(?<!\\d)(?:\\+?30|0030)?[\\p{Zs}\\-]?(?:69|2\\d)"
                + "(?:[\\p{Zs}\\-]*\\d){8}(?![\\p{Zs}\\-]*\\d)", 0));
        qa.put("DIGIT_RUN", PyRegex.compile("\\b\\d{9,11}\\b", 0));
        QA_PATTERNS = java.util.Collections.unmodifiableMap(qa);
    }

    /** Group 1 is the whole NAME: case-sensitive, and never across the "\n" joining two units. */
    static final PyPattern BENEFICIARY_LEAK_RE =
            PyRegex.compile("δικαιούχ[οη]\\s+τ(?:ον|ην)\\s+(?-i:([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+(?:[ \\t]+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+)*))", PyRegex.IGNORECASE);

    /** Java adds "υπ. αρ."/"υπ αριθμ." and "με αριθμό" to v2's cues. */
    static final PyPattern CASE_REF_LEAK_RE =
            PyRegex.compile("(?:υπ['\u2019.]?\\s*αρ(?:ιθμ?)?\\.?|με\\s+αριθμ[οό]|αρ\\.?\\s*πρωτ\\.?|αριθμ[οό]\\s+πρωτοκόλλου|εντολ[ήέ]ς?\\s+(?:μερικού\\s+)?ελέγχου|Γνωστοποίησ[ηεις]+|Αίτημ[αα]\\s+Παροχής\\s+Πληροφοριών|ΑΒΜ|ΕΞ)\\s+(\\d[0-9A-ZΑ-Ω./\\-]{2,})", PyRegex.IGNORECASE);

    // Java-only residual checks below. Each captures the VALUE in group 1, case-sensitively, never
    // across the "\n" joining two units, so the remediation is asked about exactly that slice.

    /** One capitalised word of a name (Greek or Latin; dots, ampersands and hyphens inside). */
    private static final String NAME_WORD = "[A-ZΑ-ΩΆΈΉΊΌΎΏΪΫ][A-Za-zΑ-Ωα-ωΆ-ώϊϋΐΰ.&\\-]*(?!\\w)";

    /** A company name still visible after its cue; a run of dots (an earlier redaction) is skipped. */
    static final PyPattern COMPANY_NAME_LEAK_RE =
            PyRegex.compile("(?:(?:με|υπό)\\s+(?:την\\s+)?επωνυμία|δ\\.\\s*τ\\.)\\s+(?:\\.+[ \\t]*)?(?-i:(" + NAME_WORD
                    + "(?:[ \\t]+(?:&[ \\t]+)?" + NAME_WORD + ")*))", PyRegex.IGNORECASE);

    /** An account number or IBAN still visible after an account cue. */
    static final PyPattern ACCOUNT_LEAK_RE =
            PyRegex.compile("(?:λογαριασμ(?:ός|ού|ό|ο)ν?|λογ\\.|IBAN|ΙΒΑΝ)\\s*(?:αρ\\.?\\s*|:\\s*)?(?-i:([A-Z]{2}\\d{2}[A-Z0-9]{8,30}|\\d[\\d\\-]{6,24}\\d))(?![\\w])",
                    PyRegex.IGNORECASE);

    /** A street name still visible after a street cue ("οδός Χ"), or before it after "επί της" ("επί της Χ Οδού"). */
    static final PyPattern STREET_LEAK_RE =
            PyRegex.compile("(?:οδ(?:ός|ού|ό)|Λεωφ(?:όρος|όρου)?\\.?)\\s+(?-i:([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:[ \\t]+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*))"
                    + "|επί\\s+τ(?:ης|ου)\\s+(?-i:([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:[ \\t]+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*[ \\t]+[Οο]δού))",
                    PyRegex.IGNORECASE);

    /** A company-register or gazette-issue number still visible after its cue. */
    static final PyPattern REGISTRY_LEAK_RE =
            PyRegex.compile("(?:αριθμ[οό]\\s+φύλλου|(?:αριθμ[οό]\\s+)?Γ\\.?\\s*Ε\\.?\\s*ΜΗ\\.?)\\s*(?:[:.]\\s*)?(\\d{3,})(?![\\w])",
                    PyRegex.IGNORECASE);

    static final PyPattern DECISION_BODY_START_RE =
            PyRegex.compile("\\bΑΠΟΦΑΣΗ\\b", PyRegex.IGNORECASE);

    static final PyPattern ELLIPSIS_RUN_RE =
            PyRegex.compile("\u2026+", 0);

    static final PyPattern OFFICIAL_CONTACT_LABEL_RE =
            PyRegex.compile("Τηλέφωνο|Τηλ\\.?|τηλ\\.?|Fax|Φαξ|Ταχ\\.", PyRegex.IGNORECASE);

    static final PyPattern OFFICIAL_HEADER_CONTEXT_RE =
            PyRegex.compile("(?<![\\p{L}\\p{M}\\p{N}_])(?:ΕΛΛΗΝΙΚΗ\\s+ΔΗΜΟΚΡΑΤΙΑ|Α\\.?\\s*Α\\.?\\s*Δ\\.?\\s*Ε\\.?|ΑΑΔΕ|Δ\\.?\\s*Ε\\.?\\s*Δ\\.?|ΔΕΔ|ΔΙΕΥΘΥΝΣΗ\\s+ΕΠΙΛΥΣΗΣ\\s+ΔΙΑΦΟΡΩΝ|ΥΠΟΔΙΕΥΘΥΝΣΗ\\s+ΕΠΑΝΕΞΕΤΑΣΗΣ)(?![\\p{L}\\p{M}\\p{N}_])", PyRegex.IGNORECASE);

    static final PyPattern OVER_REDACT_RE =
            PyRegex.compile("Αριθμ[οό]ς\\s+[Αα]πόφασης\\s*:\\s*\\.{3,}|ν\\.\\s*\\.{3,}|ΦΕΚ\\s+\\.{3,}|ΠΟΛ\\s*\\.{3,}|ΣτΕ\\s*\\.{3,}|ΝΣΚ\\s*\\.{3,}|\\.{2,}%", PyRegex.IGNORECASE);

    static final PyPattern PARTIAL_STAR_RESIDUE_RE =
            PyRegex.compile("\\b[A-ZΑ-Ω]{2,}\\s*\\*+[0-9A-ZΑ-Ω]+\\b", 0);

    /** Group 1 is the NAME, scoped as in {@link #BENEFICIARY_LEAK_RE}. */
    static final PyPattern PERSON_LEAK_RE =
            PyRegex.compile("(?:ενδικοφανή\\s+προσφυγή\\s+τ(?:ης|ου)\\s+|με\\s+ΑΦΜ\\s+\\.+\\s+)(?-i:([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+(?:[ \\t]+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+)*))", PyRegex.IGNORECASE);

    static final PyPattern WRONG_PLACEHOLDER_RE =
            PyRegex.compile("\\[(?:NAME|AFM|ADDRESS|COMPANY|ACT_NUMBER|REDACTED)\\]|<REDACTED>|(?:PERSON|COMPANY)_\\d+|\\*{3,}\\d+|\\*{5,}", PyRegex.IGNORECASE);

    /** Normalized invoice column headers (membership only). */
    static final Set<String> INVOICE_COLUMN_HEADERS = Set.of(
            "αρ. παραστατικου",
            "αριθμοσ",
            "παρα στατικο",
            "παραστατικο",
            "στοιχειο",
            "τιμ.",
            "τιμολογιο");

    /**
     * One property-identifier spec ({@code _PROPERTY_ID_PATTERNS}): the cue, one value's shape,
     * and the bounded comma/"και"-joined list of values or dot runs after the cue.
     */
    record PropertyIdPattern(String name, PyPattern cue, PyPattern value, PyPattern list) {
    }

    /** How far past the cue a list may run ({@code _PROPERTY_LIST_BUDGET}). */
    static final int PROPERTY_LIST_BUDGET = 160;

    static final List<PropertyIdPattern> PROPERTY_ID_PATTERNS = List.of(
            new PropertyIdPattern("ΑΤΑΚ",
                    PyRegex.compile("Α\\.?\\s*Τ\\.?\\s*Α\\.?\\s*Κ\\.?\\s*(?::\\s*)?", PyRegex.IGNORECASE),
                    PyRegex.compile("\\d{11}", 0),
                    PyRegex.compile("(?:\\d{11}|\\.+|\u2026+)(?:[ \\t]*(?:,|και)[ \\t]*(?:\\d{11}|\\.+|\u2026+))*", 0)),
            new PropertyIdPattern("ΚΑΕΚ",
                    PyRegex.compile("Κ\\.?\\s*Α\\.?\\s*Ε\\.?\\s*Κ\\.?\\s*(?::\\s*)?", PyRegex.IGNORECASE),
                    PyRegex.compile("\\d{12}(?:/\\d+)*", 0),
                    PyRegex.compile("(?:\\d{12}(?:/\\d+)*|\\.+|\u2026+)(?:[ \\t]*(?:,|και)[ \\t]*(?:\\d{12}(?:/\\d+)*|\\.+|\u2026+))*", 0)),
            new PropertyIdPattern("Ο.Τ.",
                    PyRegex.compile("Ο\\.\\s*Τ\\.?\\s*(?::\\s*)?", PyRegex.IGNORECASE),
                    PyRegex.compile("\\d+[Α-ΩA-Zα-ωά-ώa-z]?", 0),
                    PyRegex.compile("(?:\\d+[Α-ΩA-Zα-ωά-ώa-z]?|\\.+|\u2026+)(?:[ \\t]*(?:,|και)[ \\t]*(?:\\d+[Α-ΩA-Zα-ωά-ώa-z]?|\\.+|\u2026+))*", 0)),
            new PropertyIdPattern("Α.Χ.Κ.",
                    PyRegex.compile("Α\\.?\\s*Χ\\.?\\s*Κ\\.?\\s*(?::\\s*)?", PyRegex.IGNORECASE),
                    PyRegex.compile("\\d+(?:/\\d+)+|\\d{3,}", 0),
                    PyRegex.compile("(?:\\d+(?:/\\d+)+|\\d{3,}|\\.+|\u2026+)(?:[ \\t]*(?:,|και)[ \\t]*(?:\\d+(?:/\\d+)+|\\d{3,}|\\.+|\u2026+))*", 0)),
            new PropertyIdPattern("αριθμό ειδοποίησης",
                    PyRegex.compile("αριθμ[οό]\\s+ειδοποίησης\\s*(?::\\s*)?", PyRegex.IGNORECASE),
                    PyRegex.compile("\\d[\\d/\\-]*", 0),
                    PyRegex.compile("(?:\\d[\\d/\\-]*|\\.+|\u2026+)(?:[ \\t]*(?:,|και)[ \\t]*(?:\\d[\\d/\\-]*|\\.+|\u2026+))*", 0)));

    /** Structural labels whose disappearance is over-redaction ({@code _LABEL_VOCABULARY}). */
    static final List<String> LABEL_VOCABULARY = List.of(
            "Α.Φ.Μ.", "ΑΦΜ", "ΑΜΚΑ", "ΙΒΑΝ", "ΑΤΑΚ", "Α.Τ.Α.Κ.", "ΚΑΕΚ", "Ο.Τ.", "Α.Χ.Κ.", "Τ.Κ.", "κάτοικος",
            "κατοίκου", "οδός", "οδού", "Λεωφ.", "αρ.", "αριθμό πρωτοκόλλου", "αρ. πρωτ.", "αριθμό ειδοποίησης",
            "Πράξη", "Τιμολόγιο", "Τράπεζα", "Τηλέφωνο", "Ταχ. Δ/νση", "E-mail", "Fax");

    private PostcheckPatterns() {
    }
}
