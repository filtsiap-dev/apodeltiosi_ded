// Ported from v2 anonymizer/detector_patterns.py. The literals were generated from v2's compiled patterns;
// there is no generator on this branch, so a change here is made by hand and checked against v2.
package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.text.Normalizer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Regex and data constants for the deterministic detectors (port of {@code detector_patterns.py}). */
final class DetectorPatterns {

    /** Built-in pattern specs by name; {@code config/regex_patterns.yaml} overrides per key. Insertion-ordered. */
    static final Map<String, Map<String, String>> DEFAULT_PATTERNS;

    static {
        Map<String, Map<String, String>> patterns = new LinkedHashMap<>();
        patterns.put("afm", orderedSpec("prefix", "(?:Α\\.?Φ\\.?Μ\\.?|AFM)\\s*(?:[:.]\\s*)?", "body", "(\\d{9})"));
        patterns.put("amka", orderedSpec("prefix", "(?:ΑΜΚΑ|AMKA)\\s*(?:[:.]\\s*)?", "body", "(\\d{11})"));
        // Bounded to RFC 5321's 64/253 so a long run with no '@' is linear, not O(n^2) (see PostcheckPatterns).
        patterns.put("email", orderedSpec("body", "[\\w.+-]{1,64}@[\\w-]{1,253}\\.[\\w.-]{1,253}"));
        patterns.put("iban", orderedSpec("body", "[A-Z]{2}\\d{2}(?:[\\s-]?[A-Z0-9]){1,30}"));
        patterns.put("phone_intl", orderedSpec("body", "\\+30[\\s-]?(?:\\d[\\s-]?){10}"));
        patterns.put("phone_local", orderedSpec("body", "(?:2|6)\\d{9}"));
        patterns.put("phone_00", orderedSpec("body", "0030\\d{10}"));
        patterns.put("protocol_number", orderedSpec("prefix", "(?:αριθμ[οό]\\s+πρωτοκόλλου|αριθ\\.?\\s*πρωτ\\.?|αρ\\.?\\s*πρωτ\\.?|Πρωτ\\.?)\\s*(?:[:.]\\s*)?", "body", "([A-Za-z0-9Α-Ωα-ωΆ-ώ/\\-]*\\d[A-Za-z0-9Α-Ωα-ωΆ-ώ/\\-]*(?:/\\d{2,4})?)"));
        patterns.put("act_number", orderedSpec("body", "Πράξη\\s+([A-Za-z0-9Α-Ωα-ωΆ-ώ/\\-]*\\d[A-Za-z0-9Α-Ωα-ωΆ-ώ/\\-]*)"));
        patterns.put("audit_order", orderedSpec("prefix", "(?:εντολ[ήέ]ς?\\s+(?:μερικού\\s+)?ελέγχου|Γνωστοποίησ(?:η|εις)|Αίτημ(?:α|ατα)\\s+Παροχής\\s+Πληροφοριών|Πρόσκλησ(?:η|εις)|Πληροφοριακή\\s+Έκθεση|ΑΒΜ|ΕΞ)\\s+", "body", "([0-9]{2,}(?:\\s*[/&]\\s*[0-9]+)*(?:[/\\-]\\d{2,4}(?:[/\\-.]\\d{2,4})*)?)"));
        patterns.put("invoice_number", orderedSpec("body", "(?:Τιμολόγιο|Α/Α)\\s+(\\d+)"));
        patterns.put("transaction_id", orderedSpec("body", "(?:Συναλλαγή|ID)\\s*(?:[:.]\\s*)?([A-Za-z0-9]{6,})"));
        patterns.put("date_numeric", orderedSpec("body", "\\b(\\d{1,2})[/\\-.](\\d{1,2})[/\\-.](\\d{4})\\b"));
        patterns.put("date_greek", orderedSpec("body", "\\b(\\d{1,2})η?\\s+(Ιανουαρίου|Φεβρουαρίου|Μαρτίου|Απριλίου|Μαΐου|Ιουνίου|Ιουλίου|Αυγούστου|Σεπτεμβρίου|Οκτωβρίου|Νοεμβρίου|Δεκεμβρίου)\\s+(\\d{4})\\b"));
        patterns.put("dou", orderedSpec("body", "(?:Δ\\.Ο\\.Υ\\.|ΔΟΥ)\\s+([Α-ΩΆΈΉΊΌΎΏΪΫ][\\wΆ-ώ\\s]*)"));
        // A law at a word start ("των 1234/2021" is no "ν. 1234/2021", "αριθμόν 498/2020" no law either); the
        // letter Ο typed for a zero only inside the validated "ν.<number>/<year>" shape ("ν.51Ο4/2Ο24"), and
        // one stray digit typed after the year ("Ν. 5219/20255") still the same law.
        patterns.put("legal_ref_law", orderedSpec("body", "(?<![\\p{L}\\p{M}\\p{N}])(?:[Νν]\\.?\\s*|[Νν][όο]μο[υςν]?\\s+)"
                + "[0-9][0-9ΟO]{0,4}/(?:(?:19|2[0ΟO])[0-9ΟO]{2}\\d?|\\d{2})(?![\\p{N}/])"));
        patterns.put("legal_ref_pd", orderedSpec("body", "Π\\.Δ\\.\\s*(\\d+/\\d+)"));
        patterns.put("legal_ref_short", orderedSpec("body", "(?:Κ\\.Φ\\.Δ\\.|Κ\\.Ν\\.)"));
        // An article in any case or accenting ("άρθρου 21§4", "ΑΡΘΡΟ 2", "άρθρα 31 και 32", "αρθ. 34"), with its
        // paragraph ("παρ. 1 του άρθρου 33"). Never the street-number cue "αρ.": only the accented "άρ." is
        // an article, as before. A list continues only after the plural, and never into a "/year" serial.
        patterns.put("article_ref", orderedSpec("body", "(?<![\\p{L}\\p{M}\\p{N}])(?:[άα]ρθρ(?:α|ων)\\s*\\d{1,3}[Α-Ωα-ω]?"
                + "(?![\\p{N}/])(?:\\s*(?:,|και)\\s*\\d{1,3}[Α-Ωα-ω]?(?![\\p{N}/]))*|(?:[άα]ρθρ(?:ο|ου)|άρ\\.|[άα]ρθρ?\\.)\\s*"
                + "\\d{1,3}[Α-Ωα-ω]?(?![\\p{N}/]))(?:\\s*§\\s*\\d{1,3})?(?:\\s*(?:παρ\\.|παράγραφος|παραγράφου)\\s*\\d{1,3}"
                + "(?![\\p{N}/]))?|(?<![\\p{L}\\p{M}\\p{N}])(?:(?:υπο)?παρ\\.|παράγραφος|παραγράφου|παράγραφο)\\s*\\d{1,3}(?![\\p{N}/])"
                + "(?:\\s+του\\s+(?:ίδιου\\s+)?[άα]ρθρου(?:\\s+\\d{1,3}[Α-Ωα-ω]?(?![\\p{N}/]))?)?|(?:εδάφιο|περ\\.)\\s+[α-ωΑ-Ω]"));
        // An ΑΑΔΕ decision or circular by its published number ("Α.1165/22.11.2022 απόφαση του Διοικητή",
        // "εγκυκλίου Ε.2015/2020 με θέμα"): a published instrument (LEGAL_REF), and ONLY with a
        // published-act cue right after it or "εγκύκλιος" right before it. The shape alone is no evidence,
        // and never after a protocol cue: "αρ. πρωτ. Α.1234/2021" is a protocol of the taxpayer's file.
        patterns.put("legal_ref_decision", orderedSpec("body", "(?=[ΑΕAE]\\.)(?<![\\p{L}\\p{M}\\p{N}.])(?<!πρωτ\\.\\s)(?<!πρωτ\\.)"
                + "(?<!πρωτοκόλλου\\s)[ΑΕAE]\\.\\s?\\d{3,5}/(?:\\d{1,2}\\.\\d{1,2}\\.)?(?:19|20)\\d{2}(?![\\p{N}/])"
                + "(?=\\s*(?:απόφασ\\S*\\s+(?:του\\s+)?Διοικητ|εγκύκλι|με\\s+θέμα|\\(\\s*ΦΕΚ))"
                + "|(?<=εγκυκλίου\\s|εγκύκλιο\\s|εγκύκλιος\\s)[ΑΕAE]\\.\\s?\\d{3,5}/(?:19|20)\\d{2}(?![\\p{N}/])"));
        patterns.put("money", orderedSpec("body", "(?:€\\s*[\\d.,]+|[\\d.,]+\\s*(?:€|ευρώ))"));
        // Any case or accenting ("ΧΡΗΣΗ 2021", "ΦΟΡΟΛΟΓΙΚΟ ΕΤOΣ 2019" with a Latin O, "φορολογικού έτους 2021").
        patterns.put("tax_year", orderedSpec("body", "(?<![\\p{L}\\p{M}\\p{N}])(?:(?:οικονομικ|φορολογικ)(?:ό|ο|ού|ου)\\s+"
                + "[έε]τ[οόoO](?:ς|υς|ύς)|χρ[ήη]σ(?:η|ης))\\s+(?:19|2[0ΟO])[0-9ΟO]{2}(?![\\p{N}])"));
        // A Government Gazette reference: "ΦΕΚ Β΄4738/26.10.2020", "ΦΕΚ. 1136/Β/10-5-2013", "ΦΕΚ 2759/ τ. Β’/ 01.09.2016",
        // "Φ.Ε.Κ. 1177/Δ/1993"; for an OCR-damaged issue ("ΦΕΚ.1136/Β710-5-2013") the issue number alone. Never a
        // company-statute issue ("Φ.Ε.Κ. με αριθμό φύλλου 4321", "ΦΕΚ ΑΕ-ΕΠΕ"): a series letter or number must follow.
        patterns.put("legal_ref_fek", orderedSpec("body", "(?<![\\p{L}\\p{M}\\p{N}])(?:ΦΕΚ|Φ\\.Ε\\.Κ\\.)\\.?\\s*(?:[Α-ΔA-D][\u2019'ʼ\u1fbd\u0384]?\\s*"
                + "\\d{1,5}(?:\\s*/\\s*\\d{1,2}[./-]\\d{1,2}[./-]\\d{2,4})?(?![\\p{N}])|\\d{1,5}\\s*/\\s*(?:τ\\.\\s*)?[Α-ΔA-D][\u2019'ʼ\u1fbd\u0384]?\\s*/\\s*"
                + "(?:\\d{1,2}[./-]\\d{1,2}[./-]\\d{2,4}|\\d{4})|\\d{1,5}(?=\\s*/\\s*[Α-ΔA-D]))"
                + "|ΦΕΚ\\s+[Α-ΩA-Z\u2019'ʼ\u1fbd\u0384]+\\s*\\d+(?:[/,.]\\s*\\d+(?:[./]\\d+)*)?"));
        // The whole reference: "ΠΟΛ.1050/2014", "ΠΟΛ 1171/04-07-2013", "ΠΟΛ.1270/24.12.2013", "ΠΟΛ.1Ο5Ο/17.2.2Ο14".
        patterns.put("legal_ref_pol", orderedSpec("body", "(?<![\\p{L}\\p{M}\\p{N}])ΠΟΛ\\.?\\s*[0-9][0-9ΟO]{3}(?:\\s*/\\s*"
                + "(?:[0-9ΟO]{1,2}[-./][0-9ΟO]{1,2}[-./](?:19|2[0ΟO])[0-9ΟO]{2}|(?:19|2[0ΟO])[0-9ΟO]{2}))?(?![\\p{N}])"));
        // Council of State precedent: the citation and the list it heads ("ΣτΕ 453/2011, 73/2001 και
        // 1238/2018", "ΣτΕ Ολ. 1234/2015"), and a decision the text calls case law ("νομολογιακά με την υπ'
        // αριθ. 1014/29-05-2019 απόφαση του ΣτΕ"). A decision of the appellant's own case has no such cue.
        patterns.put("legal_ref_ste", orderedSpec("body", "(?<![\\p{L}\\p{M}\\p{N}])(?:ΣτΕ|Σ\\.τ\\.Ε\\.?)(?:\\s*\\(?Ολ(?:ομ)?\\.?\\)?)?"
                + "\\s*\\d{1,5}(?:-\\d{1,3})?/\\d{2,4}(?:\\s*,\\s*(?:(?:ΣτΕ|Σ\\.τ\\.Ε\\.?)\\s*)?\\d{1,5}(?:-\\d{1,3})?(?:/\\d{4})?"
                + "(?![\\p{N}/]))*(?:\\s+και\\s+(?:(?:ΣτΕ|Σ\\.τ\\.Ε\\.?)\\s*)?\\d{1,5}/\\d{4}(?![\\p{N}/]))?"
                + "|(?<![\\p{N}/])(?=\\d{1,5}/)(?<=νομολογ[^;]{0,60})\\d{1,5}/(?:\\d{1,2}[-./]\\d{1,2}[-./])?\\d{4}"
                + "(?=\\s+απόφαση\\s+του\\s+ΣτΕ)"));
        patterns.put("legal_ref_nsk", orderedSpec("body", "ΝΣΚ\\s*\\d+/\\d{2,4}"));
        patterns.put("legal_ref_aade", orderedSpec("body", "Α\\.Α\\.Δ\\.Ε\\.|\\bΑ[ΑA]ΔΕ\\b|Δ\\.Ε\\.Δ\\.|\\bΔΕΔ\\b|Κ\\.Ε\\.ΜΕ\\.Φ\\.|Κ\\.Ε\\.ΦΟ\\.ΜΕ\\.Π\\.|Υ\\.Ε\\.Δ\\.Δ\\.Ε\\."));
        patterns.put("percentage", orderedSpec("body", "\\b\\d+(?:[.,]\\d+)?\\s*%"));
        // A period between two dates ("1/1/2003 έως την 31/12/2010"), and a calendar fiscal year written as a
        // range ("01/01-31/12/2021", "01/01/2021 - 31/12/2021"): a range, never one date (a date of birth).
        patterns.put("fiscal_period", orderedSpec("body", "(?<![\\p{N}/.\\-])\\d{1,2}[-/.]\\d{1,2}[-/.]\\d{4}\\s+έως\\s+(?:την?\\s+)?"
                + "\\d{1,2}[-/.]\\d{1,2}[-/.]\\d{4}(?![\\p{N}])|(?<![\\p{N}/.\\-])0?1[-/.]0?1(?:[-/.](?:19|20)\\d{2})?\\s*-\\s*"
                + "31[-/.]12[-/.](?:19|20)\\d{2}(?![\\p{N}])|\\bφορολογική\\s+περίοδος\\s+\\d{4}"));
        // Property identifiers: cue-anchored, value in group 1, so no span reaches the label.
        patterns.put("atak", orderedSpec("prefix", "(?:Α\\.?Τ\\.?Α\\.?Κ\\.?)\\s*(?:[:.]\\s*)?", "body", "((?<!\\d)\\d{11}(?:\\s*(?:,|και)\\s*\\d{11})*(?!\\d))"));
        patterns.put("kaek", orderedSpec("prefix", "(?:Κ\\.?Α\\.?Ε\\.?Κ\\.?)\\s*(?:[:.]\\s*)?", "body", "((?<!\\d)\\d{12}(?:/\\d+)*(?:\\s*(?:,|και)\\s*\\d{12}(?:/\\d+)*)*)"));
        patterns.put("ot", orderedSpec("prefix", "Ο\\.\\s*Τ\\.?\\s*(?:[:.]\\s*)?", "body", "((?<!\\d)\\d+[Α-ΩA-Z]?(?:\\s*(?:,|και)\\s*\\d+[Α-ΩA-Z]?)*)"));
        patterns.put("axk", orderedSpec("prefix", "Α\\.?\\s*Χ\\.?\\s*Κ\\.?\\s*(?:[:.]\\s*)?", "body", "((?<!\\d)(?:\\d+(?:/\\d+)+|\\d{3,})(?:\\s*(?:,|και)\\s*(?:\\d+(?:/\\d+)+|\\d{3,}))*)"));
        patterns.put("notice_number", orderedSpec("prefix", "αριθ(?:μ[οό]\\s+|\\.\\s*)ειδοποίησης\\s*(?:[:.]\\s*)?", "body", "((?<!\\d)\\d[\\d/\\-]*)"));
        // FIELD_LABEL is hard-preserved, so a token is admitted only if it can never itself be, or
        // begin, personal data; each label demands evidence of its value (IBAN: country code and
        // check digits, not merely a digit, since "ΙΒΑΝ" is also a first name). Bounded on both
        // sides so a label cannot anchor inside a longer initialism or a word prefix.
        patterns.put("field_label", orderedSpec("body", "(?<![Α-Ωα-ωΆ-ώA-Za-z0-9.])(?:(?:Α\\.?\\s*Φ\\.?\\s*Μ\\.?|AFM)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:ΑΜΚΑ|AMKA)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:ΙΒΑΝ|IBAN)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[A-ZΑ-Ω]{2}\\s*\\d{2}|\\.{2,}|…))|(?:Α\\.?\\s*Τ\\.?\\s*Α\\.?\\s*Κ\\.?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:Κ\\.?\\s*Α\\.?\\s*Ε\\.?\\s*Κ\\.?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:Ο\\.\\s*Τ\\.?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:Α\\.?\\s*Χ\\.?\\s*Κ\\.?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:Τ\\.?\\s*Κ\\.?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:αριθμ[οό]\\s+πρωτοκόλλου|αριθμ?\\.?\\s*πρωτ\\.?|αρ\\.?\\s*πρωτ\\.?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:αριθ(?:μ[οό]\\s+|\\.\\s*)ειδοποίησης)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:αρ\\.?\\s*καταχώρισης)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩA-Z]{0,4}\\d|\\.{2,}|…))|(?:αρ\\.)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=\\s*(?:\\d|\\.{2,}|…))|(?:κάτοικ(?:ος|η|οι)|κατοίκ(?:ου|ων|ους|ης))(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩΆΈΉΊΌΎΏΪΫ]|\\.{2,}|…))|(?:οδ(?:ός|ού))(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩΆΈΉΊΌΎΏΪΫ]|\\.{2,}|…))|(?:Λεωφ(?:όρος|όρου)?\\.?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*(?:[Α-ΩΆΈΉΊΌΎΏΪΫ]|\\.{2,}|…))|(?:Ταχ\\.\\s*Δ/νση|Ταχ\\.\\s*Κώδικας)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*\\S)|(?:Τηλέφωνο|Τηλ\\.)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*\\S)|(?:Fax|Φαξ)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*\\S)|(?:E-?mail)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])(?=[:.]?\\s*\\S))"));
        DEFAULT_PATTERNS = java.util.Collections.unmodifiableMap(patterns);
    }

    static final String GREEK_CAPITALIZED = "[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+";

    /**
     * A word that is a label, not part of a place or street name, in any case: "αρ."/"ΑΡ.", "αριθ.", "ΤΚ",
     * "οδός"/"ΟΔΟΣ"/"Οδού", "Λεωφ."/"Λεωφόρος". Put in front of every word of {@link #ADDRESS_NAME}, so a
     * name ends where its label-introduced value begins ("ΟΔΟΣ ΕΡΜΟΥ ΑΡ. 5" gives "ΕΡΜΟΥ").
     */
    private static final String ADDRESS_LABEL_AHEAD =
            "(?!(?i:αρ|αριθ|τκ|οδ[όο][ςσύυ]?|λεωφ(?:όρο[ςσυ])?)(?![Α-Ωα-ωΆ-ώϊϋΐΰ]))";

    /**
     * The one character that may separate the parts of an address value: a space or a no-break space. A
     * line break, a tab or a run of spaces is a layout gap, not part of the value, so the value ends there
     * (as v2's address capture ends at "\s{2,}" and "\n").
     */
    private static final String ADDRESS_GAP = "[  ]";

    /**
     * A place or street name, CASE-SENSITIVE on purpose: a name is capitalised, so it ends at the first
     * word that is not ("κάτοικος Λαμίας, προσέφυγε κατά της πράξης" gives "Λαμίας") and at any
     * punctuation, label or layout gap. In front of it: an ordinal ("28ης Οκτωβρίου") or up to three
     * abbreviated words ("Ι. Μεταξά", "Αγ. Δημητρίου", "Ν. Σμύρνης"). At most six words: an unbounded
     * group repetition recurses once per word in java.util.regex.
     */
    private static final String ADDRESS_NAME = "(?:\\d{1,2}(?:ης|ου|η)" + ADDRESS_GAP + "|(?:" + ADDRESS_LABEL_AHEAD
            + "[Α-ΩΆΈΉΊΌΎΏΪΫ][α-ωά-ώϊϋΐΰ]{0,3}\\." + ADDRESS_GAP + "?){1,3})?" + ADDRESS_LABEL_AHEAD
            + "[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:" + ADDRESS_GAP + ADDRESS_LABEL_AHEAD + "[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+){0,5}";

    /**
     * A house number: one to four digits, an optional letter, an optional range ("12-14"). Never the start
     * of a postal code, a serial, a date or an amount (no further digit, slash, letter, or ".5"/",5").
     */
    private static final String HOUSE_NUMBER = "\\d{1,4}[Α-ΩA-Z]?(?:" + ADDRESS_GAP + "?[-–]" + ADDRESS_GAP
            + "?\\d{1,4}[Α-ΩA-Z]?)?(?![\\dΑ-Ωα-ωΆ-ώA-Za-z/]|[.,]\\d)";

    /** A comma between two parts of an address value ("Ερμού 5, Αθήνα"), on one line. */
    private static final String ADDRESS_COMMA = ADDRESS_GAP + "?," + ADDRESS_GAP + "?";

    /** Medical terms. A set in Python (hash-seed ordered); sorted by code point here so output order is stable. */
    static final List<String> MEDICAL_TERMS = List.of(
            "ασθένεια",
            "διάγνωση",
            "διαβήτης",
            "θεραπεία",
            "καρκίνος",
            "νόσος",
            "φαρμακευτική",
            "χειρουργείο");

    /** Appellant name after the appeal cue or an honorific ("κ.", "κου", "κας"); value in group 1. */
    static final PyPattern APPELLANT_NAME_RE =
            PyRegex.compile("(?i:(?:ενδικοφανή\\s+προσφυγή|προσφυγή)\\s+τ(?:ης|ου)|\\bκ(?:\\.|ον|ου|ο|α)(?![α-ωά-ώ])\\.?)\\s+((?:[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)(?:\\s+(?:[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+))*)", 0);

    static final PyPattern AUTHORITY_HEADER_CUES =
            PyRegex.compile("ΕΛΛΗΝΙΚΗ\\s+ΔΗΜΟΚΡΑΤΙΑ|ΔΙΕΥΘΥΝΣΗ\\s+ΕΠΙΛΥΣΗΣ\\s+ΔΙΑΦΟΡΩΝ|ΥΠΟΔΙΕΥΘΥΝΣΗ\\s+ΕΠΑΝΕΞΕΤΑΣΗΣ|Α\\.Α\\.Δ\\.Ε\\.|Α[ΑA]ΔΕ|Ταχ\\.\\s*Δ/νση|Ταχ\\.\\s*Κώδικας|Τηλέφωνο|Fax|E-mail", PyRegex.IGNORECASE);

    /**
     * An account identifier after an account or bank cue: an IBAN-shaped value (country letters and
     * check digits) or a digit run. Java-only narrowing: v2's value also read a bank's NAME after
     * "Τράπεζα" as an account; a bank's name is kept by policy.
     */
    static final PyPattern BANK_ACCOUNT_RE =
            PyRegex.compile("(?i:λογ\\.\\s*|λογαριασμ[οό]ν?\\s*|Τράπεζα[ς]?\\s+)([A-ZΑ-Ω]{2}\\d{2}[0-9A-ZΑ-Ω\\s]{2,27}[0-9A-ZΑ-Ω]|[0-9]{6,26})", 0);

    /**
     * Java-only: the number of a tax assessment's triplicate ("ΑΤΒ 25761/10.09.2024"), a taxpayer-file
     * number, value (the digits) in group 1. The prefix is a hard FIELD_LABEL and stays, as does a date.
     */
    static final PyPattern ATB_NUMBER_RE = PyRegex.compile("(?<![Α-Ωα-ωΆ-ώA-Za-z0-9])Α\\.?Τ\\.?Β\\.?"
            + "(?![Α-Ωα-ωΆ-ώA-Za-z0-9])[  ]*(?:[:.][  ]*)?(\\d{1,12})(?!\\d)", 0);

    /**
     * This also runs on /anonymize-text input (up to 400k characters). An unbounded group repetition
     * recurses once per word in java.util.regex and overflows the stack on a long capitalised run, so it
     * takes at most 31 words, far more than any real name.
     */
    static final PyPattern BENEFICIARY_RE =
            PyRegex.compile("(?i:δικαιούχ[οη]\\s+τ(?:ον|ην))\\s+([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+"
                    + "(?:\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+){0,30})", 0);

    /**
     * What may stand between "έδρα" and the seat itself: an article, a place preposition ("επί της",
     * "στην", ...) and a street cue ("οδό"), each optional and each led by its whitespace. Inside a
     * {@code (?i:...)} group, so any case.
     */
    private static final String SEAT_PREPOSITIONS = "(?:\\s+τ(?:ην|ον|η|ο))?(?:\\s+(?:επί\\s+τ(?:ης|ου|ων)|στην|στη"
            + "|στον|στο|στα|στις))?(?:\\s+οδ(?:[όο]ς|[οό][ύυ]|[όο]))?";

    /** "οδός"/"οδού"/"οδό" after a street's name, as part of it ("Ιερά οδού", "Ιεράς Οδού"); any case. */
    private static final String STREET_TYPE_WORD = "(?i:οδ(?:[όο]ς|[οό][ύυ]|[όο]))(?![Α-Ωα-ωΆ-ώϊϋΐΰ])";

    /**
     * The seat after "με έδρα", value in group 1. Java consumes the place-introducing phrase ("επί της",
     * "στην", "οδό") OUTSIDE group 1, where v2 lets the value start at the preposition. A seat is
     * redacted whole, so the value is the whole address: the place or street name ({@link
     * #ADDRESS_NAME}, case-sensitive: v2's case-insensitive capture ran on through the rest of the
     * clause, or stopped inside "αρ."), a street-type word after it ("Ιερά οδού"), the house number with
     * or without "αρ."/"αριθ." (the label itself is a hard FIELD_LABEL and stays visible), and the town
     * after the number ("Ερμού αρ. 5 Αθήνα", "Ερμού 5, Αθήνα"), all on one line.
     */
    static final PyPattern BUSINESS_SEAT_RE =
            PyRegex.compile("(?i:με\\s+[έε]δρα" + SEAT_PREPOSITIONS + ")\\s+(" + ADDRESS_NAME + "(?:" + ADDRESS_GAP
                    + STREET_TYPE_WORD + ")?(?:" + ADDRESS_GAP + "(?:(?i:αρ(?:ιθ)?\\.)" + ADDRESS_GAP + "?)?" + HOUSE_NUMBER
                    + "(?:(?:" + ADDRESS_COMMA + "|" + ADDRESS_GAP + ")" + ADDRESS_NAME + ")?)?)", 0);

    /**
     * The serial of a court decision cited by number and year ("με αριθμό 512/2019 απόφαση", "η υπ' αρ.
     * 512/2019 δικαστική απόφαση"). Java widens v2's cues ("υπ. αρ.", "υπ' αριθμ.", one word between
     * the year and "απόφαση"); it only ever asks pass 2, see {@code Detectors.detectCaseCourtReferences}.
     */
    static final PyPattern CASE_COURT_SERIAL_RE =
            PyRegex.compile("(?:υπ[’'ʼ᾽΄.]?\\s*αρ(?:ιθ)?μ?\\.?|με\\s+αριθμ[οό])\\s+(\\d+)\\s*/\\s*\\d{4}\\s+(?:[α-ωά-ώ]+\\s+)?απόφασ", PyRegex.IGNORECASE);

    static final PyPattern CHALLENGED_ACT_CONTEXT_RE =
            PyRegex.compile("Οριστικ|Πράξ[ηή]|Διορθωτικ|Φ\\.Π\\.Α|Τελών|φόρου|προστίμου|Επιβολής", PyRegex.IGNORECASE);

    /**
     * The serial after "υπ' αριθ." / "με αριθ.", value in group 1. Only the cue is case-insensitive (v2 also
     * compiled the value so, which made its capitals match a lowercase word), and the value must hold a digit:
     * "με αριθ. ειδοποίησης 125440/2021" proposed the label's first letters "ειδοπο" as the act's number.
     * Java also reads the capitals heading of an act ("ΑΡΙΘ. 52/2026 ΟΡΙΣΤΙΚΗ ΠΡΑΞΗ", 3096), case-sensitive.
     */
    static final PyPattern CHALLENGED_ACT_RE =
            PyRegex.compile("(?:(?i:υπ[\u2019'ʼ\u1fbd\u0384]\\s*αρ(?:ιθ)?\\.?|με\\s+αριθ\\.?)|ΑΡΙΘ\\.?)\\s+((?=[0-9Α-ΩA-Z./\\-]*\\d)"
                    + "[0-9Α-ΩA-Z][0-9Α-ΩA-Z./\\-]+)", 0);

    /**
     * A company name after an explicit cue, value in group 1, the cue left visible. Java also takes the
     * cue with its article and its equivalents ("με την επωνυμία", "υπό την επωνυμία", "με τον
     * διακριτικό τίτλο", "δ.τ."), where v2 has "με επωνυμία" only.
     */
    static final PyPattern COMPANY_NAME_AFTER_CTX =
            PyRegex.compile("(?i:(?:με|υπό)\\s+(?:την\\s+)?επωνυμία\\s+|με\\s+(?:τον\\s+)?διακριτικό\\s+τίτλο\\s+|δ\\.\\s*τ\\.\\s*|εταιρε?ία\\s+|εκδότρια\\s+(?:νομική\\s+οντότητα\\s+)?)([Α-ΩΆΈΉΊΌΎΏΪΫA-Z][Α-Ωα-ωΆ-ώa-zA-Z.&\\-]*(?:\\s+(?:&\\s+)?[Α-ΩΆΈΉΊΌΎΏΪΫA-Z][Α-Ωα-ωΆ-ώa-zA-Z.&\\-]*)*(?:\\s+(?:Α\\.?Ε\\.?|Ε\\.?Π\\.?Ε\\.?|Ι\\.?Κ\\.?Ε\\.?|Ο\\.?Ε\\.?|Ε\\.?Ε\\.?))?)", 0);

    /**
     * A court chamber: its number and, when written, its composition ("Τμήμα 1ο Τριμελές"). Public
     * court structure, kept whole (new gold); v2 captures the number alone, as an ordinary proposal.
     */
    static final PyPattern COURT_CHAMBER_RE =
            PyRegex.compile("\\bΤμήμα\\s+(\\d+[οαη]\\w*(?:\\s+(?:Μονομελές|Τριμελές|Πενταμελές|Επταμελές)\\b)?)",
                    PyRegex.IGNORECASE);

    static final PyPattern DATE_SUFFIX_RE =
            PyRegex.compile("^(.*?)([/\\-])(\\d{2}[/\\-.]\\d{2}[/\\-.]\\d{4})$", 0);

    static final PyPattern DECISION_NUMBER_RE =
            PyRegex.compile("Αριθμ[οό]ς\\s+[Αα]πόφασης\\s*:\\s*\\d+", PyRegex.IGNORECASE);

    /** The decision's place and date line; a one-digit day or month ("Αθήνα, 10-7-2026", "13 /07 /2026") too. */
    static final PyPattern DECISION_PLACE_DATE_RE =
            PyRegex.compile("(?:Αθήνα|Καλλιθέα|Θεσσαλονίκη|Πάτρα|Ηράκλειο|Λάρισα|Βόλος|Ιωάννινα)[,\\s]+\\d{1,2}\\s*[-/.]\\s*\\d{1,2}\\s*[-/.]\\s*\\d{4}", PyRegex.IGNORECASE);

    /** Java only: a cue that names the issuing authority itself, not merely a contact label. */
    static final PyPattern STRONG_AUTHORITY_CUE_RE =
            PyRegex.compile("ΕΛΛΗΝΙΚΗ\\s+ΔΗΜΟΚΡΑΤΙΑ|ΔΙΕΥΘΥΝΣΗ\\s+ΕΠΙΛΥΣΗΣ\\s+ΔΙΑΦΟΡΩΝ|ΥΠΟΔΙΕΥΘΥΝΣΗ\\s+ΕΠΑΝΕΞΕΤΑΣΗΣ",
                    PyRegex.IGNORECASE);

    private static final String CONTACT_LABEL = "(?:Ταχ\\.\\s*Δ/νση|Ταχ\\.\\s*Κ[ωώ]δικας|Τηλέφωνο|Τηλ\\.|Fax|Φαξ|E-?mail)";

    /**
     * Java only: one "label : value" pair of a contact line; several may share a line ("Ταχ. Δ/νση : Φιλαδελφείας
     * 8   Τηλέφωνο : 213…"). Group 1 is the label, group 2 the value, up to the next label or the line's end.
     */
    static final PyPattern CONTACT_PAIR_RE = PyRegex.compile("(?<![Α-Ωα-ωΆ-ώA-Za-z])(" + CONTACT_LABEL
            + ")\\s*:\\s*(.+?)\\s*(?=" + CONTACT_LABEL + "\\s*:|$)", PyRegex.IGNORECASE);

    /** Java only: a line made of contact pairs, starting with a contact label. */
    static final PyPattern CONTACT_LINE_RE = PyRegex.compile("^\\s*" + CONTACT_LABEL + "\\s*:", PyRegex.IGNORECASE);

    /** Java only: an office landline ("213 1312347", "2131312348"); a mobile is never an office line. */
    static final PyPattern LANDLINE_VALUE_RE = PyRegex.compile("2(?:[\\s-]?\\d){9}", 0);

    /** Java only: a postal code with its optional town ("104 40 - Αθήνα", "104 40 Αθήνα"). */
    static final PyPattern AUTHORITY_POSTCODE_VALUE_RE =
            PyRegex.compile("\\d{3}\\s?\\d{2}(?:\\s*(?:-\\s*)?[Α-ΩΆΈΉΊΌΎΏα-ωά-ώ][Α-ΩΆΈΉΊΌΎΏα-ωά-ώ .]{0,30})?", 0);

    /**
     * Java only: a word showing that a paragraph is about a private party (the appeal or the appellant, a
     * residence, a taxpayer, an ΑΦΜ, a seat), so the body has begun and the authority header is over.
     * Word-initial, unlike {@link #PRIVATE_PARTY_CUE_RE}, whose "αδελφ" sits inside the authority's own
     * street ("Φιλαδελφείας").
     */
    static final PyPattern HEADER_END_CUE_RE = PyRegex.compile("(?<![Α-Ωα-ωΆ-ώϊϋΐΰ])(?:προσφεύγ|προσφυγ|κάτοικ"
            + "|κατοίκ|υπόχρε|Α\\.?Φ\\.?Μ\\.?(?![Α-Ωα-ωΆ-ώϊϋΐΰ])|έδρα(?![Α-Ωα-ωΆ-ώϊϋΐΰ]))", PyRegex.IGNORECASE);

    /** The decision's title line, also letter-spaced ("Α Π Ο Φ Α Σ Η"). */
    static final PyPattern DECISION_TITLE_RE =
            PyRegex.compile("Α[ \\t]*Π[ \\t]*Ο[ \\t]*Φ[ \\t]*Α[ \\t]*Σ[ \\t]*Η\\b", 0);

    /**
     * A genitive name WITH its article (the ΔΕΔ convention blanks "του ΔΗΜΗΤΡΙΟΥ" whole); see {@code
     * Detectors.fatherNameSpan}. Group 2 is the cue after it. A street word there is no evidence of a
     * patronymic on its own ("επί της Χ Οδού" names a street): Java then also asks for a person's name
     * right before the article ({@link #PERSON_NAME_BEFORE_RE}).
     */
    static final PyPattern FATHER_NAME_RE =
            PyRegex.compile("\\b((?i:τ(?:ου|ης))\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*)\\s+((?i:με\\s+Α\\.?Φ\\.?Μ\\.?|κάτοικ(?:ος|η|οι)|κατοίκ(?:ου|ων|ους|ης)|οδ(?:ός|ού)|ατομική))", 0);

    /** Java-only: a person's name ending right before a patronymic's article ("ΠΑΠΑΔΟΠΟΥΛΟΣ του ..."). */
    static final PyPattern PERSON_NAME_BEFORE_RE =
            PyRegex.compile("[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+,?\\s+$", 0);

    /**
     * Java-only: a generic party-role phrase ("η προσφεύγουσα εταιρεία", "ο νόμιμος εκπρόσωπος", "η
     * ελεγχόμενη επιχείρηση"). It stands for a party without naming it and can never itself be, or
     * begin, personal data, so it is a hard FIELD_LABEL preserve: a REDACT that swallowed it gives it
     * back, while a proper name next to it is untouched. A closed grammatical class, case-sensitive
     * apart from a sentence-initial capital, so it is no rule about lowercase text in general.
     */
    static final PyPattern PARTY_ROLE_RE =
            PyRegex.compile("(?<![Α-Ωα-ωΆ-ώA-Za-z0-9])(?:[Ππ]ροσφεύγ(?:ων|οντα|οντος|ουσα|ουσας)(?:\\s+(?:εταιρε?ία[ς]?|επιχείρηση[ς]?))?|[Εε]λεγχόμεν(?:η|ης)\\s+(?:επιχείρηση[ς]?|εταιρε?ία[ς]?)|[Νν]όμιμ(?:ος|ου|ο|οι)\\s+εκπρόσωπ(?:ος|ου|ο|οι))(?![Α-Ωα-ωΆ-ώA-Za-z0-9])", 0);

    static final PyPattern FISCAL_ID_RE =
            PyRegex.compile("(?:αριθμ[οό]\\s+μητρώου|ταμειακ[ήη]\\s+(?:μηχαν[ήη]\\s+)?|ΦΗΜ\\s+)([A-ZΑ-Ω0-9*]{2,}[\\s\\-]*[A-ZΑ-Ω0-9*]{2,})", PyRegex.IGNORECASE);

    static final PyPattern INVOICE_CELL_RE =
            PyRegex.compile("\\b(?:ΤΙΜ\\.?|ΤΠΥ|ΔΑ|ΑΠΥ|ΤΔΑ|ΔΕΛΤΙΟ)\\s*[0-9Α-ΩA-Z./-]+(?:\\s*σειρά\\s*[Α-ΩA-Z])?", 0);

    static final PyPattern INVOICE_PARAGRAPH_RE =
            PyRegex.compile("\\b(?:ΤΙΜ\\.?|ΤΠΥ|ΔΑ|ΑΠΥ|ΤΔΑ|ΔΕΛΤΙΟ)\\s*([0-9Α-ΩA-Z./-]+)(?:\\s*σειρά\\s*([Α-ΩA-Z]))?", 0);

    static final PyPattern ISOLATED_ALLCAPS_NAME_RE =
            PyRegex.compile("^[Α-ΩΆΈΉΊΌΎΏΪΫ]+(?:\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ]+){1,3}$", 0);

    /**
     * Toponym after an AUTHORITY cue ("Δήμου Χ", "Πρωτοδικείου Χ", "Εφετείο Χ"): part of a public
     * institution's name, kept (new gold; v2 hard-redacts it). The court cues in the genitive and
     * the nominative/accusative. No Δ.Ο.Υ. cue: the DOU allowlist owns those names. Case-sensitive.
     */
    static final PyPattern LOCALITY_AUTHORITY_RE =
            PyRegex.compile("(?:Δήμ(?:ου|ο|ος)|Πρωτοδικεί(?:ου|ο)|Εφετεί(?:ου|ο)|Δικαστηρίου|Δικαστήριο|Κοινότητ(?:α|ας))\\s+(?:[Α-ΩA-Z][΄’']\\s+)?([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*)", 0);

    /**
     * The words that open a compound Greek place name and can never end one: "Νέα/Νέας", "Άγιος/
     * Αγίας", "Άνω/Κάτω", "Παλαιό", "Μεγάλη/Μικρή", and the compass adjectives ("Δυτικής"). A
     * closed GRAMMATICAL class, not a list of places: it is what lets {@code Detectors.keptPlace}
     * keep a two-word place after an authority cue whole without knowing any particular town.
     * Stored folded ({@link #foldGreek}), so case and accents do not matter.
     */
    static final Set<String> TOPONYM_MODIFIERS = Stream.of(
            "Νέα", "Νέας", "Νέο", "Νέου", "Νέων", "Νέοι",
            "Παλαιά", "Παλαιάς", "Παλαιό", "Παλαιού", "Παλαιών",
            "Άγιος", "Άγιο", "Αγίου", "Άγιοι", "Αγίων", "Αγία", "Αγίας",
            "Άνω", "Κάτω",
            "Μεγάλη", "Μεγάλης", "Μεγάλο", "Μεγάλου", "Μικρή", "Μικρής", "Μικρό", "Μικρού",
            "Βόρεια", "Βόρειας", "Βόρειο", "Βορείου", "Νότια", "Νότιας", "Νότιο", "Νοτίου",
            "Ανατολική", "Ανατολικής", "Ανατολικό", "Ανατολικού", "Δυτική", "Δυτικής", "Δυτικό", "Δυτικού")
            .map(DetectorPatterns::foldGreek).collect(Collectors.toUnmodifiableSet());

    /** Whether {@code word} is a toponym modifier ({@link #TOPONYM_MODIFIERS}), in any case or accenting. */
    static boolean isToponymModifier(String word) {
        return TOPONYM_MODIFIERS.contains(foldGreek(word));
    }

    /** Casefolded with its accents removed, so "ΝΕΑΣ", "Νέας" and "Νεας" compare equal. */
    static String foldGreek(String word) {
        StringBuilder out = new StringBuilder();
        Normalizer.normalize(word, Normalizer.Form.NFD).codePoints()
                .filter(cp -> Character.getType(cp) != Character.NON_SPACING_MARK)
                .forEach(out::appendCodePoint);
        return PyStr.casefold(out.toString());
    }

    /** Place name after a district/area cue: an ordinary proposal (0.85) for pass 2. Case-sensitive. */
    static final PyPattern LOCALITY_CONTEXT_RE =
            PyRegex.compile("(?:συνοικία[ς]?|περιοχή[ς]?)\\s+(?:[Α-ΩA-Z][΄’']\\s+)?([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*)", 0);

    /**
     * Java only: the visible tail of an account number the source already masked with letters X ("XXX 1495",
     * "ΧΧΧ7414", Latin or Greek Χ), value in group 1. Found by the real-model run of 3096, where the model kept
     * them in one run and blanked them in another, and the gold blanks them.
     */
    static final PyPattern MASKED_ACCOUNT_TAIL_RE =
            PyRegex.compile("(?<![A-Za-zΑ-Ωα-ωΆ-ώ0-9])[XΧ]{3,}[  ]?(\\d{3,8})(?![0-9])", 0);

    static final PyPattern PARTIAL_STAR_RE =
            PyRegex.compile("\\b[A-ZΑ-Ω]{2,}\\s*\\*+[0-9A-ZΑ-Ω]+\\b", 0);

    /**
     * A municipality WITH its administrative region after a residence cue, in either accent
     * placement ("κάτοικος", "κατοίκου"): v2's address capture with its residence cues only.
     * Case-sensitive; stops at any comma or the next address cue. Whether the run really ends in a
     * region is decided against {@code regions.txt} in {@code Detectors.detectAppellantIdentity}.
     */
    static final PyPattern RESIDENCE_PLACE_RE =
            PyRegex.compile("(?i:(?:κάτοικ(?:ος|η|οι)|κατοίκ(?:ου|ων|ους|ης))\\s+)([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*)(?=\\s*(?:[.,;)]|$|\\n|και\\b|οδ(?:ός|ού)\\b|Λεωφ|αρ\\.|Τ\\.?Κ\\.?\\b))", 0);

    /**
     * Java's original address capture after a residence cue ("κάτοικος", "κάτοικη") or a street cue
     * ("οδός"/"οδού"/"οδό", "Λεωφ.", "πλατεία"), cues in any case and accenting ("ΟΔΟΣ"). Group 1 is
     * the name ({@link #ADDRESS_NAME}) and, beside v2's capture, the house number written without
     * "αρ." ("οδός Ερμού 5", "επί της οδού ΒΕΛΒΕΝΔΟΥΣ 41"). It stops at the first word, punctuation
     * or label that is not part of the name, so it never takes a following clause, the "αρ." of the
     * number or the "Τ" of a "Τ.Κ." (the number and the postal code are their own spans).
     *
     * <p>Group 2 is a street written after the place with no street cue ("κάτοικος Αθηνών, Πατησίων
     * 12"): a separate span, so a decision to keep the residence locality never meets one wider
     * redaction of both. It needs its house number, which a clause after a comma does not have.
     */
    static final PyPattern PRIVATE_ADDRESS_RE =
            PyRegex.compile("(?<![Α-Ωα-ωΆ-ώϊϋΐΰ])(?i:κ[άα]τοικ(?:ος|η)|οδ(?:[όο]ς|[οό][ύυ]|[όο])|λεωφ(?:όρος|όρου)?\\.?"
                    + "|πλατε[ίι]α[ςσ]?)\\s+(" + ADDRESS_NAME + "(?:" + ADDRESS_GAP + HOUSE_NUMBER + ")?)(?:" + ADDRESS_COMMA
                    + "(" + ADDRESS_NAME + ADDRESS_GAP + HOUSE_NUMBER + "))?", 0);

    /** A street name after a street cue: v2's address capture with its street cues (the residence cues are {@link #RESIDENCE_PLACE_RE}). */
    static final PyPattern STREET_ADDRESS_RE =
            PyRegex.compile("(?i:οδ(?:ός|ού)\\s+|Λεωφ(?:όρος|όρου)?\\.?\\s+|πλατεία[ς]?\\s+)([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:\\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*)(?=\\s*(?:[.,;)]|$|\\n|και\\b|οδ(?:ός|ού)\\b|Λεωφ|αρ\\.|Τ\\.?Κ\\.?\\b))", 0);

    /** A postal code after "Τ.Κ."; the label stays. */
    static final PyPattern POSTAL_CODE_RE =
            PyRegex.compile("\\bΤ\\.?\\s*Κ\\.?\\s*(?:[:.]\\s*)?(\\d{5})\\b", PyRegex.IGNORECASE);

    /**
     * A street number after "αρ." or "αριθ."/"αριθμός" (never a reference serial: those have a slash). Java
     * applies it only directly after a street name, see {@link #STREET_BEFORE_NUMBER_RE}.
     */
    static final PyPattern ADDRESS_NUMBER_RE =
            PyRegex.compile("\\bαρ(?:ιθ(?:μ(?:ός|ού|ό))?)?\\.?\\s*(\\d+[Α-ΩA-Z]?)\\b(?!\\s*[/\\-]\\s*\\d)", PyRegex.IGNORECASE);

    /**
     * Java only: the street name an {@link #ADDRESS_NUMBER_RE} match must follow. v2 applies the number
     * rule anywhere, and "αρ." also abbreviates an article ("του αρ. 9 της …"), which the golds keep.
     * The street is introduced by a street cue in any case and accenting ("ΟΔΟΣ ΕΡΜΟΥ ΑΡ. 5"), or is a
     * business seat's ("με έδρα επί της Ιερά οδού αρ. 101"); its name is {@link #ADDRESS_NAME}'s.
     */
    static final PyPattern STREET_BEFORE_NUMBER_RE =
            PyRegex.compile("(?<![Α-Ωα-ωΆ-ώϊϋΐΰ])(?:(?i:οδ(?:[όο]ς|[οό][ύυ]|[όο])|λεωφ(?:όρος|όρου)?\\.?|πλατε[ίι]α[ςσ]?)"
                    + "|(?i:[έε]δρα" + SEAT_PREPOSITIONS + "))\\s+" + ADDRESS_NAME + "(?:" + ADDRESS_GAP + STREET_TYPE_WORD + ")?"
                    + "\\s*(?:,\\s*)?$", 0);

    /** The appeal cue that makes a following article STRUCTURAL ("προσφυγή του …"), not a patronymic. */
    static final PyPattern APPEAL_CUE_BEFORE_RE =
            PyRegex.compile("προσφυγ\\w*\\s*$", PyRegex.IGNORECASE);

    /** The article in front of a patronymic. */
    static final PyPattern ARTICLE_STRIP =
            PyRegex.compile("^τ(?:ου|ης)\\s+", PyRegex.IGNORECASE);

    // ---- span narrowing (SpanTrim), v2 span_trim

    /** A structural cue at the start of a span, as a whole word, with its separator. */
    static final PyPattern TRIM_CUE_RE =
            PyRegex.compile("^(?:(?:Α\\.?\\s*Φ\\.?\\s*Μ\\.?|AFM|ΑΜΚΑ|AMKA|ΙΒΑΝ|IBAN|Α\\.?\\s*Τ\\.?\\s*Α\\.?\\s*Κ\\.?|Κ\\.?\\s*Α\\.?\\s*Ε\\.?\\s*Κ\\.?|Ο\\.\\s*Τ\\.?|Α\\.?\\s*Χ\\.?\\s*Κ\\.?|Τ\\.?\\s*Κ\\.?|αριθμ[οό]\\s+πρωτοκόλλου|αριθμ?\\.?\\s*πρωτ\\.?|αρ\\.?\\s*πρωτ\\.?|αρ\\.?\\s*πρ\\.(?:\\s*αποστολέα)?|αριθμ[οό]\\s+ειδοποίησης|αρ\\.?\\s*καταχώρισης|αρ\\.|κάτοικ(?:ος|η|οι)|κατοίκ(?:ου|ων|ους|ης)|οδ(?:ός|ού|ό)|Λεωφ(?:όρος|όρου)?\\.?|Ταχ\\.\\s*Δ/νση|Ταχ\\.\\s*Κώδικας|Τηλέφωνο|Τηλ\\.|Fax|Φαξ|E-?mail|Πράξη|Τμήμα|Ημερομηνία|Ημ/νία|Τράπεζα[ς]?|λογ\\.|λογαριασμ[οό]ν?|κ(?:\\.|ον|ου|ο|α)(?![α-ωά-ώ])|Τιμολόγιο|ΤΙΜ\\.|Α/Α|Συναλλαγή|υπ[\u2019'ʼ\u1fbd\u0384.]\\s*αριθ\\w*\\.?|με\\s+αριθμ[οό]|αριθμ[οό]ς?))(?![Α-Ωα-ωΆ-ώA-Za-z0-9])\\s*(?:[:.\\-]\\s*)?", PyRegex.IGNORECASE);

    /** Java adds "επί" with the article it governs ("επί της"), stripped as one unit; an article alone never is. */
    static final PyPattern LEADING_PREPOSITION_RE =
            PyRegex.compile("^(?:επί(?:\\s+τ(?:ης|ου|ων|ην|ον))?|με|και|στο|στη|στην|στον|στα|σε|απ[όο]|για|προς|υπ[\u2019'ʼ\u1fbd\u0384])(?![α-ωά-ώ])\\s*", PyRegex.IGNORECASE);

    /**
     * Java-only: the words that introduce a company's or a bank's name ("με την επωνυμία", "δ.τ.",
     * "Τράπεζα", "εταιρεία"). Nouns of the sentence that can never be the first word of a name, so
     * the only cue SpanTrim takes off a span in a name category.
     */
    static final PyPattern NAME_CUE_RE =
            PyRegex.compile("^(?:(?:(?:με|υπό)\\s+)?(?:την\\s+)?επωνυμία|δ\\.\\s*τ\\.|Τράπεζα[ς]?|εταιρε?ία[ς]?)(?![Α-Ωα-ωΆ-ώA-Za-z0-9])\\s*(?:[:.\\-]\\s*)?", PyRegex.IGNORECASE);

    // A digit, or a capital O (Greek or Latin) typed in its place ("2Ο26"), as the source documents
    // do. SpanTrim also asks for real digits in whatever these match. Java also gives back a date
    // introduced by a word ("1234 της 18-3-2011"): it dates the document, it does not identify it.
    static final PyPattern TRAILING_REFERENCE_DATE_RE =
            PyRegex.compile("(?:\\s*[/\\-]\\s*|\\s+(?:της|του|από|με\\s+ημερομηνία)\\s+)[0-9ΟO]{1,2}[/\\-.][0-9ΟO]{1,2}[/\\-.][0-9ΟO]{4}$", 0);

    static final PyPattern TRAILING_YEAR_RE =
            PyRegex.compile("\\s*/\\s*(?:19|2[0ΟO])[0-9ΟO]{2}$", 0);

    /**
     * Java only, matched right after a reference REDACT that ends in a digit: the rest of a multi-part serial,
     * "/1/9871" in "11010705/1/9871/15.09.2022", "/5696634" in "1/5696634 προσωρινό", "/Ο/1109" in
     * "863/Ο/1109-2024" (a letter O for a zero, as typed). Slash-separated digit groups, none of them a four-digit
     * year, up to where the reference ends: its own date or year (which stays visible), or the end of the
     * serial. Never when what follows is itself a slash date ("/15/09/2022"), whose day and month would
     * otherwise be taken for serial parts.
     */
    static final PyPattern SERIAL_CONTINUATION_RE = PyRegex.compile("(?!/[0-9ΟO]{1,2}/[0-9ΟO]{1,2}/[0-9ΟO]{4})"
            + "(?:/(?!(?:19|2[0ΟO])[0-9ΟO]{2}(?![0-9ΟO]))[0-9ΟO]{1,10}){1,4}?(?:(?=[/\\-](?:[0-9ΟO]{1,2}[/\\-.]"
            + "[0-9ΟO]{1,2}[/\\-.][0-9ΟO]{4}|(?:19|2[0ΟO])[0-9ΟO]{2})(?![0-9ΟO/]|[.\\-][0-9ΟO]))|(?![0-9ΟO]|[/\\-.,][0-9ΟO]))",
            0);

    /** A reference serial: four or more digits, nothing else. */
    static final PyPattern SERIAL_TOKEN_RE = PyRegex.compile("^\\d{4,}$", 0);

    /**
     * The fixed parts of a composite protocol reference: an issuing unit's code ("ΔΕΔ", "ΕΛ.ΚΕ.1",
     * "ΑΤ", "ΔΑ"; at most three capitals per dotted segment, so an ordinary word cannot pass for one),
     * its ordinal, a register code with or without its year ("ΕΞ", "ΕΙ2024"), a year, a type code
     * ("ΕΜΠ"), a lone slash. Never the serial.
     */
    static final PyPattern REFERENCE_CODE_TOKEN_RE =
            PyRegex.compile("^(?:[Α-ΩA-Z]{1,3}(?:\\.[Α-ΩA-Z]{1,3})*\\.?\\d{0,2}|\\d{1,2}|(?:ΕΞ|ΕΙ)?(?:19|2[0ΟO])[0-9ΟO]{2}|/)$", 0);

    /** Java also accepts the abbreviation ("αριθ. ειδοποίησης"). */
    static final PyPattern NOTICE_CUE_BEFORE_RE =
            PyRegex.compile("αριθ(?:μ[οό]|\\.)\\s*ειδοποίησης\\s*(?:[:.]\\s*)?$", PyRegex.IGNORECASE);

    static final PyPattern PRIVATE_PARTY_CUE_RE =
            PyRegex.compile("προσφεύγ|υπόχρε|ΑΦΜ|κάτοικ|έδρα|δικαιούχ|πατέρ|αδελφ|σύζυγ|λογαριασμ", PyRegex.IGNORECASE);

    /**
     * POSITIVE evidence that a date is procedural, and nothing weaker: PROCEDURAL_DATE is
     * hard-preserved, so "no birth cue nearby" can never qualify a date.
     */
    static final PyPattern PROCEDURAL_DATE_CUE_RE =
            PyRegex.compile("(?:ημερομηνία\\s+κατάθεσης|ημερομηνία\\s+έκδοσης|εκδόθηκε\\s+στις|κοινοποιήθηκε\\s+στις)\\s*(?:[:.]\\s*)?$", PyRegex.IGNORECASE);

    /** How far back of a date the procedural cue may end: one short clause. */
    static final int PROCEDURAL_DATE_WINDOW = 40;

    static final PyPattern SIGNATURE_TITLE_RE =
            PyRegex.compile("Ακριβ[εέ]ς\\s+[Αα]ντίγραφο|ΜΕ\\s+ΕΝΤΟΛΗ|Με\\s+εντολή|Ο\\s+ΠΡΟΪΣΤΑΜΕΝΟΣ|Η\\s+ΠΡΟΪΣΤΑΜΕΝΗ|Ο\\s+ΔΙΕΥΘΥΝΤΗΣ|Η\\s+ΔΙΕΥΘΥΝΤΡΙΑ|Υποδιεύθυνσης\\s+Επανεξέτασης|Διοικητικής\\s+Υποστήριξης", PyRegex.IGNORECASE);

    // ---- the official signatory and the name lists (Detectors 14 and 16)

    /**
     * A signing official's title, on FOLDED text: the head or deputy head of a unit, the employee who
     * certifies the copy, "by order of". Only opens a signature block; never a span.
     */
    static final PyPattern SIGNATORY_TITLE_RE = PyRegex.compile(
            "(?<![\\p{L}\\p{M}])(?:προισταμεν|αναπληρωτ|διευθυντ|υποδιευθυντ|υπαλληλ|με\\s+εντολη|ακριβεσ\\s+αντιγραφο)");

    /**
     * What makes a line of a signature block the title's continuation rather than a name, on FOLDED
     * text: an article, a unit's or an authority's word, a digit, a slash ("Δ/ΝΣΗΣ", "Α4").
     */
    static final PyPattern SIGNATORY_BLOCK_WORD_RE = PyRegex.compile(
            "(?<![\\p{L}\\p{M}])(?:τησ|του|των|τμημ|διευθυνσ|υποδιευθυνσ|επανεξετασ|επιλυσ|διαφορ|διοικητικ|υποστηριξ"
                    + "|αυτοτελ|ελεγχ|φορολογ|κεντρ|περιφερ|ααδε|α\\.α\\.δ\\.ε)|\\d|/");

    /** A name on a line of its own: two to four words, each with a capital first letter. */
    static final PyPattern SIGNATORY_NAME_RE = PyRegex.compile(
            "^[A-ZΑ-ΩΆΈΉΊΌΎΏΪΫ][\\p{L}\\p{M}'’.\\-]*(?:[ \\u00a0\\t]+[A-ZΑ-ΩΆΈΉΊΌΎΏΪΫ][\\p{L}\\p{M}'’.\\-]*){1,3}$");

    /** A word of two or more letters with a capital first letter (Greek or Latin), as a whole word. */
    static final PyPattern CAPITALISED_WORD_RE = PyRegex.compile(
            "(?<![\\p{L}\\p{M}\\p{N}_])[A-ZΑ-ΩΆΈΉΊΌΎΏΪΫ][\\p{L}\\p{M}]+(?![\\p{L}\\p{M}\\p{N}_])");

    /** A person's-name context: a name field or column ("Ονοματεπώνυμο", "Επώνυμο", "Όνομα") or an honorific. */
    static final PyPattern NAME_CONTEXT_RE = PyRegex.compile(
            "(?i:ονοματεπώνυμ\\w*|ονοματεπωνυμ\\w*|επώνυμο\\w*|επωνυμο\\w*|όνομα\\b|ονομα\\b|ονόματι)|\\bκ(?:\\.|ου\\b|ας\\b)",
            0);

    private DetectorPatterns() {
    }

    private static Map<String, String> orderedSpec(String... keyValues) {
        Map<String, String> spec = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            spec.put(keyValues[i], keyValues[i + 1]);
        }
        return java.util.Collections.unmodifiableMap(spec);
    }
}
