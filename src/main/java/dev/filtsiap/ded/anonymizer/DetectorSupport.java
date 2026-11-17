package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pure helpers shared by the deterministic detectors (port of {@code detector_support.py}).
 * Regex constants live in {@link DetectorPatterns}; everything data-driven arrives via
 * {@link DetectorRules}.
 */
public final class DetectorSupport {

    private static final Map<String, PyPattern> CACHE = new ConcurrentHashMap<>();
    private static final PyPattern SPACE_OR_HYPHEN_RUN = PyRegex.compile("[\\s-]+");
    private static final PyPattern YEAR_SUFFIX_RE = PyRegex.compile("^(.*?\\S)\\s*/\\s*((?:19|20)\\d{2})$");

    private DetectorSupport() {
    }

    /** Compiles with a cache, like Python's {@code re} module cache for string patterns. */
    static PyPattern compile(String pattern, int flags) {
        return CACHE.computeIfAbsent(flags + ":" + pattern, k -> PyRegex.compile(pattern, flags));
    }

    // ------------------------------------------------------------------ pattern resolution

    /** The {@code body} regex for {@code name}: rules override, else the built-in default. */
    static String body(DetectorRules rules, String name) {
        Map<String, String> override = rules.patterns().getOrDefault(name, Map.of());
        String fallback = DetectorPatterns.DEFAULT_PATTERNS.get(name).get("body");
        return override.getOrDefault("body", fallback);
    }

    /** The {@code prefix} regex for {@code name}, defaulting to empty. */
    static String prefix(DetectorRules rules, String name) {
        Map<String, String> override = rules.patterns().getOrDefault(name, Map.of());
        String fallback = DetectorPatterns.DEFAULT_PATTERNS.get(name).getOrDefault("prefix", "");
        return override.getOrDefault("prefix", fallback);
    }

    /**
     * Case-insensitive matches of every gazetteer entry, longest entries first. Python orders
     * equal-length entries by set iteration (hash-seed dependent); here they are ordered by code
     * point so the output is stable.
     */
    static List<PyMatch> allowlistMatches(String text, Collection<String> entries) {
        return allowlistMatches(text, entries, false);
    }

    /** Legal dotted prefixes may precede their reference number without intervening whitespace. */
    static List<PyMatch> allowlistMatches(String text, Collection<String> entries, boolean legalPrefixes) {
        List<String> ordered = new ArrayList<>(entries);
        ordered.sort(Comparator.comparingInt((String e) -> -PyStr.len(e)).thenComparing(PyStr.CODE_POINT_ORDER));
        List<PyMatch> matches = new ArrayList<>();
        for (String entry : ordered) {
            if (entry.isEmpty()) {
                continue;
            }
            // Punctuation inside a gazetteer entry is literal; its outside edges must not
            // grant hard authority to part of a longer identifier or a decomposed word.
            String right = legalPrefixes && entry.endsWith(".") ? "(?![\\p{L}\\p{M}_])"
                    : "(?![\\p{L}\\p{M}\\p{N}_])";
            matches.addAll(compile("(?<![\\p{L}\\p{M}\\p{N}_])" + PyRegex.escape(entry)
                    + right, PyRegex.IGNORECASE).finditer(text));
        }
        return matches;
    }

    // ------------------------------------------------------------------ phrase families

    /** Whole words only: no letter, combining mark, digit or underscore may touch either edge. */
    private static final String WORD_EDGE_BEFORE = "(?<![\\p{L}\\p{M}\\p{N}_])";
    private static final String WORD_EDGE_AFTER = "(?![\\p{L}\\p{M}\\p{N}_])";
    /** One written space in a family pattern: bounded whitespace (a tab between header columns included). */
    private static final String FAMILY_SPACE = "(?:\\s{1,3})";
    /** Combining marks after a letter: a class, since the regex translator reads a bare {@code \p{..}} brace as literal. */
    private static final String MARKS = "[\\p{M}]*";
    /**
     * What may stand before a LABEL on its line, once stripped: list numbering, a bullet, an opening
     * quote, or nothing. Applied to stripped text and bounded, so a long whitespace run costs linear time.
     */
    private static final PyPattern LABEL_LEAD_RE =
            PyRegex.compile("(?:(?:\\d{1,2}|[a-zα-ω])[.)])?(?:\\s{0,3}[«\"'(•–\\-])?");
    /** What may follow a LABEL on its line, once stripped, when no colon follows it: closing punctuation only. */
    private static final String LABEL_TAIL_CHARS = ".»\"')";

    /**
     * Compiles one family pattern written FOLDED (lowercase, no accents, σ for every sigma) into the
     * regex that runs on {@code GreekFold}-folded text: every letter and character class may be
     * followed by combining marks (a decomposed accent survives folding as a mark of its own), every
     * space is bounded whitespace, and the whole is held to word edges. Inline flags, named groups and
     * multi-character escapes are refused: they would not survive the rewrite.
     *
     * @return the compiled pattern and how many capturing groups it has
     * @throws IllegalArgumentException with the reason, for a pattern that is not a valid family pattern
     */
    static Map.Entry<PyPattern, Integer> compileFamilyPattern(String folded) {
        StringBuilder out = new StringBuilder();
        int groups = 0;
        boolean inClass = false;
        int[] cps = folded.codePoints().toArray();
        for (int i = 0; i < cps.length; i++) {
            int cp = cps[i];
            if (cp == '\\') {
                if (i + 1 >= cps.length) {
                    throw new IllegalArgumentException("dangling backslash");
                }
                int next = cps[++i];
                if (next == 'p' || next == 'P' || next == 'N' || next == 'k' || next == 'x' || next == 'u'
                        || Character.isDigit(next)) {
                    throw new IllegalArgumentException("escape \\" + Character.toString(next) + " is not allowed");
                }
                out.append('\\').appendCodePoint(next);
                continue;
            }
            if (inClass) {
                out.appendCodePoint(cp);
                if (cp == ']' && cps[i - 1] != '[' && !(cps[i - 1] == '^' && cps[i - 2] == '[')) {
                    out.append(MARKS).append(')');
                    inClass = false;
                } else if (Character.isLetter(cp)) {
                    requireFolded(cp);
                }
                continue;
            }
            if (cp == '[') {
                out.append("(?:[");
                inClass = true;
            } else if (cp == '(') {
                if (i + 1 < cps.length && cps[i + 1] == '?') {
                    int kind = i + 2 < cps.length ? cps[i + 2] : -1;
                    if (kind != ':' && kind != '=' && kind != '!') {
                        throw new IllegalArgumentException("only (?:, (?= and (?! groups are allowed");
                    }
                } else {
                    groups++;
                }
                out.append('(');
            } else if (cp == ' ') {
                out.append(FAMILY_SPACE);
            } else if (Character.isLetter(cp)) {
                requireFolded(cp);
                out.append("(?:").appendCodePoint(cp).append(MARKS).append(')');
            } else {
                out.appendCodePoint(cp);
            }
        }
        if (inClass) {
            throw new IllegalArgumentException("unclosed character class");
        }
        return Map.entry(PyRegex.compile(WORD_EDGE_BEFORE + "(?:" + out + ")" + WORD_EDGE_AFTER), groups);
    }

    private static void requireFolded(int cp) {
        String one = Character.toString(cp);
        if (!dev.filtsiap.ded.anonymizer.chat.GreekFold.fold(one).equals(one)) {
            throw new IllegalArgumentException("letter '" + one + "' is not folded (write lowercase, unaccented, σ)");
        }
    }

    /**
     * A unit's text as the phrase families read it: folded by {@code GreekFold} (case, accents, final
     * sigma; one code point for one), with a line break put back between two of its paragraphs (a
     * table cell joins its paragraphs with nothing, so "ΤμήματοςΔιοικητικής" would otherwise be one
     * word). {@code toUnit[v]} is the unit offset of view position {@code v}: an inserted break maps
     * to the first character after it, and {@code toUnit[length]} is the unit's length.
     */
    record MatchView(String text, int[] toUnit) {
    }

    static MatchView matchView(TextUnit unit) {
        String text = unit.normalizedText();
        String folded = dev.filtsiap.ded.anonymizer.chat.GreekFold.fold(text);
        int n = PyStr.len(text);
        boolean mapped = unit.charMap().size() == n;
        StringBuilder view = new StringBuilder(folded.length() + 8);
        List<Integer> toUnit = new ArrayList<>(n + 8);
        String paragraph = null;
        int i = 0;
        for (int offset = 0; offset < folded.length(); i++) {
            int cp = folded.codePointAt(offset);
            offset += Character.charCount(cp);
            if (mapped) {
                String here = paragraphOf(unit.charMap().get(i));
                if (paragraph != null && !here.equals(paragraph)) {
                    view.append('\n');
                    toUnit.add(i);
                }
                paragraph = here;
            }
            view.appendCodePoint(cp);
            toUnit.add(i);
        }
        toUnit.add(n);
        return new MatchView(view.toString(), toUnit.stream().mapToInt(Integer::intValue).toArray());
    }

    /** A character's paragraph: its XML path without the run and the text node. */
    static String paragraphOf(XmlCharRef ref) {
        String path = ref.textNodePath();
        int last = path.lastIndexOf('/');
        int run = last > 0 ? path.lastIndexOf('/', last - 1) : -1;
        return run > 0 ? path.substring(0, run) : path;
    }

    /**
     * The spans one phrase family draws in {@code unit}: the whole match, or, for a composite
     * reference, the match without its variable group 1 (each remaining side trimmed of whitespace),
     * found in the unit's {@link MatchView} and mapped back to the unit's own offsets.
     */
    static List<Span> familySpans(TextUnit unit, MatchView view, DetectorRules.PreserveFamily family) {
        List<Span> spans = new ArrayList<>();
        String text = unit.normalizedText();
        int[] at = view.toUnit();
        for (PyMatch m : family.pattern().finditer(view.text())) {
            if (family.scope() == DetectorRules.Scope.LABEL && !standsAsLabel(view.text(), m.start(), m.end())) {
                continue;
            }
            List<int[]> pieces = new ArrayList<>();
            if (family.variable() && m.start(1) >= 0) {
                pieces.add(new int[] {at[m.start()], at[m.start(1)]});
                pieces.add(new int[] {at[m.end(1)], at[m.end()]});
            } else {
                pieces.add(new int[] {at[m.start()], at[m.end()]});
            }
            for (int[] piece : pieces) {
                int start = piece[0];
                int end = piece[1];
                while (start < end && PyUnicode.isSpace(PyStr.codePointAt(text, start))) {
                    start++;
                }
                while (end > start && PyUnicode.isSpace(PyStr.codePointAt(text, end - 1))) {
                    end--;
                }
                if (start < end) {
                    spans.add(makeSpan(unit, start, end, family.category(), "phrase_family:" + family.name(), 1.0,
                            SpanAction.PRESERVE, "Structural phrase family " + family.name()));
                }
            }
        }
        return spans;
    }

    /** Whether {@code [start, end)} is its line's label: alone on it, or first on it before a colon. */
    private static boolean standsAsLabel(String folded, int start, int end) {
        int lineStart = PyStr.rfind(folded, "\n", 0, start) + 1;
        int newline = PyStr.find(folded, "\n", end);
        int lineEnd = newline < 0 ? PyStr.len(folded) : newline;
        String lead = PyStr.strip(PyStr.slice(folded, lineStart, start));
        if (!lead.isEmpty() && LABEL_LEAD_RE.fullmatch(lead) == null) {
            return false;
        }
        String tail = PyStr.strip(PyStr.slice(folded, end, lineEnd));
        return tail.startsWith(":") || tail.chars().allMatch(c -> LABEL_TAIL_CHARS.indexOf(c) >= 0);
    }

    // ------------------------------------------------------------------ span construction

    /** Every rule-engine span is built here, so this is where deterministic origin is declared. */
    static Span makeSpan(TextUnit unit, int start, int end, SpanCategory category, String detector,
                         double confidence, SpanAction action, String reason) {
        return new Span(unit.unitId(), start, end, PyStr.slice(unit.normalizedText(), start, end),
                category, detector, confidence, action, reason, SpanOrigin.DETERMINISTIC);
    }

    /** One span per full match; {@code flags} is used only for string patterns (default IGNORECASE). */
    static List<Span> regexSpans(TextUnit unit, String regex, SpanCategory category, String detector,
                                 double confidence, SpanAction action, String reason, int flags) {
        return regexSpans(unit, compile(regex, flags), category, detector, confidence, action, reason);
    }

    static List<Span> regexSpans(TextUnit unit, String regex, SpanCategory category, String detector,
                                 double confidence, SpanAction action, String reason) {
        return regexSpans(unit, regex, category, detector, confidence, action, reason, PyRegex.IGNORECASE);
    }

    static List<Span> regexSpans(TextUnit unit, PyPattern compiled, SpanCategory category, String detector,
                                 double confidence, SpanAction action, String reason) {
        List<Span> spans = new ArrayList<>();
        for (PyMatch m : compiled.finditer(unit.normalizedText())) {
            spans.add(makeSpan(unit, m.start(), m.end(), category, detector, confidence, action, reason));
        }
        return spans;
    }

    /** One span per capture group; non-participating, empty or missing groups are skipped. */
    static List<Span> captureSpans(TextUnit unit, String pattern, int group, SpanCategory category,
                                   String detector, double confidence, SpanAction action, String reason) {
        return captureSpans(unit, compile(pattern, PyRegex.IGNORECASE), group, category, detector,
                confidence, action, reason);
    }

    static List<Span> captureSpans(TextUnit unit, PyPattern compiled, int group, SpanCategory category,
                                   String detector, double confidence, SpanAction action, String reason) {
        List<Span> spans = new ArrayList<>();
        for (PyMatch m : compiled.finditer(unit.normalizedText())) {
            int gs;
            int ge;
            try {
                gs = m.start(group);
                ge = m.end(group);
            } catch (IndexOutOfBoundsException noSuchGroup) {
                continue;
            }
            if (0 <= gs && gs < ge) {
                spans.add(makeSpan(unit, gs, ge, category, detector, confidence, action, reason));
            }
        }
        return spans;
    }

    // ------------------------------------------------------------------ validators

    /**
     * Greek AFM: nine digits; power-of-two weighted checksum mod 11 mod 10 equals the last digit.
     *
     * @param value the candidate, ASCII digits
     * @return true when {@code value} is a valid AFM
     */
    public static boolean validAfm(String value) {
        return PostcheckSupport.afmChecksumOk(value);
    }

    /**
     * AMKA: 11 digits whose leading DDMMYY is a real birth date between 1900 and this year.
     *
     * @param value the candidate, ASCII digits
     * @return true when the digits are 11 and the date part is plausible
     */
    public static boolean validAmkaBirthDate(String value) {
        return validAmkaBirthDate(value, LocalDate.now().getYear());
    }

    static boolean validAmkaBirthDate(String value, int currentYear) {
        if (PyStr.len(value) != 11 || !PyStr.isDigit(value)) {
            return false;
        }
        int day;
        int month;
        int yearSuffix;
        try {
            day = PyStr.parseDecimal(PyStr.slice(value, 0, 2));
            month = PyStr.parseDecimal(PyStr.slice(value, 2, 4));
            yearSuffix = PyStr.parseDecimal(PyStr.slice(value, 4, 6));
        } catch (NumberFormatException e) {
            return false;
        }
        int currentSuffix = currentYear % 100;
        int year = yearSuffix <= currentSuffix ? 2000 + yearSuffix : 1900 + yearSuffix;
        if (year < 1900 || year > currentYear) {
            return false;
        }
        try {
            LocalDate.of(year, month, day);
        } catch (DateTimeException e) {
            return false;
        }
        return true;
    }

    /** IBAN validity after removing spaces/hyphens and upper-casing. */
    static boolean ibanIsValid(String value) {
        return Iban.isValid(PyStr.upper(SPACE_OR_HYPHEN_RUN.subLiteral("", value)));
    }

    // ------------------------------------------------------------------ text helpers

    /** A serial number with a trailing date. */
    record SerialDate(String serial, String date) {
    }

    /** Splits "serial/date" or "serial-date"; null when the structure is ambiguous. */
    static SerialDate splitSerialDate(String value) {
        PyMatch m = DetectorPatterns.DATE_SUFFIX_RE.match(PyStr.strip(value));
        if (m != null && !PyStr.strip(m.group(1), "/\\-").isEmpty()) {
            return new SerialDate(m.group(1), m.group(3));
        }
        return null;
    }

    /**
     * Splits a bare trailing "/YYYY" off a serial ("34519/2026"); null when there is none. Only
     * the detectors whose ΔΕΔ convention keeps the year visible use this.
     */
    static SerialDate splitYearSuffix(String value) {
        PyMatch m = YEAR_SUFFIX_RE.match(PyStr.strip(value));
        return m != null ? new SerialDate(m.group(1), m.group(2)) : null;
    }

    /** Whitespace collapsed to single spaces, then casefolded: for table-header comparison. */
    static String normalizeHeader(String value) {
        return PyStr.casefold(PyStr.collapseWhitespace(value));
    }
}
