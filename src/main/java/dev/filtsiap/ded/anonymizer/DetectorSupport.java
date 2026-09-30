package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
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
final class DetectorSupport {

    private static final Map<String, PyPattern> CACHE = new ConcurrentHashMap<>();
    private static final PyPattern SPACE_OR_HYPHEN_RUN = PyRegex.compile("[\\s-]+");

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
        List<String> ordered = new ArrayList<>(entries);
        ordered.sort(Comparator.comparingInt((String e) -> -PyStr.len(e)).thenComparing(PyStr.CODE_POINT_ORDER));
        List<PyMatch> matches = new ArrayList<>();
        for (String entry : ordered) {
            if (entry.isEmpty()) {
                continue;
            }
            matches.addAll(compile(PyRegex.escape(entry), PyRegex.IGNORECASE).finditer(text));
        }
        return matches;
    }

    // ------------------------------------------------------------------ span construction

    static Span makeSpan(TextUnit unit, int start, int end, SpanCategory category, String detector,
                         double confidence, SpanAction action, String reason) {
        return new Span(unit.unitId(), start, end, PyStr.slice(unit.normalizedText(), start, end),
                category, detector, confidence, action, reason);
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

    /** Greek AFM: nine digits; power-of-two weighted checksum mod 11 mod 10 equals the last digit. */
    static boolean validAfm(String value) {
        return PostcheckSupport.afmChecksumOk(value);
    }

    /** AMKA: 11 digits whose leading DDMMYY is a real birth date between 1900 and this year. */
    static boolean validAmkaBirthDate(String value) {
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

    /** Whitespace collapsed to single spaces, then casefolded: for table-header comparison. */
    static String normalizeHeader(String value) {
        return PyStr.casefold(PyStr.collapseWhitespace(value));
    }
}
