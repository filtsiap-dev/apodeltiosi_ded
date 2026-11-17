package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Narrowing for REDACT spans the LLM produced (port of {@code span_trim.py}). The prompt asks pass 2
 * to quote the value and not the label in front of it; this holds whatever comes back to that rule,
 * so the PLAN records what was actually redacted.
 *
 * <p>ONLY EVER NARROWS: every result is a sub-range of the span given, or null. That is not the
 * same as being safe, since narrowing a span that was right publishes what it gives up. Two guards
 * are therefore load-bearing: a cue counts only as a whole word ({@code TRIM_CUE_RE} carries the
 * boundary), and no structural label is trimmed from a span in a NAME category ("Ιβάν" is a name,
 * "ΙΒΑΝ" a label). A name category gives back only the words that introduce a name ("με την
 * επωνυμία", "Τράπεζα"; Java-only), which can never be its first word.
 *
 * <p>ONE DELIBERATE DIFFERENCE FROM v2, in the region step: a region is given back only when it is
 * a whole word, preceded by whitespace or a comma. v2 compares the tail of the span to each region
 * with no boundary, so a synthetic surname such as "Παπακρήτης" narrows to "Παπα" and publishes
 * "κρήτης". Regions are also tried longest first, so the result never depends on set order.
 */
public final class SpanTrim {

    /**
     * Reference categories: the ΔΕΔ convention keeps a trailing "/YYYY" or date visible, and a
     * composite protocol reference gives up only its serial. A closed list (Java adds the act and
     * invoice numbers to v2's).
     */
    static final Set<SpanCategory> YEAR_SUFFIX_CATEGORIES = EnumSet.of(SpanCategory.PROTOCOL_NUMBER,
            SpanCategory.AUDIT_ORDER, SpanCategory.CHALLENGED_ACT_NUMBER, SpanCategory.CASE_REF_NUMBER,
            SpanCategory.CASE_COURT_REFERENCE, SpanCategory.ACT_NUMBER, SpanCategory.INVOICE_NUMBER,
            SpanCategory.INVOICE_TABLE_ID);

    /**
     * Spans whose content IS a name: no structural label is ever trimmed from them, only edge
     * punctuation and the words that introduce a name ({@code NAME_CUE_RE}).
     */
    static final Set<SpanCategory> NAME_CATEGORIES = EnumSet.of(SpanCategory.POSSIBLE_PERSON,
            SpanCategory.POSSIBLE_COMPANY, SpanCategory.APPELLANT_NAME, SpanCategory.FATHER_NAME,
            SpanCategory.PRIVATE_BENEFICIARY, SpanCategory.PRIVATE_COMPANY_NAME, SpanCategory.OFFICIAL_SIGNATORY);

    private static final PyPattern TOKEN_RE = PyRegex.compile("\\S+");

    /** Punctuation a model's quote picks up from the sentence, not the value. */
    static final String EDGE_CHARS = " \t\n\r.,;:·()[]{}«»\"'’‚“”/-–—";

    private SpanTrim() {
    }

    /**
     * The narrowed {@code [start, end)} of a REDACT span in {@code unitText}, or null when nothing is
     * left. The unit is the authority on what sits at the offsets; the model's quote is never read.
     * In order: edge punctuation; leading prepositions and structural cues (a name category: only the
     * words that introduce a name), repeatedly; a trailing full date (any category but a name or a
     * date) or year (reference categories and a notice number); the lone serial of a composite
     * protocol reference; a trailing administrative region. One step widens instead: a reference that
     * stopped inside its multi-part serial takes the serial's remaining parts ({@link
     * DetectorPatterns#SERIAL_CONTINUATION_RE}).
     */
    public static int[] narrowRedaction(String unitText, int start, int end, SpanCategory category,
                                        Set<String> regions) {
        int length = PyStr.len(unitText);
        start = Math.max(0, Math.min(length, start));
        end = Math.max(0, Math.min(length, end));
        if (start >= end) {
            return null;
        }
        String text = PyStr.slice(unitText, start, end);

        // 1. edges
        String stripped = lstrip(text, EDGE_CHARS);
        start += PyStr.len(text) - PyStr.len(stripped);
        text = rstrip(stripped, EDGE_CHARS);
        end = start + PyStr.len(text);
        if (text.isEmpty()) {
            return null;
        }

        // 2. leading prepositions and structural cues, until neither matches. They stack ("με
        // Α.Φ.Μ. 123456789"); bounded so a pattern that can match empty cannot spin.
        boolean isName = NAME_CATEGORIES.contains(category);
        for (int round = 0; round < 4; round++) {
            PyMatch m = DetectorPatterns.LEADING_PREPOSITION_RE.match(text);
            if (m != null && isName) {
                // Capitalised, the word is not doing a preposition's job: it begins the name.
                String word = PyStr.strip(m.group());
                if (!word.isEmpty() && !word.equals(PyStr.lower(word))) {
                    m = null;
                }
            }
            if (m == null && !isName) {
                m = DetectorPatterns.TRIM_CUE_RE.match(text);
            } else if (m == null) {
                m = DetectorPatterns.NAME_CUE_RE.match(text);
            }
            if (m == null || m.end() == 0) {
                break;
            }
            if (m.end() >= PyStr.len(text)) {
                return null; // nothing BUT a cue: there is no value in it to redact
            }
            start += m.end();
            text = PyStr.sliceFrom(text, m.end());
            stripped = lstrip(text, EDGE_CHARS);
            start += PyStr.len(text) - PyStr.len(stripped);
            text = stripped;
            end = start + PyStr.len(text);
            if (text.isEmpty()) {
                return null;
            }
        }

        // 3. the date or year a reference number keeps. PROPERTY_ID is not a reference category
        // ("Α.Χ.Κ. 76/19062" is a serial), but a notice number is, and only the cue in front says so.
        boolean keepsSuffix = YEAR_SUFFIX_CATEGORIES.contains(category) || (category == SpanCategory.PROPERTY_ID
                && DetectorPatterns.NOTICE_CUE_BEFORE_RE.search(PyStr.slice(unitText, 0, start)) != null);
        // Java-only: a FULL date after a value dates its document in any category that is neither a
        // name nor a date, whatever the model called it; a bare year is given back for references only.
        boolean keepsDate = keepsSuffix || !(isName || category == SpanCategory.DATE
                || category == SpanCategory.PROCEDURAL_DATE || category == SpanCategory.FISCAL_PERIOD);
        for (var tailRe : List.of(DetectorPatterns.TRAILING_REFERENCE_DATE_RE, DetectorPatterns.TRAILING_YEAR_RE)) {
            if (!(tailRe == DetectorPatterns.TRAILING_YEAR_RE ? keepsSuffix : keepsDate)) {
                continue;
            }
            PyMatch tail = tailRe.search(text);
            // The patterns accept a letter O for a zero; three real digits keep them dates and years.
            if (tail != null && tail.start() > 0 && tail.group().chars().filter(Character::isDigit).count() >= 3) {
                end = start + tail.start();
                text = PyStr.slice(text, 0, tail.start());
            }
        }

        // 3b. A composite protocol reference ("ΔΕΔ 123456 ΕΞ 2026 ΕΜΠ") gives up only its serial: every
        // other whole token must be an issuing-unit, register or type code, or a year, and exactly one
        // token may be the serial; anything else leaves the span as it is.
        if (YEAR_SUFFIX_CATEGORIES.contains(category)) {
            int[] serial = loneSerial(text);
            if (serial != null) {
                end = start + serial[1];
                start += serial[0];
                text = PyStr.slice(text, serial[0], serial[1]);
            }
        }

        // 3c. Java-only, the one step that can WIDEN the span: a reference REDACT that stopped short of its own
        // serial ("11010705" of "11010705/1/9871/15.09.2022" in 3127, "1" of "1/5696634" in 3096, both found by the
        // real-model runs) takes the serial's remaining slash-separated parts, up to where the serial ends or the
        // date or year that ends the reference (which stays visible).
        if (YEAR_SUFFIX_CATEGORIES.contains(category) && end < length
                && Character.isDigit(PyStr.codePointAt(unitText, end - 1))) {
            PyMatch more = DetectorPatterns.SERIAL_CONTINUATION_RE.match(PyStr.sliceFrom(unitText, end));
            if (more != null) {
                end += PyStr.len(more.group());
                text = PyStr.slice(unitText, start, end);
            }
        }

        // 4. the administrative region a span may not take with the municipality.
        int giveBack = trailingRegion(text, regions);
        if (giveBack > 0) {
            end -= giveBack;
        }
        if (start >= end) {
            return null;
        }
        return new int[] {start, end};
    }

    /**
     * The {@code [start, end)} of the one serial token in a composite reference, or null when the
     * text is a single token, holds no serial or more than one, or holds any token that is not a code.
     */
    static int[] loneSerial(String text) {
        int[] serial = null;
        int tokens = 0;
        for (PyMatch token : TOKEN_RE.finditer(text)) {
            tokens++;
            // A code first: a year is never the serial ("ΕΞ 2026"); a reference whose only number
            // looks like a year has no serial here and stays whole.
            if (DetectorPatterns.REFERENCE_CODE_TOKEN_RE.match(token.group()) != null) {
                continue;
            }
            if (DetectorPatterns.SERIAL_TOKEN_RE.match(token.group()) == null || serial != null) {
                return null;
            }
            serial = new int[] {token.start(), token.end()};
        }
        return tokens > 1 ? serial : null;
    }

    /**
     * How many code points of {@code text} are a trailing administrative region, as a whole word;
     * 0 when it does not end in one. The cut uses the allowlist entry's own length, never a folded
     * length. A span that is nothing but a region is not this function's to give back.
     */
    static int trailingRegion(String text, Set<String> regions) {
        String stripped = rstrip(text, " \t,");
        int strippedLen = PyStr.len(stripped);
        List<String> entries = new ArrayList<>(regions);
        entries.sort(Comparator.comparingInt(PyStr::len).reversed().thenComparing(PyStr.CODE_POINT_ORDER));
        for (String region : entries) {
            int regionLen = PyStr.len(region);
            if (regionLen == 0 || regionLen >= strippedLen) {
                continue;
            }
            String tail = PyStr.sliceFrom(stripped, strippedLen - regionLen);
            if (!PyStr.casefold(tail).equals(PyStr.casefold(region))) {
                continue;
            }
            String head = PyStr.slice(stripped, 0, strippedLen - regionLen);
            int before = PyStr.codePointAt(head, PyStr.len(head) - 1);
            if (!(PyUnicode.isSpace(before) || before == ',')) {
                continue; // the end of a longer word, not a region
            }
            if (!PyStr.strip(head, " \t,").isEmpty()) {
                return PyStr.len(text) - PyStr.len(rstrip(head, " \t,"));
            }
        }
        return 0;
    }

    /** Python {@code s.lstrip(chars)}. */
    static String lstrip(String s, String chars) {
        int i = 0;
        while (i < s.length() && chars.indexOf(s.codePointAt(i)) >= 0) {
            i += Character.charCount(s.codePointAt(i));
        }
        return s.substring(i);
    }

    /** Python {@code s.rstrip(chars)}. */
    static String rstrip(String s, String chars) {
        int end = s.length();
        while (end > 0 && chars.indexOf(s.codePointBefore(end)) >= 0) {
            end -= Character.charCount(s.codePointBefore(end));
        }
        return s.substring(0, end);
    }
}
