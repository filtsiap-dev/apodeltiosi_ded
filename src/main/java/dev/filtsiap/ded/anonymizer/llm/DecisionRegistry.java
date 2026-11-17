package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.Resolver;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.SpanOrigin;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.chat.GreekFold;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One document's REDACT/PRESERVE decisions, by exact complete value, so a decision made for a value
 * in one place can be reused for the same value elsewhere in the document. Request-local: built and
 * discarded inside one {@code runLlmDetection}, never shared between documents or kept.
 *
 * <p>Every value is classified ({@link Reuse}); the classes say what may be reused, never who wins:
 * <ul>
 *   <li>{@code GLOBAL_REDACT}: a confirmed complete private person or company name (an LLM REDACT of
 *       two or more words, or a company name of five or more letters) and a verified identifier (a
 *       deterministic HARD redact: AFM, AMKA, IBAN, e-mail, a property identifier). Reused at every
 *       other occurrence of exactly that value;
 *   <li>{@code GLOBAL_PRESERVE}: the values the deterministic HARD PRESERVE rules kept (the phrase
 *       families, the gazetteers). Those rules already run on the whole document; here they are a VETO
 *       (a value they keep is never globally redacted). An LLM PRESERVE never becomes one, and the
 *       official signatory's name is not one either (it is protected where it signs, nowhere else);
 *   <li>{@code CONTEXT_DEPENDENT}: everything else (dates, phones, places, addresses, short numbers,
 *       references, a single word, a value two decisions disagree about): decided place by place.
 * </ul>
 *
 * <p>Matching is EXACT: the complete value, as whole words, compared case- and accent-insensitively
 * (the {@code GreekFold} form, whitespace collapsed: registering and searching use the same definition,
 * so any run of horizontal whitespace between two words matches, a line break does not; every other
 * character is literal) but never across grammatical forms: "ΜΙΧΟΥ
 * ΝΙΚΟΛΑΟΥ" and "ΜΙΧΟΣ ΝΙΚΟΛΑΟΣ" are two values. A reused decision keeps its real authority: the
 * span carries the ORIGIN, category and confidence of the decision it repeats (an LLM decision stays
 * an LLM decision; a hard redact stays deterministic), and enters the one resolver like any other, so
 * a hard preserve, the signatory and a place's own PRESERVE decision still win where they stand.
 *
 * <p>CONFLICTS are explicit and order-free: the registry is built only after every chunk has
 * finished, from all decisions sorted by place, and a value both REDACTed and PRESERVEd by LLM
 * decisions is CONTEXT_DEPENDENT: no reuse, each place keeps its own decision. No extra question is
 * ever asked to settle one.
 */
final class DecisionRegistry {

    /** What may be reused for a value across the document. */
    enum Reuse {
        GLOBAL_REDACT, GLOBAL_PRESERVE, CONTEXT_DEPENDENT
    }

    /** The decision a GLOBAL_REDACT value repeats: its first source, in place order. */
    record Entry(String key, Reuse reuse, Span source) {
    }

    /** Person-name categories an LLM REDACT of two or more words makes a complete reusable name. */
    private static final Set<SpanCategory> PERSON_NAMES = EnumSet.of(SpanCategory.APPELLANT_NAME,
            SpanCategory.POSSIBLE_PERSON, SpanCategory.PRIVATE_BENEFICIARY);
    /** Company-name categories: one word is enough when it is five letters or more. */
    private static final Set<SpanCategory> COMPANY_NAMES = EnumSet.of(SpanCategory.PRIVATE_COMPANY_NAME,
            SpanCategory.POSSIBLE_COMPANY);
    /** Verified identifiers: reusable only as a deterministic HARD redact. */
    private static final Set<SpanCategory> IDENTIFIERS = EnumSet.of(SpanCategory.AFM, SpanCategory.AMKA,
            SpanCategory.IBAN, SpanCategory.EMAIL, SpanCategory.PROPERTY_ID);
    /** The reuse detector's prefix; the source decision's detector follows it. */
    static final String DETECTOR_PREFIX = "registry_reuse:";

    private final Map<String, Entry> entries;
    private final Set<String> preserved;

    private DecisionRegistry(Map<String, Entry> entries, Set<String> preserved) {
        this.entries = entries;
        this.preserved = preserved;
    }

    /** The exact-value key: folded (case, accents, final sigma), whitespace collapsed. */
    static String key(String value) {
        return GreekFold.fold(PyStr.collapseWhitespace(PyStr.strip(value)));
    }

    /**
     * The registry from every decision known so far: the rule engine's spans (only its HARD decisions
     * count) and the LLM decisions ({@code llmDecisions}: pass-1 decisions applied, pass-2 answers),
     * in place order whatever order the workers finished in.
     */
    static DecisionRegistry of(List<Span> deterministicSpans, List<Span> llmDecisions, PolicySettings policy) {
        Set<String> preserved = new HashSet<>();
        for (Span s : deterministicSpans) {
            if (Resolver.isHardPreserve(s, policy) && s.category() != SpanCategory.OFFICIAL_SIGNATORY) {
                preserved.add(key(s.text()));
            }
        }
        List<Span> ordered = new ArrayList<>();
        deterministicSpans.stream().filter(s -> Resolver.isHardRedact(s, policy) && IDENTIFIERS.contains(s.category())
                && eligibleIdentifier(s.text())).forEach(ordered::add);
        ordered.addAll(llmDecisions);
        ordered.sort(Comparator.comparing((Span s) -> unitOrder(s.unitId())).thenComparingInt(Span::start)
                .thenComparingInt(Span::end));
        Map<String, Set<SpanAction>> llmActions = new LinkedHashMap<>();
        for (Span s : llmDecisions) {
            if (s.action() == SpanAction.REDACT || s.action() == SpanAction.PRESERVE) {
                llmActions.computeIfAbsent(key(s.text()), k -> EnumSet.noneOf(SpanAction.class)).add(s.action());
            }
        }
        Map<String, Entry> entries = new LinkedHashMap<>();
        for (Span s : ordered) {
            String k = key(s.text());
            if (entries.containsKey(k) || s.action() != SpanAction.REDACT) {
                continue;
            }
            entries.put(k, new Entry(k, classify(s, k, preserved, llmActions.get(k)), s));
        }
        return new DecisionRegistry(entries, preserved);
    }

    private static Reuse classify(Span s, String key, Set<String> preserved, Set<SpanAction> llmActions) {
        if (preserved.contains(key)) {
            return Reuse.CONTEXT_DEPENDENT; // a value the hard preserve rules keep is never globally redacted
        }
        if (llmActions != null && llmActions.contains(SpanAction.PRESERVE)) {
            return Reuse.CONTEXT_DEPENDENT; // LLM decisions disagree about it: place by place
        }
        if (s.origin() == SpanOrigin.DETERMINISTIC) {
            return Reuse.GLOBAL_REDACT; // a hard redact of a verified identifier (filtered in of())
        }
        if (PERSON_NAMES.contains(s.category()) && completeName(s.text())) {
            return Reuse.GLOBAL_REDACT;
        }
        if (COMPANY_NAMES.contains(s.category()) && letters(s.text()) >= 5 && !hasDigit(s.text())) {
            return Reuse.GLOBAL_REDACT;
        }
        return Reuse.CONTEXT_DEPENDENT;
    }

    /** Two or more words of two or more letters, no digit, six letters at least: a complete name. */
    private static boolean completeName(String text) {
        List<String> words = PyStr.split(text);
        return words.size() >= 2 && words.stream().allMatch(w -> letters(w) >= 2) && letters(text) >= 6
                && !hasDigit(text);
    }

    private static boolean eligibleIdentifier(String text) {
        return PyStr.len(PyStr.strip(text)) >= 6;
    }

    private static int letters(String text) {
        return (int) text.codePoints().filter(Character::isLetter).count();
    }

    private static boolean hasDigit(String text) {
        return text.codePoints().anyMatch(Character::isDigit);
    }

    /** "u12" sorts as 12: units are numbered in document order. */
    private static int unitOrder(String unitId) {
        try {
            return Integer.parseInt(unitId.substring(1));
        } catch (RuntimeException e) {
            return Integer.MAX_VALUE;
        }
    }

    /** The GLOBAL_REDACT entry for exactly this value, or null. */
    Entry globalRedact(String value) {
        Entry e = entries.get(key(value));
        return e != null && e.reuse() == Reuse.GLOBAL_REDACT ? e : null;
    }

    /** How the registry classifies {@code value} (a value it has no decision for is CONTEXT_DEPENDENT). */
    Reuse classification(String value) {
        String k = key(value);
        Entry e = entries.get(k);
        if (e != null) {
            return e.reuse();
        }
        return preserved.contains(k) ? Reuse.GLOBAL_PRESERVE : Reuse.CONTEXT_DEPENDENT;
    }

    /** The reused decision at one place: the source's origin, category, confidence and action. */
    static Span reuse(Entry entry, String unitId, int start, int end, String unitText) {
        Span s = entry.source();
        return new Span(unitId, start, end, PyStr.slice(unitText, start, end), s.category(),
                DETECTOR_PREFIX + s.detector(), s.confidence(), SpanAction.REDACT,
                "Same complete value as a confirmed decision elsewhere in the document (" + s.origin().wire()
                        + " " + s.category().wire() + ")", s.origin());
    }

    /**
     * Every GLOBAL_REDACT value's other occurrences in {@code units} (whole words, exact value), as
     * reused decisions, skipping a place that hard policy keeps ({@code hard}: a hard preserve, the
     * signatory), a place with a PRESERVE decision of its own among {@code placeDecisions}, and a place
     * a decision already covers exactly (nothing to add).
     */
    List<Span> applyEverywhere(List<TextUnit> units, HardDecisions hard, List<Span> placeDecisions) {
        List<Entry> global = entries.values().stream().filter(e -> e.reuse() == Reuse.GLOBAL_REDACT).toList();
        if (global.isEmpty()) {
            return List.of();
        }
        Set<List<Object>> decided = new HashSet<>();
        Map<String, List<Span>> keptAt = new LinkedHashMap<>();
        for (Span s : placeDecisions) {
            decided.add(List.of(s.unitId(), s.start(), s.end()));
            if (s.action() == SpanAction.PRESERVE) {
                keptAt.computeIfAbsent(s.unitId(), k -> new ArrayList<>()).add(s);
            }
        }
        // One pattern per value, built once: the value's own words, literal, in the key's folded form.
        Map<Entry, Pattern> patterns = new LinkedHashMap<>();
        for (Entry e : global) {
            if (!e.key().isEmpty()) {
                patterns.put(e, valuePattern(e.key()));
            }
        }
        List<Span> out = new ArrayList<>();
        for (TextUnit unit : units) {
            String text = unit.normalizedText();
            String folded = GreekFold.fold(text);
            for (Map.Entry<Entry, Pattern> value : patterns.entrySet()) {
                Entry e = value.getKey();
                Matcher matcher = value.getValue().matcher(folded);
                int from = 0;
                while (from <= folded.length() && matcher.find(from)) {
                    // Code points: the fold keeps every code point's place, so these are the unit's offsets.
                    int start = PyStr.toCodePoint(folded, matcher.start());
                    int end = PyStr.toCodePoint(folded, matcher.end());
                    from = matcher.start() + Character.charCount(folded.codePointAt(matcher.start()));
                    if (!wholeWords(folded, start, end)) {
                        continue;
                    }
                    UnitSlice place = new UnitSlice(unit.unitId(), start, end);
                    if (!hard.masked(place).isEmpty()) {
                        continue; // a hard redaction already blanks it: the rule engine's own decision stands
                    }
                    boolean kept = hard.preserved(place) || !hard.shieldedParts(place).isEmpty()
                            || keptAt.getOrDefault(unit.unitId(), List.of()).stream()
                            .anyMatch(p -> p.start() < end && start < p.end());
                    if (kept || decided.contains(List.of(unit.unitId(), start, end))) {
                        continue;
                    }
                    out.add(reuse(e, unit.unitId(), start, end, text));
                }
            }
        }
        return out;
    }

    /**
     * Horizontal whitespace only (the {@code PyUnicode.isSpace} set without its line and paragraph
     * breaks): a value is matched across any run of spaces, tabs or no-break spaces, never across a line.
     */
    static final String VALUE_GAP = "[\\t \\u00A0\\u1680\\u2000-\\u200A\\u202F\\u205F\\u3000]+";

    /**
     * The search pattern of an exact-value key (already folded, whitespace collapsed to single spaces):
     * each word LITERAL ({@link Pattern#quote}, so the dots, brackets, plus signs and ampersands of a
     * company name are characters, never operators), the words joined by {@link #VALUE_GAP}. That gap is
     * the only flexibility: no fuzziness, no other form of a word.
     */
    static Pattern valuePattern(String key) {
        List<String> words = new ArrayList<>();
        for (String word : key.split(" ")) {
            if (!word.isEmpty()) {
                words.add(Pattern.quote(word));
            }
        }
        return Pattern.compile(String.join(VALUE_GAP, words));
    }

    private static boolean wholeWords(String text, int start, int end) {
        return (start == 0 || !wordChar(PyStr.codePointAt(text, start - 1)))
                && (end >= PyStr.len(text) || !wordChar(PyStr.codePointAt(text, end)));
    }

    private static boolean wordChar(int cp) {
        return Character.isLetterOrDigit(cp) || Character.getType(cp) == Character.NON_SPACING_MARK || cp == '_'
                || (!PyUnicode.isSpace(cp) && Character.isLetter(cp));
    }
}
