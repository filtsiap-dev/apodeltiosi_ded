package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Deterministic screening for text shaped like an instruction to the model (port of
 * {@code injection_screen.py}), run before either LLM pass sees the document.
 *
 * <p>ADDITIONAL PROTECTION, NOT THE PROTECTION: fixed system prompts, strict response validation,
 * the hard-policy tiers and the provenance resolver stay the real defences. A regex cannot
 * enumerate a language.
 *
 * <p>Rules are matched against a NORMALISED COPY (compatibility-normalised, format characters
 * dropped, casefolded, accents dropped, whitespace squeezed), so "αγνόησε", "αγνοησε" and
 * "α&#x200B;γνόησε" are one thing. The copy is a copy: the stored text and every redaction offset
 * derived from it are untouched. Patterns are therefore written lowercase and accent-free, which
 * {@link #compileRules} enforces. There is no off switch, by decision: recovery from a false
 * positive is editing {@code config/prompt_injection.yaml} and restarting, which is why the log
 * names the rule that fired.
 */
public final class InjectionScreen {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.injection_screen");

    /** An identifier an operator will type into a config file and grep for in a log. */
    private static final PyPattern RULE_ID_RE = PyRegex.compile("^[a-z0-9_]{1,64}$");

    private InjectionScreen() {
    }

    /** One compiled high-confidence pattern, and what it is for. */
    public record Rule(String ruleId, String description, PyPattern pattern) {
    }

    /** Where a rule fired: a rule id and an index into the ORIGINAL text, never the text. */
    record Found(String ruleId, int sourceIndex) {
    }

    /**
     * The folded string, and for each of its code points the code-point index in the source it
     * came from. The map is the only reason a match can be attributed to a text unit without the
     * matched text ever being read, stored or reported.
     */
    record Folded(String text, int[] origin) {
    }

    /**
     * Folds {@code text} for matching, per source code point and in v2's order: NFKC, drop
     * format characters (Cf), casefold, NFD, drop combining marks (Mn), squeeze whitespace runs to
     * one space.
     */
    static Folded normalizeForScreening(String text) {
        StringBuilder folded = new StringBuilder(text.length());
        int[] origin = new int[Math.max(16, text.length())];
        int count = 0;
        boolean lastSpace = false;
        int index = 0;
        for (int i = 0; i < text.length(); index++) {
            int cp = text.codePointAt(i);
            i += Character.charCount(cp);
            String compatible = Normalizer.normalize(new String(Character.toChars(cp)), Normalizer.Form.NFKC);
            for (int c : compatible.codePoints().toArray()) {
                if (Character.getType(c) == Character.FORMAT) {
                    // Invisible to a reader, so invisible to a pattern too.
                    continue;
                }
                for (int lowered : PyUnicode.casefold(new String(Character.toChars(c))).codePoints().toArray()) {
                    String decomposed = Normalizer.normalize(new String(Character.toChars(lowered)),
                            Normalizer.Form.NFD);
                    for (int d : decomposed.codePoints().toArray()) {
                        if (Character.getType(d) == Character.NON_SPACING_MARK) {
                            continue;
                        }
                        if (PyUnicode.isSpace(d)) {
                            if (lastSpace) {
                                continue;
                            }
                            folded.append(' ');
                            lastSpace = true;
                        } else {
                            folded.appendCodePoint(d);
                            lastSpace = false;
                        }
                        if (count == origin.length) {
                            origin = Arrays.copyOf(origin, origin.length * 2);
                        }
                        origin[count++] = index;
                    }
                }
            }
        }
        return new Folded(folded.toString(), Arrays.copyOf(origin, count));
    }

    /**
     * Greek characters in {@code patternText} that the folding would have changed. Only Greek:
     * regex syntax uses Latin letters whose case is meaningful, while a Greek letter in a pattern
     * is always a literal, so a final sigma or a tonos is unambiguously a mistake.
     */
    static String unfoldableGreek(String patternText) {
        Set<Integer> offenders = new LinkedHashSet<>();
        patternText.codePoints().forEach(c -> {
            if (!((c >= 0x0370 && c <= 0x03FF) || (c >= 0x1F00 && c <= 0x1FFF))) {
                return;
            }
            String character = new String(Character.toChars(c));
            if (!normalizeForScreening(character).text().equals(character)) {
                offenders.add(c);
            }
        });
        return offenders.stream().map(c -> String.format("U+%04X", c)).collect(Collectors.joining(" "));
    }

    /**
     * Validates and compiles the rule definitions loaded from {@code source}. Throws
     * {@link ConfigurationError} for anything that would otherwise surface while processing a
     * request: a malformed file, a duplicate or unusable id, a pattern that does not compile, or
     * one that matches the empty string (which would refuse every document).
     */
    public static List<Rule> compileRules(Map<?, ?> raw, String source) {
        if (!(raw.get("rules") instanceof List<?> entries) || entries.isEmpty()) {
            throw new ConfigurationError(source + ": 'rules:' must be a non-empty list");
        }
        List<Rule> rules = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int position = 0;
        for (Object item : entries) {
            position++;
            if (!(item instanceof Map<?, ?> entry)) {
                throw new ConfigurationError(source + ": rule " + position + " is not a mapping");
            }
            String ruleId = PyStr.strip(PyRepr.str(entry.containsKey("id") ? entry.get("id") : ""));
            if (RULE_ID_RE.match(ruleId) == null) {
                throw new ConfigurationError(source + ": rule " + position + " has an invalid id "
                        + "(lowercase letters, digits and underscores, 1-64 characters)");
            }
            if (!seen.add(ruleId)) {
                throw new ConfigurationError(source + ": duplicate rule id " + PyRepr.repr(ruleId));
            }
            if (!(entry.get("pattern") instanceof String patternText) || PyStr.strip(patternText).isEmpty()) {
                throw new ConfigurationError(source + ": rule " + PyRepr.repr(ruleId) + " has no pattern");
            }
            String unfolded = unfoldableGreek(patternText);
            if (!unfolded.isEmpty()) {
                // A pattern spelled the way the language is written can never match the folded
                // text: it would load and quietly never fire. Refuse it at startup instead.
                throw new ConfigurationError(source + ": rule " + PyRepr.repr(ruleId) + " contains Greek "
                        + "characters that the screening normalisation removes (" + unfolded + "); write "
                        + "patterns lowercase, accent-free, and with a plain sigma");
            }
            PyPattern compiled;
            try {
                compiled = PyRegex.compile(patternText);
            } catch (IllegalArgumentException e) {
                throw new ConfigurationError(source + ": rule " + PyRepr.repr(ruleId) + " has an invalid pattern: "
                        + e.getMessage());
            }
            if (compiled.search("") != null) {
                throw new ConfigurationError(source + ": rule " + PyRepr.repr(ruleId) + " matches the empty "
                        + "string, so it would refuse every document");
            }
            String description = PyStr.strip(PyRepr.str(entry.containsKey("description") ? entry.get("description") : ""));
            rules.add(new Rule(ruleId, description, compiled));
        }
        return List.copyOf(rules);
    }

    /** The first rule that matches the folded copy of {@code text}, or null. */
    static Found findInjection(String text, List<Rule> rules) {
        if (rules.isEmpty()) {
            return null;
        }
        Folded folded = normalizeForScreening(text);
        if (folded.text().isEmpty()) {
            return null;
        }
        for (Rule rule : rules) {
            PyMatch m = rule.pattern().search(folded.text());
            if (m != null) {
                int position = Math.min(m.start(), folded.origin().length - 1);
                return new Found(rule.ruleId(), folded.origin()[position]);
            }
        }
        return null;
    }

    /**
     * Refuses {@code document} with {@link PromptInjectionError} if any rule matches its text.
     * Reads the units' normalized text and writes nothing. The units are joined with "\n", as the
     * LLM chunks and the postcheck see them, so a phrase split across two paragraphs is one phrase.
     */
    public static void screenDocument(DocumentData document, List<Rule> rules) {
        List<TextUnit> units = document.textUnits();
        if (units.isEmpty()) {
            return;
        }
        int[] offsets = new int[units.size()];
        int cursor = 0;
        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < units.size(); i++) {
            offsets[i] = cursor;
            String unitText = units.get(i).normalizedText();
            cursor += PyStr.len(unitText) + 1;
            if (i > 0) {
                joined.append('\n');
            }
            joined.append(unitText);
        }
        Found found = findInjection(joined.toString(), rules);
        if (found == null) {
            return;
        }
        int index = 0;
        while (index + 1 < offsets.length && offsets[index + 1] <= found.sourceIndex()) {
            index++;
        }
        TextUnit unit = units.get(index);
        // The operator is told which rule fired, so a false positive can be fixed in the rules
        // file; the caller is not (the public detail says only that a pattern matched). Neither
        // gets the matched text: it is the attempt itself.
        LOG.warn("screen_refused rule={} location={}:{}", found.ruleId(), unit.partName(), unit.unitId());
        throw new PromptInjectionError("prompt-injection rule " + found.ruleId() + " matched in "
                + unit.partName() + ":" + unit.unitId());
    }
}
