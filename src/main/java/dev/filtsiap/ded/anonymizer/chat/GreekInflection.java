package dev.filtsiap.ded.anonymizer.chat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The few paradigms Greek first names and surnames follow, on FOLDED forms (no accents, σ for ς).
 * Enough to expand a Wikidata nominative ("γιωργοσ") into what people type ("γιωργο", "γιωργου"),
 * and to find a confirmed name's other forms in the same text.
 */
public final class GreekInflection {
    /** Nominative ending, then every ending of its paradigm (the nominative first). */
    private static final List<Map.Entry<String, List<String>>> PARADIGMS = List.of(
            Map.entry("ουσ", List.of("ουσ", "ου")),
            Map.entry("οσ", List.of("οσ", "ου", "ο", "ε")),
            Map.entry("ησ", List.of("ησ", "η")),
            Map.entry("ασ", List.of("ασ", "α")),
            Map.entry("εσ", List.of("εσ", "ε")),
            Map.entry("α", List.of("α", "ασ")),
            Map.entry("η", List.of("η", "ησ")),
            Map.entry("ω", List.of("ω", "ωσ")));

    /** A stem shorter than this is not inflected ("ο", "η" are words, not stems). */
    private static final int MIN_STEM = 2;

    private GreekInflection() {
    }

    /**
     * Every form of a nominative; an ending no paradigm knows ("-ου" surnames, foreign names) is invariant.
     *
     * @param foldedNominative a folded nominative
     * @return the nominative and its other forms, folded
     */
    public static Set<String> forms(String foldedNominative) {
        Set<String> out = new TreeSet<>();
        out.add(foldedNominative);
        for (Map.Entry<String, List<String>> p : PARADIGMS) {
            String nominative = p.getKey();
            if (foldedNominative.endsWith(nominative)
                    && foldedNominative.length() - nominative.length() >= MIN_STEM) {
                String stem = foldedNominative.substring(0, foldedNominative.length() - nominative.length());
                p.getValue().forEach(e -> out.add(stem + e));
                return out;
            }
        }
        return out;
    }

    /**
     * Every form of every nominative {@code foldedAnyForm} could be a form of. Over-generates on purpose.
     *
     * @param foldedAnyForm a folded form of a name
     * @return that form and every form of its possible nominatives, folded
     */
    public static Set<String> family(String foldedAnyForm) {
        Set<String> out = new TreeSet<>();
        out.add(foldedAnyForm);
        for (Map.Entry<String, List<String>> p : PARADIGMS) {
            for (String ending : p.getValue()) {
                if (foldedAnyForm.endsWith(ending) && foldedAnyForm.length() - ending.length() >= MIN_STEM) {
                    String stem = foldedAnyForm.substring(0, foldedAnyForm.length() - ending.length());
                    p.getValue().forEach(e -> out.add(stem + e));
                }
            }
        }
        return out;
    }
}
