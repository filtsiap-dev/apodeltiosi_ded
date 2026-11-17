package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Data-driven detector inputs (port of {@code config.DetectorRules}): regex overrides from
 * {@code regex_patterns.yaml} and the allowlists. Sets are for membership only; detectors that
 * iterate them sort first, so iteration order never reaches output.
 *
 * <p>{@code regions} are the administrative regions of {@code allowlists/regions.txt}. They never
 * produce a span of their own: they say where a kept place-name run legitimately ends ("Νέας
 * Σμύρνης Αττικής"). Empty means a kept run is its place only.
 *
 * <p>{@code preserveFamilies} are the structural phrase families of {@code regex_patterns.yaml}'s
 * {@code preserve_families} (their one definition), compiled once at load. {@code givenNames} and
 * {@code surnames} are the folded name lists of {@code config/chat} (every inflected form), used by
 * the DOCX detectors as POSITIVE evidence of a person's name only; empty when the lists are absent.
 */
public record DetectorRules(
        Map<String, Map<String, String>> patterns,
        Set<String> douAllowlist,
        Set<String> publicServices,
        Set<String> legalRefs,
        Set<String> preserveEmailDomains,
        Set<String> regions,
        List<PreserveFamily> preserveFamilies,
        Set<String> givenNames,
        Set<String> surnames) {

    /**
     * Where a phrase family applies. {@code ANY}: the phrase wherever it stands, as whole words.
     * {@code LABEL}: only as a label, i.e. the whole line (a heading, a table cell, ignoring list
     * numbering, quotes and a trailing colon), or at the start of a line followed by a colon (a
     * label-value cell): the word is then a label, not part of a name that happens to contain it.
     */
    public enum Scope {
        ANY, LABEL
    }

    /**
     * One compiled phrase family. {@code pattern} runs on the FOLDED unit text ({@code GreekFold}, so
     * its offsets are the unit's own); {@code variable} says its group 1 is the variable part of a
     * composite reference (a serial), which is left out of the preserve.
     */
    public record PreserveFamily(String name, SpanCategory category, Scope scope, PyPattern pattern,
                                 boolean variable) {
    }

    public DetectorRules {
        Map<String, Map<String, String>> copy = new LinkedHashMap<>();
        patterns.forEach((k, v) -> copy.put(k, Collections.unmodifiableMap(new LinkedHashMap<>(v))));
        patterns = Collections.unmodifiableMap(copy);
        douAllowlist = Set.copyOf(douAllowlist);
        publicServices = Set.copyOf(publicServices);
        legalRefs = Set.copyOf(legalRefs);
        preserveEmailDomains = Set.copyOf(preserveEmailDomains);
        regions = Set.copyOf(regions);
        preserveFamilies = List.copyOf(preserveFamilies);
        givenNames = Set.copyOf(givenNames);
        surnames = Set.copyOf(surnames);
    }

    /** Rules without phrase families or name lists (the shape before either existed). */
    public DetectorRules(Map<String, Map<String, String>> patterns, Set<String> douAllowlist,
                         Set<String> publicServices, Set<String> legalRefs, Set<String> preserveEmailDomains,
                         Set<String> regions) {
        this(patterns, douAllowlist, publicServices, legalRefs, preserveEmailDomains, regions, List.of(), Set.of(),
                Set.of());
    }
}
