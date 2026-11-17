package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Resolves overlapping REDACT/PRESERVE candidates per text unit by character-level ownership
 * and policy priority tiers (port of {@code resolver.py}).
 *
 * <p>The tier ladder is the whole arbitration rule, and its shape is the pipeline's authority
 * model:
 *
 * <pre>
 *     hard policy decision              (deterministic, by CATEGORY)
 *         v
 *     pass-2 final decision             (the adjudicator's answer)
 *         v
 *     pass-1 REDACT                     (agreed, pass-1 only, or the pass-2 fallback)
 *         v
 *     ordinary deterministic detection  (by confidence, as before)
 *         v
 *     pass-1 PRESERVE                   (loses to every ordinary deterministic REDACT)
 * </pre>
 *
 * <p>Hard status is reached by policy category on a {@link SpanOrigin#DETERMINISTIC} span only;
 * neither LLM pass can reach either hard tier under any category it returns. A pass-2 decision
 * outranks every ordinary rule span and every pass-1 decision. A pass-1 decision is applied
 * without a pass-2 question only where nothing disagrees with it (or as the documented fallback
 * when pass 2 is unavailable), so its tiers matter only against what a router left beside it:
 * its REDACT beats an ordinary deterministic PRESERVE (the fail-safe direction) and its PRESERVE
 * never beats an ordinary deterministic REDACT. Ordinary rule spans keep their confidence ladder
 * and own only the characters no higher authority claimed. Higher wins a contested character; an
 * exact tie leaves the incumbent.
 *
 * <p>ONE GEOMETRIC EXCEPTION to the ladder, a deliberate change from v2: a pass-2 PRESERVE never
 * carves a hole in a REDACT it was not answering. It keeps a character only when every REDACT
 * covering that character is one pass 2 PRESERVED AT EXACTLY ITS OWN SLICE (its answer to that
 * candidate, which is how a false-positive rule span is corrected). A PRESERVE that is nested in,
 * wider than, shifted against or partly over another REDACT gives that character back to the
 * ladder as if the pass-2 PRESERVE did not exist. Hard redact and hard preserve are untouched, and
 * so is every comparison that does not involve a pass-2 PRESERVE.
 */
public final class Resolver {

    /** Structured identifier categories with a dedicated high-confidence tier. In-code by design. */
    private static final Set<SpanCategory> STRUCTURED_REDACT_CATEGORIES =
            EnumSet.of(SpanCategory.AFM, SpanCategory.AMKA, SpanCategory.IBAN, SpanCategory.EMAIL);

    // Hard-redact over hard-preserve: an identifier the policy calls unsuppressable stays so even
    // under institutional boilerplate. Pass-2 preserve over pass-2 redact, matching the ordinary
    // rungs, so two overlapping pass-2 answers resolve like two overlapping rule spans.
    /** Deterministic, {@code hard_redact_categories}, at {@code >= redact_high_confidence}. */
    static final int TIER_HARD_REDACT = 10;
    /** Deterministic PRESERVE in {@code hard_preserve_categories}, at any confidence. */
    static final int TIER_HARD_PRESERVE = 9;
    /** Pass-2 final PRESERVE, at any confidence. */
    static final int TIER_PASS2_PRESERVE = 8;
    /** Pass-2 final REDACT, at any confidence. */
    static final int TIER_PASS2_REDACT = 7;
    /** Pass-1 REDACT applied without a pass-2 question, at any confidence. */
    static final int TIER_PASS1_REDACT = 6;
    /** Deterministic AFM/AMKA/IBAN/EMAIL REDACT at {@code >= redact_high_confidence}. */
    static final int TIER_STRUCTURED_REDACT = 5;
    /** Ordinary deterministic PRESERVE at {@code >= preserve_high_confidence}. */
    static final int TIER_PRESERVE_CONFIDENT = 4;
    /** Ordinary deterministic REDACT at {@code >= redact_threshold}. */
    static final int TIER_REDACT = 3;
    /** Pass-1 PRESERVE applied without a pass-2 question, at any confidence. */
    static final int TIER_PASS1_PRESERVE = 2;
    /** Ordinary deterministic PRESERVE below the confidence bar. */
    static final int TIER_PRESERVE = 1;
    /** Can never claim a character. */
    static final int TIER_IGNORED = 0;

    /**
     * Total order over one unit's candidates, so the plan cannot depend on the order they
     * arrived in: geometry first (earliest, longest, most confident), then every remaining field
     * as a fixed tiebreak. Strings compare by code point, as Python's tuple comparison does.
     */
    private static final Comparator<Span> CANDIDATE_ORDER = Comparator.comparingInt(Span::start)
            .thenComparingInt(s -> -length(s))
            .thenComparingDouble(s -> -s.confidence())
            .thenComparing(s -> s.action().wire(), PyStr.CODE_POINT_ORDER)
            .thenComparing(s -> s.origin().wire(), PyStr.CODE_POINT_ORDER)
            .thenComparing(s -> s.category().wire(), PyStr.CODE_POINT_ORDER)
            .thenComparing(Span::detector, PyStr.CODE_POINT_ORDER)
            .thenComparing(Span::reason, PyStr.CODE_POINT_ORDER);

    private Resolver() {
    }

    private static int length(Span span) {
        return Math.max(0, span.end() - span.start());
    }

    private static boolean isPass2Decision(Span span) {
        return span.origin() == SpanOrigin.LLM_PASS2;
    }

    private static boolean isDeterministic(Span span) {
        return span.origin() == SpanOrigin.DETERMINISTIC;
    }

    /**
     * A deterministic PRESERVE in one of the policy's {@code hard_preserve_categories}, at any
     * confidence. Withheld from the pass-2 queue and outranked only by a hard redact. Never true
     * for an LLM span (pass 1 or pass 2), whatever category it came back with.
     */
    public static boolean isHardPreserve(Span span, PolicySettings policy) {
        return isDeterministic(span)
                && span.action() == SpanAction.PRESERVE
                && policy.hardPreserveCategories().contains(span.category().wire());
    }

    /**
     * A deterministic REDACT in a {@code hard_redact_categories} category at or above the
     * high-confidence redact threshold. Deterministic-only for the same reason as
     * {@link #isHardPreserve}: otherwise an LLM answer labelled {@code AFM} would overturn a
     * hard preserve.
     */
    public static boolean isHardRedact(Span span, PolicySettings policy) {
        return isDeterministic(span)
                && span.action() == SpanAction.REDACT
                && policy.hardRedactCategories().contains(span.category().wire())
                && span.confidence() >= policy.redactHighConfidenceThreshold();
    }

    /**
     * What the ordinary deterministic ladder alone makes of {@code spans} at a place they all cover:
     * the action of the highest-ranked span that can claim a character at all, or null when every
     * one of them is below its threshold. This is the resolver's own precedence, exposed so the
     * LLM router can tell what the rules decided at a place without re-implementing it.
     */
    public static SpanAction deterministicAction(List<Span> spans, PolicySettings policy) {
        Span best = null;
        int bestTier = TIER_IGNORED;
        for (Span span : spans) {
            if (!isDeterministic(span)) {
                continue;
            }
            int tier = priority(span, policy);
            if (tier > bestTier) {
                best = span;
                bestTier = tier;
            }
        }
        return best == null ? null : best.action();
    }

    /**
     * The span's tier: hard policy first, then pass-2 decisions (deliberately confidence-blind,
     * since pass 2 does not score its answers), then pass-1 decisions (confidence-blind as well,
     * placed around the ordinary deterministic ladder), then ordinary deterministic evidence by
     * confidence.
     */
    static int priority(Span span, PolicySettings policy) {
        if (isHardRedact(span, policy)) {
            return TIER_HARD_REDACT;
        }
        if (isHardPreserve(span, policy)) {
            return TIER_HARD_PRESERVE;
        }
        if (isPass2Decision(span)) {
            return switch (span.action()) {
                case REDACT -> TIER_PASS2_REDACT;
                case PRESERVE -> TIER_PASS2_PRESERVE;
                case REVIEW -> TIER_IGNORED;
            };
        }
        if (span.origin() == SpanOrigin.LLM_PASS1) {
            return switch (span.action()) {
                case REDACT -> TIER_PASS1_REDACT;
                case PRESERVE -> TIER_PASS1_PRESERVE;
                case REVIEW -> TIER_IGNORED;
            };
        }
        double confidence = span.confidence();
        if (span.action() == SpanAction.REDACT) {
            if (STRUCTURED_REDACT_CATEGORIES.contains(span.category())
                    && confidence >= policy.redactHighConfidenceThreshold()) {
                return TIER_STRUCTURED_REDACT;
            }
            return confidence >= policy.redactThreshold() ? TIER_REDACT : TIER_IGNORED;
        }
        if (span.action() == SpanAction.PRESERVE) {
            return confidence >= policy.preserveHighConfidenceThreshold() ? TIER_PRESERVE_CONFIDENT : TIER_PRESERVE;
        }
        return TIER_IGNORED;
    }

    /** Whether {@code incoming} takes a character from {@code existing} (which may be null). */
    static boolean incomingReplacesExisting(Span incoming, Span existing, PolicySettings policy) {
        int incomingPriority = priority(incoming, policy);
        if (incomingPriority <= TIER_IGNORED) {
            return false;
        }
        return existing == null || incomingPriority > priority(existing, policy);
    }

    /** The ladder over one unit: every character goes to the highest-ranked span, in {@link #CANDIDATE_ORDER}. */
    private static Span[] claim(List<Span> sortedCandidates, int textLen, PolicySettings policy) {
        Span[] owners = new Span[textLen];
        for (Span span : sortedCandidates) {
            int start = Math.max(0, Math.min(textLen, span.start()));
            int end = Math.max(0, Math.min(textLen, span.end()));
            for (int index = start; index < end; index++) {
                if (incomingReplacesExisting(span, owners[index], policy)) {
                    owners[index] = span;
                }
            }
        }
        return owners;
    }

    private static boolean isPass2Preserve(Span span) {
        return span != null && isPass2Decision(span) && span.action() == SpanAction.PRESERVE;
    }

    /**
     * The characters a pass-2 PRESERVE may not take: those covered by a claiming REDACT that no pass-2
     * PRESERVE answered at exactly its own slice. Geometry decides, never text or category.
     */
    private static boolean[] shieldedFromPass2Preserve(List<Span> candidates, int textLen, PolicySettings policy) {
        Set<List<Integer>> answered = new HashSet<>();
        for (Span span : candidates) {
            if (isPass2Preserve(span)) {
                answered.add(List.of(span.start(), span.end()));
            }
        }
        boolean[] shielded = new boolean[textLen];
        for (Span span : candidates) {
            if (span.action() != SpanAction.REDACT || priority(span, policy) <= TIER_IGNORED
                    || answered.contains(List.of(span.start(), span.end()))) {
                continue;
            }
            for (int index = Math.max(0, span.start()); index < Math.min(textLen, span.end()); index++) {
                shielded[index] = true;
            }
        }
        return shielded;
    }

    /**
     * One span per run of characters owned by the same span object, in text order. Each keeps
     * its owner's origin, so the plan records which authority decided every surviving run.
     */
    private static List<Span> recoverSpansFromOwners(String normalizedText, Span[] owners) {
        List<Span> resolved = new ArrayList<>();
        int i = 0;
        int n = owners.length;
        while (i < n) {
            Span owner = owners[i];
            if (owner == null) {
                i++;
                continue;
            }
            int start = i;
            i++;
            while (i < n && owners[i] == owner) {
                i++;
            }
            resolved.add(new Span(owner.unitId(), start, i, PyStr.slice(normalizedText, start, i),
                    owner.category(), owner.detector(), owner.confidence(), owner.action(), owner.reason(),
                    owner.origin()));
        }
        return resolved;
    }

    /**
     * Warns about strings (casefolded) that are redacted in one place and preserved in another.
     * The string itself is never quoted: a short hash and its length only.
     */
    private static List<String> consistencySweep(Map<String, List<Span>> resolvedByUnit) {
        Set<String> redacted = new TreeSet<>(PyStr.CODE_POINT_ORDER);
        Set<String> preserved = new TreeSet<>(PyStr.CODE_POINT_ORDER);
        for (List<Span> unitSpans : resolvedByUnit.values()) {
            for (Span span : unitSpans) {
                if (span.action() == SpanAction.REDACT) {
                    redacted.add(PyStr.casefold(span.text()));
                } else if (span.action() == SpanAction.PRESERVE) {
                    preserved.add(PyStr.casefold(span.text()));
                }
            }
        }
        List<String> warnings = new ArrayList<>();
        for (String s : redacted) {
            if (!preserved.contains(s)) {
                continue;
            }
            String digest = sha256Hex(s).substring(0, 12);
            warnings.add("Inconsistent treatment of a span (sha256:" + digest + ", " + PyStr.len(s)
                    + " chars): both redacted and preserved in different parts of the document.");
        }
        return warnings;
    }

    /**
     * Resolves candidates into the final plan, with consistency warnings. {@code candidateSpans}
     * mixes both authorities, each declaring itself through {@link Span#origin()}; every character
     * goes to the highest-ranked span covering it, so a pass-2 decision governs the characters it
     * spoke about and the rule spans stay as fallback evidence for the rest. The list's order
     * carries no meaning.
     */
    public static RedactionPlan resolveRedactions(DocumentData document, List<Span> candidateSpans,
                                                  PolicySettings policy) {
        for (Span span : candidateSpans) {
            if (span.action() != SpanAction.REDACT && span.action() != SpanAction.PRESERVE) {
                throw new IllegalStateException("REVIEW span reached the resolver — programming bug");
            }
        }
        Map<String, List<Span>> candidatesByUnit = new LinkedHashMap<>();
        for (Span span : candidateSpans) {
            candidatesByUnit.computeIfAbsent(span.unitId(), k -> new ArrayList<>()).add(span);
        }

        Map<String, List<Span>> resolvedByUnit = new LinkedHashMap<>();
        for (TextUnit unit : document.textUnits()) {
            String normalizedText = unit.normalizedText();
            int textLen = PyStr.len(normalizedText);

            List<Span> unitCandidates = new ArrayList<>(candidatesByUnit.getOrDefault(unit.unitId(), List.of()));
            unitCandidates.sort(CANDIDATE_ORDER);
            Span[] owners = claim(unitCandidates, textLen, policy);

            boolean[] shielded = shieldedFromPass2Preserve(unitCandidates, textLen, policy);
            Span[] withoutPass2Preserves = null;
            for (int index = 0; index < textLen; index++) {
                if (shielded[index] && isPass2Preserve(owners[index])) {
                    if (withoutPass2Preserves == null) {
                        withoutPass2Preserves = claim(unitCandidates.stream().filter(s -> !isPass2Preserve(s)).toList(),
                                textLen, policy);
                    }
                    owners[index] = withoutPass2Preserves[index];
                }
            }
            resolvedByUnit.put(unit.unitId(), recoverSpansFromOwners(normalizedText, owners));
        }

        List<String> warnings = consistencySweep(resolvedByUnit);
        List<Span> resolved = new ArrayList<>();
        resolvedByUnit.values().forEach(resolved::addAll);
        // Python sorts unit ids as strings ("u10" < "u2"); keep that exact order.
        resolved.sort(Comparator.comparing(Span::unitId, PyStr.CODE_POINT_ORDER).thenComparingInt(Span::start));
        return new RedactionPlan(document.documentId(), resolved, warnings);
    }

    static String sha256Hex(String s) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
