package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Resolves overlapping REDACT/PRESERVE candidates per text unit by character-level ownership
 * and policy priority tiers (port of {@code resolver.py}).
 */
public final class Resolver {

    /** Structured identifier categories with a dedicated high-confidence tier. In-code by design. */
    private static final Set<SpanCategory> STRUCTURED_REDACT_CATEGORIES =
            EnumSet.of(SpanCategory.AFM, SpanCategory.AMKA, SpanCategory.IBAN, SpanCategory.EMAIL);

    private Resolver() {
    }

    private static int length(Span span) {
        return Math.max(0, span.end() - span.start());
    }

    /** Priority tiers. There is no tier 2: the REVIEW tier was deleted in v2. */
    static int priority(Span span, PolicySettings policy) {
        double confidence = span.confidence();
        if (span.action() == SpanAction.PRESERVE && confidence >= policy.preserveHighConfidenceThreshold()) {
            return 6;
        }
        if (span.action() == SpanAction.REDACT && STRUCTURED_REDACT_CATEGORIES.contains(span.category())
                && confidence >= policy.redactHighConfidenceThreshold()) {
            return 5;
        }
        if (span.action() == SpanAction.REDACT && confidence >= policy.redactThreshold()) {
            return 4;
        }
        if (span.action() == SpanAction.PRESERVE && confidence < policy.preserveHighConfidenceThreshold()) {
            return 3;
        }
        return 0;
    }

    private static boolean isHardPreserve(Span span, PolicySettings policy) {
        return span.action() == SpanAction.PRESERVE
                && policy.hardPreserveCategories().contains(span.category().wire());
    }

    private static boolean isHardRedact(Span span, PolicySettings policy) {
        return span.action() == SpanAction.REDACT
                && policy.hardRedactCategories().contains(span.category().wire())
                && span.confidence() >= policy.redactHighConfidenceThreshold();
    }

    /** Whether {@code incoming} takes a character from {@code existing} (which may be null). */
    static boolean incomingReplacesExisting(Span incoming, Span existing, PolicySettings policy) {
        int incomingPriority = priority(incoming, policy);
        if (incomingPriority <= 0) {
            return false;
        }
        if (existing == null) {
            return true;
        }
        boolean incomingHardRedact = isHardRedact(incoming, policy);
        boolean existingHardRedact = isHardRedact(existing, policy);
        boolean incomingHardPreserve = isHardPreserve(incoming, policy);
        boolean existingHardPreserve = isHardPreserve(existing, policy);

        if (incomingHardRedact && existingHardPreserve) {
            return true;
        }
        if (existingHardRedact && incomingHardPreserve) {
            return false;
        }
        if (incomingHardPreserve && existing.action() == SpanAction.REDACT && !existingHardRedact) {
            return true;
        }
        if (existingHardPreserve && incoming.action() == SpanAction.REDACT && !incomingHardRedact) {
            return false;
        }
        return incomingPriority > priority(existing, policy);
    }

    /** One span per run of characters owned by the same span object, in text order. */
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
                    owner.category(), owner.detector(), owner.confidence(), owner.action(), owner.reason()));
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

    /** Resolves candidates into the final plan, with consistency warnings. */
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
            Span[] owners = new Span[textLen];

            List<Span> unitCandidates = new ArrayList<>(candidatesByUnit.getOrDefault(unit.unitId(), List.of()));
            unitCandidates.sort(Comparator.comparingInt(Span::start)
                    .thenComparingInt(s -> -length(s))
                    .thenComparingDouble(s -> -s.confidence()));

            for (Span span : unitCandidates) {
                int start = Math.max(0, Math.min(textLen, span.start()));
                int end = Math.max(0, Math.min(textLen, span.end()));
                if (start >= end) {
                    continue;
                }
                for (int index = start; index < end; index++) {
                    if (incomingReplacesExisting(span, owners[index], policy)) {
                        owners[index] = span;
                    }
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
