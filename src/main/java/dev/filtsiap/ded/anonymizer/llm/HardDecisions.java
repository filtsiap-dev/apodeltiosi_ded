package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.Models;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.Resolver;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The hard policy decisions the model is never asked about, code point by code point, and the
 * masked text view every LLM pass reads.
 *
 * <p>A HARD REDACT is a deterministic REDACT that {@link Resolver#isHardRedact} accepts (its
 * category is configured hard-redact AND it meets the high-confidence threshold); nothing else
 * is. Its code points are BLANKED in {@link #maskedView}: one {@link Models#REDACTION_GLYPH} per
 * code point, so every unit keeps its id, location, char map and code-point length, and every
 * coordinate in the view is the same coordinate in the document. The view exists for the model
 * only: the document keeps its own text for the resolver and the write-back, and nothing is
 * serialized or parsed again to make it. Only {@code normalizedText}, the text the passes read,
 * is masked.
 *
 * <p>A HARD PRESERVE ({@link Resolver#isHardPreserve}) is not blanked: it stays readable
 * context. A place it covers entirely is settled all the same ({@link #preserved}).
 *
 * <p>The confirmed OFFICIAL SIGNATORY's name is a hard preserve that is also SHIELDED: readable,
 * but cut out of every question like a mask ({@link #questionable}), so no wider proposal that
 * overlaps it (a pass-1 quote, a shape hint, a post-redaction residual) can put it to pass 2; what
 * is left of such a proposal is still asked, so nothing beside the name escapes.
 */
final class HardDecisions {

    /** No hard decision at all: the view is the document itself. */
    static final HardDecisions NONE = new HardDecisions(Map.of(), Map.of(), Map.of());

    private final Map<String, BitSet> redacted;
    private final Map<String, BitSet> preserved;
    private final Map<String, BitSet> shielded;

    private HardDecisions(Map<String, BitSet> redacted, Map<String, BitSet> preserved, Map<String, BitSet> shielded) {
        this.redacted = redacted;
        this.preserved = preserved;
        this.shielded = shielded;
    }

    /** The rule engine's hard decisions, by the resolver's own predicates. */
    static HardDecisions of(List<Span> deterministicSpans, PolicySettings policy) {
        return of(deterministicSpans, policy, null);
    }

    /**
     * The same, with {@code document} for the units' text: whitespace lying BETWEEN two hard-preserved
     * stretches of a unit then counts as settled too (it is never personal data), so a place made only
     * of kept phrases and the spaces or tabs between them is not a question.
     */
    static HardDecisions of(List<Span> deterministicSpans, PolicySettings policy, DocumentData document) {
        List<Span> hardPreserves = deterministicSpans.stream().filter(s -> Resolver.isHardPreserve(s, policy)).toList();
        return new HardDecisions(
                coverage(deterministicSpans.stream().filter(s -> Resolver.isHardRedact(s, policy)).toList()),
                bridged(coverage(hardPreserves), document), coverage(signatories(hardPreserves)));
    }

    /**
     * Hard decisions CARRIED into another document's coordinates: {@code hardRedacts} and
     * {@code hardPreserves} are the spans the caller already chose with {@link Resolver#isHardRedact}
     * and {@link Resolver#isHardPreserve} and placed in this document's coordinates (the
     * post-redaction re-ask's, see {@code Pipeline}); nothing is re-derived from any text.
     */
    static HardDecisions carried(List<Span> hardRedacts, List<Span> hardPreserves) {
        return carried(hardRedacts, hardPreserves, null);
    }

    /** The same, with {@code document}'s text to settle the whitespace between kept stretches (see {@link #of}). */
    static HardDecisions carried(List<Span> hardRedacts, List<Span> hardPreserves, DocumentData document) {
        return new HardDecisions(coverage(hardRedacts), bridged(coverage(hardPreserves), document),
                coverage(signatories(hardPreserves)));
    }

    /** {@code kept} with every all-whitespace gap between two kept stretches of a unit filled in. */
    private static Map<String, BitSet> bridged(Map<String, BitSet> kept, DocumentData document) {
        if (document == null || kept.isEmpty()) {
            return kept;
        }
        for (TextUnit unit : document.textUnits()) {
            BitSet bits = kept.get(unit.unitId());
            if (bits == null) {
                continue;
            }
            int[] cps = unit.normalizedText().codePoints().toArray();
            int first = bits.nextSetBit(0);
            if (first < 0) {
                continue;
            }
            int gap = bits.nextClearBit(first);
            while (gap < cps.length) {
                int next = bits.nextSetBit(gap);
                if (next < 0) {
                    break;
                }
                boolean blank = true;
                for (int i = gap; i < next && blank; i++) {
                    blank = PyUnicode.isSpace(cps[i]);
                }
                if (blank) {
                    bits.set(gap, next);
                }
                gap = bits.nextClearBit(next);
            }
        }
        return kept;
    }

    private static List<Span> signatories(List<Span> hardPreserves) {
        return hardPreserves.stream().filter(s -> s.category() == SpanCategory.OFFICIAL_SIGNATORY).toList();
    }

    private static Map<String, BitSet> coverage(List<Span> spans) {
        Map<String, BitSet> covered = new HashMap<>();
        for (Span span : spans) {
            int start = Math.max(0, span.start());
            if (span.end() > start) {
                covered.computeIfAbsent(span.unitId(), k -> new BitSet()).set(start, span.end());
            }
        }
        return covered;
    }

    /** How many code points of the document are blanked; for the log line, nothing else. */
    int maskedCodePoints() {
        return redacted.values().stream().mapToInt(BitSet::cardinality).sum();
    }

    /**
     * The document as the model may see it: every hard-redacted code point of every unit's
     * {@code normalizedText} replaced by the redaction glyph, everything else identical.
     */
    DocumentData maskedView(DocumentData document) {
        if (redacted.isEmpty()) {
            return document;
        }
        List<TextUnit> units = new ArrayList<>();
        for (TextUnit unit : document.textUnits()) {
            BitSet mask = redacted.get(unit.unitId());
            if (mask == null || mask.isEmpty()) {
                units.add(unit);
                continue;
            }
            units.add(new TextUnit(unit.unitId(), unit.partName(), unit.unitType(), unit.text(),
                    mask(unit.normalizedText(), mask), unit.charMap(), unit.location()));
        }
        return new DocumentData(document.documentId(), units, document.partsInventory(), document.warnings());
    }

    private static String mask(String text, BitSet mask) {
        StringBuilder out = new StringBuilder(text.length());
        int index = 0;
        for (int offset = 0; offset < text.length(); ) {
            int codePoint = text.codePointAt(offset);
            if (mask.get(index)) {
                out.append(Models.REDACTION_GLYPH);
            } else {
                out.appendCodePoint(codePoint);
            }
            offset += Character.charCount(codePoint);
            index++;
        }
        return out.toString();
    }

    /**
     * The contiguous parts of {@code slice} that are not blanked, in text order, each in the
     * same unit's coordinates: the whole slice when nothing in it is masked, nothing when all of
     * it is.
     */
    List<UnitSlice> unmasked(UnitSlice slice) {
        return clear(slice, redacted.get(slice.unitId()));
    }

    /**
     * The contiguous parts of {@code slice} that may be a question at all: neither blanked nor the
     * shielded signatory name. Equal to {@link #unmasked} wherever no signatory is involved.
     */
    List<UnitSlice> questionable(UnitSlice slice) {
        BitSet shield = shielded.get(slice.unitId());
        if (shield == null) {
            return unmasked(slice);
        }
        BitSet excluded = (BitSet) shield.clone();
        BitSet mask = redacted.get(slice.unitId());
        if (mask != null) {
            excluded.or(mask);
        }
        return clear(slice, excluded);
    }

    /** The contiguous parts of {@code slice} that are the shielded signatory name (and not blanked), in text order. */
    List<UnitSlice> shieldedParts(UnitSlice slice) {
        BitSet shield = shielded.get(slice.unitId());
        List<UnitSlice> parts = new ArrayList<>();
        if (shield == null) {
            return parts;
        }
        for (UnitSlice part : unmasked(slice)) {
            parts.addAll(set(part, shield));
        }
        return parts;
    }

    private static List<UnitSlice> clear(UnitSlice slice, BitSet mask) {
        if (mask == null || mask.nextSetBit(slice.start()) < 0 || mask.nextSetBit(slice.start()) >= slice.end()) {
            return List.of(slice);
        }
        List<UnitSlice> parts = new ArrayList<>();
        int position = slice.start();
        while (position < slice.end()) {
            int from = mask.nextClearBit(position);
            if (from >= slice.end()) {
                break;
            }
            int next = mask.nextSetBit(from);
            int to = next < 0 ? slice.end() : Math.min(next, slice.end());
            parts.add(new UnitSlice(slice.unitId(), from, to));
            position = to;
        }
        return parts;
    }

    private static List<UnitSlice> set(UnitSlice slice, BitSet mask) {
        List<UnitSlice> parts = new ArrayList<>();
        if (mask == null) {
            return parts;
        }
        int position = slice.start();
        while (position < slice.end()) {
            int from = mask.nextSetBit(position);
            if (from < 0 || from >= slice.end()) {
                break;
            }
            int to = Math.min(mask.nextClearBit(from), slice.end());
            parts.add(new UnitSlice(slice.unitId(), from, to));
            position = to;
        }
        return parts;
    }

    /**
     * The contiguous parts of {@code slice} that ARE blanked, in text order: the complement of
     * {@link #unmasked} within it, so the two together cover the slice exactly.
     */
    List<UnitSlice> masked(UnitSlice slice) {
        return set(slice, redacted.get(slice.unitId()));
    }

    /** Whether hard policy preserves every code point of {@code slice}: then nothing in it is a question. */
    boolean preserved(UnitSlice slice) {
        BitSet kept = preserved.get(slice.unitId());
        if (kept == null || slice.end() <= slice.start()) {
            return false;
        }
        return kept.nextClearBit(slice.start()) >= slice.end();
    }
}
