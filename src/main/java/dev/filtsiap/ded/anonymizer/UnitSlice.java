package dev.filtsiap.ded.anonymizer;

/**
 * One exact slice of one text unit: {@code (unit_id, start, end)} in code points (port of
 * {@code Location} in {@code llm/detector.py}). The coordinates the detectors, the pass-2 queue and
 * the resolver all use; carrying them is what makes an answer applicable without a text search.
 */
public record UnitSlice(String unitId, int start, int end) {
}
