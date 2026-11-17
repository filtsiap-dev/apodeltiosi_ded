package dev.filtsiap.ded.anonymizer.chat;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Applies spans as a UNION: a code point inside any span is masked, whoever proposed it. There is
 * no arbitration here on purpose: chat has no adjudicator that could discard a proposal, and a
 * missed identifier costs more than an extra mask, so every proposal counts (recall first).
 */
public final class Masker {
    /** The code point that replaces a masked one. */
    public static final int MASK = '.';

    private Masker() {
    }

    /**
     * Every non-whitespace code point inside any span becomes '.'; the code-point length is unchanged.
     *
     * @param text  the text to mask
     * @param spans the code-point ranges to mask; they may overlap, and a range past the end is clipped
     * @return the masked text
     */
    public static String mask(String text, List<ChatSpan> spans) {
        int[] cps = text.codePoints().toArray();
        for (ChatSpan s : spans) {
            int end = Math.min(s.end(), cps.length);
            for (int i = s.start(); i < end; i++) {
                if (!Character.isWhitespace(cps[i])) {
                    cps[i] = MASK;
                }
            }
        }
        return new String(cps, 0, cps.length);
    }

    /**
     * Per type, the number of separate regions: overlapping or touching spans of one type count once.
     *
     * @param spans the spans that were masked
     * @return the region count of every type that has one
     */
    public static Map<PiiType, Integer> counts(List<ChatSpan> spans) {
        Map<PiiType, List<ChatSpan>> byType = new EnumMap<>(PiiType.class);
        for (ChatSpan s : spans) {
            if (s.end() > s.start()) {
                byType.computeIfAbsent(s.type(), k -> new ArrayList<>()).add(s);
            }
        }
        Map<PiiType, Integer> counts = new EnumMap<>(PiiType.class);
        byType.forEach((type, list) -> {
            list.sort(Comparator.comparingInt(ChatSpan::start));
            int regions = 0;
            int reach = -1;
            for (ChatSpan s : list) {
                if (s.start() > reach) {
                    regions++;
                }
                reach = Math.max(reach, s.end());
            }
            counts.put(type, regions);
        });
        return counts;
    }

    /**
     * {@code PERSON=2,AFM=1} in {@link PiiType} declaration order, or {@code none}.
     *
     * @param counts the region counts from {@link #counts}
     * @return the {@code x-redaction-counts} header value
     */
    public static String countsHeader(Map<PiiType, Integer> counts) {
        if (counts.isEmpty()) {
            return "none";
        }
        StringJoiner joined = new StringJoiner(",");
        new EnumMap<>(counts).forEach((type, n) -> joined.add(type.name() + "=" + n));
        return joined.toString();
    }
}
