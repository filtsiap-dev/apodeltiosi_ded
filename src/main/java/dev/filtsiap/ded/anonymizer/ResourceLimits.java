package dev.filtsiap.ded.anonymizer;

/**
 * The finite bounds every document is processed within (port of {@code limits.py}).
 *
 * <p>Every other bound is a consequence of the input, and an attacker chooses the input: a
 * 20 MB upload cap says nothing about how far the ZIP expands, how many parts it holds, or how
 * many provider calls it costs. Each field closes one of those gaps. Carried on
 * {@link RuntimeConfig#limits()}, overridable through the {@code ANON_*} variable named beside it.
 *
 * <p>The defaults are v2's, calibrated against a real decision from the corpus (166,064 bytes on
 * the wire, 23 members, 1,133,152 bytes expanded, 37,986 characters, 19 chunks), leaving it
 * between eight and sixty times of headroom.
 *
 * @param maxUploadBytes             {@code ANON_MAX_UPLOAD_BYTES}: exactly 20,000,000, not 20 MiB
 * @param maxZipMembers              {@code ANON_MAX_ZIP_MEMBERS}
 * @param maxZipMemberBytes          {@code ANON_MAX_ZIP_MEMBER_BYTES}: one part, expanded; above the
 *                                   upload cap so only a compressed member can trip it
 * @param maxZipTotalBytes           {@code ANON_MAX_ZIP_TOTAL_BYTES}: the whole package, expanded
 * @param maxCompressionRatio        {@code ANON_MAX_COMPRESSION_RATIO}, judged only above the floor
 * @param compressionRatioFloorBytes {@code ANON_COMPRESSION_RATIO_FLOOR_BYTES}: small XML parts
 *                                   legitimately reach 30:1 and higher
 * @param maxTextChars               {@code ANON_MAX_TEXT_CHARS}: extracted text, across every unit;
 *                                   enforced while it is extracted, not after
 * @param maxChunks                  {@code ANON_MAX_CHUNKS}: bounds provider cost directly
 * @param maxXmlBytes                {@code ANON_MAX_XML_BYTES}: the .xml/.rels members, expanded. Every
 *                                   one becomes a DOM, at up to {@link MemoryGate#HEAP_PER_XML_BYTE}
 *                                   bytes of heap per byte, so this, not the package total, bounds a
 *                                   document's memory (Java-only; v2 has no such limit)
 * @param memoryBudgetBytes          {@code ANON_MEMORY_BUDGET_BYTES}: heap the documents in progress
 *                                   may reserve together ({@link MemoryGate}); 0 = 60% of the max heap
 */
public record ResourceLimits(
        long maxUploadBytes,
        long maxZipMembers,
        long maxZipMemberBytes,
        long maxZipTotalBytes,
        double maxCompressionRatio,
        long compressionRatioFloorBytes,
        long maxTextChars,
        long maxChunks,
        long maxXmlBytes,
        long memoryBudgetBytes) {

    public static final ResourceLimits DEFAULTS = new ResourceLimits(
            20_000_000L, 500L, 25_000_000L, 60_000_000L, 50.0, 1_000_000L, 400_000L, 150L, 10_000_000L, 0L);
}
