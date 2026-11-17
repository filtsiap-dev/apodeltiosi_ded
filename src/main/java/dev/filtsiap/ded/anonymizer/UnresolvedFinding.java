package dev.filtsiap.ded.anonymizer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One thing the LLM stage could not settle, or settled in a way a person must confirm, described
 * without quoting it (port of {@code UnresolvedFinding} in {@code models.py}).
 *
 * <p>These are why a document comes back {@code needs-review}. The undecided kinds are NOT pass-2
 * decisions: pass 2 writes nothing for them and they never become a pass-2 PRESERVE; the text is
 * covered by whatever ordinary deterministic evidence reaches it, or, where pass 1 had decided that
 * place, by pass 1's decision as the documented fallback (the detail says so), and a person is told
 * where to look. The two {@code HIGH_RESIDUAL_*} kinds are the opposite case: pass 2 DID answer, and the
 * document carries that answer, but a HIGH post-redaction finding is still visible in it, so the
 * finding is kept in front of a person rather than closed by the model's word alone.
 *
 * <p>CARRIES NO DOCUMENT TEXT, EVER: {@code locations} says where, {@code category} what it was
 * thought to be, {@code audit} which scan finding it came from. It reaches logs, the CLI and (as a
 * count) an HTTP header.
 *
 * @param chunkIndex  0-based chunk; {@link #chunkNumber()} is the 1-based form people read; -1 when
 *                    the finding was never placed in a chunk
 * @param category    the category it was thought to be, or null when that was the unusable part
 * @param locations   every slice a reviewer should look at; empty when it could not be located
 * @param candidateId the transient {@code C<n>} handle, meaningful only within its chunk's logs
 * @param detail      a short machine-written phrase: counts, ids and kinds only
 * @param audit       the post-redaction scan findings behind it; empty outside the remediation
 */
public record UnresolvedFinding(int chunkIndex, Kind kind, String category, List<UnitSlice> locations,
                                String candidateId, String detail, List<AuditRef> audit) {

    /** Why a finding was left for a person. */
    public enum Kind {
        /** Discovery did not provide complete usable coverage of this chunk. */
        DISCOVERY_INCOMPLETE("discovery_incomplete"),
        /** A queued candidate came back with no final decision, even after the corrective retry. */
        CANDIDATE_UNDECIDED("candidate_undecided"),
        /** The final response answered one id twice, so every answer for it was voided. */
        CANDIDATE_DUPLICATED("candidate_duplicated"),
        /**
         * A span pass 2 found for itself was re-asked by id and still came back undecided. No longer
         * produced (pass 2 adjudicates its candidates only); kept so the wire vocabulary is stable.
         */
        DISCOVERY_UNDECIDED("discovery_undecided"),
        /** Pass 2 returned the same new text twice with different answers. No longer produced, as above. */
        DISCOVERY_CONFLICTING("discovery_conflicting"),
        /** A new finding with no usable action or category. No longer produced, as above. */
        DISCOVERY_MALFORMED("discovery_malformed"),
        /**
         * A usable discovery finding whose text is not in the excerpt (a pass-1 finding the rendered
         * chunk cannot place): nowhere to write it, no id to ask pass 2 by.
         */
        DISCOVERY_UNLOCATABLE("discovery_unlocatable"),
        /**
         * A HIGH post-redaction finding that the remediation's pass 2 answered PRESERVE. The
         * document keeps it visible, as pass 2 decided, and a person must confirm that.
         */
        HIGH_RESIDUAL_PRESERVED("high_residual_preserved"),
        /**
         * A HIGH post-redaction finding that is still visible although pass 2 did not preserve
         * it: the REDACT it answered did not cover the whole value (hard policy kept part of it),
         * or hard policy keeps it so it was never a question, or the finding could not be put to
         * pass 2 at all, or the final scan of the returned bytes still sees it.
         */
        HIGH_RESIDUAL_UNREDACTED("high_residual_unredacted"),
        /**
         * A pass-2 question pass 2 could not answer: the provider was still failing after its retries
         * (or never produced a usable reading). One per candidate, with its own id and locations; the
         * detail names the cause, the recommendations, and the fallback applied (or that none could
         * be). Never a pass-2 decision; a person must confirm what the fallback did.
         */
        PASS2_UNAVAILABLE("pass2_unavailable"),
        /**
         * A pass-1 REDACT applied without a pass-2 question whose quote narrows to no redactable value
         * (only a label, punctuation or a public region): it was not applied, and is never dropped
         * silently.
         */
        PASS1_REDACT_UNREPRESENTABLE("pass1_redact_unrepresentable");

        private final String wire;

        Kind(String wire) {
            this.wire = wire;
        }

        public String wire() {
            return wire;
        }
    }

    /**
     * Which post-redaction scan finding a remediation question came from: its id in scan order
     * ({@code P3} is the third INITIAL scan finding; {@code F3} is the third FINAL scan finding), its
     * severity, its kind and its {@code part:unit} location. Ids and kinds only, never the text.
     */
    public record AuditRef(String findingId, PostcheckFinding.Severity severity, String kind, String location) {
        public String phase() {
            return findingId.startsWith("F") ? "final_scan" : "initial_scan";
        }
    }

    public UnresolvedFinding {
        locations = List.copyOf(locations);
        audit = List.copyOf(audit);
    }

    /** A finding with no post-redaction provenance. */
    public UnresolvedFinding(int chunkIndex, Kind kind, String category, List<UnitSlice> locations,
                             String candidateId, String detail) {
        this(chunkIndex, kind, category, locations, candidateId, detail, List.of());
    }

    /** The same finding, with the scan findings it came from. */
    public UnresolvedFinding withAudit(List<AuditRef> refs) {
        return new UnresolvedFinding(chunkIndex, kind, category, locations, candidateId, detail, refs);
    }

    /** The chunk as a person counts it: 1-based, like every other report. */
    public int chunkNumber() {
        return chunkIndex + 1;
    }

    /** This finding with snake_case keys, for {@code --summary-json}: ids, kinds and offsets only. */
    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("chunk", chunkIndex < 0 ? null : chunkNumber());
        m.put("kind", kind.wire());
        m.put("category", category);
        m.put("locations", locations.stream().map(l -> {
            Map<String, Object> at = new LinkedHashMap<>();
            at.put("unit", l.unitId());
            at.put("start", l.start());
            at.put("end", l.end());
            return at;
        }).toList());
        m.put("candidate_id", candidateId);
        m.put("phase", audit.isEmpty() ? "initial_llm" : audit.getFirst().phase().equals("final_scan")
                ? "final_scan" : "remediation");
        m.put("detail", detail);
        m.put("audit", audit.stream().map(a -> {
            Map<String, Object> ref = new LinkedHashMap<>();
            ref.put("finding_id", a.findingId());
            ref.put("scan_phase", a.phase());
            ref.put("severity", a.severity().name());
            ref.put("kind", a.kind());
            ref.put("location", a.location());
            return ref;
        }).toList());
        return m;
    }
}
