package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.Resolver;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanTrim;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.SpanOrigin;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.UnresolvedFinding;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The pass-2 decision queue: candidates, the strict validation of an answer to them, and the
 * spans an accepted answer writes (port of the queue half of {@code llm/detector.py}).
 *
 * <p>A CANDIDATE CARRIES ITS LOCATIONS. Every proposal's exact {@code (unit_id, start, end)} is
 * kept here; the model is shown a transient id, the candidate's text, every source's
 * recommendation and 40 code points of the MASKED rendered chunk either side, and nothing else,
 * and it answers BY ID. The answer is then written back by looking the id up, never by searching
 * for text. The only text search left locates a pass-1 finding, which arrives as a bare string,
 * once, when the queue is built, in the rendered chunk pass 1 read.
 *
 * <p>DEDUPLICATION IS DONE HERE, EXACTLY; the model is never asked to merge anything. Two
 * locations share one candidate only when their whole question (text, recommendations, both
 * context windows) is identical, so the same digits in an authority header and in the
 * appellant's details stay two questions with two answers.
 *
 * <p>ELIGIBILITY IS DECIDED AFTER THE MERGE. Every proposal is located, cut free of the hard
 * redactions the model cannot see ({@link HardDecisions#unmasked}), and merged location by
 * location first; only then is a place left out because hard policy has settled it, or because
 * nobody proposed anything but PRESERVE for it. A PRESERVE that disagrees with a REDACT or a
 * REVIEW at the same place stays, as the disagreement it is.
 *
 * <p>THE FIRST ADJUDICATION IS ROUTED ({@link #route}), ONE DOCUMENT-WIDE QUEUE. A place becomes a
 * question when a source said REVIEW, when the rules' own decision and pass 1's disagree (found by
 * cutting each pass-1 quote into ATOMIC INTERVALS against the rule spans, exact coordinates only), or
 * when a rule REDACT has no pass-1 decision over its whole place: every actionable candidate gets an
 * LLM decision, pass 1's or pass 2's. Hard decisions are never questions. A pass-1 decision that is not
 * a question is applied as an {@link SpanOrigin#LLM_PASS1} span, and the rules' spans still go to the
 * resolver as evidence (and as the documented fallback). The questions of every chunk are then folded
 * into one queue ({@link #consolidate}) with stable ids and split into bounded batches ({@link #batches});
 * a question the document-wide {@link DecisionRegistry} already answers is not asked.
 * {@link #build} is the post-redaction re-ask's queue.
 */
final class Pass2Queue {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.llm.detector");

    /** Code points of document text sent on each side of a candidate: a contract with the prompt. */
    static final int CONTEXT_WINDOW = 40;
    /** A text shorter than this is only ever matched as a standalone token. */
    static final int STANDALONE_ONLY_BELOW = 4;
    /** Every pass-2 span's confidence: the model does not score its answers. */
    static final double LLM_CONFIDENCE = 0.9;
    private static final PyPattern CANDIDATE_ID_RE = PyRegex.compile("^C\\d+$");

    private Pass2Queue() {
    }

    // ------------------------------------------------------------------ the candidate model

    /**
     * One source's opinion. Only the post-redaction re-ask fills the last two: {@code check} is the
     * scan pattern that flagged the place, {@code text} the stretch an earlier recommendation was
     * about when it is not exactly the candidate's. Both stay out of the payload when null, so the
     * first adjudication is unchanged.
     */
    record Recommendation(List<String> sources, SpanAction action, SpanCategory category, String check, String text) {
        Recommendation {
            sources = List.copyOf(sources);
        }

        Recommendation(List<String> sources, SpanAction action, SpanCategory category) {
            this(sources, action, category, null, null);
        }

        Map<String, Object> asPayload() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("sources", sources);
            m.put("action", action.wire());
            m.put("category", category == null ? null : category.wire());
            if (check != null) {
                m.put("check", check);
            }
            if (text != null) {
                m.put("text", text);
            }
            return m;
        }
    }

    /**
     * One question put to pass 2, and every location the answer applies to. {@code category} is
     * the fallback for an off-schema answer (the first recommendation's, so the rules outrank
     * pass 1). {@code chunkIndex} is the chunk its first location came from (-1 when the queue is
     * one chunk's own, as the post-redaction re-ask's is), and {@code fallback} what the place gets
     * if pass 2 cannot be had for it (null: the re-ask, which has none).
     */
    record Candidate(String id, String text, SpanCategory category, List<Recommendation> recommendations,
                     List<UnitSlice> locations, String before, String after, int chunkIndex, Fallback fallback) {
        Candidate {
            recommendations = List.copyOf(recommendations);
            locations = List.copyOf(locations);
        }

        Candidate(String id, String text, SpanCategory category, List<Recommendation> recommendations,
                  List<UnitSlice> locations, String before, String after) {
            this(id, text, category, recommendations, locations, before, after, -1, null);
        }

        /** Whether this still maps to usable slices; checked before a decision for it is accepted. */
        boolean hasLocation() {
            return !text.isEmpty() && !locations.isEmpty()
                    && locations.stream().allMatch(l -> !l.unitId().isEmpty() && l.end() > l.start());
        }

        /** One CANDIDATES entry. Locations, and how many there are, are deliberately not sent. */
        Map<String, Object> asPayload() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("text", text);
            m.put("recommendations", recommendations.stream().map(Recommendation::asPayload).toList());
            m.put("before", before);
            m.put("after", after);
            return m;
        }
    }

    /**
     * One chunk's queue: the candidates to ask about, and the usable pass-1 findings that could
     * not be located in the excerpt at all (nowhere to write them, nothing to ask by id).
     */
    record Queue(List<Candidate> candidates, List<LlmDetector.Finding> unlocated) {
        Queue {
            candidates = List.copyOf(candidates);
            unlocated = List.copyOf(unlocated);
        }
    }

    /** A validated answer addressed to a candidate by id; REVIEW was coerced to REDACT when {@code coerced}. */
    record Decision(String candidateId, SpanCategory category, SpanAction action, boolean coerced) {
    }

    /**
     * What one pass-2 response yielded and everything wrong with it: {@code voided} ids were
     * answered more than once (every answer discarded), and {@code distrusted} means an entry
     * belonged to no candidate at all.
     */
    record Validation(List<Decision> decisions, List<String> rejections, List<String> voided, boolean distrusted) {
    }

    // ------------------------------------------------------------------ locating text

    /**
     * The rendered text immediately around one location, cut to the window and to the location's own
     * block (its table, when the work item holds several); ("", "") when unplaced.
     */
    static String[] windowsAt(Chunk.Rendered rendered, UnitSlice location) {
        Integer origin = rendered.offsets().get(location.unitId());
        if (origin == null) {
            return new String[] {"", ""};
        }
        int position = origin + location.start();
        int tail = position + (location.end() - location.start());
        Chunk.Rendered.Range block = rendered.blockAt(position);
        return new String[] {
            PyStr.slice(rendered.text(), Math.max(block.start(), position - CONTEXT_WINDOW), position),
            PyStr.slice(rendered.text(), tail, Math.min(block.end(), tail + CONTEXT_WINDOW))};
    }

    /**
     * Whether {@code text} occurs in the rendering and EVERY occurrence lies wholly inside a read-only
     * context line (a table's title or a repeated header): the model quoted the copy, whose real text is
     * judged where it stands, in its own place. Nothing is written for such a quote, and it is not a
     * finding with nowhere to go either.
     */
    static boolean onlyInContext(Chunk.Rendered rendered, String text) {
        if (text.isEmpty() || rendered.contexts().isEmpty()) {
            return false;
        }
        String haystack = rendered.text();
        int position = 0;
        boolean any = false;
        while (true) {
            int start = PyStr.find(haystack, text, position);
            if (start == -1) {
                return any;
            }
            int end = start + PyStr.len(text);
            if (!rendered.inContext(start, end)) {
                return false;
            }
            any = true;
            position = start + 1;
        }
    }

    private static boolean standalone(String haystack, int start, int end) {
        String before = start > 0 ? PyStr.charAt(haystack, start - 1) : "";
        String after = end < PyStr.len(haystack) ? PyStr.charAt(haystack, end) : "";
        return !((!before.isEmpty() && PyStr.isAlnum(before)) || (!after.isEmpty() && PyStr.isAlnum(after)));
    }

    /**
     * Locates a pass-1 finding in the RENDERED chunk pass 1 read, then maps it back through the
     * segments, so a quote across a paragraph break or a table " | " becomes one slice per unit
     * rather than being lost. Every occurrence is returned. Empty means nowhere to write it.
     */
    static List<UnitSlice> locateInRendered(Chunk.Rendered rendered, String text) {
        return occurrencesInRendered(rendered, text).stream().flatMap(List::stream).toList();
    }

    /** The same search, one entry per OCCURRENCE (each its slices, one per unit it touches). */
    static List<List<UnitSlice>> occurrencesInRendered(Chunk.Rendered rendered, String text) {
        if (text.isEmpty()) {
            return List.of();
        }
        String haystack = rendered.text();
        boolean standaloneOnly = PyStr.len(text) < STANDALONE_ONLY_BELOW;
        List<List<UnitSlice>> found = new ArrayList<>();
        int position = 0;
        while (true) {
            int start = PyStr.find(haystack, text, position);
            if (start == -1) {
                break;
            }
            int end = start + PyStr.len(text);
            if (standaloneOnly && !standalone(haystack, start, end)) {
                position = start + 1;
                continue;
            }
            List<UnitSlice> slices = rendered.locate(start, end);
            if (!slices.isEmpty()) {
                found.add(slices);
            }
            position = end;
        }
        if (found.isEmpty()) {
            List<UnitSlice> loose = looseOccurrence(rendered, text, standaloneOnly);
            if (loose != null) {
                found.add(loose);
            }
        }
        return found;
    }

    /**
     * The fallback when a quote is not in the rendering as written: the same words, with any run of whitespace
     * (spaces, tabs, line breaks) in the quote matching any run in the rendering, at the rendering's own
     * offsets. A model often re-spaces what it copies ("Α  \tΒ" for "Α \tΒ"). Taken only when exactly ONE
     * place fits: a quote that fits several is never guessed at, and stays unplaced.
     */
    private static List<UnitSlice> looseOccurrence(Chunk.Rendered rendered, String text, boolean standaloneOnly) {
        List<String> words = PyStr.split(text);
        if (words.isEmpty()) {
            return null;
        }
        String pattern = String.join("\\s+", words.stream().map(PyRegex::escape).toList());
        String haystack = rendered.text();
        List<UnitSlice> only = null;
        for (PyRegex.PyMatch m : PyRegex.compile(pattern, 0).finditer(haystack)) {
            if (standaloneOnly && !standalone(haystack, m.start(), m.end())) {
                continue;
            }
            List<UnitSlice> slices = rendered.locate(m.start(), m.end());
            if (slices.isEmpty()) {
                continue; // read-only context: nothing to write there
            }
            if (only != null) {
                return null; // a second place fits: ambiguous
            }
            only = slices;
        }
        return only;
    }

    // ------------------------------------------------------------------ building the queue

    /** One proposal's question; {@code check} is the scan pattern behind a post-redaction residual, else null. */
    private record Pair(SpanAction action, SpanCategory category, String check) {
    }

    private static final String POSTCHECK_DETECTOR_PREFIX = "postcheck_";

    /** One source's proposals grouped by exact location, exact repeats of a pair collapsed. */
    private static Map<UnitSlice, List<Pair>> collectByLocation(List<Map.Entry<UnitSlice, Pair>> proposals) {
        Map<UnitSlice, List<Pair>> pairs = new LinkedHashMap<>();
        for (Map.Entry<UnitSlice, Pair> p : proposals) {
            List<Pair> atLocation = pairs.computeIfAbsent(p.getKey(), k -> new ArrayList<>());
            if (!atLocation.contains(p.getValue())) {
                atLocation.add(p.getValue());
            }
        }
        return pairs;
    }

    /**
     * A pair both sources produced is one recommendation naming both; disagreement stays two.
     * {@code proposedBy} names the located proposals: "deterministic" for the rule engine, "postcheck"
     * for the post-redaction audit's findings, so one builder serves both queues.
     */
    private static List<Recommendation> mergeRecommendations(List<Pair> deterministic, List<Pair> pass1,
                                                             String proposedBy) {
        Map<Pair, List<String>> sources = new LinkedHashMap<>();
        for (Map.Entry<String, List<Pair>> source : List.of(Map.entry(proposedBy, deterministic),
                Map.entry("pass1", pass1))) {
            for (Pair pair : source.getValue()) {
                List<String> names = sources.computeIfAbsent(pair, k -> new ArrayList<>());
                if (!names.contains(source.getKey())) {
                    names.add(source.getKey());
                }
            }
        }
        List<Recommendation> recommendations = new ArrayList<>();
        sources.forEach((pair, names) -> recommendations.add(new Recommendation(names, pair.action(), pair.category(),
                pair.check(), null)));
        return recommendations;
    }

    /** Whether a place is a question at all: somebody proposed a REDACT or could not decide. */
    private static boolean asksForADecision(List<Recommendation> recommendations) {
        return recommendations.stream().anyMatch(r -> r.action() == SpanAction.REDACT || r.action() == SpanAction.REVIEW);
    }

    /** The whole question as pass 2 sees it; two locations share a candidate only on an exact match. */
    private record Identity(String text, List<Recommendation> recommendations, String before, String after) {
    }

    /**
     * The chunk's pass-2 queue. {@code chunk} and {@code rendered} are the MASKED view, the text the
     * model reads; {@code hard} is what masked it. Hard decisions must already be filtered out of the
     * spans. Five exact stages: the deterministic spans (already located) cut free of the masks and
     * deduplicated among themselves; the pass-1 findings located in the rendered chunk, cut the same
     * way and deduplicated among themselves; a merge location by location; the eligibility filter;
     * and a grouping of locations whose entire question is identical into one candidate.
     */
    static Queue build(Chunk chunk, List<Span> deterministicSpans, List<Span> reviewHints,
                       List<LlmDetector.Finding> findings, Chunk.Rendered rendered, HardDecisions hard) {
        return build(chunk, deterministicSpans, reviewHints, findings, rendered, hard, "deterministic", List.of());
    }

    /**
     * The same queue, its located proposals labelled {@code source} in the payload. The post-redaction
     * re-ask passes "postcheck" and the first adjudication's {@code evidence}: every earlier
     * recommendation whose slice overlaps a location is added to that location's question, with the
     * text it was about when that is not exactly the candidate's (read from THIS chunk's units, so a
     * redacted stretch shows as the dots it now is). Exact coordinates; nothing is searched for.
     */
    static Queue build(Chunk chunk, List<Span> deterministicSpans, List<Span> reviewHints,
                       List<LlmDetector.Finding> findings, Chunk.Rendered rendered, HardDecisions hard, String source,
                       List<LlmDetector.Evidence> evidence) {
        Map<String, TextUnit> unitsById = new LinkedHashMap<>();
        chunk.units().forEach(u -> unitsById.put(u.unitId(), u));

        List<Map.Entry<UnitSlice, Pair>> deterministic = new ArrayList<>();
        List<Span> located = new ArrayList<>(deterministicSpans);
        located.addAll(reviewHints);
        for (Span span : located) {
            if (unitsById.containsKey(span.unitId())) {
                String check = span.detector().startsWith(POSTCHECK_DETECTOR_PREFIX)
                        ? PyStr.sliceFrom(span.detector(), PyStr.len(POSTCHECK_DETECTOR_PREFIX)) : null;
                Pair pair = new Pair(span.action(), span.category(), check);
                // What a hard redaction already blanked is not a question; what is left of the span still is.
                for (UnitSlice part : hard.questionable(new UnitSlice(span.unitId(), span.start(), span.end()))) {
                    deterministic.add(Map.entry(part, pair));
                }
            }
        }
        Map<UnitSlice, List<Pair>> deterministicPairs = collectByLocation(deterministic);

        List<Map.Entry<UnitSlice, Pair>> pass1 = new ArrayList<>();
        List<LlmDetector.Finding> unlocated = new ArrayList<>();
        for (LlmDetector.Finding finding : findings) {
            List<UnitSlice> at = locateInRendered(rendered, finding.text());
            if (at.isEmpty() && onlyInContext(rendered, finding.text())) {
                continue; // a quote of read-only context: the copied text is judged where it really stands
            }
            if (at.isEmpty()) {
                // A usable finding with nowhere to be written: carried out for a person, never dropped.
                LOG.warn("pass-1 finding matched nothing in the excerpt ({} chars); retained as unresolved",
                        PyStr.len(finding.text()));
                if (!unlocated.contains(finding)) {
                    unlocated.add(finding);
                }
                continue;
            }
            Pair pair = new Pair(finding.action(), finding.category(), null);
            int parts = 0;
            for (UnitSlice location : at) {
                for (UnitSlice part : hard.questionable(location)) {
                    pass1.add(Map.entry(part, pair));
                    parts++;
                }
            }
            if (parts == 0) {
                LOG.debug("a pass-1 finding lies wholly inside hard redactions; nothing in it is a question");
            }
        }
        Map<UnitSlice, List<Pair>> pass1Pairs = collectByLocation(pass1);

        List<UnitSlice> merged = new ArrayList<>(deterministicPairs.keySet());
        pass1Pairs.keySet().stream().filter(l -> !deterministicPairs.containsKey(l)).forEach(merged::add);

        Map<Identity, List<UnitSlice>> grouped = new LinkedHashMap<>();
        int settled = 0;
        int preserveOnly = 0;
        for (UnitSlice location : merged) {
            // The unit's own slice is the authority on what sits at this location.
            String unitText = unitsById.get(location.unitId()).normalizedText();
            String text = PyStr.slice(unitText, location.start(), location.end());
            if (text.isEmpty()) {
                LOG.debug("dropping a candidate whose location holds no text");
                continue;
            }
            List<Recommendation> recommendations = mergeRecommendations(
                    deterministicPairs.getOrDefault(location, List.of()), pass1Pairs.getOrDefault(location, List.of()),
                    source);
            for (LlmDetector.Evidence e : evidence) {
                UnitSlice at = e.location();
                if (!at.unitId().equals(location.unitId()) || at.end() <= location.start() || location.end() <= at.start()) {
                    continue;
                }
                Recommendation earlier = new Recommendation(e.sources(), e.action(), e.category(), null,
                        at.equals(location) ? null : PyStr.slice(unitText, at.start(), at.end()));
                if (!recommendations.contains(earlier)) {
                    recommendations.add(earlier);
                }
            }
            // Eligibility, on the merged question: hard policy has the last word on a place it covers
            // whole, and a place only PRESERVE was proposed for asks nothing.
            if (hard.preserved(location)) {
                settled++;
                continue;
            }
            if (!asksForADecision(recommendations)) {
                preserveOnly++;
                continue;
            }
            String[] window = windowsAt(rendered, location);
            grouped.computeIfAbsent(new Identity(text, recommendations, window[0], window[1]),
                    k -> new ArrayList<>()).add(location);
        }
        if (settled + preserveOnly > 0) {
            LOG.debug("pass-2 queue: {} place(s) settled by hard policy and {} with only PRESERVE proposed were not "
                    + "queued", settled, preserveOnly);
        }

        List<Candidate> candidates = new ArrayList<>();
        grouped.forEach((identity, locations) -> candidates.add(new Candidate("C" + (candidates.size() + 1),
                identity.text(), identity.recommendations().get(0).category(), identity.recommendations(), locations,
                identity.before(), identity.after())));
        int folded = candidates.stream().mapToInt(c -> c.locations().size()).sum() - candidates.size();
        if (folded > 0) {
            LOG.debug("pass-2 queue: {} location(s) folded into identical candidates", folded);
        }
        return new Queue(candidates, unlocated);
    }

    // ------------------------------------------------------------------ routing the first adjudication

    /** Every pass-1 span's confidence: the model does not score its answers, and pass 1 ranks below pass 2. */
    static final double PASS1_CONFIDENCE = 0.8;
    static final String PASS1_DETECTOR = "llm_pass1";
    static final String PASS1_FALLBACK_DETECTOR = "llm_pass1_fallback";

    /**
     * What a queued place gets when pass 2 cannot be had for it, decided when the place is routed,
     * from the same evidence and never from text. {@code pass1} is the pass-1 decision applied as an
     * {@link SpanOrigin#LLM_PASS1} span (with {@code pass1Category}), or null when the rules' own spans,
     * which reach the resolver anyway, settle the place. {@code deterministic} is what the ordinary
     * deterministic ladder alone makes of it (null: nothing it can claim). {@code conflict} marks a
     * pass-1 PRESERVE that the rules' REDACT overrides.
     *
     * <p>The table: a pass-1 REDACT is applied; a pass-1 PRESERVE against an effective rule REDACT is
     * not (the REDACT stands, flagged); with no pass-1 decision the rules decide by their ladder; a
     * pass-1 PRESERVE with no rule REDACT is applied; only REVIEW leaves the place undecided.
     */
    record Fallback(SpanAction pass1, SpanCategory pass1Category, SpanAction deterministic, boolean conflict) {

        static Fallback of(SpanAction pass1Decision, SpanCategory pass1Category, SpanAction deterministic) {
            if (pass1Decision == SpanAction.REDACT) {
                return new Fallback(SpanAction.REDACT, pass1Category, deterministic, false);
            }
            if (pass1Decision == SpanAction.PRESERVE && deterministic == SpanAction.REDACT) {
                return new Fallback(null, null, deterministic, true);
            }
            if (pass1Decision == SpanAction.PRESERVE) {
                return new Fallback(SpanAction.PRESERVE, pass1Category, deterministic, false);
            }
            return new Fallback(null, null, deterministic, false);
        }

        /** The action the place ends up with under the fallback; null leaves it undecided. */
        SpanAction finalAction() {
            return pass1 != null ? pass1 : deterministic;
        }
    }

    /** One routed place still needing pass 2, before it has an id: where, what is asked, and its fallback. */
    record Question(int chunkIndex, UnitSlice location, String text, List<Recommendation> recommendations,
                    String before, String after, Fallback fallback) {
        Question {
            recommendations = List.copyOf(recommendations);
        }
    }

    /** How a chunk was routed; counts for the log line, nothing else. */
    record RouteCounts(int agreed, int pass1Only, int deterministicOnly, int questions, int settled, int redundant) {
        RouteCounts plus(RouteCounts o) {
            return new RouteCounts(agreed + o.agreed, pass1Only + o.pass1Only, deterministicOnly + o.deterministicOnly,
                    questions + o.questions, settled + o.settled, redundant + o.redundant);
        }
    }

    /**
     * One chunk, routed. {@code pass1Spans}: pass-1 decisions applied without a question (the rules'
     * own spans reach the resolver unchanged, from the caller). {@code questions}: what pass 2 must
     * decide. {@code unlocated}: usable pass-1 findings with nowhere to be written. {@code unresolved}:
     * pass-1 REDACTs that cannot be represented. {@code evidence}: every place carrying a REDACT or
     * REVIEW recommendation, with what was recommended there.
     */
    record Routed(List<Span> pass1Spans, List<Question> questions, List<LlmDetector.Finding> unlocated,
                  List<UnresolvedFinding> unresolved, List<LlmDetector.Evidence> evidence, RouteCounts counts) {
    }

    /**
     * One located proposal, cut free of the masks: a rule span or review hint ({@code span}), or a
     * pass-1 finding. {@code repeated}: a pass-1 finding whose text occurs more than once in the
     * chunk. Pass 1 answers once per TEXT, so where such a finding is not confirmed by the rules, which
     * occurrence it meant is unknown: that place is a question, never a decision by text alone.
     * {@code occurrence} names the pass-1 occurrence a part was cut from (its first located slice; null
     * for a rule span), and {@code masked} says hard policy blanked part of that occurrence: a quote is
     * judged whole, so a leftover label beside a masked value is not a redaction that went missing.
     */
    private record Proposal(UnitSlice part, Span span, SpanAction action, SpanCategory category, boolean pass1,
                            boolean repeated, UnitSlice occurrence, boolean masked) {
        Pair pair() {
            String check = span != null && span.detector().startsWith(POSTCHECK_DETECTOR_PREFIX)
                    ? PyStr.sliceFrom(span.detector(), PyStr.len(POSTCHECK_DETECTOR_PREFIX)) : null;
            return new Pair(action, category, check);
        }
    }

    /** One atomic interval of a pass-1 quote, with what the rules alone decide there (null: nothing). */
    private record Region(UnitSlice slice, SpanAction deterministic) {
    }

    private static boolean overlaps(UnitSlice a, UnitSlice b) {
        return a.unitId().equals(b.unitId()) && a.start() < b.end() && b.start() < a.end();
    }

    private static boolean contains(UnitSlice outer, UnitSlice inner) {
        return outer.unitId().equals(inner.unitId()) && outer.start() <= inner.start() && inner.end() <= outer.end();
    }

    /**
     * A pass-1 quote cut into ATOMIC INTERVALS by the rule spans that partly overlap it, each with the
     * action the resolver's own ladder gives the rule spans covering it whole
     * ({@link Resolver#deterministicAction}; null where they cannot claim a character, or there are none).
     * Exact coordinates only; the text is never compared.
     */
    private static List<Region> regions(UnitSlice quote, List<Proposal> rules, PolicySettings policy) {
        List<Proposal> overlapping = rules.stream().filter(r -> overlaps(r.part(), quote)).toList();
        TreeSet<Integer> cuts = new TreeSet<>(List.of(quote.start(), quote.end()));
        for (Proposal r : overlapping) {
            if (r.part().start() > quote.start()) {
                cuts.add(r.part().start());
            }
            if (r.part().end() < quote.end()) {
                cuts.add(r.part().end());
            }
        }
        List<Region> regions = new ArrayList<>();
        Integer previous = null;
        for (int boundary : cuts) {
            if (previous != null) {
                UnitSlice piece = new UnitSlice(quote.unitId(), previous, boundary);
                regions.add(new Region(piece, Resolver.deterministicAction(overlapping.stream()
                        .filter(r -> contains(r.part(), piece)).map(Proposal::span).toList(), policy)));
            }
            previous = boundary;
        }
        return regions;
    }

    /** A recommendation from {@code p} told about {@code place}: its text is named when it is about another stretch. */
    private static Recommendation toldAbout(Proposal p, UnitSlice place, String unitText) {
        return new Recommendation(List.of(p.pass1() ? "pass1" : "deterministic"), p.action(), p.category(), null,
                p.part().equals(place) ? null : PyStr.slice(unitText, p.part().start(), p.part().end()));
    }

    /**
     * Routes one chunk (see the class comment). {@code chunk} and {@code rendered} are the MASKED view;
     * {@code deterministicSpans} are the chunk's non-hard rule spans (REDACT/PRESERVE) and
     * {@code reviewHints} its REVIEW hints; {@code sourceUnits} are the DOCUMENT's units, from which
     * every span's text is read and every REDACT narrowed.
     *
     * <p>THE RULES' SPANS ARE NEVER CUT OR WITHHELD: they reach the resolver as detected, which settles
     * a conflict among them by its existing ladder and keeps its geometric guard (a pass-2 PRESERVE
     * never carves a hole in a REDACT it was not answering at exactly its own slice). Routing decides
     * only which places are questions and which pass-1 decisions are applied directly:
     *
     * <ul>
     *   <li>a REVIEW (a rule hint, or pass 1 could not decide) is a question at that exact place;
     *   <li>each pass-1 REDACT or PRESERVE quote is cut into atomic intervals against the rule spans
     *       ({@link #regions}). Where the rules' decision and pass 1's DISAGREE, the question is the
     *       REDACT side's whole value (pass 1's quote, or the rule span), since only a PRESERVE at
     *       exactly that slice can reverse it; the PRESERVE side stays as evidence. A pass-1 REDACT
     *       from a text that occurs more than once, not confirmed by the rules, is a question too;
     *   <li>every other pass-1 decision is applied as an {@link SpanOrigin#LLM_PASS1} span: agreement,
     *       pass 1 alone, and a pass-1 PRESERVE (which never outranks a rule REDACT);
     *   <li>a rule REDACT that no pass-1 decision covers over its whole place is a question at its own
     *       place: a proposal needs an LLM decision (pass 1's or pass 2's) before the resolver, the rules'
     *       span staying evidence and the documented fallback. A rule PRESERVE alone asks nothing (it
     *       changes nothing), and a HARD decision is never a question;
     *   <li>a place a hard preserve covers whole is settled, and a question pass 2's answer cannot
     *       change (covered whole by applied pass-1 REDACTs of other slices, which outrank every rule
     *       span and shield it from a pass-2 PRESERVE) is not asked.
     * </ul>
     */
    static Routed route(int chunkIndex, Chunk chunk, List<Span> deterministicSpans, List<Span> reviewHints,
                        List<LlmDetector.Finding> findings, Chunk.Rendered rendered, HardDecisions hard,
                        PolicySettings policy, Map<String, TextUnit> sourceUnits, Set<String> regions) {
        Set<String> unitIds = chunk.unitIds();
        // 1. Every proposal, at its exact place, cut free of the masks the model could not see.
        Set<Proposal> proposals = new LinkedHashSet<>();
        List<Span> located = new ArrayList<>(deterministicSpans);
        located.addAll(reviewHints);
        for (Span span : located) {
            if (!unitIds.contains(span.unitId())) {
                continue;
            }
            for (UnitSlice part : hard.questionable(new UnitSlice(span.unitId(), span.start(), span.end()))) {
                proposals.add(new Proposal(part, span, span.action(), span.category(), false, false, null, false));
            }
        }
        List<LlmDetector.Finding> unlocated = new ArrayList<>();
        for (LlmDetector.Finding finding : findings) {
            List<List<UnitSlice>> occurrences = occurrencesInRendered(rendered, finding.text());
            if (occurrences.isEmpty() && onlyInContext(rendered, finding.text())) {
                continue; // a quote of read-only context: the copied text is judged where it really stands
            }
            if (occurrences.isEmpty()) {
                // A usable finding with nowhere to be written (not even whitespace-tolerantly, in one place): carried
                // out, never dropped. The caller decides what it costs: a PRESERVE is audited, anything else reviewed.
                LOG.warn("pass-1 {} finding matched nothing in the excerpt ({} chars)", finding.action(),
                        PyStr.len(finding.text()));
                if (!unlocated.contains(finding)) {
                    unlocated.add(finding);
                }
                continue;
            }
            boolean repeated = occurrences.size() > 1;
            for (List<UnitSlice> occurrence : occurrences) {
                UnitSlice first = occurrence.getFirst();
                // Hard policy took part of the quote: blanked it, or it is the shielded signatory name.
                boolean masked = occurrence.stream().anyMatch(l -> !hard.masked(l).isEmpty()
                        || !hard.shieldedParts(l).isEmpty());
                for (UnitSlice location : occurrence) {
                    for (UnitSlice part : hard.questionable(location)) {
                        proposals.add(new Proposal(part, null, finding.action(), finding.category(), true, repeated,
                                first, masked));
                    }
                }
            }
        }
        List<Proposal> rules = proposals.stream().filter(p -> !p.pass1() && p.action() != SpanAction.REVIEW).toList();
        List<Proposal> pass1 = proposals.stream().filter(p -> p.pass1() && p.action() != SpanAction.REVIEW).toList();

        // 2. What was proposed at each exact place: the rules' places first, then pass 1's.
        Map<UnitSlice, List<Pair>> rulePairs = collectByLocation(proposals.stream().filter(p -> !p.pass1())
                .map(p -> Map.entry(p.part(), p.pair())).toList());
        Map<UnitSlice, List<Pair>> pass1Pairs = collectByLocation(proposals.stream().filter(Proposal::pass1)
                .map(p -> Map.entry(p.part(), p.pair())).toList());
        List<UnitSlice> places = new ArrayList<>(rulePairs.keySet());
        pass1Pairs.keySet().stream().filter(l -> !rulePairs.containsKey(l)).forEach(places::add);

        // 3. Which places are questions, and what pass 2 must be told beyond what was proposed there.
        Set<UnitSlice> asked = new HashSet<>();
        Map<UnitSlice, List<Recommendation>> told = new HashMap<>();
        Map<UnitSlice, Proposal> preservedAgainst = new HashMap<>();
        proposals.stream().filter(p -> p.action() == SpanAction.REVIEW).forEach(p -> asked.add(p.part()));
        int agreed = 0;
        int pass1Only = 0;
        for (Proposal p : pass1) {
            String unitText = sourceUnits.get(p.part().unitId()).normalizedText();
            List<Region> pieces = regions(p.part(), rules, policy);
            boolean conflict = pieces.stream().anyMatch(r -> r.deterministic() != null && r.deterministic() != p.action());
            boolean confirmed = pieces.stream().allMatch(r -> r.deterministic() == p.action());
            if (p.action() == SpanAction.REDACT) {
                if (conflict) {
                    // The REDACT side is pass 1's quote: asked whole, told of the rules' PRESERVE inside it.
                    asked.add(p.part());
                    for (Proposal rule : rules) {
                        if (rule.action() == SpanAction.PRESERVE && overlaps(rule.part(), p.part())) {
                            addOnce(told.computeIfAbsent(p.part(), k -> new ArrayList<>()), toldAbout(rule, p.part(), unitText));
                        }
                    }
                } else if (p.repeated() && !confirmed) {
                    asked.add(p.part());
                }
            } else {
                // The REDACT side is the rule span the resolver applies there: asked whole, told of pass 1's PRESERVE.
                for (Region r : pieces) {
                    if (r.deterministic() != SpanAction.REDACT) {
                        continue;
                    }
                    for (Proposal rule : rules) {
                        if (rule.action() == SpanAction.REDACT && contains(rule.part(), r.slice())
                                && Resolver.deterministicAction(List.of(rule.span()), policy) == SpanAction.REDACT) {
                            asked.add(rule.part());
                            addOnce(told.computeIfAbsent(rule.part(), k -> new ArrayList<>()), toldAbout(p, rule.part(), unitText));
                            preservedAgainst.putIfAbsent(rule.part(), p);
                        }
                    }
                }
            }
        }

        // 3b. A rule REDACT pass 1 decided nothing about (no pass-1 decision covers its whole place) has no LLM
        // decision yet: it is asked at its own place. Where pass 1 agreed or disagreed it is already settled
        // or asked above.
        Map<String, BitSet> pass1Covered = new HashMap<>();
        for (Proposal p : pass1) {
            pass1Covered.computeIfAbsent(p.part().unitId(), k -> new BitSet()).set(p.part().start(), p.part().end());
        }
        for (Proposal rule : rules) {
            if (rule.action() != SpanAction.REDACT || asked.contains(rule.part())) {
                continue;
            }
            BitSet covered = pass1Covered.get(rule.part().unitId());
            if (covered == null || covered.nextClearBit(rule.part().start()) < rule.part().end()) {
                asked.add(rule.part());
            }
        }

        // 4. Pass 1's decisions that are not questions are applied: one LLM_PASS1 span per quoted piece, a
        // REDACT narrowed over the whole piece. An occurrence NONE of whose pieces could be written (and
        // whose value neither the rules nor hard policy redact anyway) is held for a person, never dropped.
        List<Span> pass1Spans = new ArrayList<>();
        List<UnitSlice> applied = new ArrayList<>();
        List<UnresolvedFinding> unresolved = new ArrayList<>();
        Set<List<Object>> emitted = new HashSet<>();
        Set<List<Object>> settledOccurrences = new HashSet<>();
        Map<List<Object>, List<UnitSlice>> unwritable = new LinkedHashMap<>();
        Map<List<Object>, SpanCategory> unwritableCategory = new HashMap<>();
        for (Proposal p : pass1) {
            List<Object> occurrence = List.of(p.occurrence(), p.action());
            if (asked.contains(p.part()) || hard.preserved(p.part())) {
                settledOccurrences.add(occurrence);
                continue;
            }
            String unitText = sourceUnits.get(p.part().unitId()).normalizedText();
            List<Region> pieces = regions(p.part(), rules, policy);
            if (pieces.stream().anyMatch(r -> r.deterministic() == p.action())) {
                agreed++;
            } else {
                pass1Only++;
            }
            int start = p.part().start();
            int end = p.part().end();
            if (p.action() == SpanAction.REDACT) {
                int[] narrowed = SpanTrim.narrowRedaction(unitText, start, end, p.category(), regions);
                if (narrowed == null) {
                    if (p.masked() || pieces.stream().allMatch(r -> r.deterministic() == SpanAction.REDACT)) {
                        settledOccurrences.add(occurrence); // the value is hard-masked, or the rules redact it
                    } else {
                        unwritable.computeIfAbsent(occurrence, k -> new ArrayList<>()).add(p.part());
                        unwritableCategory.putIfAbsent(occurrence, p.category());
                    }
                    continue;
                }
                start = narrowed[0];
                end = narrowed[1];
            }
            settledOccurrences.add(occurrence);
            if (emitted.add(List.of(p.part().unitId(), start, end, p.action()))) {
                pass1Spans.add(pass1Span(p.part().unitId(), start, end, unitText, p.category(), p.action(), PASS1_DETECTOR,
                        "LLM pass-1 decision applied without a pass-2 question: " + p.action().wire()));
                if (p.action() == SpanAction.REDACT) {
                    applied.add(new UnitSlice(p.part().unitId(), start, end));
                }
            }
        }
        unwritable.forEach((occurrence, parts) -> {
            if (settledOccurrences.contains(occurrence)) {
                return; // another piece of the same quote was written, asked or settled
            }
            int length = parts.stream().mapToInt(s -> s.end() - s.start()).sum();
            LOG.warn("a pass-1 REDACT ({} chars) narrows to no redactable value; not applied, retained for human review",
                    length);
            unresolved.add(new UnresolvedFinding(chunkIndex, UnresolvedFinding.Kind.PASS1_REDACT_UNREPRESENTABLE,
                    unwritableCategory.get(occurrence).wire(), parts, null, "a pass-1 REDACT (" + length
                    + " chars) narrows to no redactable value and was not applied"));
        });
        int deterministicOnly = (int) rules.stream().filter(r -> pass1.stream().noneMatch(p -> overlaps(p.part(), r.part())))
                .count();

        // 5. The questions, in place order.
        List<Question> questions = new ArrayList<>();
        List<LlmDetector.Evidence> evidence = new ArrayList<>();
        int settled = 0;
        int redundant = 0;
        for (UnitSlice place : places) {
            String unitText = sourceUnits.get(place.unitId()).normalizedText();
            String text = PyStr.slice(unitText, place.start(), place.end());
            if (text.isEmpty()) {
                continue;
            }
            List<Recommendation> recommendations = mergeRecommendations(rulePairs.getOrDefault(place, List.of()),
                    pass1Pairs.getOrDefault(place, List.of()), "deterministic");
            told.getOrDefault(place, List.of()).forEach(r -> addOnce(recommendations, r));
            // Hard policy has the last word on a place it covers whole.
            if (hard.preserved(place)) {
                settled++;
                continue;
            }
            if (asksForADecision(recommendations)) {
                for (Recommendation r : recommendations) {
                    evidence.add(new LlmDetector.Evidence(place, r.sources(), r.action(), r.category()));
                }
            }
            if (!asked.contains(place) || PyStr.strip(text).isEmpty()) {
                continue;
            }
            if (coveredByOthers(place, applied, asked)) {
                redundant++;
                continue;
            }
            String[] window = windowsAt(rendered, place);
            questions.add(new Question(chunkIndex, place, text, recommendations, window[0], window[1],
                    fallbackAt(place, pass1Pairs.getOrDefault(place, List.of()), preservedAgainst.get(place), rules,
                            policy)));
        }
        return new Routed(pass1Spans, questions, unlocated, unresolved, evidence,
                new RouteCounts(agreed, pass1Only, deterministicOnly, questions.size(), settled, redundant));
    }

    private static <T> void addOnce(List<T> list, T item) {
        if (!list.contains(item)) {
            list.add(item);
        }
    }

    /**
     * Whether every code point of {@code place} is covered by applied pass-1 REDACTs of OTHER slices that
     * no question is about: only those shield it from a pass-2 PRESERVE whatever pass 2 answers elsewhere
     * (a pass-2 PRESERVE at exactly an applied slice would lift that slice's shield).
     */
    private static boolean coveredByOthers(UnitSlice place, List<UnitSlice> applied, Set<UnitSlice> asked) {
        BitSet covered = new BitSet();
        for (UnitSlice a : applied) {
            if (!a.equals(place) && !asked.contains(a) && overlaps(a, place)) {
                covered.set(Math.max(a.start(), place.start()), Math.min(a.end(), place.end()));
            }
        }
        return covered.nextClearBit(place.start()) >= place.end();
    }

    /**
     * The fallback for one question: pass 1's decision at exactly this place (REDACT before PRESERVE),
     * or the pass-1 PRESERVE that disagreed with the rule span asked about here; and what the rules
     * covering the whole place decide by their ladder.
     */
    private static Fallback fallbackAt(UnitSlice place, List<Pair> pass1Here, Proposal preservedAgainst,
                                       List<Proposal> rules, PolicySettings policy) {
        SpanAction pass1 = null;
        SpanCategory category = null;
        for (Pair pair : pass1Here) {
            if (pair.action() == SpanAction.REDACT && pass1 != SpanAction.REDACT) {
                pass1 = SpanAction.REDACT;
                category = pair.category();
            } else if (pair.action() == SpanAction.PRESERVE && pass1 == null) {
                pass1 = SpanAction.PRESERVE;
                category = pair.category();
            }
        }
        if (pass1 == null && preservedAgainst != null) {
            pass1 = SpanAction.PRESERVE;
            category = preservedAgainst.category();
        }
        SpanAction deterministic = Resolver.deterministicAction(rules.stream()
                .filter(r -> contains(r.part(), place)).map(Proposal::span).toList(), policy);
        return Fallback.of(pass1, category, deterministic);
    }

    private static Span pass1Span(String unitId, int start, int end, String unitText, SpanCategory category,
                                  SpanAction action, String detector, String reason) {
        return new Span(unitId, start, end, PyStr.slice(unitText, start, end), category, detector, PASS1_CONFIDENCE,
                action, reason, SpanOrigin.LLM_PASS1);
    }

    /**
     * The fallback's spans for one candidate pass 2 could not decide: the pass-1 decision written at
     * every stored location (a REDACT narrowed per location, exactly as a pass-2 REDACT would be), or
     * nothing when the rules' own spans settle it. Locations a REDACT cannot be written at are added
     * to {@code unrepresentable}; nothing is dropped silently.
     */
    static List<Span> fallbackSpans(Candidate candidate, Map<String, TextUnit> unitsById, Set<String> regions,
                                    List<UnitSlice> unrepresentable) {
        Fallback fallback = candidate.fallback();
        if (fallback == null || fallback.pass1() == null) {
            return List.of();
        }
        List<Span> spans = new ArrayList<>();
        for (UnitSlice l : candidate.locations()) {
            TextUnit unit = unitsById.get(l.unitId());
            if (unit == null) {
                unrepresentable.add(l);
                continue;
            }
            int start = l.start();
            int end = l.end();
            if (fallback.pass1() == SpanAction.REDACT) {
                int[] narrowed = SpanTrim.narrowRedaction(unit.normalizedText(), start, end, fallback.pass1Category(),
                        regions);
                if (narrowed == null) {
                    unrepresentable.add(l);
                    continue;
                }
                start = narrowed[0];
                end = narrowed[1];
            }
            spans.add(pass1Span(l.unitId(), start, end, unit.normalizedText(), fallback.pass1Category(), fallback.pass1(),
                    PASS1_FALLBACK_DETECTOR, "LLM pass 2 unavailable: pass-1 " + fallback.pass1().wire()
                            + " applied as the fallback"));
        }
        return spans;
    }

    // ------------------------------------------------------------------ one document-wide queue

    /**
     * Every chunk's questions as ONE queue, in the order given (chunk, unit, offset). Ids {@code C1..Cn}
     * are issued here, once, and never change: batching, retries and the fallback all use them. Two
     * places share a candidate only when the whole question is identical (text, recommendations, both
     * context windows) AND so is the fallback; the same name in two contexts stays two candidates.
     */
    static List<Candidate> consolidate(List<Question> questions) {
        record Key(String text, List<Recommendation> recommendations, String before, String after, Fallback fallback) {
        }
        Map<Key, List<Question>> grouped = new LinkedHashMap<>();
        for (Question q : questions) {
            grouped.computeIfAbsent(new Key(q.text(), q.recommendations(), q.before(), q.after(), q.fallback()),
                    k -> new ArrayList<>()).add(q);
        }
        List<Candidate> candidates = new ArrayList<>();
        grouped.forEach((key, group) -> {
            Question first = group.getFirst();
            candidates.add(new Candidate("C" + (candidates.size() + 1), key.text(),
                    key.recommendations().getFirst().category(), key.recommendations(),
                    group.stream().map(Question::location).toList(), key.before(), key.after(), first.chunkIndex(),
                    key.fallback()));
        });
        return candidates;
    }

    /** Most candidates one pass-2 batch carries; fewer when the completion budget cannot answer that many. */
    static final int PASS2_BATCH_MAX_CANDIDATES = 30;
    /**
     * Most estimated candidate-payload TOKENS one batch carries (the candidates' JSON only; not the 7,000
     * CHARACTER chunk size, a different setting in a different unit). The system prompt and the message
     * wrapper are counted separately, by {@link #batches(List, int, int, int)}, when a model context limit
     * is known.
     */
    static final int PASS2_BATCH_TOKEN_BUDGET = 7_000;
    /**
     * Output tokens reserved per candidate: one {"id", "action", "category"} entry, generously. An
     * ESTIMATE: answers are not measured here, so it is deliberately high.
     */
    static final int PASS2_OUTPUT_TOKENS_PER_CANDIDATE = 40;
    /**
     * The share of the completion budget the answers may use. The rest is headroom, and it is also where
     * any reasoning the model does must fit: reasoning tokens are part of the same completion budget
     * ({@code max_completion_tokens}) and no separate reasoning budget is configured.
     */
    static final double PASS2_OUTPUT_SHARE = 0.6;

    /**
     * A deliberately high token estimate for text sent to the model, without a tokenizer: ASCII at
     * three characters a token, every other code point (Greek) at one and a half. GPT tokenizers do
     * better on both, so a batch sized by this is smaller than it needs to be, never larger.
     */
    static int estimateTokens(String text) {
        long ascii = 0;
        long other = 0;
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (cp < 128) {
                ascii++;
            } else {
                other++;
            }
            i += Character.charCount(cp);
        }
        return (int) Math.ceil(ascii / 3.0 + other / 1.5);
    }

    /** The estimated tokens of one candidate's payload entry. */
    static int estimateTokens(Candidate candidate) {
        return estimateTokens(PyJson.dumps(candidate.asPayload()));
    }

    /** How many candidates a batch may hold so that every one of them can be answered within the completion limit. */
    static int maxCandidatesPerBatch(int maxCompletionTokens) {
        int byOutput = (int) Math.floor(PASS2_OUTPUT_SHARE * maxCompletionTokens / PASS2_OUTPUT_TOKENS_PER_CANDIDATE);
        return Math.max(1, Math.min(PASS2_BATCH_MAX_CANDIDATES, byOutput));
    }

    /**
     * Estimated tokens a pass-2 request carries besides its candidates: the instruction line, the JSON
     * array's framing, the chat message wrappers and, on a corrective retry, the rejection notes and
     * their instructions. A deliberately generous ESTIMATE (a retry with many rejection notes is the
     * largest case); it only matters when a context window is configured.
     */
    static final int PASS2_MESSAGE_OVERHEAD_TOKENS = 1_000;

    /** Estimated input tokens of every pass-2 request before its candidates: the system prompt and the overhead. */
    static int pass2FixedInputTokens() {
        return estimateTokens(Prompts.SYSTEM_PROMPT_PASS2) + PASS2_MESSAGE_OVERHEAD_TOKENS;
    }

    /**
     * The batches to send, and the candidates no request can carry within the configured context
     * window ({@code unsendable}: never sent, never cut, never dropped; the caller gives each the same
     * documented fallback as a candidate pass 2 was unavailable for). Every candidate is in exactly one
     * of the two, with its id, in id order.
     */
    record Batches(List<List<Candidate>> sendable, List<Candidate> unsendable) {
        Batches {
            sendable = List.copyOf(sendable);
            unsendable = List.copyOf(unsendable);
        }
    }

    /** {@link #batches(List, int, int, int)} with no model context limit known: every candidate is sent. */
    static List<List<Candidate>> batches(List<Candidate> candidates, int maxCompletionTokens) {
        return batches(candidates, maxCompletionTokens, 0, 0).sendable();
    }

    /**
     * The queue cut into batches, in id order. Three separate limits, each checked on its own:
     * <ul>
     *   <li>COMPLETION: at most {@link #maxCandidatesPerBatch} candidates, so every answer fits the
     *       completion budget with its headroom (reasoning tokens are part of that same budget);
     *   <li>PAYLOAD: at most {@link #PASS2_BATCH_TOKEN_BUDGET} estimated candidate-payload tokens;
     *   <li>WHOLE REQUEST, only when {@code contextTokenLimit} (the model's context window, as configured)
     *       is known (&gt; 0): system prompt and message overhead ({@code fixedInputTokens}), payload and the
     *       whole completion budget together must fit it. No limit is ever assumed from a deployment's name.
     * </ul>
     * A candidate over the payload budget on its own is sent alone, whole: it is never cut (its text is
     * the question) and never dropped, and keeps the ordinary retry, validation and fallback. With a
     * context window configured, a candidate that cannot fit it even alone is never sent: it is returned
     * as {@code unsendable}, because that request is already known to exceed the limit.
     */
    static Batches batches(List<Candidate> candidates, int maxCompletionTokens, int contextTokenLimit,
                           int fixedInputTokens) {
        int maxCount = maxCandidatesPerBatch(maxCompletionTokens);
        int budget = PASS2_BATCH_TOKEN_BUDGET;
        // What a request may spend on candidates; unbounded when no window is known.
        long available = contextTokenLimit > 0
                ? (long) contextTokenLimit - fixedInputTokens - maxCompletionTokens : Long.MAX_VALUE;
        if (available < budget) {
            budget = (int) Math.max(0, available);
        }
        List<List<Candidate>> batches = new ArrayList<>();
        List<Candidate> unsendable = new ArrayList<>();
        List<Candidate> current = new ArrayList<>();
        int tokens = 0;
        for (Candidate c : candidates) {
            int t = estimateTokens(c);
            if (t > available) {
                unsendable.add(c); // even alone, its request would exceed the configured window
                continue;
            }
            if (!current.isEmpty() && (current.size() >= maxCount || tokens + t > budget)) {
                batches.add(List.copyOf(current));
                current = new ArrayList<>();
                tokens = 0;
            }
            current.add(c);
            tokens += t;
            if (t > budget) {
                batches.add(List.copyOf(current)); // alone, by the check above
                current = new ArrayList<>();
                tokens = 0;
            }
        }
        if (!current.isEmpty()) {
            batches.add(List.copyOf(current));
        }
        return new Batches(batches, unsendable);
    }

    // ------------------------------------------------------------------ validating an answer

    /** Echoes a model-supplied id only when it looks like one this code could have issued. */
    private static String safeId(String value) {
        return CANDIDATE_ID_RE.match(value) != null ? value : "<malformed id>";
    }

    private record ActionRead(String action, boolean coerced) {
        /** The shared rule: REVIEW coerces to REDACT (the fail-safe direction); nothing else bends. */
        static ActionRead of(Map<?, ?> entry) {
            String action = PyStr.upper(PyStr.strip(LlmDetector.field(entry, "action")));
            return action.equals("REVIEW") ? new ActionRead("REDACT", true) : new ActionRead(action, false);
        }

        boolean isFinal() {
            return action.equals("REDACT") || action.equals("PRESERVE");
        }
    }

    /**
     * Validates a pass-2 response entry by entry against the queue it was asked about.
     *
     * <p>Raises {@link AIProviderError} when the payload is not a JSON array. Otherwise every
     * entry is judged and nothing is quietly dropped. DUPLICATES ARE COUNTED BEFORE ANYTHING IS
     * VALIDATED: an id answered twice voids every copy, including one that would have validated
     * and including when one copy is malformed, so the outcome cannot depend on which copy came
     * first. An id this queue never issued ({@code NEW} included: there is no other kind of
     * entry), an entry with no id, or a non-object marks the whole response distrusted.
     */
    static Validation validate(String raw, Map<String, Candidate> candidatesById) {
        List<?> entries = LlmDetector.extractJsonArray(raw);
        if (entries == null) {
            throw new AIProviderError("pass-2 output could not be parsed as a JSON array");
        }
        // The pre-scan: nothing is judged until everything is counted.
        Map<String, Integer> idCounts = new LinkedHashMap<>();
        for (Object o : entries) {
            if (o instanceof Map<?, ?> entry) {
                String entryId = PyStr.upper(PyStr.strip(LlmDetector.field(entry, "id")));
                if (!entryId.isEmpty()) {
                    idCounts.merge(entryId, 1, Integer::sum);
                }
            }
        }
        Set<String> duplicatedIds = new HashSet<>();
        idCounts.forEach((id, count) -> {
            if (count > 1) {
                duplicatedIds.add(id);
            }
        });

        List<Decision> decisions = new ArrayList<>();
        List<String> rejections = new ArrayList<>();
        List<String> voided = new ArrayList<>();
        boolean distrusted = false;
        int position = 0;
        for (Object o : entries) {
            position++;
            if (!(o instanceof Map<?, ?> entry)) {
                rejections.add("entry " + position + " is not a JSON object");
                distrusted = true;
                continue;
            }
            String candidateId = PyStr.upper(PyStr.strip(LlmDetector.field(entry, "id")));
            if (candidateId.isEmpty()) {
                rejections.add("entry " + position + " carries no candidate id");
                distrusted = true;
                continue;
            }
            Candidate candidate = candidatesById.get(candidateId);
            if (candidate == null) {
                rejections.add(safeId(candidateId) + " is not a candidate in this queue");
                distrusted = true;
                continue;
            }
            if (duplicatedIds.contains(candidateId)) {
                // Every copy is skipped, the first included: the candidate is undecided.
                if (!voided.contains(candidateId)) {
                    voided.add(candidateId);
                    rejections.add(candidateId + " is answered more than once; every answer for it was "
                            + "discarded and it must be decided again");
                }
                continue;
            }
            if (!candidate.hasLocation()) {
                rejections.add(candidateId + " no longer maps to a location");
                continue;
            }
            SpanCategory category = LlmDetector.readCategory(entry);
            if (category == null) {
                if (candidate.category() == null) {
                    rejections.add(candidateId + " has a category outside the vocabulary and no recommended "
                            + "one to fall back to");
                    continue;
                }
                category = candidate.category();
            }
            ActionRead action = ActionRead.of(entry);
            if (!action.isFinal()) {
                rejections.add(candidateId + " has no final REDACT/PRESERVE action");
                continue;
            }
            decisions.add(new Decision(candidateId, category, SpanAction.valueOf(action.action()), action.coerced()));
        }

        if (!voided.isEmpty()) {
            LOG.warn("pass-2: {} candidate id(s) answered more than once; their answers were discarded and "
                    + "they will be re-asked", voided.size());
        }
        if (!rejections.isEmpty()) {
            LOG.warn("pass-2: {} unusable entry/entries — {}", rejections.size(),
                    String.join("; ", rejections.subList(0, Math.min(5, rejections.size())))
                            + (rejections.size() > 5 ? " ..." : ""));
        }
        return new Validation(List.copyOf(decisions), List.copyOf(rejections), List.copyOf(voided), distrusted);
    }

    /** Ids of the candidates left undecided: an exact set difference on ids, no text comparison. */
    static List<String> unresolvedIds(List<Decision> decisions, List<Candidate> candidates) {
        Set<String> decided = new HashSet<>();
        decisions.forEach(d -> decided.add(d.candidateId()));
        return candidates.stream().map(Candidate::id).filter(id -> !decided.contains(id)).toList();
    }

    // ------------------------------------------------------------------ writing spans

    /**
     * Each decision written at its candidate's stored locations: a dictionary lookup and nothing
     * else. One decision covers several locations only when they posed an identical question. A
     * REDACT is narrowed to its value ({@link SpanTrim}), since the candidate's geometry came from
     * whichever stage proposed it; the span's text is then re-read at the narrowed offsets.
     * {@code unitsById} are the DOCUMENT's units, never the masked view's: what is written, and
     * how it is narrowed, is decided on the real text.
     */
    static List<Span> spansFromDecisions(List<Decision> decisions, Map<String, Candidate> candidatesById,
                                         Map<String, TextUnit> unitsById, Set<String> regions) {
        List<Span> spans = new ArrayList<>();
        for (Decision decision : decisions) {
            Candidate candidate = candidatesById.get(decision.candidateId());
            if (candidate == null || !candidate.hasLocation()) {
                // Unreachable through the orchestrator; writing at an unsure location would corrupt the document.
                LOG.warn("pass-2 decision for {} has no usable candidate location; dropped", decision.candidateId());
                continue;
            }
            if (decision.coerced()) {
                LOG.warn("pass-2 coerced REVIEW to REDACT for candidate {} (category {})", decision.candidateId(),
                        decision.category().wire());
            }
            for (UnitSlice l : candidate.locations()) {
                int start = l.start();
                int end = l.end();
                String text = candidate.text();
                TextUnit unit = unitsById.get(l.unitId());
                if (decision.action() == SpanAction.REDACT && unit != null) {
                    int[] narrowed = SpanTrim.narrowRedaction(unit.normalizedText(), start, end, decision.category(),
                            regions);
                    if (narrowed == null) {
                        continue;
                    }
                    start = narrowed[0];
                    end = narrowed[1];
                    text = PyStr.slice(unit.normalizedText(), start, end);
                }
                spans.add(new Span(l.unitId(), start, end, text, decision.category(), "llm_pass2",
                        LLM_CONFIDENCE, decision.action(), "LLM pass-2 decision: " + decision.action().wire(),
                        SpanOrigin.LLM_PASS2));
            }
        }
        return spans;
    }
}
