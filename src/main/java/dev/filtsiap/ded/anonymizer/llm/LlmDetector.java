package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.AITimeoutError;
import dev.filtsiap.ded.anonymizer.AIUnavailableError;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Two-pass LLM detection (port of {@code llm/detector.py}).
 *
 * <p>Pass 1 reads each chunk blind and proposes decisions. Pass 2 receives the chunk plus every
 * known span (deterministic detections and located pass-1 proposals) and must answer
 * completely: every rule-flagged REVIEW hint needs a final REDACT or PRESERVE. A malformed or
 * incomplete pass-2 answer is retried once, naming the missing texts; a second failure raises
 * {@link AIProviderError}. Only pass-2 decisions become spans. The LLM stage is mandatory.
 */
public final class LlmDetector {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.llm.detector");

    /** Normalizes model category improvisations back onto the schema. */
    static final Map<String, String> CATEGORY_ALIASES = Map.ofEntries(
            Map.entry("PERSON", "POSSIBLE_PERSON"),
            Map.entry("COMPANY", "POSSIBLE_COMPANY"),
            Map.entry("ADDRESS", "POSSIBLE_PRIVATE_LOCATION"),
            Map.entry("PROTOCOL", "PROTOCOL_NUMBER"),
            Map.entry("TAXPAYER", "APPELLANT_NAME"),
            Map.entry("APPELLANT", "APPELLANT_NAME"),
            Map.entry("FATHER", "FATHER_NAME"),
            Map.entry("PATRONYMIC", "FATHER_NAME"),
            Map.entry("COMPANY_NAME", "PRIVATE_COMPANY_NAME"),
            Map.entry("BUSINESS_ADDRESS", "BUSINESS_SEAT"),
            Map.entry("DEVICE_ID", "FISCAL_DEVICE_ID"),
            Map.entry("FISCAL_DEVICE", "FISCAL_DEVICE_ID"),
            Map.entry("INVOICE_ID", "INVOICE_TABLE_ID"),
            Map.entry("INVOICE", "INVOICE_TABLE_ID"),
            Map.entry("BENEFICIARY", "PRIVATE_BENEFICIARY"),
            Map.entry("BANK", "BANK_ACCOUNT"),
            Map.entry("CASE_REF", "CASE_REF_NUMBER"),
            Map.entry("ACT_REF", "CHALLENGED_ACT_NUMBER"),
            Map.entry("SIGNATORY", "OFFICIAL_SIGNATORY"),
            Map.entry("AUTHORITY_HEADER", "PUBLIC_AUTHORITY_HEADER"),
            Map.entry("DECISION_NUMBER", "DECISION_METADATA"));

    static final int CONTEXT_WINDOW = 40;
    private static final PyPattern BRACKETED_ARRAY = PyRegex.compile("\\[.*\\]", PyRegex.DOTALL);

    private LlmDetector() {
    }

    // ------------------------------------------------------------------ chunks

    /** One LLM work item: a whole table, or a run of paragraph units. */
    public record Chunk(List<TextUnit> units, boolean isTable, Integer tableIndex) {
        public Chunk {
            units = List.copyOf(units);
        }

        Set<String> unitIds() {
            return units.stream().map(TextUnit::unitId).collect(Collectors.toSet());
        }

        /** Tables: "TABLE:" plus one pipe-joined line per row; paragraphs: newline-joined texts. */
        public String text() {
            if (isTable) {
                Map<Integer, List<TextUnit>> rows = new TreeMap<>();
                for (TextUnit unit : units) {
                    TextUnit.TableCellLocation loc = (TextUnit.TableCellLocation) unit.location();
                    rows.computeIfAbsent(loc.rowIndex(), k -> new ArrayList<>()).add(unit);
                }
                List<String> lines = new ArrayList<>(List.of("TABLE:"));
                for (List<TextUnit> row : rows.values()) {
                    List<TextUnit> cells = new ArrayList<>(row);
                    cells.sort(Comparator.comparingInt(u -> ((TextUnit.TableCellLocation) u.location()).colIndex()));
                    lines.add(cells.stream().map(TextUnit::normalizedText).collect(Collectors.joining(" | ")));
                }
                return String.join("\n", lines);
            }
            return units.stream().map(TextUnit::normalizedText).collect(Collectors.joining("\n"));
        }
    }

    /**
     * Tables first (one chunk each, grouped by part and table index, first-seen order), then
     * non-empty paragraph units accumulated while the joined text fits {@code chunkSizeChars}.
     * A unit is never split; an oversized unit becomes its own chunk.
     */
    public static List<Chunk> splitIntoChunks(DocumentData document, int chunkSizeChars) {
        List<Chunk> chunks = new ArrayList<>();
        record TableKey(String partName, int tableIndex) {
        }
        Map<TableKey, List<TextUnit>> tables = new LinkedHashMap<>();
        for (TextUnit unit : document.textUnits()) {
            if (unit.unitType() != UnitType.TABLE_CELL) {
                continue;
            }
            TextUnit.TableCellLocation loc = (TextUnit.TableCellLocation) unit.location();
            tables.computeIfAbsent(new TableKey(unit.partName(), loc.tableIndex()), k -> new ArrayList<>()).add(unit);
        }
        tables.forEach((key, units) -> chunks.add(new Chunk(units, true, key.tableIndex())));

        List<TextUnit> current = new ArrayList<>();
        int currentLen = 0;
        for (TextUnit unit : document.textUnits()) {
            if (unit.unitType() == UnitType.TABLE_CELL || unit.normalizedText().isEmpty()) {
                continue;
            }
            int unitLen = PyStr.len(unit.normalizedText());
            if (!current.isEmpty() && currentLen + 1 + unitLen > chunkSizeChars) {
                chunks.add(new Chunk(current, false, null));
                current = new ArrayList<>();
                currentLen = 0;
            }
            currentLen = current.isEmpty() ? unitLen : currentLen + 1 + unitLen;
            current.add(unit);
        }
        if (!current.isEmpty()) {
            chunks.add(new Chunk(current, false, null));
        }
        return chunks;
    }

    // ------------------------------------------------------------------ JSON extraction

    /** {@code json.loads(raw)}, else the first-"[" to last-"]" substring; null unless a list results. */
    static List<?> extractJsonArray(String raw) {
        Object parsed;
        try {
            parsed = PyJson.loads(raw);
        } catch (PyJson.JsonDecodeError e) {
            PyMatch m = BRACKETED_ARRAY.search(raw == null ? "" : raw);
            if (m == null) {
                return null;
            }
            try {
                parsed = PyJson.loads(m.group());
            } catch (PyJson.JsonDecodeError e2) {
                return null;
            }
        }
        return parsed instanceof List<?> list ? list : null;
    }

    private static String field(Map<?, ?> entry, String key) {
        return entry.containsKey(key) ? PyRepr.str(entry.get(key)) : "";
    }

    private static String canonicalCategory(Map<?, ?> entry) {
        String category = PyStr.upper(PyStr.strip(field(entry, "category")));
        return CATEGORY_ALIASES.getOrDefault(category, category);
    }

    private static boolean inSchema(String category) {
        return SpanCategory.fromWire(category).isPresent();
    }

    // ------------------------------------------------------------------ pass 1 (lenient)

    /** An advisory pass-1 finding; never becomes a Span. */
    public record Finding(String text, String action, String category) {
    }

    /** Lenient: unparseable output logs one warning and gives no findings (pass 2 then runs blind). */
    public static List<Finding> parsePass1Findings(String raw) {
        List<?> decisions = extractJsonArray(raw);
        if (decisions == null) {
            LOG.warn("pass-1 output unparseable; continuing with empty findings");
            return List.of();
        }
        List<Finding> findings = new ArrayList<>();
        for (Object o : decisions) {
            if (!(o instanceof Map<?, ?> entry)) {
                continue;
            }
            String text = PyStr.strip(field(entry, "text"));
            if (text.isEmpty()) {
                continue;
            }
            String action = PyStr.upper(PyStr.strip(field(entry, "action")));
            if (action.equals("SKIP")) {
                continue;
            }
            if (!Set.of("REDACT", "PRESERVE", "REVIEW").contains(action)) {
                LOG.debug("pass-1 dropping entry with unknown action");
                continue;
            }
            String category = canonicalCategory(entry);
            if (!inSchema(category)) {
                LOG.debug("pass-1 dropping entry with invalid category");
                continue;
            }
            findings.add(new Finding(text, action, category));
        }
        return findings;
    }

    // ------------------------------------------------------------------ pass 2 (strict)

    /** A validated pass-2 entry; {@code action} is final (REDACT, PRESERVE or SKIP). */
    public record Pass2Decision(String text, String category, String action, boolean coerced) {
    }

    /**
     * Validates pass-2 output item by item. A payload that is not a JSON array raises
     * {@link AIProviderError}; bad items are dropped. Category is checked before action, so a
     * REVIEW-to-REDACT coercion is only recorded for an otherwise valid entry.
     */
    public static List<Pass2Decision> validatePass2Entries(String raw) {
        List<?> decisions = extractJsonArray(raw);
        if (decisions == null) {
            throw new AIProviderError("pass-2 output could not be parsed as a JSON array");
        }
        List<Pass2Decision> validated = new ArrayList<>();
        int dropped = 0;
        for (Object o : decisions) {
            if (!(o instanceof Map<?, ?> entry)) {
                dropped++;
                continue;
            }
            String text = PyStr.strip(field(entry, "text"));
            if (text.isEmpty()) {
                dropped++;
                continue;
            }
            String category = canonicalCategory(entry);
            if (!inSchema(category)) {
                LOG.debug("pass-2 dropping entry with invalid category");
                dropped++;
                continue;
            }
            String action = PyStr.upper(PyStr.strip(field(entry, "action")));
            boolean coerced = false;
            if (action.equals("REVIEW")) {
                action = "REDACT";
                coerced = true;
            }
            if (!Set.of("REDACT", "PRESERVE", "SKIP").contains(action)) {
                LOG.debug("pass-2 dropping entry with unsupported action");
                dropped++;
                continue;
            }
            validated.add(new Pass2Decision(text, category, action, coerced));
        }
        if (dropped > 0) {
            LOG.warn("pass-2: dropped {} invalid entry/entries", dropped);
        }
        return validated;
    }

    /** Whitespace-normalized, case-insensitive containment in either direction. */
    static boolean covers(String decisionText, String hintText) {
        String a = PyStr.casefold(PyStr.collapseWhitespace(decisionText));
        String b = PyStr.casefold(PyStr.collapseWhitespace(hintText));
        if (a.isEmpty() || b.isEmpty()) {
            return false;
        }
        return a.equals(b) || b.contains(a) || a.contains(b);
    }

    /** Texts of REVIEW hints no REDACT/PRESERVE decision covers (SKIP does not resolve). Empty = complete. */
    public static List<String> unresolvedReviewHints(List<Pass2Decision> decisions, List<Span> hints) {
        List<Pass2Decision> decided = decisions.stream()
                .filter(d -> d.action().equals("REDACT") || d.action().equals("PRESERVE"))
                .toList();
        List<String> unresolved = new ArrayList<>();
        for (Span hint : hints) {
            if (decided.stream().anyMatch(d -> covers(d.text(), hint.text()))) {
                continue;
            }
            if (!unresolved.contains(hint.text())) {
                unresolved.add(hint.text());
            }
        }
        return unresolved;
    }

    /**
     * Locates each non-SKIP decision in every unit of the chunk (repeated find); short REDACT
     * texts (under 4 characters) only as standalone tokens. Unlocatable decisions are counted
     * and logged, never silently lost.
     */
    public static List<Span> locatePass2Decisions(List<Pass2Decision> decisions, Chunk chunk) {
        List<Span> spans = new ArrayList<>();
        int unlocated = 0;
        for (Pass2Decision decision : decisions) {
            if (decision.action().equals("SKIP")) {
                continue;
            }
            String text = decision.text();
            int textLen = PyStr.len(text);
            boolean guardShort = decision.action().equals("REDACT") && textLen < 4;
            SpanCategory category = SpanCategory.fromWire(decision.category()).orElseThrow();
            SpanAction action = SpanAction.fromWire(decision.action()).orElseThrow();
            int located = 0;
            for (TextUnit unit : chunk.units()) {
                String ntext = unit.normalizedText();
                int ntextLen = PyStr.len(ntext);
                int pos = 0;
                while (true) {
                    int idx = PyStr.find(ntext, text, pos);
                    if (idx == -1) {
                        break;
                    }
                    int end = idx + textLen;
                    if (guardShort) {
                        String before = idx > 0 ? PyStr.charAt(ntext, idx - 1) : "";
                        String after = end < ntextLen ? PyStr.charAt(ntext, end) : "";
                        if ((!before.isEmpty() && PyStr.isAlnum(before)) || (!after.isEmpty() && PyStr.isAlnum(after))) {
                            pos = idx + 1;
                            continue;
                        }
                    }
                    spans.add(new Span(unit.unitId(), idx, end, text, category, "llm_pass2", 0.9, action,
                            "LLM pass-2 decision: " + decision.action()));
                    located++;
                    pos = end;
                }
            }
            if (decision.coerced() && located > 0) {
                LOG.warn("pass-2 coerced REVIEW to REDACT for category {}", decision.category());
            }
            if (located == 0) {
                unlocated++;
            }
        }
        if (unlocated > 0) {
            LOG.warn("pass-2: {} validated decision(s) could not be located in any unit and were dropped", unlocated);
        }
        return spans;
    }

    /** {@link #validatePass2Entries} then {@link #locatePass2Decisions}; no completeness check. */
    public static List<Span> parsePass2Spans(String raw, Chunk chunk) {
        return locatePass2Decisions(validatePass2Entries(raw), chunk);
    }

    // ------------------------------------------------------------------ known spans

    private static String window(String text, int start, int end) {
        int lo = Math.max(0, start - CONTEXT_WINDOW);
        int hi = Math.min(PyStr.len(text), end + CONTEXT_WINDOW);
        String snippet = PyStr.slice(text, lo, hi);
        if (lo > 0) {
            snippet = "..." + snippet;
        }
        if (hi < PyStr.len(text)) {
            snippet = snippet + "...";
        }
        return snippet;
    }

    private static Map<String, Object> knownSpan(String text, String category, String action, String context) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("text", text);
        m.put("category", category);
        m.put("action", action);
        m.put("context", context);
        return m;
    }

    static Map<String, Object> suggestion(Span span, Map<String, TextUnit> unitsById) {
        TextUnit unit = unitsById.get(span.unitId());
        String context = unit == null ? span.text() : window(unit.normalizedText(), span.start(), span.end());
        return knownSpan(span.text(), span.category().wire(), span.action().wire(), context);
    }

    static Map<String, Object> findingKnownSpan(Finding finding, Chunk chunk) {
        String context = finding.text();
        for (TextUnit unit : chunk.units()) {
            int idx = PyStr.find(unit.normalizedText(), finding.text(), 0);
            if (idx == -1) {
                continue;
            }
            context = window(unit.normalizedText(), idx, idx + PyStr.len(finding.text()));
            break;
        }
        return knownSpan(finding.text(), finding.category(), finding.action(), context);
    }

    // ------------------------------------------------------------------ provider call

    static String call(LlmClient client, RuntimeConfig cfg, String systemPrompt, String userMessage,
                       int chunkIndex, int passNumber) {
        String where = "(chunk " + chunkIndex + ", pass " + passNumber + ")";
        String content;
        try {
            content = client.complete(new LlmClient.ChatRequest(cfg.modelHandle(), systemPrompt, userMessage,
                    cfg.maxCompletionTokens()));
        } catch (LlmCallException e) {
            throw switch (e.kind()) {
                case TIMEOUT -> new AITimeoutError("LLM call timed out after " + PyFloat.repr(cfg.llmTimeoutS())
                        + "s " + where, e);
                case CONNECTION -> new AIUnavailableError("LLM provider unreachable " + where, e);
                case STATUS -> new AIProviderError("provider returned HTTP " + e.statusCode() + " " + where, e);
                case OTHER -> new AIProviderError("provider error " + where, e);
            };
        }
        if (content == null || content.isEmpty()) {
            throw new AIProviderError("empty completion (possible content filter) " + where);
        }
        return content;
    }

    private record Attempt(List<Pass2Decision> decisions, String reason, List<String> unresolved) {
    }

    private static Attempt pass2Attempt(LlmClient client, RuntimeConfig cfg, Chunk chunk,
                                        List<Map<String, Object>> knownSpans, List<Span> hints, int chunkIndex,
                                        boolean retry, String retryReason, List<String> unresolved) {
        String message = retry
                ? Prompts.buildPass2RetryMessage(chunk.text(), knownSpans, unresolved == null ? List.of() : unresolved,
                        retryReason)
                : Prompts.buildPass2Message(chunk.text(), knownSpans);
        String raw = call(client, cfg, Prompts.SYSTEM_PROMPT_PASS2, message, chunkIndex, 2);
        List<Pass2Decision> decisions;
        try {
            decisions = validatePass2Entries(raw);
        } catch (AIProviderError e) {
            return new Attempt(List.of(), e.getMessage(), unresolved == null ? List.of() : List.copyOf(unresolved));
        }
        List<String> stillUnresolved = unresolvedReviewHints(decisions, hints);
        if (!stillUnresolved.isEmpty()) {
            return new Attempt(decisions, stillUnresolved.size()
                    + " rule-flagged REVIEW entry/entries received no REDACT or PRESERVE decision", stillUnresolved);
        }
        return new Attempt(decisions, null, List.of());
    }

    // ------------------------------------------------------------------ orchestration

    /**
     * Runs both passes over every chunk, concurrently on at most {@code llm_concurrency} virtual
     * threads. Results are collected in chunk order, so output does not depend on completion
     * order. The first failure (in chunk order) cancels chunks not yet started and is rethrown
     * once in-flight chunks finish.
     */
    public static List<Span> runLlmDetection(DocumentData document, List<Span> deterministicSpans,
                                             List<Span> reviewHints, LlmClient client, RuntimeConfig cfg) {
        Map<String, TextUnit> unitsById = new HashMap<>();
        document.textUnits().forEach(u -> unitsById.put(u.unitId(), u));
        List<Chunk> chunks = splitIntoChunks(document, cfg.chunkSizeChars());
        int total = chunks.size();
        if (total == 0) {
            return List.of();
        }
        int workers = Math.min(Math.max(1, cfg.llmConcurrency()), total);
        LOG.info("LLM detection: {} chunks, {} workers", total, workers);

        List<Span> all = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(workers, Thread.ofVirtual().name("llm-chunk-", 0).factory());
        try {
            List<Future<List<Span>>> futures = new ArrayList<>();
            for (int i = 0; i < total; i++) {
                int chunkIndex = i;
                Chunk chunk = chunks.get(i);
                futures.add(pool.submit(() -> processChunk(chunkIndex, chunk, total, deterministicSpans, reviewHints,
                        unitsById, client, cfg)));
            }
            try {
                for (Future<List<Span>> f : futures) {
                    all.addAll(f.get());
                }
            } catch (ExecutionException e) {
                futures.forEach(f -> f.cancel(false));
                Throwable cause = e.getCause();
                if (cause instanceof RuntimeException re) {
                    throw re;
                }
                if (cause instanceof Error err) {
                    throw err;
                }
                throw new AIProviderError("LLM detection failed", cause);
            } catch (InterruptedException e) {
                futures.forEach(f -> f.cancel(true));
                Thread.currentThread().interrupt();
                throw new AIProviderError("LLM detection interrupted", e);
            }
        } finally {
            pool.shutdown();
            try {
                while (!pool.awaitTermination(1, java.util.concurrent.TimeUnit.MINUTES)) {
                    // In-flight chunks finish, as Python's executor context manager waits for them.
                }
            } catch (InterruptedException e) {
                pool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        return all;
    }

    private static List<Span> processChunk(int chunkIndex, Chunk chunk, int total, List<Span> deterministicSpans,
                                           List<Span> reviewHints, Map<String, TextUnit> unitsById,
                                           LlmClient client, RuntimeConfig cfg) {
        long startNanos = System.nanoTime();
        Set<String> unitIds = chunk.unitIds();
        List<Span> chunkDeterministic = deterministicSpans.stream().filter(s -> unitIds.contains(s.unitId())).toList();
        List<Span> chunkHints = reviewHints.stream().filter(s -> unitIds.contains(s.unitId())).toList();

        LOG.info("chunk {}/{}: pass 1 (blind reading)", chunkIndex + 1, total);
        String raw1 = call(client, cfg, Prompts.SYSTEM_PROMPT_PASS1, Prompts.buildPass1Message(chunk.text()),
                chunkIndex, 1);
        List<Finding> findings = parsePass1Findings(raw1);

        List<Map<String, Object>> knownSpans = new ArrayList<>();
        chunkDeterministic.forEach(s -> knownSpans.add(suggestion(s, unitsById)));
        chunkHints.forEach(s -> knownSpans.add(suggestion(s, unitsById)));
        findings.forEach(f -> knownSpans.add(findingKnownSpan(f, chunk)));

        LOG.info("chunk {}/{}: pass 2 (validation of {} known spans)", chunkIndex + 1, total, knownSpans.size());
        Attempt attempt = pass2Attempt(client, cfg, chunk, knownSpans, chunkHints, chunkIndex, false, "", null);
        if (attempt.reason() != null) {
            LOG.warn("chunk {}/{}: pass 2 rejected ({}); retrying once", chunkIndex + 1, total, attempt.reason());
            attempt = pass2Attempt(client, cfg, chunk, knownSpans, chunkHints, chunkIndex, true, attempt.reason(),
                    attempt.unresolved());
            if (attempt.reason() != null) {
                throw new AIProviderError("pass 2 still incomplete after one retry (chunk " + chunkIndex + "): "
                        + attempt.reason());
            }
        }
        List<Span> chunkSpans = locatePass2Decisions(attempt.decisions(), chunk);
        LOG.info("chunk {}/{}: done — {} spans located ({}s)", chunkIndex + 1, total, chunkSpans.size(),
                PyFloat.fixed((System.nanoTime() - startNanos) / 1e9, 1));
        return chunkSpans;
    }
}
