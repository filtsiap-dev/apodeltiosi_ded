package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.AITimeoutError;
import dev.filtsiap.ded.anonymizer.AIUnavailableError;
import dev.filtsiap.ded.anonymizer.AnonymizerError;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.Deadline;
import dev.filtsiap.ded.anonymizer.DocumentData;
import dev.filtsiap.ded.anonymizer.DocumentTimeoutError;
import dev.filtsiap.ded.anonymizer.PolicySettings;
import dev.filtsiap.ded.anonymizer.Resolver;
import dev.filtsiap.ded.anonymizer.ResourceLimitExceededError;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.SpanCategory;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitSlice;
import dev.filtsiap.ded.anonymizer.UnresolvedFinding;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.Completion;
import dev.filtsiap.ded.anonymizer.llm.Pass2Queue.Candidate;
import dev.filtsiap.ded.anonymizer.llm.Pass2Queue.Decision;
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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.function.DoubleSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Two-pass LLM detection (port of {@code llm/detector.py}).
 *
 * <p>EVERY PASS READS THE MASKED VIEW ({@link HardDecisions}): the rule engine's hard redactions
 * are runs of dots in every excerpt and every context window sent, at the same coordinates as the
 * document, which keeps its own text for the resolver and the write-back.
 *
 * <p>Pass 1 is DISCOVERY: its only input is the masked rendered chunk. A completed response that
 * cannot be used gets ONE corrective call; one still unusable, or one the provider never
 * delivered, leaves explicit incomplete-coverage review work. The chunk continues with usable
 * evidence and rules; incomplete discovery can never mean a fully processed document.
 *
 * <p>ROUTING, THEN ONE DOCUMENT-WIDE PASS 2. After pass 1, every chunk is routed
 * ({@link Pass2Queue#route}): each proposal (rule span, rule REVIEW hint, located pass-1 finding)
 * is cut into atomic intervals. An atom where a source said REVIEW, where the rules' own decision
 * and pass 1's disagree, or where a rule REDACT has no pass-1 decision over its whole place, is a
 * question: every actionable candidate gets an LLM decision, pass 1's or pass 2's. Agreement and a
 * pass-1-only decision are applied as {@code LLM_PASS1} spans; the rules' spans reach the resolver
 * as evidence; hard policy is never asked about. The questions of all chunks become one queue: a
 * question the document's {@link DecisionRegistry} already answers (the same complete value, with a
 * confirmed reusable decision) is not asked; the rest get stable ids, exact duplicates folded
 * ({@link Pass2Queue#consolidate}), and are cut into bounded batches ({@link Pass2Queue#batches}).
 * An empty queue makes no pass-2 call. Afterwards the registry's reusable decisions are applied at
 * every other occurrence of their value, through the same resolver.
 *
 * <p>Pass 2 is ADJUDICATION of a candidate queue and nothing else: each candidate's id, text,
 * every recommendation made for it and 40 code points of masked context either side, never the
 * chunk. Pass 2 must return exactly one final REDACT or PRESERVE per issued id and nothing else.
 * Answers are keyed by id and written at the candidate's stored locations (see
 * {@link Pass2Queue}). A usable pass-1 finding that cannot be located is carried out as an
 * {@link UnresolvedFinding}, never dropped as if it had been decided.
 *
 * <p>A pass-2 response is judged by the provider's finish reason BEFORE its body: a truncated,
 * filtered or refused completion is not a reading. A response that is a reading but left things
 * open (an id missing, an id answered twice) keeps what it got right and gets ONE targeted
 * corrective retry; anything still open afterwards becomes an {@link UnresolvedFinding} for a
 * person rather than a guessed answer. A batch pass 2 never managed to read, or whose provider
 * stayed unavailable, no longer fails the document: what it had already decided is kept, and
 * every other candidate in it gets the documented fallback ({@link Pass2Queue.Fallback}) and a
 * {@code PASS2_UNAVAILABLE} finding of its own, so the document is returned needs-review.
 *
 * <p>Transport retries are separate and live here too ({@link Provider#call}): the SDK makes
 * exactly one attempt, and this class retries transient failures, six attempts in all. A valid
 * {@code retry-after-ms} from the provider is waited exactly (zero included); otherwise the wait is
 * an exponential backoff with jitter. All the waits of one request together never exceed
 * {@link #MAX_CUMULATIVE_WAIT_MS}; a wait that does not fit there, or in the document's budget,
 * ends the retries.
 *
 * <p>Everything runs inside the document's {@link RunContext}: no chunk, pass, corrective retry,
 * provider attempt or retry sleep begins once the budget is spent, and each attempt's timeout is
 * cut to what is left of it.
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

    private static final PyPattern BRACKETED_ARRAY = PyRegex.compile("\\[.*\\]", PyRegex.DOTALL);

    /** Six attempts per logical request: the first and five retries. */
    static final int MAX_PROVIDER_ATTEMPTS = 6;
    /**
     * The nominal backoff before retry 1 when the provider named no wait; it doubles for each later
     * retry (2, 4, 8, 16, 32 s) and the actual wait is drawn from [nominal/2, nominal).
     */
    static final long BACKOFF_BASE_MS = 2_000L;
    /** All the waits of one logical request together, header and backoff alike, never exceed this. */
    static final long MAX_CUMULATIVE_WAIT_MS = 65_000L;
    /** Statuses worth repeating a request for, besides 5xx; any other 4xx is the request being wrong. */
    private static final Set<Integer> RETRYABLE_STATUS_CODES = Set.of(408, 409, 429);
    /** A retry sleep is only worth starting if there is room for the call that follows it. */
    private static final double MIN_SLEEP_HEADROOM_S = 1.0;

    private LlmDetector() {
    }

    /**
     * What the LLM stage produced for a whole document. {@code spans}: the LLM's decisions for the
     * resolver (pass-2 answers, pass-1 decisions applied without a question, and the fallback's pass-1
     * decisions); the rules' own spans are not among them and go to the resolver unchanged.
     * {@code unresolved}: what it could not settle. {@code evidence}: every place with a REDACT or
     * REVIEW recommendation and what the rule engine and pass 1 recommended there, which the
     * post-redaction re-ask is given back; it is never a decision.
     */
    public record Result(List<Span> spans, List<UnresolvedFinding> unresolved, List<Evidence> evidence) {
        public Result {
            spans = List.copyOf(spans);
            unresolved = List.copyOf(unresolved);
            evidence = List.copyOf(evidence);
        }
    }

    /** One recommendation one or more sources made at one exact location of the first adjudication. */
    public record Evidence(UnitSlice location, List<String> sources, SpanAction action, SpanCategory category) {
        public Evidence {
            sources = List.copyOf(sources);
        }
    }

    /** Names a chunk for a person: always 1-based. */
    static String chunkLabel(int chunkIndex) {
        return "chunk " + (chunkIndex + 1);
    }

    static String chunkLabel(int chunkIndex, int total) {
        return chunkLabel(chunkIndex) + "/" + total;
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

    /** Python {@code str(entry.get(key, ""))}. */
    static String field(Map<?, ?> entry, String key) {
        return entry.containsKey(key) ? PyRepr.str(entry.get(key)) : "";
    }

    /** An entry's category with aliases resolved; null when it is off-schema. The one place model categories enter. */
    static SpanCategory readCategory(Map<?, ?> entry) {
        String category = PyStr.upper(PyStr.strip(field(entry, "category")));
        return SpanCategory.fromWire(CATEGORY_ALIASES.getOrDefault(category, category)).orElse(null);
    }

    // ------------------------------------------------------------------ pass 1 (lenient)

    /** A pass-1 proposal. Never a span: it reaches the plan only by being adjudicated in pass 2. */
    public record Finding(String text, SpanAction action, SpanCategory category) {
    }

    /** Lenient: a bad entry is dropped and the rest survive; unparseable output gives no findings. */
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
            SpanCategory category = readCategory(entry);
            if (category == null) {
                LOG.debug("pass-1 dropping entry with invalid category");
                continue;
            }
            findings.add(new Finding(text, SpanAction.valueOf(action), category));
        }
        return findings;
    }

    /** How one chunk's pass 1 turned out. */
    enum Pass1Outcome {
        SUCCESS("pass1_success"), PARSE_FAILURE("pass1_parse_failure"), OUTPUT_TRUNCATED("pass1_output_truncated"),
        PROVIDER_FAILURE("pass1_provider_failure");

        final String wire;

        Pass1Outcome(String wire) {
            this.wire = wire;
        }
    }

    /** What one chunk's pass 1 was worth; {@code detail} is counts and shapes only, never model text. */
    record Pass1Reading(List<Finding> findings, Pass1Outcome outcome, String detail) {
        boolean degraded() {
            return outcome != Pass1Outcome.SUCCESS;
        }
    }

    /**
     * Decides what a completed pass-1 call contributes. Never raises: pass 1 is evidence, and an
     * unusable one costs its findings, nothing else. A truncated body is dropped whole, since a
     * prefix of a list looks exactly like a complete shorter list.
     */
    static Pass1Reading readPass1(Completion completion) {
        if (completion.truncated()) {
            return new Pass1Reading(List.of(), Pass1Outcome.OUTPUT_TRUNCATED, "output stopped at the token limit");
        }
        if (!completion.complete()) {
            return new Pass1Reading(List.of(), Pass1Outcome.PARSE_FAILURE, completion.problem());
        }
        if (PyStr.strip(completion.text()).isEmpty()) {
            return new Pass1Reading(List.of(), Pass1Outcome.PARSE_FAILURE, "the completion was empty");
        }
        List<?> entries = extractJsonArray(completion.text());
        if (entries == null) {
            return new Pass1Reading(List.of(), Pass1Outcome.PARSE_FAILURE, "the output was not a JSON array");
        }
        List<Finding> findings = parsePass1Findings(completion.text());
        long invalid = entries.stream().filter(o -> {
            if (!(o instanceof Map<?, ?> entry) || !(entry.get("action") instanceof String action)) {
                return true;
            }
            action = PyStr.upper(PyStr.strip(action));
            if (action.equals("SKIP")) {
                return false;
            }
            return !Set.of("REDACT", "PRESERVE", "REVIEW").contains(action)
                    || !(entry.get("text") instanceof String text) || PyStr.strip(text).isEmpty()
                    || readCategory(entry) == null;
        }).count();
        if (invalid > 0) {
            return new Pass1Reading(findings, Pass1Outcome.PARSE_FAILURE,
                    invalid + " of " + entries.size() + " discovery entries unusable");
        }
        return new Pass1Reading(findings, Pass1Outcome.SUCCESS, findings.size() + " finding(s)");
    }

    // ------------------------------------------------------------------ provider calls

    /** Waits between provider retries, in milliseconds, interruptibly; replaceable so tests need not really sleep. */
    @FunctionalInterface
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    static final Sleeper REAL_SLEEP = Thread::sleep;

    /** Uniform in [0, 1): the jitter of a backoff wait; replaceable so tests are deterministic. */
    static final DoubleSupplier REAL_JITTER = () -> ThreadLocalRandom.current().nextDouble();

    /** One retry's wait and where it came from: {@code header} (the provider asked) or {@code backoff}. */
    record RetryDelay(long millis, String source) {
    }

    /**
     * The wait before retry {@code retry} (1-based). A valid {@code retry-after-ms} is the wait,
     * exactly, zero included: never shortened and never lengthened. Without one, an exponential
     * backoff with "equal" jitter: nominal {@code BACKOFF_BASE_MS * 2^(retry-1)}, drawn from
     * [nominal/2, nominal) by {@code jitter} in [0, 1). The cumulative cap is applied by the caller.
     */
    static RetryDelay retryDelay(int retry, Long retryAfterMs, double jitter) {
        if (retryAfterMs != null) {
            return new RetryDelay(retryAfterMs, "header");
        }
        long nominal = BACKOFF_BASE_MS << Math.max(0, retry - 1);
        long half = nominal / 2;
        double unit = Math.min(Math.max(jitter, 0.0), Math.nextDown(1.0));
        return new RetryDelay(half + (long) (unit * (nominal - half)), "backoff");
    }

    /** One failed call, classified once: a log label with no provider text, and the typed error to raise. */
    private record ProviderFailure(String label, boolean retryable, AnonymizerError error, Integer httpStatus) {
    }

    /** Maps a provider failure to a retry decision (timeouts, connections, 408/409/429 and 5xx retry). */
    private static ProviderFailure classify(LlmCallException e, String unit, int index, int passNumber,
                                            RuntimeConfig cfg) {
        String where = "(" + unit + " " + (index + 1) + ", pass " + passNumber + ")";
        return switch (e.kind()) {
            case TIMEOUT -> new ProviderFailure("timeout", true, new AITimeoutError(
                    "LLM call timed out after " + PyFloat.repr(cfg.llmTimeoutS()) + "s " + where, e), null);
            case CONNECTION -> new ProviderFailure("connection", true,
                    new AIUnavailableError("LLM provider unreachable " + where, e), null);
            case STATUS -> {
                int status = e.statusCode();
                // 429 gets its own label: rate limiting has a specific remedy and must be findable.
                yield new ProviderFailure(status == 429 ? "rate_limited" : "http_" + status,
                        RETRYABLE_STATUS_CODES.contains(status) || (status >= 500 && status <= 599),
                        new AIProviderError("provider returned HTTP " + status + " " + where, e), status);
            }
            case OTHER -> new ProviderFailure("provider_error", false,
                    new AIProviderError("provider error " + where, e), null);
        };
    }

    /** The client, its configuration, how retries wait (and their jitter), and whose budget they spend. */
    record Provider(LlmClient client, RuntimeConfig cfg, Sleeper sleeper, RunContext ctx, DoubleSupplier jitter) {

        Provider(LlmClient client, RuntimeConfig cfg, Sleeper sleeper, RunContext ctx) {
            this(client, cfg, sleeper, ctx, REAL_JITTER);
        }

        /** A request on behalf of one chunk (pass 1, the post-redaction re-ask). */
        Completion call(String systemPrompt, String userMessage, int chunkIndex, CallKind kind) {
            return call(systemPrompt, userMessage, "chunk", chunkIndex, chunkIndex, kind);
        }

        /**
         * One logical request on behalf of {@code unit} {@code index} ("chunk" or "batch", 0-based),
         * retrying transient failures up to {@link #MAX_PROVIDER_ATTEMPTS} times, each wait chosen by
         * {@link #retryDelay}. A non-retryable failure stops at once; an exhausted ladder raises what
         * the last attempt classified as. Every non-plain outcome is logged with counts, positions,
         * the wait and an error label only, never a response body. A request that completed always
         * returns its {@link Completion}, however unusable: judging it is the caller's job.
         *
         * <p>THE WAITS: a valid {@code retry-after-ms} exactly (never shortened), else the jittered
         * backoff, and all of one request's waits together within {@link #MAX_CUMULATIVE_WAIT_MS}: a
         * backoff wait is clipped to what is left of it, a provider-requested wait that does not fit
         * ends the retries. Retries also end when the document is cancelled
         * ({@link DocumentTimeoutError}), or when the wait and the call after it could not finish
         * within the document's budget: then the classified provider error is raised, so the caller's
         * documented fallback applies, unless no more than {@link Deadline#MIN_ATTEMPT_BUDGET_S} is
         * left, which is the document running out of time ({@link DocumentTimeoutError}).
         *
         * <p>Every attempt spends the document's budget: none starts once the document is
         * cancelled or has no more than {@link Deadline#MIN_ATTEMPT_BUDGET_S} left, and each gets the
         * smaller of the configured timeout and the remaining budget.
         *
         * <p>Every attempt is booked on the document's {@link UsageRecorder} as {@code kind}: a
         * response with what the provider reported about it (before its body is judged, since a
         * truncated or empty completion still cost tokens), a failed attempt with its time only.
         * {@code ledgerChunk} is the chunk the ledger books the call under (for a batch, the chunk of its
         * first candidate), so a truncation report names a chunk, never a batch number.
         */
        Completion call(String systemPrompt, String userMessage, String unit, int index, int ledgerChunk,
                        CallKind kind) {
            int passNumber = kind.passNumber();
            String tag = unit.equals("chunk") ? ctx.chunkTag(index, passNumber, kind.attempt())
                    : ctx.tag() + " " + unit + "=" + (index + 1) + " pass=" + passNumber + " attempt=" + kind.attempt();
            String stage = "llm pass " + passNumber;
            Deadline deadline = ctx.deadline();
            String provider = cfg.provider().wire();
            long waited = 0;
            int chunkNumber = ledgerChunk + 1;
            for (int transport = 1; ; transport++) {
                if (deadline.cancelled()) {
                    if (transport > 1) {
                        LOG.warn("llm_retry_aborted {} transport_attempt={} reason=cancelled waited_ms={}", tag,
                                transport, waited);
                    }
                    throw new DocumentTimeoutError(stage);
                }
                LlmClient.ChatRequest request;
                try {
                    request = new LlmClient.ChatRequest(cfg.modelHandle(), systemPrompt, userMessage,
                            cfg.maxCompletionTokens(), deadline.budget(cfg.llmTimeoutS(), stage));
                } catch (DocumentTimeoutError e) {
                    if (transport > 1) {
                        LOG.warn("llm_retry_aborted {} transport_attempt={} reason=deadline waited_ms={}", tag,
                                transport, waited);
                    }
                    throw e;
                }
                if (transport > 1) {
                    LOG.info("llm_retry_started {} transport_attempt={} waited_ms={}", tag, transport, waited);
                }
                Completion completion;
                long started = System.nanoTime();
                try {
                    completion = client.complete(request);
                } catch (LlmCallException e) {
                    long attemptNanos = System.nanoTime() - started;
                    ctx.usage().recordFailedAttempt(attemptNanos);
                    ProviderFailure failure = classify(e, unit, index, passNumber, cfg);
                    Object status = failure.httpStatus() == null ? "-" : failure.httpStatus();
                    ctx.progress().providerFailed(chunkNumber, passNumber, failure.label(), failure.httpStatus());
                    if (deadline.expired()) {
                        LOG.warn("llm_deadline_expired {} transport_attempt={} error={}", tag, transport,
                                failure.label());
                        throw new DocumentTimeoutError(stage);
                    }
                    if (!failure.retryable()) {
                        LOG.warn("llm_not_retryable {} transport_attempt={} error={} provider={} http_status={} "
                                + "will_retry=no", tag, transport, failure.label(), provider, status);
                        throw failure.error();
                    }
                    if (transport == MAX_PROVIDER_ATTEMPTS) {
                        LOG.error("llm_retry_exhausted {} attempts={} error={} provider={} http_status={} "
                                + "waited_ms={} will_retry=no", tag, transport, failure.label(), provider, status,
                                waited);
                        throw failure.error();
                    }
                    if (deadline.cancelled()) {
                        LOG.warn("llm_retry_skipped {} reason=cancelled error={}", tag, failure.label());
                        throw new DocumentTimeoutError(stage);
                    }
                    RetryDelay delay = retryDelay(transport, e.retryAfterMs(), jitter.getAsDouble());
                    long room = MAX_CUMULATIVE_WAIT_MS - waited;
                    boolean backoff = delay.source().equals("backoff");
                    if (backoff && delay.millis() > room) {
                        delay = new RetryDelay(room, "backoff"); // clipped to what is left of the cap
                    }
                    if (delay.millis() > room || (backoff && room <= 0)) {
                        // The request has waited all it may; a provider-asked wait is never shortened to fit.
                        LOG.warn("llm_retry_skipped {} reason=wait_budget delay_ms={} delay_source={} waited_ms={} "
                                + "error={} will_retry=no", tag, delay.millis(), delay.source(), waited,
                                failure.label());
                        throw failure.error();
                    }
                    if (deadline.remaining() < delay.millis() / 1000.0 + MIN_SLEEP_HEADROOM_S) {
                        // Sleeping through the rest of the budget to make a call that cannot finish. With
                        // time still left this is the provider being unavailable in time, and the caller's
                        // fallback applies; with none left it is the document running out of time.
                        LOG.warn("llm_retry_skipped {} reason=deadline delay_ms={} delay_source={} remaining_s={} "
                                + "error={} will_retry=no", tag, delay.millis(), delay.source(),
                                PyFloat.fixed(deadline.remaining(), 1), failure.label());
                        if (deadline.remaining() <= Deadline.MIN_ATTEMPT_BUDGET_S) {
                            throw new DocumentTimeoutError(stage);
                        }
                        throw failure.error();
                    }
                    LOG.warn("llm_retry {} transport_attempt={} retry={}/{} delay_ms={} delay_source={} error={} "
                                    + "provider={} http_status={} attempt_ms={} waited_ms={} will_retry=yes", tag,
                            transport, transport, MAX_PROVIDER_ATTEMPTS - 1, delay.millis(), delay.source(),
                            failure.label(), provider, status, attemptNanos / 1_000_000, waited);
                    try {
                        sleeper.sleep(delay.millis());
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        LOG.warn("llm_retry_interrupted {} transport_attempt={} waited_ms={} error={}", tag, transport,
                                waited, failure.label());
                        throw new AIProviderError("LLM detection interrupted", ie);
                    }
                    waited += delay.millis();
                    continue;
                } catch (RuntimeException e) {
                    // Not a provider failure: nothing above classified it, so name it before it propagates.
                    LOG.error("llm_call_failed_unexpectedly {} transport_attempt={} error={}", tag, transport,
                            e.getClass().getSimpleName());
                    throw e;
                }
                long elapsed = System.nanoTime() - started;
                if (transport > 1) {
                    LOG.info("llm_retry_succeeded {} transport_attempt={} waited_ms={}", tag, transport, waited);
                    ctx.progress().providerRecovered(chunkNumber, passNumber);
                }
                if (completion == null) {
                    completion = new Completion("", null, false);
                }
                ctx.usage().record(completion, ledgerChunk, kind, cfg.maxCompletionTokens(), elapsed);
                if (completion.truncated()) {
                    LOG.warn("llm_truncated {} limit={}", tag, cfg.maxCompletionTokens());
                }
                return completion;
            }
        }
    }

    // ------------------------------------------------------------------ pass 1: discovery, never fatal

    /**
     * One chunk's discovery. A completed response that cannot be used (the existing pass-1
     * criteria, {@link #readPass1}) gets at most ONE corrective call: the same masked excerpt and
     * a machine-written line asking for a complete answer, itself on the normal transport ladder.
     * Whatever is still unusable, and a provider failure that kept discovery from happening at
     * all, leaves incomplete-coverage review work. Usable proposals from partial readings survive;
     * neither an exhausted correction nor a provider failure starts another discovery call.
     *
     * <p>Only provider failures are absorbed. The deadline, cancellation (an interrupted wait
     * included) and every other error propagate exactly as before.
     */
    private static Pass1Reading discover(Provider provider, String excerpt, int chunkIndex) {
        RunContext ctx = provider.ctx();
        UsageRecorder usage = ctx.usage();
        String tag = ctx.chunkTag(chunkIndex, 1, CallKind.PASS1.attempt());
        Pass1Reading reading = null;
        try {
            reading = readPass1(provider.call(Prompts.SYSTEM_PROMPT_PASS1, Prompts.buildPass1Message(excerpt),
                    chunkIndex, CallKind.PASS1));
            if (reading.degraded()) {
                LOG.warn("pass1_unusable {} reason={} detail={} corrective_call=yes", tag, reading.outcome().wire,
                        reading.detail());
                ctx.deadline().check("llm pass 1 corrective retry");
                Pass1Reading corrected = readPass1(provider.call(Prompts.SYSTEM_PROMPT_PASS1,
                        Prompts.buildPass1RetryMessage(excerpt, reading.detail()), chunkIndex, CallKind.PASS1));
                if (corrected.degraded()) {
                    List<Finding> usable = new ArrayList<>(reading.findings());
                    corrected.findings().stream().filter(f -> !usable.contains(f)).forEach(usable::add);
                    reading = new Pass1Reading(List.copyOf(usable), corrected.outcome(), corrected.detail());
                } else {
                    reading = corrected;
                }
            }
        } catch (AIProviderError | AITimeoutError | AIUnavailableError e) {
            if (Thread.currentThread().isInterrupted() || ctx.deadline().done()) {
                throw e; // cancellation or the deadline, not the provider
            }
            reading = new Pass1Reading(reading == null ? List.of() : reading.findings(),
                    Pass1Outcome.PROVIDER_FAILURE, "provider did not deliver complete discovery coverage");
            usage.recordPass1(reading.outcome());
            LOG.warn("pass1_discovery_degraded {} reason=pass1_provider_failure error={} code={} — continuing with "
                    + "incomplete discovery coverage", tag, e.getClass().getSimpleName(), e.code());
            return reading;
        }
        usage.recordPass1(reading.outcome());
        if (reading.degraded()) {
            LOG.warn("pass1_discovery_degraded {} reason={} detail={} — discovery coverage needs review", tag,
                    reading.outcome().wire, reading.detail());
        } else {
            LOG.info("{} pass 1 {} — {}", tag, reading.outcome().wire, reading.detail());
        }
        return reading;
    }

    // ------------------------------------------------------------------ pass 2 (strict)

    /** What one pass-2 call was worth before anything in it is believed; only COMPLETE is a reading. */
    enum AttemptOutcome {
        COMPLETE("complete"), INCOMPLETE_LENGTH("incomplete_length"), INCOMPLETE_FILTERED("incomplete_filtered"),
        INCOMPLETE_OTHER("incomplete_other"), INCOMPLETE_EMPTY("incomplete_empty"), UNPARSEABLE("unparseable");

        final String wire;

        AttemptOutcome(String wire) {
            this.wire = wire;
        }
    }

    /** One pass-2 call and its verdict; {@code reason} is null exactly when it is usable AND complete. */
    private record Pass2Attempt(List<Decision> decisions, String reason, AttemptOutcome outcome,
                                List<String> rejections, List<String> voided, boolean distrusted) {

        static Pass2Attempt unusable(AttemptOutcome outcome, String reason) {
            return new Pass2Attempt(List.of(), reason, outcome, List.of(), List.of(), false);
        }

        /** Whether the response was a reading at all; a usable one can still have left things open. */
        boolean usable() {
            return outcome == AttemptOutcome.COMPLETE;
        }
    }

    /**
     * One queue's settled outcome (a batch, or a chunk of the post-redaction re-ask); attempts includes
     * any bounded length-triggered subdivisions. {@code unavailable} are the candidates pass 2 could not
     * be had for (the provider stayed unavailable after its retries, or never produced a usable
     * reading), each with its own safe cause label in {@code causes} (by candidate id: the halves of a
     * length-split batch can fail differently); decisions already accepted are kept.
     */
    record Adjudication(List<Decision> decisions, List<UnresolvedFinding> unresolved, int attempts,
                        List<Candidate> unavailable, Map<String, String> causes) {
        Adjudication {
            decisions = List.copyOf(decisions);
            unresolved = List.copyOf(unresolved);
            unavailable = List.copyOf(unavailable);
            causes = Map.copyOf(causes);
        }

        Adjudication(List<Decision> decisions, List<UnresolvedFinding> unresolved, int attempts) {
            this(decisions, unresolved, attempts, List.of(), Map.of());
        }
    }

    /**
     * HTTP statuses that say the service is MISCONFIGURED (a wrong key, no access, no such deployment)
     * rather than unavailable: never absorbed by the fallback, so a broken configuration fails loudly
     * instead of quietly returning every document needs-review.
     */
    private static final Set<Integer> CONFIGURATION_STATUSES = Set.of(401, 403, 404);

    private static boolean misconfigured(AnonymizerError e) {
        for (Throwable c = e; c != null; c = c.getCause() == c ? null : c.getCause()) {
            if (c instanceof LlmCallException call) {
                return call.kind() == LlmCallException.Kind.STATUS && CONFIGURATION_STATUSES.contains(call.statusCode());
            }
        }
        return false;
    }

    /** Adjudicates one queue with at most one corrective retry; the queue is all it sends. */
    private static final class Adjudicator {
        private final Provider provider;
        private final List<Candidate> candidates;
        /** 0-based: the batch, or for the re-ask the chunk. */
        private final int index;
        private final String unit;
        private final String label;
        /** The candidates come from the ALREADY-REDACTED document; selects one instruction line and nothing else. */
        private final boolean remediation;
        private final int total;
        private Pass2Attempt first;
        /** What a usable reading has already decided; survives a later provider failure. */
        private final Map<String, Decision> accepted = new LinkedHashMap<>();
        private int calls;

        /** {@code index} of {@code total}: a document-wide batch, or (for the re-ask) a chunk. */
        Adjudicator(Provider provider, List<Candidate> candidates, int index, int total, boolean remediation) {
            this.provider = provider;
            this.candidates = candidates;
            this.index = index;
            this.unit = remediation ? "chunk" : "batch";
            this.label = unit + " " + (index + 1) + "/" + total;
            this.remediation = remediation;
            this.total = total;
        }

        /**
         * {@link #adjudicate}, with the provider's unavailability absorbed: when pass 2 cannot be had
         * (a provider error after its retries, a retry that could not fit in time, or no usable reading
         * after the corrective retry) whatever a usable reading already decided is kept and the rest
         * is returned as {@code unavailable}, for the caller's documented fallback. Cancellation, the
         * deadline, a misconfigured service (HTTP 401/403/404) and every other error propagate exactly
         * as before.
         */
        Adjudication run() {
            try {
                return adjudicate();
            } catch (AIProviderError | AITimeoutError | AIUnavailableError e) {
                if (Thread.currentThread().isInterrupted() || provider.ctx().deadline().done()) {
                    throw e; // cancellation or the deadline, not the provider
                }
                if (misconfigured(e)) {
                    throw e; // a configuration to fix, not an outage to work around
                }
                List<Decision> kept = candidates.stream().filter(c -> accepted.containsKey(c.id()))
                        .map(c -> accepted.get(c.id())).toList();
                List<Candidate> unavailable = candidates.stream().filter(c -> !accepted.containsKey(c.id())).toList();
                String cause = failureCause(e);
                LOG.warn("{}: pass2_unavailable cause={} error={} code={} kept_decisions={} left_to_fallback={} {}",
                        label, cause, e.getClass().getSimpleName(), e.code(), kept.size(), unavailable.size(),
                        provider.ctx().tag());
                Map<String, String> causes = new LinkedHashMap<>();
                unavailable.forEach(c -> causes.put(c.id(), cause));
                return new Adjudication(kept, List.of(), calls, unavailable, causes);
            }
        }

        /**
         * THREE THINGS CAN BE WRONG, and they get different answers: (1) not a reading at all:
         * the whole queue is asked again, and a second non-reading means pass 2 is unavailable for
         * the queue; (2) not tracking the queue (an id it never issued, {@code NEW} included): its
         * decisions are not trusted and the whole queue is asked again; (3) a reading that left things
         * open: everything it got right is kept and only the outstanding items are re-asked.
         */
        private Adjudication adjudicate() {
            first = attempt(candidates, false, null, true);
            if (first.outcome() == AttemptOutcome.INCOMPLETE_LENGTH && candidates.size() > 1) {
                return splitAfterLength(1);
            }
            if (first.usable() && !first.distrusted()) {
                // Only a trusted reading's decisions are kept, also should a later call fail.
                first.decisions().forEach(d -> accepted.put(d.candidateId(), d));
            }

            if (first.reason() == null) {
                return new Adjudication(candidates.stream().map(c -> accepted.get(c.id())).toList(), List.of(), 1);
            }

            if (!first.usable() || first.distrusted()) {
                if (!first.usable()) {
                    LOG.warn("{}: pass 2 was not a usable reading ({}); asking the whole queue again ({} "
                            + "candidate(s))", label, first.reason(), candidates.size());
                } else {
                    LOG.warn("{}: pass 2 rejected ({}); it answered ids this queue never issued, so the whole queue "
                            + "is being asked again ({} candidate(s))", label, first.reason(), candidates.size());
                }
                provider.ctx().deadline().check("llm pass 2 corrective retry");
                Pass2Attempt second = attempt(candidates, true, first, false);
                if (second.outcome() == AttemptOutcome.INCOMPLETE_LENGTH && candidates.size() > 1) {
                    return splitAfterLength(2);
                }
                if (!second.usable() || second.distrusted()) {
                    throw abandon(second);
                }
                return settle(Map.of(), second, 2);
            }

            List<Candidate> queue = candidates.stream().filter(c -> !accepted.containsKey(c.id())).toList();
            if (queue.isEmpty()) {
                // Every rejection was already accounted for; nothing is outstanding.
                return settle(accepted, null, 1);
            }
            LOG.warn("{}: pass 2 rejected ({}); retrying {} of {} candidate(s), keeping {} already decided", label,
                    first.reason(), queue.size(), candidates.size(), accepted.size());
            provider.ctx().deadline().check("llm pass 2 corrective retry");
            Pass2Attempt second = attempt(queue, true, first, true);
            if (!second.usable()) {
                // The first attempt WAS a reading; only the correction failed. Keep it, leave the rest for review.
                LOG.warn("{}: the corrective retry was not a usable reading ({}); keeping the first reading and "
                        + "leaving {} item(s) for human review", label, second.reason(), queue.size());
                return settle(accepted, null, 2);
            }
            return settle(accepted, second, 2);
        }

        /** No truncated prefix is accepted. Original IDs/locations survive a strictly decreasing split. */
        private Adjudication splitAfterLength(int spent) {
            provider.ctx().deadline().check("llm pass 2 length split");
            int middle = candidates.size() / 2;
            LOG.info("{}: pass 2 length split candidates={} into={}+{} remediation={}", label,
                    candidates.size(), middle, candidates.size() - middle, remediation);
            // Each half absorbs its own provider failure, so what one half decided survives the other.
            Adjudication left = new Adjudicator(provider, candidates.subList(0, middle), index, total, remediation).run();
            provider.ctx().deadline().check("llm pass 2 length split");
            Adjudication right = new Adjudicator(provider, candidates.subList(middle, candidates.size()),
                    index, total, remediation).run();
            List<Decision> decisions = new ArrayList<>(left.decisions());
            decisions.addAll(right.decisions());
            List<UnresolvedFinding> unresolved = new ArrayList<>(left.unresolved());
            unresolved.addAll(right.unresolved());
            List<Candidate> unavailable = new ArrayList<>(left.unavailable());
            unavailable.addAll(right.unavailable());
            Map<String, String> causes = new LinkedHashMap<>(left.causes());
            causes.putAll(right.causes());
            return new Adjudication(decisions, unresolved, spent + left.attempts() + right.attempts(), unavailable,
                    causes);
        }

        private AIProviderError abandon(Pass2Attempt second) {
            String headline = !second.usable() ? "pass 2 produced no usable reading after one retry"
                    : "pass 2 never tracked its queue, after one retry";
            return new AIProviderError(headline + " (" + unit + " " + (index + 1) + "): first attempt: "
                    + first.reason() + "; retry: " + second.reason());
        }

        /**
         * Makes one pass-2 call over {@code asked} and judges it. The finish reason is read before
         * the body; a usable attempt is additionally complete only when nothing was rejected and
         * every asked candidate came back decided.
         */
        private Pass2Attempt attempt(List<Candidate> asked, boolean retry, Pass2Attempt previous, boolean keptPrevious) {
            Map<String, Candidate> byId = new LinkedHashMap<>();
            asked.forEach(c -> byId.put(c.id(), c));
            List<Map<String, Object>> payload = asked.stream().map(Candidate::asPayload).toList();
            String message = retry && previous != null
                    ? Prompts.buildPass2RetryMessage(payload, previous.rejections(),
                            previous.reason() == null ? "" : previous.reason(), keptPrevious, remediation)
                    : Prompts.buildPass2Message(payload, remediation);
            String which = retry ? "retry" : "first";
            calls++;
            // The ledger records a call by the chunk its text came from: a batch's first candidate's.
            int ledgerChunk = remediation || asked.getFirst().chunkIndex() < 0 ? index : asked.getFirst().chunkIndex();
            Completion completion = provider.call(Prompts.SYSTEM_PROMPT_PASS2, message, unit, index, ledgerChunk,
                    CallKind.pass2(retry, remediation));

            if (!completion.complete()) {
                AttemptOutcome outcome = completion.truncated() ? AttemptOutcome.INCOMPLETE_LENGTH
                        : completion.filtered() ? AttemptOutcome.INCOMPLETE_FILTERED : AttemptOutcome.INCOMPLETE_OTHER;
                return unusable(which, outcome, completion.problem());
            }
            if (PyStr.strip(completion.text()).isEmpty()) {
                // No pass-1 leniency here: pass 2's answer IS the decision.
                return unusable(which, AttemptOutcome.INCOMPLETE_EMPTY,
                        "empty completion (possible content filter) (" + unit + " " + (index + 1) + ", pass 2)");
            }
            Pass2Queue.Validation validation;
            try {
                validation = Pass2Queue.validate(completion.text(), byId);
            } catch (AIProviderError e) {
                return unusable(which, AttemptOutcome.UNPARSEABLE, e.getMessage());
            }
            provider.ctx().usage().recordPass2Attempt(true);
            List<String> undecided = Pass2Queue.unresolvedIds(validation.decisions(), asked);
            List<String> problems = new ArrayList<>();
            if (!validation.rejections().isEmpty()) {
                problems.add(validation.rejections().size() + " unusable entry/entries");
            }
            if (!undecided.isEmpty()) {
                problems.add(undecided.size() + " of " + asked.size()
                        + " candidate(s) received no REDACT or PRESERVE decision");
            }
            return new Pass2Attempt(validation.decisions(), problems.isEmpty() ? null : String.join("; ", problems),
                    AttemptOutcome.COMPLETE, validation.rejections(), validation.voided(), validation.distrusted());
        }

        private Pass2Attempt unusable(String which, AttemptOutcome outcome, String reason) {
            provider.ctx().usage().recordPass2Attempt(false);
            LOG.warn("{}: pass 2 {} attempt unusable: outcome={} ({})", unit + " " + (index + 1), which,
                    outcome.wire, reason);
            return Pass2Attempt.unusable(outcome, reason);
        }

        /** Combines what was kept with what the retry settled, and names everything still open. */
        private Adjudication settle(Map<String, Decision> kept, Pass2Attempt last, int attempts) {
            Map<String, Decision> merged = new LinkedHashMap<>(kept);
            // Voided by EITHER attempt and still open is reported as duplicated: that is what happened to it.
            Set<String> voided = new HashSet<>(first.voided());
            if (last != null) {
                voided.addAll(last.voided());
                if (!last.distrusted()) {
                    last.decisions().forEach(d -> merged.put(d.candidateId(), d));
                }
            }
            List<Decision> decisions = candidates.stream().filter(c -> merged.containsKey(c.id()))
                    .map(c -> merged.get(c.id())).toList();

            List<UnresolvedFinding> unresolved = new ArrayList<>();
            for (Candidate c : candidates) {
                if (!merged.containsKey(c.id())) {
                    UnresolvedFinding.Kind kind = voided.contains(c.id()) ? UnresolvedFinding.Kind.CANDIDATE_DUPLICATED
                            : UnresolvedFinding.Kind.CANDIDATE_UNDECIDED;
                    unresolved.add(new UnresolvedFinding(c.chunkIndex() >= 0 ? c.chunkIndex() : index, kind,
                            wire(c.category()), c.locations(), c.id(), "no final decision after the corrective retry"));
                }
            }
            if (!unresolved.isEmpty()) {
                LOG.warn("{}: pass 2 left {} finding(s) unresolved after the corrective retry; they are retained for "
                        + "human review", label, unresolved.size());
            }
            return new Adjudication(decisions, unresolved, attempts);
        }
    }

    private static String wire(SpanCategory category) {
        return category == null ? null : category.wire();
    }

    /** The cause label of a candidate never sent: no request could carry it within ANON_LLM_CONTEXT_TOKENS. */
    static final String CONTEXT_LIMIT_CAUSE = "context_limit";

    /** Estimated tokens of a small pass-2 candidate (short text, two 40-character windows, two recommendations). */
    static final int MIN_CANDIDATE_TOKENS = 300;

    /**
     * The startup check of {@code ANON_LLM_CONTEXT_TOKENS}. Unset: says once that no whole-request check
     * is made (the batch limits still apply), and nothing else. Set: the window must hold the largest
     * ordinary request (pass 1: its system prompt, a full excerpt of {@code ANON_CHUNK_SIZE_CHARS} counted
     * as Greek, the message overhead and the whole completion budget; pass 2: its fixed input, one small
     * candidate and the completion budget), by the same conservative estimate the batching uses; a window
     * that cannot is a configuration error, not something to discover document by document.
     */
    public static void checkContextLimit(RuntimeConfig cfg) {
        if (cfg.provider() == RuntimeConfig.Provider.REGEX) {
            return;
        }
        int limit = cfg.llmContextTokens();
        if (limit <= 0) {
            LOG.info("context-window check disabled: ANON_LLM_CONTEXT_TOKENS is not set, so no whole-request limit "
                    + "is enforced (batch limits still apply)");
            return;
        }
        long pass1 = Pass2Queue.estimateTokens(Prompts.SYSTEM_PROMPT_PASS1) + Pass2Queue.PASS2_MESSAGE_OVERHEAD_TOKENS
                + (long) Math.ceil(cfg.chunkSizeChars() / 1.5) + cfg.maxCompletionTokens();
        long pass2 = Pass2Queue.pass2FixedInputTokens() + MIN_CANDIDATE_TOKENS + cfg.maxCompletionTokens();
        long needed = Math.max(pass1, pass2);
        if (limit < needed) {
            throw new ConfigurationError("ANON_LLM_CONTEXT_TOKENS=" + limit
                    + " cannot hold one ordinary request (estimated " + needed + " tokens: the system prompt, an excerpt "
                    + "of ANON_CHUNK_SIZE_CHARS=" + cfg.chunkSizeChars() + " and ANON_MAX_COMPLETION_TOKENS="
                    + cfg.maxCompletionTokens() + "); raise it, or lower the chunk size or the completion budget");
        }
        LOG.info("context-window check enabled: ANON_LLM_CONTEXT_TOKENS={} (largest ordinary request estimated at {})",
                limit, needed);
    }

    /** A safe label for why pass 2 was unavailable: the failure class only, never provider or document text. */
    static String failureCause(AnonymizerError e) {
        for (Throwable c = e; c != null; c = c.getCause() == c ? null : c.getCause()) {
            if (c instanceof LlmCallException call) {
                return switch (call.kind()) {
                    case TIMEOUT -> "timeout";
                    case CONNECTION -> "connection";
                    case STATUS -> call.statusCode() == 429 ? "rate_limited" : "http_" + call.statusCode();
                    case OTHER -> "provider_error";
                };
            }
        }
        return "no_usable_reading";
    }

    // ------------------------------------------------------------------ orchestration

    /**
     * Runs the LLM stage inside {@code ctx}: pass 1 and routing for every chunk of the masked view,
     * concurrently on at most {@code llm_concurrency} virtual threads; then ONE document-wide pass-2
     * queue, in bounded batches, on at most as many. Deterministic hard decisions are never a question
     * (a hard redact is blanked in the view as well). Pass 2 is skipped exactly when the whole
     * document's queue is empty. A document splitting into more than {@code max_chunks} chunks is
     * refused before any provider call.
     *
     * <p>Results are stored by index but awaited by completion, so a failure that is not the provider's
     * (the deadline, cancellation, a bug) is seen at once: it cancels the budget (workers stop at their
     * next checkpoint), drops queued work, and does not wait for in-flight work, each of which is
     * already bounded by the budget. A provider that stays unavailable for a pass-2 batch is not such a
     * failure: that batch keeps what it decided, its other candidates get the documented fallback,
     * and every other batch is unaffected. Pass 1's results are never recomputed.
     */
    public static Result runLlmDetection(DocumentData document, List<Span> deterministicSpans, List<Span> reviewHints,
                                         LlmClient client, RuntimeConfig cfg, PolicySettings policy, Set<String> regions,
                                         RunContext ctx) {
        return runLlmDetection(document, deterministicSpans, reviewHints, new Provider(client, cfg, REAL_SLEEP, ctx),
                policy, regions);
    }

    /**
     * {@code regions} is the administrative-region allowlist: a REDACT span an LLM pass draws across a
     * municipality and its region gives the region back, as the detectors' own captures do.
     */
    static Result runLlmDetection(DocumentData document, List<Span> deterministicSpans, List<Span> reviewHints,
                                  Provider provider, PolicySettings policy, Set<String> regions) {
        RuntimeConfig cfg = provider.cfg();
        RunContext ctx = provider.ctx();
        // What the model may see: the same units at the same coordinates, hard redactions blanked.
        HardDecisions hard = HardDecisions.of(deterministicSpans, policy, document);
        DocumentData view = hard.maskedView(document);
        List<Chunk> chunks = Chunk.split(view, cfg.chunkSizeChars());
        int total = chunks.size();
        // Hard decisions are decisions, not questions: never routed, never asked about (and an LLM span
        // could not outrank one at the resolver). The caller passes them to the resolver itself.
        List<Span> adjudicable = deterministicSpans.stream()
                .filter(s -> !Resolver.isHardPreserve(s, policy) && !Resolver.isHardRedact(s, policy)).toList();
        if (total == 0) {
            return new Result(List.of(), List.of(), List.of());
        }
        if (total > cfg.limits().maxChunks()) {
            // Every table is its own chunk regardless of size, so many small tables are many chunks
            // (and many provider calls) from very little text.
            throw new ResourceLimitExceededError("document splits into " + total + " chunks; the limit is "
                    + cfg.limits().maxChunks(), "TOO_MANY_CHUNKS");
        }
        int withheld = deterministicSpans.size() - adjudicable.size();
        if (withheld > 0) {
            LOG.info("LLM detection: {} hard-policy span(s) withheld from the pass-2 queue; {} code point(s) masked in "
                    + "the text the model reads", withheld, hard.maskedCodePoints());
        }
        // The document's own units: what every LLM span is narrowed against and written from.
        Map<String, TextUnit> sourceUnits = new HashMap<>();
        document.textUnits().forEach(u -> sourceUnits.put(u.unitId(), u));
        int concurrency = Math.max(1, cfg.llmConcurrency());
        ctx.progress().chunksStarted(total);
        LOG.info("LLM detection: {} chunks, {} workers {}", total, Math.min(concurrency, total), ctx.tag());

        // Phase 1: discovery and routing, chunk by chunk, held in memory.
        List<Callable<ChunkResult>> discovery = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            int chunkIndex = i;
            Chunk chunk = chunks.get(i);
            discovery.add(() -> {
                ChunkResult result = processChunk(chunkIndex, chunk, total, adjudicable, reviewHints, hard,
                        sourceUnits, provider, policy, regions);
                ctx.progress().chunkCompleted();
                return result;
            });
        }
        List<ChunkResult> routed = runAll(discovery, Math.min(concurrency, total), "llm-chunk-", ctx);

        List<Span> spans = new ArrayList<>();
        List<UnresolvedFinding> unresolved = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();
        List<Pass2Queue.Question> questions = new ArrayList<>();
        Pass2Queue.RouteCounts counts = new Pass2Queue.RouteCounts(0, 0, 0, 0, 0, 0);
        for (ChunkResult r : routed) {
            spans.addAll(r.routed().pass1Spans());
            unresolved.addAll(r.unresolved());
            evidence.addAll(r.routed().evidence());
            questions.addAll(r.routed().questions());
            counts = counts.plus(r.routed().counts());
        }

        // The document-wide registry, request-local (built only now that every chunk has finished, so
        // no worker's timing decides anything). A question whose exact complete value already has a
        // confirmed GLOBAL_REDACT decision (a verified identifier, or a name pass 1 redacted elsewhere),
        // and nothing at its place recommends keeping it, is answered by that decision, not asked again.
        List<Span> pass1Decisions = List.copyOf(spans);
        DecisionRegistry known = DecisionRegistry.of(deterministicSpans, pass1Decisions, policy);
        List<Pass2Queue.Question> toAsk = new ArrayList<>();
        for (Pass2Queue.Question q : questions) {
            DecisionRegistry.Entry reusable = known.globalRedact(q.text());
            if (reusable != null && q.recommendations().stream().noneMatch(r -> r.action() == SpanAction.PRESERVE)) {
                spans.add(DecisionRegistry.reuse(reusable, q.location().unitId(), q.location().start(),
                        q.location().end(), sourceUnits.get(q.location().unitId()).normalizedText()));
            } else {
                toAsk.add(q);
            }
        }

        // Phase 2: one document-wide queue, stable ids, exact duplicates folded.
        List<Candidate> candidates = Pass2Queue.consolidate(toAsk);
        LOG.info("llm_routing pass1_agreed={} pass1_only={} deterministic_only={} settled_by_hard_policy={} "
                        + "questions={} unchangeable_questions_skipped={} pass2_candidates={} pass1_spans={} {}",
                counts.agreed(), counts.pass1Only(), counts.deterministicOnly(), counts.settled(), counts.questions(),
                counts.redundant(), candidates.size(), spans.size(), ctx.tag());
        if (candidates.isEmpty()) {
            ctx.usage().recordPass2(UsageRecorder.Pass2Outcome.SKIPPED, false);
            LOG.info("pass2=skipped reason=empty_queue {}", ctx.tag());
            spans.addAll(reuseEverywhere(deterministicSpans, pass1Decisions, List.of(), policy, document, hard, spans));
            return new Result(spans, unresolved, evidence);
        }
        ctx.deadline().check("llm pass 2");
        Pass2Queue.Batches planned = Pass2Queue.batches(candidates, cfg.maxCompletionTokens(), cfg.llmContextTokens(),
                Pass2Queue.pass2FixedInputTokens());
        List<List<Candidate>> batches = planned.sendable();
        int batchTotal = batches.size();
        long oversized = batches.stream().filter(b -> b.size() == 1
                && Pass2Queue.estimateTokens(b.getFirst()) > Pass2Queue.PASS2_BATCH_TOKEN_BUDGET).count();
        LOG.info("pass 2: candidates={} batches={} max_per_batch={} pass2_oversized_candidates={}{} {}",
                candidates.size(), batchTotal, Pass2Queue.maxCandidatesPerBatch(cfg.maxCompletionTokens()), oversized,
                planned.unsendable().isEmpty() ? "" : " context_limited=" + planned.unsendable().size(), ctx.tag());
        List<Callable<Adjudication>> work = new ArrayList<>();
        for (int b = 0; b < batchTotal; b++) {
            int batchIndex = b;
            List<Candidate> batch = batches.get(b);
            work.add(() -> adjudicateBatch(batchIndex, batchTotal, batch, provider));
        }
        List<Adjudication> outcomes = runAll(work, Math.min(concurrency, batchTotal), "llm-pass2-", ctx);

        // Phase 3: every answer written back by id, at the candidate's own locations.
        Map<String, Candidate> byId = new LinkedHashMap<>();
        candidates.forEach(c -> byId.put(c.id(), c));
        List<Decision> decisions = new ArrayList<>();
        Set<String> accounted = new HashSet<>();
        int failedBatches = 0;
        for (Adjudication a : outcomes) {
            decisions.addAll(a.decisions());
            a.decisions().forEach(d -> accounted.add(d.candidateId()));
            for (UnresolvedFinding open : a.unresolved()) {
                accounted.add(open.candidateId());
                // Pass 2 answered but never decided this one, even after its corrective retry: pass 2 failed for
                // it, so the same documented fallback applies as when it was unavailable (a pass-1 REDACT is
                // not left unapplied because the model was sloppy). Still a finding of the same kind.
                Candidate c = byId.get(open.candidateId());
                Pass2Queue.Fallback f = c == null ? null : c.fallback();
                if (f == null || f.pass1() == null) {
                    unresolved.add(open);
                    continue;
                }
                List<UnitSlice> unwritable = new ArrayList<>();
                spans.addAll(Pass2Queue.fallbackSpans(c, sourceUnits, regions, unwritable));
                unresolved.add(new UnresolvedFinding(open.chunkIndex(), open.kind(), open.category(), open.locations(),
                        open.candidateId(), open.detail() + "; fallback=pass1_" + f.pass1().wire() + " applied"
                        + (unwritable.isEmpty() ? "" : " (" + unwritable.size() + " location(s) could not be written)"),
                        open.audit()));
            }
            if (!a.unavailable().isEmpty()) {
                failedBatches++;
            }
        }
        List<Span> pass2Decisions = Pass2Queue.spansFromDecisions(decisions, byId, sourceUnits, regions);
        spans.addAll(pass2Decisions);
        // A candidate no request could carry within the configured context window was never sent: it takes
        // the same documented fallback as one pass 2 was unavailable for, under its own cause label.
        List<Adjudication> withUnsent = new ArrayList<>(outcomes);
        if (!planned.unsendable().isEmpty()) {
            Map<String, String> causes = new LinkedHashMap<>();
            planned.unsendable().forEach(c -> causes.put(c.id(), CONTEXT_LIMIT_CAUSE));
            withUnsent.add(new Adjudication(List.of(), List.of(), 0, planned.unsendable(), causes));
            LOG.warn("pass 2: {} candidate(s) cannot fit ANON_LLM_CONTEXT_TOKENS={} even alone; not sent, fallback "
                    + "applies {}", planned.unsendable().size(), cfg.llmContextTokens(), ctx.tag());
        }
        fallBack(withUnsent, failedBatches, sourceUnits, regions, spans, unresolved, accounted, ctx);
        spans.addAll(reuseEverywhere(deterministicSpans, pass1Decisions, pass2Decisions, policy, document, hard, spans));
        List<Candidate> lost = candidates.stream().filter(c -> !accounted.contains(c.id())).toList();
        if (!lost.isEmpty()) {
            // Unreachable by construction; a person is told rather than the place being taken as decided.
            LOG.error("pass 2: {} candidate(s) ended neither decided, undecided nor unavailable; retained as undecided {}",
                    lost.size(), ctx.tag());
            lost.forEach(c -> unresolved.add(new UnresolvedFinding(c.chunkIndex(),
                    UnresolvedFinding.Kind.CANDIDATE_UNDECIDED, wire(c.category()), c.locations(), c.id(),
                    "no outcome was recorded for this candidate")));
        }
        return new Result(spans, unresolved, evidence);
    }

    /**
     * The registry's last step: every GLOBAL_REDACT value applied at its other occurrences across the
     * whole document (including chunks routed before the decision existed), through the ordinary span
     * list and so the one resolver. Built from the pass-1 decisions applied and pass 2's answers only:
     * never from a fallback or from another reuse, so nothing feeds on itself.
     */
    private static List<Span> reuseEverywhere(List<Span> deterministicSpans, List<Span> pass1Decisions,
                                              List<Span> pass2Decisions, PolicySettings policy, DocumentData document,
                                              HardDecisions hard, List<Span> placeDecisions) {
        List<Span> decisions = new ArrayList<>(pass1Decisions);
        decisions.addAll(pass2Decisions);
        return DecisionRegistry.of(deterministicSpans, decisions, policy)
                .applyEverywhere(document.textUnits(), hard, placeDecisions);
    }

    /** One batch, on its own: a provider that stays unavailable is absorbed by the {@link Adjudicator}. */
    private static Adjudication adjudicateBatch(int batchIndex, int batchTotal, List<Candidate> batch,
                                                Provider provider) {
        String label = "batch " + (batchIndex + 1) + "/" + batchTotal;
        RunContext ctx = provider.ctx();
        // The cooperative half of cancellation: a batch that has not started never starts once the
        // document is out of time or abandoned.
        if (ctx.deadline().done()) {
            throw new DocumentTimeoutError("llm pass 2 (" + label + ")");
        }
        long startNanos = System.nanoTime();
        LOG.info("{}: pass 2 (adjudicating {} candidate(s)) {}", label, batch.size(), ctx.tag());
        Adjudication adjudication;
        try {
            adjudication = new Adjudicator(provider, batch, batchIndex, batchTotal, false).run();
        } catch (AnonymizerError e) {
            ctx.usage().recordPass2(UsageRecorder.Pass2Outcome.FAILED, false);
            LOG.error("{}: pass2=failed error={} code={} {}", label, e.getClass().getSimpleName(), e.code(), ctx.tag());
            throw e;
        }
        boolean failed = !adjudication.unavailable().isEmpty();
        ctx.usage().recordPass2(failed ? UsageRecorder.Pass2Outcome.FAILED : UsageRecorder.Pass2Outcome.EXECUTED,
                adjudication.attempts() > 1);
        LOG.info("{}: pass2={} attempts={} decided={}/{} unresolved={} unavailable={} {} ({}s)", label,
                failed ? "unavailable" : "executed", adjudication.attempts(), adjudication.decisions().size(),
                batch.size(), adjudication.unresolved().size(), adjudication.unavailable().size(), ctx.tag(),
                seconds(startNanos));
        return adjudication;
    }

    /**
     * The documented fallback, for every candidate pass 2 could not be had for: its pass-1 decision
     * written where one applies ({@link Pass2Queue#fallbackSpans}), the rules' own spans otherwise
     * (already on their way to the resolver), and in every case one {@code PASS2_UNAVAILABLE} finding
     * of its own, with its id, its locations, its recommendations and the action it ended with.
     * Nothing here is a pass-2 decision. The log line carries counts only.
     */
    private static void fallBack(List<Adjudication> outcomes, int failedBatches, Map<String, TextUnit> sourceUnits,
                                 Set<String> regions, List<Span> spans, List<UnresolvedFinding> unresolved,
                                 Set<String> accounted, RunContext ctx) {
        int pass1 = 0;
        int rules = 0;
        int conflicts = 0;
        int undecided = 0;
        int unwritable = 0;
        int total = 0;
        for (Adjudication a : outcomes) {
            for (Candidate c : a.unavailable()) {
                total++;
                accounted.add(c.id());
                List<UnitSlice> unrepresentable = new ArrayList<>();
                spans.addAll(Pass2Queue.fallbackSpans(c, sourceUnits, regions, unrepresentable));
                Pass2Queue.Fallback f = c.fallback();
                String outcome;
                if (f != null && f.pass1() != null) {
                    pass1++;
                    outcome = "pass1_" + f.pass1().wire();
                } else if (f != null && f.deterministic() != null) {
                    rules++;
                    outcome = "rules_" + f.deterministic().wire();
                } else {
                    undecided++;
                    outcome = "none (undecided)";
                }
                boolean conflict = f != null && f.conflict();
                if (conflict) {
                    conflicts++;
                }
                if (!unrepresentable.isEmpty()) {
                    unwritable++;
                }
                String recommendations = c.recommendations().stream().map(r -> String.join("+", r.sources()) + ":"
                        + r.action().wire() + "/" + (r.category() == null ? "-" : r.category().wire()))
                        .collect(java.util.stream.Collectors.joining(", ", "[", "]"));
                unresolved.add(new UnresolvedFinding(c.chunkIndex(), UnresolvedFinding.Kind.PASS2_UNAVAILABLE,
                        wire(c.category()), c.locations(), c.id(), "pass 2 unavailable (cause=" + a.causes().get(c.id())
                        + "); recommendations=" + recommendations + "; fallback=" + outcome
                        + (conflict ? "; conflict: the rules' REDACT overrides pass 1's PRESERVE" : "")
                        + (unrepresentable.isEmpty() ? "" : "; " + unrepresentable.size()
                        + " location(s) could not be written as a redaction")));
            }
        }
        if (total > 0) {
            LOG.warn("pass2_fallback fallback_used=true candidates={} batches_failed={} pass1_applied={} rules_applied={} "
                            + "conflicts={} undecided={} unwritable={} needs_review=true {}", total, failedBatches, pass1,
                    rules, conflicts, undecided, unwritable, ctx.tag());
        }
    }

    /**
     * Runs {@code tasks} on at most {@code workers} virtual threads and returns their results in task
     * order, awaiting them by completion: the first failure cancels the document's budget, drops queued
     * tasks, abandons in-flight ones, and propagates.
     */
    @SuppressWarnings("unchecked")
    private static <T> List<T> runAll(List<Callable<T>> tasks, int workers, String threadPrefix, RunContext ctx) {
        int n = tasks.size();
        Object[] results = new Object[n];
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, workers),
                Thread.ofVirtual().name(threadPrefix, 0).factory());
        CompletionService<Integer> completed = new ExecutorCompletionService<>(pool);
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < n; i++) {
                int index = i;
                Callable<T> task = tasks.get(i);
                futures.add(completed.submit(() -> {
                    results[index] = task.call();
                    return index;
                }));
            }
            for (int received = 0; received < n; ) {
                Future<Integer> done = completed.poll((long) (ctx.deadline().remaining() * 1e9), TimeUnit.NANOSECONDS);
                if (done == null) {
                    // Nothing finished in the time that was left. The stage still running keeps its name, so the
                    // document's final line says where it was (not a generic "llm").
                    ctx.deadline().check(ctx.deadline().lastStage());
                    continue;
                }
                done.get();
                received++;
            }
        } catch (ExecutionException e) {
            abort(ctx, pool, futures, e.getCause());
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new AIProviderError("LLM detection failed", cause);
        } catch (InterruptedException e) {
            abort(ctx, pool, futures, e);
            Thread.currentThread().interrupt();
            throw new AIProviderError("LLM detection interrupted", e);
        } catch (RuntimeException | Error e) {
            // An Error on this thread too (a StackOverflowError, an OutOfMemoryError while waiting):
            // the other tasks' provider calls must not run on, billed, for a document that failed.
            abort(ctx, pool, futures, e);
            throw e;
        }
        pool.shutdown();
        List<T> out = new ArrayList<>(n);
        for (Object r : results) {
            out.add((T) r);
        }
        return out;
    }

    /** Stops the other workers at their next checkpoint and abandons queued and in-flight work. */
    private static void abort(RunContext ctx, ExecutorService pool, List<Future<Integer>> futures, Throwable cause) {
        ctx.deadline().cancel();
        long pending = futures.stream().filter(f -> !f.isDone()).count();
        futures.forEach(f -> f.cancel(true));
        pool.shutdownNow();
        // The class of what stopped the run, never its message: a message can quote the document.
        LOG.warn("llm_run_aborted {} pending={} cause={}", ctx.tag(), pending,
                cause == null ? "-" : cause.getClass().getSimpleName());
    }

    /** One chunk after pass 1 and routing: what was routed, and what is already known to need a person. */
    private record ChunkResult(Pass2Queue.Routed routed, List<UnresolvedFinding> unresolved) {
    }

    /** A usable pass-1 finding with nowhere to be written, for a person: its category and length, never its text. */
    private static UnresolvedFinding unlocatable(int chunkIndex, Finding finding) {
        return new UnresolvedFinding(chunkIndex, UnresolvedFinding.Kind.DISCOVERY_UNLOCATABLE,
                wire(finding.category()), List.of(), null,
                "a pass-1 finding (" + PyStr.len(finding.text()) + " chars) is not in the excerpt");
    }

    /** One chunk's pass 1 and routing; no pass-2 call is made here. */
    private static ChunkResult processChunk(int chunkIndex, Chunk chunk, int total, List<Span> adjudicable,
                                            List<Span> reviewHints, HardDecisions hard,
                                            Map<String, TextUnit> sourceUnits, Provider provider,
                                            PolicySettings policy, Set<String> regions) {
        long startNanos = System.nanoTime();
        String label = chunkLabel(chunkIndex, total);
        String tag = provider.ctx().tag();
        // The cooperative half of cancellation: a chunk that has not started never starts once the
        // document is out of time or abandoned.
        if (provider.ctx().deadline().done()) {
            throw new DocumentTimeoutError("llm " + label);
        }
        // Rendered once, from the masked view: the text pass 1 reads, the windows pass 2 is shown,
        // and the map that places pass 1's findings back on their units.
        Chunk.Rendered rendered = chunk.render();

        LOG.info("{}: pass 1 (discovery) {}", label, tag);
        Pass1Reading discovery = discover(provider, rendered.text(), chunkIndex);

        // The two independent paths meet here, and not before.
        Set<String> unitIds = chunk.unitIds();
        List<Span> chunkDeterministic = adjudicable.stream().filter(s -> unitIds.contains(s.unitId())).toList();
        List<Span> chunkHints = reviewHints.stream().filter(s -> unitIds.contains(s.unitId())).toList();
        Pass2Queue.Routed routed = Pass2Queue.route(chunkIndex, chunk, chunkDeterministic, chunkHints,
                discovery.findings(), rendered, hard, policy, sourceUnits, regions);
        // A PRESERVE with nowhere to go changes nothing in the document: audited in the log, not review work. A
        // REDACT (or a REVIEW) that could not be placed, even whitespace-tolerantly and unambiguously, is.
        List<Finding> unplacedPreserves = routed.unlocated().stream()
                .filter(f -> f.action() == SpanAction.PRESERVE).toList();
        List<UnresolvedFinding> unresolved = new ArrayList<>(routed.unlocated().stream()
                .filter(f -> f.action() != SpanAction.PRESERVE).map(f -> unlocatable(chunkIndex, f)).toList());
        if (!unplacedPreserves.isEmpty()) {
            LOG.info("{}: pass1_unplaced_preserve count={} categories={}: nothing to write, not review work {}", label,
                    unplacedPreserves.size(), new java.util.TreeSet<>(unplacedPreserves.stream()
                            .map(f -> wire(f.category())).toList()), tag);
        }
        if (!unresolved.isEmpty()) {
            LOG.warn("{}: {} usable pass-1 finding(s) could not be located in the excerpt; retained for human review "
                    + "{}", label, unresolved.size(), tag);
        }
        unresolved.addAll(routed.unresolved());
        if (discovery.degraded()) {
            // Missing discovery is never agreement and never an empty reading: the chunk is held for a person.
            unresolved.add(new UnresolvedFinding(chunkIndex, UnresolvedFinding.Kind.DISCOVERY_INCOMPLETE, null,
                    chunk.units().stream().map(u -> new UnitSlice(u.unitId(), 0, PyStr.len(u.normalizedText()))).toList(),
                    null, "incomplete discovery coverage: " + discovery.outcome().wire));
        }
        Pass2Queue.RouteCounts c = routed.counts();
        LOG.info("{}: routed pass1_agreed={} pass1_only={} deterministic_only={} settled={} questions={} "
                        + "unchangeable_questions_skipped={} pass1_spans={} {} ({}s)", label, c.agreed(), c.pass1Only(),
                c.deterministicOnly(), c.settled(), c.questions(), c.redundant(), routed.pass1Spans().size(), tag,
                seconds(startNanos));
        return new ChunkResult(routed, unresolved);
    }

    private static String seconds(long startNanos) {
        return PyFloat.fixed((System.nanoTime() - startNanos) / 1e9, 1);
    }

    // ------------------------------------------------------------------ post-redaction remediation

    /**
     * One remediable post-redaction finding, as the remediation is asked about it: the REVIEW
     * proposal at the exact slice the scan found it ({@code span}), and the scan finding it came
     * from ({@code ref}). The provenance is CARRIED, never recovered by matching text: the
     * candidate a residual became is the one holding its exact slice.
     */
    public record Residual(UnresolvedFinding.AuditRef ref, Span span) {

        UnitSlice slice() {
            return new UnitSlice(span.unitId(), span.start(), span.end());
        }
    }

    /** The hard policy decision that settled a fragment without a question. */
    public enum SettledBy {
        /** Already blanked by a carried hard redaction. */
        HARD_REDACT,
        /** Wholly covered by a carried hard preserve. */
        HARD_PRESERVE
    }

    /**
     * What became of one FRAGMENT of a residual: the part of its slice at {@code slice}, which
     * masking left whole or cut out of it. Either hard policy settled it ({@code settledBy}, with the
     * decision that policy is: REDACT or PRESERVE) and nobody was asked, or it was put to pass 2 as
     * {@code candidateId} and {@code decision} is that candidate's final answer (null: left
     * undecided). {@code candidateId} and {@code settledBy} both null: it was never put to pass 2.
     */
    public record FragmentOutcome(UnitSlice slice, String candidateId, SpanAction decision, SettledBy settledBy) {

        /** A fragment never put to pass 2 and settled by nothing. */
        static FragmentOutcome unasked(UnitSlice slice) {
            return new FragmentOutcome(slice, null, null, null);
        }

        boolean answered() {
            return decision != null;
        }
    }

    /**
     * What happened to one residual, kept with the residual itself, so its audit reference stays
     * with every part of it: original residual, then its fragments, then their candidate ids, then
     * their decisions. Masking can cut one residual into several fragments, and each can become a
     * candidate of its own; nothing here assumes a residual is one candidate. {@code chunkIndex} is
     * -1 when no chunk held the residual.
     */
    public record ResidualOutcome(Residual residual, int chunkIndex, List<FragmentOutcome> fragments) {
        public ResidualOutcome {
            fragments = List.copyOf(fragments);
        }

        /**
         * The residual's answer, aggregated over its fragments: PRESERVE when any part of it was kept
         * (by pass 2 or by hard policy), REDACT when every part was redacted (by pass 2, or already by
         * a hard redaction), null while any part is undecided or was never asked.
         */
        public SpanAction decision() {
            if (fragments.stream().anyMatch(f -> f.decision() == SpanAction.PRESERVE)) {
                return SpanAction.PRESERVE;
            }
            return !fragments.isEmpty() && fragments.stream().allMatch(f -> f.decision() == SpanAction.REDACT)
                    ? SpanAction.REDACT : null;
        }

        /** Whether every part of it that was kept, was kept by hard policy rather than by pass 2. */
        public boolean preservedByPolicy() {
            List<FragmentOutcome> kept = fragments.stream().filter(f -> f.decision() == SpanAction.PRESERVE).toList();
            return !kept.isEmpty() && kept.stream().allMatch(f -> f.settledBy() == SettledBy.HARD_PRESERVE);
        }

        /** The ids its fragments were asked as, in text order, without repeats. */
        public List<String> candidateIds() {
            return fragments.stream().map(FragmentOutcome::candidateId).filter(java.util.Objects::nonNull)
                    .distinct().toList();
        }

        /** Whether any part of it was considered at all: put to pass 2, or settled by hard policy. */
        public boolean considered() {
            return fragments.stream().anyMatch(f -> f.candidateId() != null || f.settledBy() != null);
        }
    }

    /**
     * What one post-redaction re-adjudication produced (port of {@code RemediationResult}).
     * {@code spans} are pass 2's decisions, in the coordinates of the REDACTED document, ready for
     * the ordinary resolver; {@code unresolved} is what it still could not settle, each carrying the
     * scan findings behind it. {@code outcomes} is one entry per residual, in the order they were
     * given: what the postcheck outcome policy judges. {@code candidateIds} and {@code pass2Calls}
     * exist for the stage's one log line: an id list and a number, nothing derived from the text.
     */
    public record Remediation(List<Span> spans, List<UnresolvedFinding> unresolved, List<String> candidateIds,
                              int pass2Calls, List<ResidualOutcome> outcomes) {
        public Remediation {
            spans = List.copyOf(spans);
            unresolved = List.copyOf(unresolved);
            candidateIds = List.copyOf(candidateIds);
            outcomes = List.copyOf(outcomes);
        }
    }

    /**
     * Re-adjudicates the post-redaction audit's findings. PASS 2 ONLY (port of
     * {@code run_pass2_remediation}).
     *
     * <p>{@code document} is the parse of the ALREADY-REDACTED bytes, and {@code residuals} are
     * the audit's findings as located REVIEW proposals in it, exactly where the scan found them,
     * each with its provenance; nothing here searches for a string. {@code hardRedacts} and
     * {@code hardPreserves} are the first resolve's hard decisions in THIS document's coordinates
     * (empty when the caller cannot vouch for them), the same policy the first adjudication
     * applied: hard redactions are blanked in what the model is shown (though a written redaction
     * is a run of dots already), and a place hard policy settles is never asked about.
     *
     * <p>PROVENANCE IS EXPLICIT: residual, then fragments, then candidate ids, then decisions.
     * Masking can cut one residual into several FRAGMENTS; each fragment hard policy settles is
     * recorded as that policy decision ({@link SettledBy}) without a question, and each other one
     * is asked as the residual's own REVIEW proposal cut to it. Every fragment keeps its residual,
     * so the outcome ({@link ResidualOutcome}) and every unresolved item carry the original audit
     * reference however the residual was cut.
     *
     * <p>This stage reports what pass 2 said and nothing more. What that answer MEANS for the
     * document (a PRESERVE on a HIGH finding still needs a person) is the postcheck outcome
     * policy's call, made in {@code Pipeline} from {@link Remediation#outcomes()}.
     *
     * <p>PASS 1 IS NOT RUN: the audit has named the slices in question. Pass 2 is asked about
     * exactly those, with the same candidate-only contract as the first adjudication: their text,
     * recommendations and context windows, never the excerpt.
     *
     * <p>Everything else is the ordinary machinery as it stands: {@link Chunk#split} cuts the
     * masked view of the redacted document, {@link Pass2Queue#build} turns the residuals into a
     * queue (labelled {@code postcheck}), {@link Pass2Queue#batches} cuts it under the first
     * adjudication's limits (candidates and payload per request, and the configured context window:
     * a candidate no request could carry is never sent, and is {@code PASS2_UNAVAILABLE} with
     * {@code cause=context_limit}), and the same {@link Adjudicator} makes each batch's call with its
     * usual validation, its one corrective retry and its refusal to believe an unfinished response,
     * through the same {@link Provider} (the document's own retry ladder and deadline). Chunks and
     * their batches are visited one after another: only chunks holding a residual, a small fraction
     * of the work. Every batch keeps the chunk's candidate ids, so the provenance is the same however
     * the queue was cut.
     *
     * <p>{@code evidence} is the first adjudication's ({@link Result#evidence()}), in coordinates the
     * caller has checked still mean the same places in {@code document} (else empty): each question
     * also carries what the rule engine and pass 1 recommended where it overlaps, so pass 2 decides
     * knowing why the place was flagged and what was said about it before.
     *
     * <p>A provider that stays unavailable for a chunk's questions (or never produces a usable reading)
     * does NOT fail the document: those questions become {@code PASS2_UNAVAILABLE} findings carrying
     * their residuals' audit references, nothing is written for them, and the outcome policy keeps every
     * HIGH residual among them in front of a person. {@code DocumentTimeoutError} (the budget is gone),
     * cancellation and every other error still propagate.
     */
    public static Remediation runPass2Remediation(DocumentData document, List<Residual> residuals,
                                                  List<Evidence> evidence, List<Span> hardRedacts,
                                                  List<Span> hardPreserves, LlmClient client, RuntimeConfig cfg,
                                                  Set<String> regions, RunContext ctx) {
        return runPass2Remediation(document, residuals, evidence, hardRedacts, hardPreserves,
                new Provider(client, cfg, REAL_SLEEP, ctx), regions);
    }

    /** One part of one residual on its way to an outcome; the residual, and so its audit reference, travels with it. */
    private record Fragment(Residual residual, UnitSlice slice, SettledBy settledBy) {

        /** The residual's own REVIEW proposal cut to this fragment: same category, detector and reason. */
        Span question(TextUnit unit) {
            Span s = residual.span();
            return new Span(slice.unitId(), slice.start(), slice.end(),
                    PyStr.slice(unit.normalizedText(), slice.start(), slice.end()), s.category(), s.detector(),
                    s.confidence(), s.action(), s.reason(), s.origin());
        }
    }

    /**
     * A residual's fragments, in text order, covering its slice exactly: each part a hard redaction
     * blanked, and each part masking left, settled when a hard preserve covers it whole.
     */
    private static List<Fragment> cut(Residual residual, HardDecisions hard) {
        UnitSlice slice = residual.slice();
        List<Fragment> fragments = new ArrayList<>();
        for (UnitSlice part : hard.questionable(slice)) {
            fragments.add(new Fragment(residual, part, hard.preserved(part) ? SettledBy.HARD_PRESERVE : null));
        }
        // The shielded signatory name is settled by hard policy, never asked, whatever the residual around it.
        for (UnitSlice part : hard.shieldedParts(slice)) {
            fragments.add(new Fragment(residual, part, SettledBy.HARD_PRESERVE));
        }
        for (UnitSlice part : hard.masked(slice)) {
            fragments.add(new Fragment(residual, part, SettledBy.HARD_REDACT));
        }
        fragments.sort(Comparator.comparingInt(f -> f.slice().start()));
        return fragments;
    }

    /** What became of one fragment: the policy decision that settled it, or its candidate's answer. */
    private static FragmentOutcome fragmentOutcome(Fragment fragment, Map<UnitSlice, String> candidateAt,
                                             Map<String, SpanAction> decided) {
        if (fragment.settledBy() != null) {
            return new FragmentOutcome(fragment.slice(), null, fragment.settledBy() == SettledBy.HARD_REDACT
                    ? SpanAction.REDACT : SpanAction.PRESERVE, fragment.settledBy());
        }
        String id = candidateAt.get(fragment.slice());
        return id == null ? FragmentOutcome.unasked(fragment.slice())
                : new FragmentOutcome(fragment.slice(), id, decided.get(id), null);
    }

    static Remediation runPass2Remediation(DocumentData document, List<Residual> residuals, List<Evidence> evidence,
                                           List<Span> hardRedacts, List<Span> hardPreserves, Provider provider,
                                           Set<String> regions) {
        if (residuals.isEmpty()) {
            return new Remediation(List.of(), List.of(), List.of(), 0, List.of());
        }
        RunContext ctx = provider.ctx();
        HardDecisions hard = HardDecisions.carried(hardRedacts, hardPreserves, document);
        List<Chunk> chunks = Chunk.split(hard.maskedView(document), provider.cfg().chunkSizeChars());
        Map<String, TextUnit> sourceUnits = new HashMap<>();
        document.textUnits().forEach(u -> sourceUnits.put(u.unitId(), u));
        int total = chunks.size();
        Map<String, Integer> chunkOfUnit = new HashMap<>();
        for (int i = 0; i < total; i++) {
            for (String unitId : chunks.get(i).unitIds()) {
                chunkOfUnit.put(unitId, i);
            }
        }
        Map<Residual, ResidualOutcome> outcomeOf = new HashMap<>();
        Map<Integer, List<Residual>> queued = new TreeMap<>();
        for (Residual residual : residuals) {
            Integer chunkIndex = chunkOfUnit.get(residual.span().unitId());
            if (chunkIndex == null) {
                // An empty unit no chunk holds: there is no context to show the model, so nothing to ask.
                LOG.warn("postcheck_remediation: a residual names a unit no chunk holds; it was not put to pass 2");
                outcomeOf.put(residual, new ResidualOutcome(residual, -1,
                        List.of(FragmentOutcome.unasked(residual.slice()))));
                continue;
            }
            queued.computeIfAbsent(chunkIndex, k -> new ArrayList<>()).add(residual);
        }

        List<Span> spans = new ArrayList<>();
        List<UnresolvedFinding> unresolved = new ArrayList<>();
        List<String> candidateIds = new ArrayList<>();
        int calls = 0;
        int settled = 0;
        for (Map.Entry<Integer, List<Residual>> entry : queued.entrySet()) {
            int index = entry.getKey();
            List<Residual> here = entry.getValue();
            Chunk chunk = chunks.get(index);
            Chunk.Rendered rendered = chunk.render();
            // Residual -> fragments: what hard policy settles is recorded as its decision; every other
            // fragment is a question, the residual's own REVIEW proposal cut to that fragment.
            Map<Residual, List<Fragment>> fragmentsOf = new LinkedHashMap<>();
            List<Span> questions = new ArrayList<>();
            for (Residual r : here) {
                List<Fragment> parts = cut(r, hard);
                fragmentsOf.put(r, parts);
                for (Fragment f : parts) {
                    if (f.settledBy() == null) {
                        questions.add(f.question(sourceUnits.get(f.slice().unitId())));
                    } else {
                        settled++;
                    }
                }
            }
            // Fragments -> candidate ids. The fragments enter as REVIEW hints: same builder, same grouping,
            // same windows as an ordinary queue; only the source label differs. The queue keys every
            // candidate by the exact slices it was built from, which are the fragments themselves.
            List<Candidate> candidates = questions.isEmpty() ? List.of() : Pass2Queue.build(chunk, List.of(), questions,
                    List.of(), rendered, hard, "postcheck", evidence).candidates();
            Map<UnitSlice, String> candidateAt = new HashMap<>();
            candidates.forEach(c -> c.locations().forEach(l -> candidateAt.put(l, c.id())));
            // Candidate ids -> decisions.
            Map<String, SpanAction> decided = new HashMap<>();
            if (!candidates.isEmpty()) {
                candidates.forEach(c -> candidateIds.add("remediation:chunk" + (index + 1) + ":" + c.id()));
                String label = chunkLabel(index, total);
                // The first adjudication's safeguards, the same code: at most so many candidates and so many
                // payload tokens per request, and within a configured context window, or not sent at all.
                // Every batch is asked by the chunk's ids, so the provenance below is unchanged by the cut.
                Pass2Queue.Batches planned = Pass2Queue.batches(candidates, provider.cfg().maxCompletionTokens(),
                        provider.cfg().llmContextTokens(), Pass2Queue.pass2FixedInputTokens());
                List<List<Candidate>> batches = planned.sendable();
                List<Decision> decisions = new ArrayList<>();
                List<UnresolvedFinding> open = new ArrayList<>();
                List<Candidate> unavailable = new ArrayList<>();
                Map<String, String> causes = new HashMap<>();
                for (int b = 0; b < batches.size(); b++) {
                    String batchLabel = batches.size() > 1 ? " batch " + (b + 1) + "/" + batches.size() : "";
                    ctx.deadline().check("postcheck remediation (" + label + batchLabel + ")");
                    LOG.info("{}{}: postcheck remediation pass 2 ({} candidate(s)) {}", label, batchLabel,
                            batches.get(b).size(), ctx.tag());
                    // Each batch absorbs its own provider failure, so what one decided survives another's.
                    Adjudication adjudication = new Adjudicator(provider, batches.get(b), index, total, true).run();
                    calls += adjudication.attempts();
                    decisions.addAll(adjudication.decisions());
                    open.addAll(adjudication.unresolved());
                    unavailable.addAll(adjudication.unavailable());
                    causes.putAll(adjudication.causes());
                }
                // A candidate no request could carry within ANON_LLM_CONTEXT_TOKENS was never sent: it is left
                // unanswered exactly as one pass 2 was unavailable for, under its own cause label.
                for (Candidate c : planned.unsendable()) {
                    unavailable.add(c);
                    causes.put(c.id(), CONTEXT_LIMIT_CAUSE);
                }
                decisions.forEach(d -> decided.put(d.candidateId(), d.action()));
                Map<String, Candidate> candidatesById = new HashMap<>();
                candidates.forEach(c -> candidatesById.put(c.id(), c));
                spans.addAll(Pass2Queue.spansFromDecisions(decisions, candidatesById, sourceUnits, regions));
                // Pass 2 unavailable for some of these questions: nothing is decided for them and nothing
                // is written, each is a finding of its own, and the outcome policy below keeps every
                // HIGH residual among them in front of a person. The document is still returned.
                for (Candidate c : unavailable) {
                    open.add(new UnresolvedFinding(index, UnresolvedFinding.Kind.PASS2_UNAVAILABLE,
                            wire(c.category()), c.locations(), c.id(), "pass 2 unavailable (cause="
                            + causes.get(c.id()) + "); post-redaction question left unanswered; nothing "
                            + "written"));
                }
                if (!unavailable.isEmpty()) {
                    LOG.warn("postcheck_remediation: pass2_fallback fallback_used=true candidates={} cause={} "
                            + "needs_review=true {}", unavailable.size(), new java.util.TreeSet<>(causes.values()),
                            ctx.tag());
                }
                for (UnresolvedFinding finding : open) {
                    // Which scan findings are behind what was left open: every residual with a fragment
                    // asked as this candidate.
                    List<UnresolvedFinding.AuditRef> refs = here.stream()
                            .filter(r -> fragmentsOf.get(r).stream()
                                    .anyMatch(f -> finding.candidateId() != null
                                            && finding.candidateId().equals(candidateAt.get(f.slice()))))
                            .map(Residual::ref).toList();
                    unresolved.add(refs.isEmpty() ? finding : finding.withAudit(refs));
                }
            }
            // ... and back to each original residual.
            for (Residual r : here) {
                outcomeOf.put(r, new ResidualOutcome(r, index,
                        fragmentsOf.get(r).stream().map(f -> fragmentOutcome(f, candidateAt, decided)).toList()));
            }
        }
        if (settled > 0) {
            LOG.info("postcheck_remediation: {} residual fragment(s) settled by hard policy without a pass-2 question {}",
                    settled, ctx.tag());
        }
        return new Remediation(spans, unresolved, candidateIds, calls,
                residuals.stream().map(outcomeOf::get).toList());
    }
}
