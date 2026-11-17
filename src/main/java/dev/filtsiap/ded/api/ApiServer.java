package dev.filtsiap.ded.api;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import dev.filtsiap.ded.AppHome;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.FileConfig;
import dev.filtsiap.ded.anonymizer.ProcessEnv;
import dev.filtsiap.ded.anonymizer.RequestProgress;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.chat.ChatLists;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.ChatSettings;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.LlmClients;
import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyNumber;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;

/**
 * HTTP service entry point: replaces the FastAPI app plus {@code gunicorn.conf.py}, on the
 * JDK's built-in HTTP server with requests handled on virtual threads.
 *
 * <p>Startup mirrors the Python lifespan: {@code .env} next to the application and in the
 * working directory fill in the environment; the service refuses to start without
 * {@code ANON_API_KEY}; file config comes from {@code ./config}, and the chat word lists of
 * POST /anonymize-text from {@code ./config/chat} (a missing or corrupt list is a configuration
 * error, exit 3). Server knobs:
 * {@code ANON_HOST} (0.0.0.0), {@code ANON_PORT} (8000), {@code ANON_GRACEFUL_TIMEOUT} (120 s,
 * the whole shutdown budget, at most 120; see {@link #stop(ShutdownBudget)}) and
 * {@code ANON_MAX_CONCURRENT_REQUESTS} (40). Keep-alive is 5 s, as gunicorn's.
 *
 * <p>ADMISSION. At most {@code ANON_MAX_CONCURRENT_REQUESTS} requests are handled at once; the
 * rest wait, in arrival order, for a free slot (queued, not refused). This is the one Java-only
 * knob, and it exists because the Python service has the same bound without naming it: v2
 * serves POST /anonymize as a plain {@code def} endpoint, which Starlette runs on AnyIO's
 * worker-thread pool, whose default capacity is 40 threads per process. Everything a request
 * does, the body read included, happens on that thread, so a 41st request waits for one. A
 * virtual thread per request has no such ceiling, which would leave the per-document limits as
 * the only bound. The default reproduces v2's; beyond that pool v2 documents no global limit
 * ("Size your deployment with WEB_CONCURRENCY"), so this is the operator's lever for the same
 * sizing within one Java process.
 *
 * <p>SHUTDOWN is owned here, not by {@code HttpServer.stop(delay)}, whose wait cannot be relied
 * on: before JDK-8304065 (fixed in 25, backported to 21.0.10, never to 24) it always waits the
 * whole delay, and after it the JDK's own exchange count is never decremented for an exchange
 * that ended abnormally (a client that disconnected mid-upload), so one such request made every
 * later shutdown wait the whole delay too. The server counts its own requests instead
 * ({@link RequestTracker}) and only ever asks the JDK to close the listener and the connections.
 */
public final class ApiServer {

    /** v2's effective per-process bound: AnyIO's default worker-thread limiter. */
    static final String DEFAULT_MAX_CONCURRENT_REQUESTS = "40";

    /**
     * 115 s to drain, 5 s to cancel and close. Longer than the 30 s a Kubernetes pod gets by default
     * between SIGTERM and SIGKILL: set {@code terminationGracePeriodSeconds} (or {@code docker stop -t})
     * above it, or lower this.
     */
    static final String DEFAULT_GRACEFUL_TIMEOUT = "120";

    /** The whole shutdown, never longer. */
    static final int MAX_GRACEFUL_TIMEOUT_S = 120;

    private static final byte[] SHUTTING_DOWN = "{\"detail\":\"the server is shutting down\"}"
            .getBytes(StandardCharsets.UTF_8);

    /** How often the drain looks for exchanges that reached the worker queue after it was emptied. */
    private static final long REQUEUE_CHECK_NANOS = TimeUnit.MILLISECONDS.toNanos(200);

    private final HttpServer server;
    private final ThreadPoolExecutor workers;
    private final RequestTracker requests;
    private final LlmClient client;
    /** The first stop()'s deadline, set by the same step that claims the shutdown: never seen unset. */
    private final AtomicReference<Long> stopDeadline = new AtomicReference<>();
    private final CountDownLatch stopped = new CountDownLatch(1);

    private ApiServer(HttpServer server, ThreadPoolExecutor workers, RequestTracker requests, LlmClient client) {
        this.server = server;
        this.workers = workers;
        this.requests = requests;
        this.client = client;
    }

    /**
     * Looked up when used, never in a static field: this class is loaded before {@link #main}
     * chooses the logging profile, and the first logger fixes it.
     */
    private static Logger log() {
        return LoggerFactory.getLogger("anonymizer.api");
    }

    /**
     * Starts serving; the caller owns the returned handle. {@code chat} null leaves /anonymize-text at 503.
     *
     * @param cfg                   the runtime configuration (the API key is required)
     * @param files                 the file configuration
     * @param chat                  the chat pipeline, or null for none
     * @param client                the LLM client
     * @param address               where to listen
     * @param maxConcurrentRequests the number of requests served at once
     * @return the running server
     * @throws ConfigurationError when {@code ANON_API_KEY} is not set
     */
    public static ApiServer start(RuntimeConfig cfg, FileConfig files, ChatPipeline chat, LlmClient client,
                                  InetSocketAddress address, int maxConcurrentRequests) {
        if (cfg.anonApiKey() == null || cfg.anonApiKey().isEmpty()) {
            // Fail closed: there is no unauthenticated mode for the HTTP transport.
            throw new ConfigurationError("ANON_API_KEY is required to serve the HTTP API "
                    + "(POST /anonymize is bearer-authenticated)");
        }
        RequestTracker requests = new RequestTracker();
        return serve(new ApiHandler(cfg, files, client, chat, requests), client, address, maxConcurrentRequests,
                requests);
    }

    /**
     * As before /anonymize-text existed: no chat pipeline.
     *
     * @param cfg                   the runtime configuration (the API key is required)
     * @param files                 the file configuration
     * @param client                the LLM client
     * @param address               where to listen
     * @param maxConcurrentRequests the number of requests served at once
     * @return the running server
     * @throws ConfigurationError when {@code ANON_API_KEY} is not set
     */
    public static ApiServer start(RuntimeConfig cfg, FileConfig files, LlmClient client, InetSocketAddress address,
                                  int maxConcurrentRequests) {
        return start(cfg, files, null, client, address, maxConcurrentRequests);
    }

    static ApiServer serve(HttpHandler handler, LlmClient client, InetSocketAddress address,
                           int maxConcurrentRequests) {
        return serve(handler, client, address, maxConcurrentRequests, new RequestTracker());
    }

    /**
     * {@code maxConcurrentRequests} virtual threads, reused: requests past that many queue for one.
     * Once shutdown has begun, an exchange runs at once on a thread of its own instead, where it
     * is refused: nothing waits in the queue for a slot that is not coming.
     */
    static ApiServer serve(HttpHandler handler, LlmClient client, InetSocketAddress address,
                           int maxConcurrentRequests, RequestTracker requests) {
        ThreadPoolExecutor workers = new ThreadPoolExecutor(maxConcurrentRequests, maxConcurrentRequests, 0L,
                TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>(), Thread.ofVirtual().name("api-", 0).factory());
        Executor dispatch = exchange -> {
            if (!requests.closed()) {
                try {
                    workers.execute(exchange);
                    return;
                } catch (RejectedExecutionException e) {
                    // shut down since the check: refused like any other late arrival
                }
            }
            refuseLater(exchange);
        };
        try {
            HttpServer server = HttpServer.create(address, 0);
            server.createContext("/", tracked(handler, requests));
            server.setExecutor(dispatch);
            server.start();
            return new ApiServer(server, workers, requests, client);
        } catch (IOException e) {
            workers.shutdown();
            throw new UncheckedIOException(e);
        }
    }

    /** Counts every request inside {@code handler}, however it leaves; refuses new ones once shutdown began. */
    private static HttpHandler tracked(HttpHandler handler, RequestTracker requests) {
        return exchange -> {
            if (!requests.enter()) {
                refuse(exchange);
                return;
            }
            try {
                handler.handle(exchange);
            } finally {
                requests.exit();
            }
        };
    }

    /** 503 without reading the body, connection closed after it: the request was never processed. */
    private static void refuse(HttpExchange exchange) throws IOException {
        try {
            exchange.getResponseHeaders().set("content-type", "application/json");
            exchange.getResponseHeaders().set("connection", "close");
            if (exchange.getRequestMethod().equals("HEAD")) {
                exchange.sendResponseHeaders(503, -1);
            } else {
                exchange.sendResponseHeaders(503, SHUTTING_DOWN.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(SHUTTING_DOWN);
                }
            }
        } finally {
            exchange.close();
        }
    }

    /** An exchange that will not get a worker: on a thread of its own, it reaches {@link #refuse}. */
    private static void refuseLater(Runnable exchange) {
        Thread.ofVirtual().name("api-refused-", 0).start(exchange);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /**
     * How a shutdown budget is spent: the first {@code drain} lets admitted requests finish, the
     * last {@code cleanup} is reserved for cancelling what is left and closing connections and the
     * provider client. For {@code ANON_GRACEFUL_TIMEOUT=seconds} the reserve is half the budget, at
     * least 1 s and at most 5 s, so the default 25 s drains for 20, and 0 drains for nothing and
     * still gets 1 s to cancel and close.
     */
    record ShutdownBudget(Duration drain, Duration cleanup) {
        static ShutdownBudget of(int seconds) {
            long budgetMillis = seconds * 1000L;
            long cleanupMillis = Math.max(1000L, Math.min(5000L, budgetMillis / 2));
            return new ShutdownBudget(Duration.ofMillis(Math.max(0L, budgetMillis - cleanupMillis)),
                    Duration.ofMillis(cleanupMillis));
        }

        Duration total() {
            return drain.plus(cleanup);
        }
    }

    /** Shuts down within {@code graceSeconds} (0..60, validated by {@link #gracefulTimeout}); 1 s for 0. */
    public void stop(int graceSeconds) {
        stop(ShutdownBudget.of(graceSeconds));
    }

    /**
     * ONE deadline for the whole shutdown, fixed by the first call: a repeated or concurrent call
     * waits for that same deadline and never starts another.
     *
     * <ol>
     * <li>Stop admitting: the listening socket closes; a request that reaches the handler from now
     *     on (a keep-alive connection's next request, one still queued for a worker: "queued" in
     *     the log) is refused with 503 and never processed.
     * <li>Drain: wait for the requests inside the handler up to {@code drain}, returning as soon
     *     as the last one leaves. With none, nothing is waited for: idle keep-alive connections
     *     are not work.
     * <li>Cancel: whatever is still inside the handler is interrupted (a body read, a response
     *     write, the wait for provider calls, which cancels those calls in turn) and leaves with a
     *     503 and outcome {@code cancelled}, never as a success.
     * <li>Close every connection and the provider client, inside the {@code cleanup} reserve.
     * </ol>
     */
    void stop(ShutdownBudget budget) {
        long startedNanos = System.nanoTime();
        long drainEndNanos = startedNanos + budget.drain().toNanos();
        long deadlineNanos = drainEndNanos + budget.cleanup().toNanos();
        if (!stopDeadline.compareAndSet(null, deadlineNanos)) {
            awaitStopped(stopDeadline.get());
            return;
        }
        int cancelled = 0;
        try {
            int active = requests.close();
            // Each document still running, by its own ids: the line that says where a shutdown caught it.
            for (RunContext document : requests.documentsInFlight()) {
                RequestProgress.Snapshot progress = document.progress().snapshot();
                log().info("shutdown_inflight {} stage={} elapsed_s={} chunks_completed={} chunks_total={} "
                                + "failed_provider_attempts={}", document.tag(),
                        document.deadline().lastStage().replace(' ', '_'), seconds(document.deadline().elapsedMillis()
                                * 1_000_000L), progress.chunksCompleted(), progress.chunksTotal(),
                        document.usage().snapshot().failedProviderAttempts());
            }
            // Closes the listening socket at once (every JDK does that first), then waits; it is
            // released by closeConnections, never by its own count of exchanges.
            int delay = (int) Math.max(1, budget.total().toSeconds());
            Thread.ofPlatform().name("api-stop-listener").daemon().start(() -> server.stop(delay));
            int queued = refuseQueued();
            if (active == 0) {
                log().info("No pending requests: active=0, queued={}. Shutting down without waiting for the {} s "
                        + "grace period.", queued, seconds(budget.drain().toNanos()));
            } else if (budget.drain().isZero()) {
                log().warn("Immediate shutdown (no grace period): cancelling active={} request(s), refusing "
                        + "queued={}", active, queued);
            } else {
                log().info("There are pending requests: active={}, queued={}. Waiting up to {} seconds before "
                        + "shutdown.", active, queued, seconds(budget.drain().toNanos()));
            }
            boolean drained = awaitDrained(drainEndNanos);
            if (drained && active > 0) {
                log().info("All pending requests finished after {} s; shutting down early", elapsed(startedNanos));
            } else if (!drained) {
                cancelled = requests.active();
                if (!budget.drain().isZero()) {
                    log().warn("The {} s grace period expired with active={} request(s) still running; cancelling "
                            + "them", seconds(budget.drain().toNanos()), cancelled);
                }
            }
            cancel(drained, deadlineNanos - budget.cleanup().toNanos() / 2);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cancelled = requests.active();
            requests.cancel();
            workers.shutdown();
            refuseQueued();
        } finally {
            closeConnections(deadlineNanos);
            closeClient(deadlineNanos);
            int stillRunning = requests.active();
            if (stillRunning > 0) {
                log().warn("Shutdown is not waiting any longer for active={} cancelled request(s)", stillRunning);
            }
            log().info("Shutdown complete: elapsed_s={} cancelled={} refused={} still_running={}",
                    elapsed(startedNanos), cancelled, requests.refused(), stillRunning);
            stopped.countDown();
        }
    }

    /**
     * Interrupts the requests still inside the handler, and only those, and gives them until
     * {@code untilNanos} to leave, so their 503 can still go out on a connection that is open.
     * Workers still reading a request's headers are left alone: they reach the handler and are
     * refused with a 503, or their connection is closed by {@link #closeConnections}. Exchanges
     * that slipped into the queue are refused.
     */
    private void cancel(boolean drained, long untilNanos) throws InterruptedException {
        workers.shutdown();
        refuseQueued();
        if (!drained) {
            requests.cancel();
            requests.awaitIdle(untilNanos);
        }
    }

    /** A repeated stop(): the first call's deadline, plus a moment for its last log line, never more. */
    private void awaitStopped(long deadlineNanos) {
        try {
            long left = deadlineNanos - System.nanoTime();
            stopped.await(Math.max(0L, left) + TimeUnit.SECONDS.toNanos(1), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Waits for the admitted requests to leave, refusing exchanges that reach the queue meanwhile. */
    private boolean awaitDrained(long drainEndNanos) throws InterruptedException {
        while (!requests.awaitIdle(Math.min(drainEndNanos, System.nanoTime() + REQUEUE_CHECK_NANOS))) {
            if (System.nanoTime() - drainEndNanos >= 0) {
                return false;
            }
            refuseQueued();
        }
        return true;
    }

    /** Exchanges waiting for a worker never start: each is refused on a thread of its own. */
    private int refuseQueued() {
        List<Runnable> queued = new ArrayList<>();
        workers.getQueue().drainTo(queued);
        queued.forEach(ApiServer::refuseLater);
        return queued.size();
    }

    /**
     * {@code HttpServer.stop(0)} closes every connection at once on every JDK, and releases the
     * listener-closing call that is still waiting. On a thread of its own, so it cannot outlast the
     * deadline.
     */
    private void closeConnections(long deadlineNanos) {
        join(Thread.ofPlatform().name("api-close-connections").daemon().start(() -> server.stop(0)), deadlineNanos);
    }

    /** Closes the provider client, bounded by the deadline like everything else. */
    private void closeClient(long deadlineNanos) {
        join(Thread.ofPlatform().name("api-close-llm").daemon().start(() -> {
            try {
                client.close();
            } catch (RuntimeException e) {
                log().warn("closing the LLM client failed: {}", e.getClass().getSimpleName());
            }
        }), deadlineNanos);
    }

    private static void join(Thread thread, long deadlineNanos) {
        long left = deadlineNanos - System.nanoTime();
        try {
            if (left > 0) {
                thread.join(Duration.ofNanos(left));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String seconds(long nanos) {
        return PyFloat.fixed(nanos / 1e9, 1);
    }

    private static String elapsed(long startedNanos) {
        return seconds(System.nanoTime() - startedNanos);
    }

    /**
     * Python logging level names, which the config has already validated and upper-cased
     * ({@code Config} refuses any other name at load time); logback has no WARNING/CRITICAL.
     */
    static String logbackLevel(String pythonLevel) {
        return Map.of("DEBUG", "DEBUG", "INFO", "INFO", "WARNING", "WARN", "ERROR", "ERROR", "CRITICAL", "ERROR",
                "NOTSET", "ALL").get(pythonLevel);
    }

    /** A request slot count: an integer, and at least one (zero would admit nothing). */
    static int maxConcurrentRequests(String raw) {
        int value = PyNumber.parseInt(raw).filter(v -> v.bitLength() < 32).map(v -> v.intValue())
                .orElseThrow(() -> new ConfigurationError("ANON_MAX_CONCURRENT_REQUESTS must be an integer, got "
                        + PyRepr.repr(raw)));
        if (value <= 0) {
            throw new ConfigurationError("ANON_MAX_CONCURRENT_REQUESTS must be greater than zero, got " + value);
        }
        return value;
    }

    /**
     * The shutdown budget in whole seconds, 0 or more. Above {@link #MAX_GRACEFUL_TIMEOUT_S} it is
     * capped with a warning rather than refused: a deployment that kept v2's 900 still starts, and
     * gets a shutdown its platform will actually wait for.
     */
    static int gracefulTimeout(String raw) {
        BigInteger value = PyNumber.parseInt(raw).orElseThrow(() -> new ConfigurationError(
                "ANON_GRACEFUL_TIMEOUT must be a whole number of seconds, got " + PyRepr.repr(raw)));
        if (value.signum() < 0) {
            throw new ConfigurationError("ANON_GRACEFUL_TIMEOUT must not be negative, got " + value);
        }
        if (value.compareTo(BigInteger.valueOf(MAX_GRACEFUL_TIMEOUT_S)) > 0) {
            log().warn("ANON_GRACEFUL_TIMEOUT={} exceeds the {} s maximum shutdown budget; using {}", value,
                    MAX_GRACEFUL_TIMEOUT_S, MAX_GRACEFUL_TIMEOUT_S);
            return MAX_GRACEFUL_TIMEOUT_S;
        }
        return value.intValue();
    }

    private static int intKnob(String name, String defaultValue) {
        String raw = ProcessEnv.get(name, defaultValue);
        return PyNumber.parseInt(raw).filter(v -> v.bitLength() < 32).map(v -> v.intValue())
                .orElseThrow(() -> new ConfigurationError(name + " must be an integer"));
    }

    public static void main(String[] args) {
        // Before any logger exists: server logging profile and gunicorn's keep-alive.
        System.setProperty("logback.configurationFile", "logback-server.xml");
        System.setProperty("sun.net.httpserver.idleInterval", "5");
        try {
            Config.loadEnvFile(AppHome.resolve().resolve(".env")); // gunicorn.conf.py
            RuntimeConfig cfg = Config.loadRuntimeConfig();        // also ./.env
            System.setProperty("anonymizer.logLevel", logbackLevel(cfg.logLevel()));
            if (cfg.anonApiKey() == null) {
                throw new ConfigurationError("ANON_API_KEY is required to serve the HTTP API "
                        + "(POST /anonymize is bearer-authenticated)");
            }
            FileConfig files = Config.loadFileConfig(Path.of("config"));
            ChatLists chatLists = ChatLists.load(Path.of("config", "chat"));
            ChatPipeline chat = ChatPipeline.production(files, chatLists,
                    ChatSettings.load(Path.of("config", "chat")));
            log().info("chat lists loaded: {} MB", chatLists.footprintBytes() / 1_000_000);
            String host = ProcessEnv.get("ANON_HOST", "0.0.0.0");
            int port = intKnob("ANON_PORT", "8000");
            int grace = gracefulTimeout(ProcessEnv.get("ANON_GRACEFUL_TIMEOUT", DEFAULT_GRACEFUL_TIMEOUT));
            int slots = maxConcurrentRequests(ProcessEnv.get("ANON_MAX_CONCURRENT_REQUESTS",
                    DEFAULT_MAX_CONCURRENT_REQUESTS));
            ApiServer server = start(cfg, files, chat, LlmClients.build(cfg), new InetSocketAddress(host, port), slots);
            ShutdownBudget budget = ShutdownBudget.of(grace);
            log().info("listening on {}:{}", host, server.port());
            log().info("shutdown budget: ANON_GRACEFUL_TIMEOUT={} s (requests may drain for {} s, {} s reserved "
                    + "for cancellation and cleanup)", grace, seconds(budget.drain().toNanos()),
                    seconds(budget.cleanup().toNanos()));
            Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(budget), "api-shutdown"));
        } catch (ConfigurationError e) {
            System.err.println("configuration error: " + e.getMessage());
            System.exit(3);
        }
    }
}
