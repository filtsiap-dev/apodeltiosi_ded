package dev.filtsiap.ded.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpHandler;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.InvalidDocumentError;
import dev.filtsiap.ded.anonymizer.Pipeline;
import dev.filtsiap.ded.anonymizer.TestDocx;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.OpenAiLlmClient;

/**
 * Shutdown of a real server over real sockets, with short budgets: one deadline, no wait when
 * idle, early return when the work finishes, cancellation when it does not, refusal of what never
 * started. The process-level behaviour (signal, shutdown hook, exit) is {@link ApiServerProcessTest}.
 */
class ApiServerShutdownTest {

    static final String DOCX = ApiHandler.DOCX_MEDIA_TYPE;

    /** A server, the tracker its handler learns about cancellation from, and its provider client. */
    record Served(ApiServer server, RequestTracker requests, CountingLlm llm) {
        int port() {
            return server.port();
        }
    }

    /** A provider stand-in that only counts how often it was closed. */
    static final class CountingLlm implements LlmClient {
        final AtomicInteger closed = new AtomicInteger();

        @Override
        public Completion complete(ChatRequest request) {
            throw new AssertionError("no provider call expected");
        }

        @Override
        public void close() {
            closed.incrementAndGet();
        }
    }

    static Served serve(ApiHandler.Processor processor, int slots) {
        RequestTracker requests = new RequestTracker();
        return serve(new ApiHandler(ApiHandlerTest.CFG, System::nanoTime, processor, requests::cancelling), slots,
                requests);
    }

    static Served serve(HttpHandler handler, int slots, RequestTracker requests) {
        CountingLlm llm = new CountingLlm();
        return new Served(ApiServer.serve(handler, llm, new InetSocketAddress("127.0.0.1", 0), slots, requests),
                requests, llm);
    }

    static ApiServer.ShutdownBudget budget(long drainMillis, long cleanupMillis) {
        return new ApiServer.ShutdownBudget(Duration.ofMillis(drainMillis), Duration.ofMillis(cleanupMillis));
    }

    /** Seconds the whole stop() took. */
    static double stop(Served served, ApiServer.ShutdownBudget budget) {
        long started = System.nanoTime();
        served.server().stop(budget);
        return (System.nanoTime() - started) / 1e9;
    }

    /** Blocks until interrupted, then fails the way the LLM stage does when its wait is interrupted. */
    static final ApiHandler.Processor UNTIL_INTERRUPTED = (docx, ctx) -> {
        try {
            new CountDownLatch(1).await();
            throw new AssertionError("unreachable");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AIProviderError("LLM detection interrupted", e);
        }
    };

    static String head(int contentLength) {
        return "POST /anonymize HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: Bearer k3y\r\n"
                + "Content-Type: " + DOCX + "\r\nContent-Length: " + contentLength + "\r\n\r\n";
    }

    /** One request on its own connection; the whole response as text, or what ended it instead. */
    static String exchange(int port, String head, byte[] body) {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(15_000);
            OutputStream out = socket.getOutputStream();
            out.write(head.getBytes(StandardCharsets.ISO_8859_1));
            out.write(body);
            out.flush();
            return readAll(socket.getInputStream());
        } catch (IOException e) {
            return "IOException " + e.getClass().getSimpleName();
        }
    }

    static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        try {
            while ((n = in.read(buf)) >= 0) {
                got.write(buf, 0, n);
            }
        } catch (IOException e) {
            if (got.size() == 0) {
                throw e;
            }
        }
        return got.toString(StandardCharsets.UTF_8);
    }

    /** Exactly one response from a connection that stays open: headers, then Content-Length bytes. */
    static String readOneResponse(InputStream in) throws IOException {
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        while (true) {
            int b = in.read();
            if (b < 0) {
                throw new IOException("closed before a whole response");
            }
            got.write(b);
            String text = got.toString(StandardCharsets.ISO_8859_1);
            int split = text.indexOf("\r\n\r\n");
            if (split >= 0) {
                java.util.regex.Matcher len = java.util.regex.Pattern.compile("(?i)content-length: (\\d+)")
                        .matcher(text.substring(0, split));
                int want = len.find() ? Integer.parseInt(len.group(1)) : 0;
                if (text.length() - split - 4 >= want) {
                    return text;
                }
            }
        }
    }

    static final ExecutorService CLIENTS = Executors.newVirtualThreadPerTaskExecutor();

    static CompletableFuture<String> exchangeAsync(int port, String head, byte[] body) {
        return CompletableFuture.supplyAsync(() -> exchange(port, head, body), CLIENTS);
    }

    static void awaitTrue(BooleanSupplier condition, long millis) throws InterruptedException {
        long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                throw new AssertionError("condition not reached in " + millis + " ms");
            }
            Thread.sleep(10);
        }
    }

    /** The server's own log lines (logger "anonymizer.api"), captured at INFO for one test. */
    static final class Logs implements AutoCloseable {
        private final ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) LoggerFactory
                .getLogger("anonymizer.api");
        private final Level level = logger.getLevel();
        private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

        Logs() {
            logger.setLevel(Level.INFO);
            appender.start();
            logger.addAppender(appender);
        }

        List<String> lines() {
            return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        }

        boolean has(String fragment) {
            return lines().stream().anyMatch(l -> l.contains(fragment));
        }

        long count(String fragment) {
            return lines().stream().filter(l -> l.contains(fragment)).count();
        }

        @Override
        public void close() {
            logger.detachAppender(appender);
            logger.setLevel(level);
        }
    }

    // ------------------------------------------------------------------ idle

    @Test
    void anIdleServerStopsAtOnceWhateverItsGracePeriod() {
        Served served = serve(ApiHandlerTest.UNREACHABLE, 2);
        try (Logs logs = new Logs()) {
            assertTrue(stop(served, budget(20_000, 5_000)) < 2.0);
            assertTrue(logs.has("No pending requests: active=0, queued=0"), logs.lines().toString());
            assertTrue(logs.has("Shutdown complete:"), logs.lines().toString());
        }
        assertEquals(1, served.llm().closed.get());
    }

    /**
     * The reported defect: HttpServer.stop never uncounts an exchange that ended abnormally, so one
     * aborted upload made every later shutdown wait out the whole delay. Every way a request can end
     * leaves the server idle, and an idle server does not wait.
     */
    @Test
    void requestsThatEndedEveryWayLeaveNothingPendingAndStopDoesNotWait() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        Served served = serve((docx, ctx) -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException("synthetic bug"); // 500
            }
            throw new InvalidDocumentError("synthetic invalid"); // 400
        }, 2);
        int port = served.port();
        assertTrue(exchange(port, head(1), new byte[] {1}).startsWith("HTTP/1.1 500 "));
        assertTrue(exchange(port, head(1), new byte[] {1}).startsWith("HTTP/1.1 400 "));
        assertTrue(exchange(port, "POST /anonymize HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 1\r\n\r\n",
                new byte[] {1}).startsWith("HTTP/1.1 401 "));
        assertTrue(exchange(port, head(1).replace(DOCX, "text/plain"), new byte[] {1}).startsWith("HTTP/1.1 415 "));
        assertTrue(exchange(port, "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", new byte[0])
                .startsWith("HTTP/1.1 404 "));
        assertTrue(exchange(port, "BROKEN\r\n\r\n", new byte[0]).startsWith("HTTP/1.1 400 ")); // the JDK's own reply
        try (Socket aborted = new Socket("127.0.0.1", port)) { // promises 100 000 bytes, sends 10, hangs up
            aborted.getOutputStream().write(head(100_000).getBytes(StandardCharsets.ISO_8859_1));
            aborted.getOutputStream().write(new byte[10]);
            aborted.getOutputStream().flush();
            Thread.sleep(200);
        }
        awaitTrue(() -> served.requests().active() == 0, 5_000);
        try (Logs logs = new Logs()) {
            assertTrue(stop(served, budget(20_000, 5_000)) < 2.0);
            assertTrue(logs.has("No pending requests: active=0"), logs.lines().toString());
        }
    }

    @Test
    void anIdleKeepAliveConnectionIsNotWorkAndIsClosed() throws Exception {
        Served served = serve(ApiHandlerTest.UNREACHABLE, 2);
        try (Socket keepAlive = new Socket("127.0.0.1", served.port())) {
            keepAlive.setSoTimeout(5_000);
            keepAlive.getOutputStream().write("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            InputStream in = keepAlive.getInputStream();
            String first = readOneResponse(in);
            assertTrue(first.startsWith("HTTP/1.1 200 "), first);
            assertTrue(stop(served, budget(20_000, 5_000)) < 2.0);
            byte[] buf = new byte[4096];
            int next;
            try {
                next = in.read(buf);
            } catch (IOException e) {
                next = -1;
            }
            assertEquals(-1, next); // closed by the server, not left open
        }
    }

    // ------------------------------------------------------------------ busy

    @Test
    void aRequestThatFinishesInsideTheGracePeriodCompletesAndStopReturnsEarly() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        Served served = serve((docx, ctx) -> {
            inside.countDown();
            try {
                Thread.sleep(700);
            } catch (InterruptedException e) {
                throw new AssertionError("interrupted inside its grace period", e);
            }
            return ApiHandlerTest.pipeline(docx, ctx);
        }, 2);
        byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος.").bytes();
        CompletableFuture<String> response = exchangeAsync(served.port(), head(docx.length), docx);
        assertTrue(inside.await(5, TimeUnit.SECONDS));
        try (Logs logs = new Logs()) {
            double took = stop(served, budget(10_000, 2_000));
            assertTrue(took >= 0.4 && took < 3.0, "took " + took);
            assertTrue(logs.has("There are pending requests: active=1, queued=0. Waiting up to 10.0 seconds before "
                    + "shutdown."), logs.lines().toString());
            assertTrue(logs.has("All pending requests finished after"), logs.lines().toString());
            assertTrue(logs.has("cancelled=0"), logs.lines().toString());
        }
        String text = response.get(5, TimeUnit.SECONDS);
        assertTrue(text.startsWith("HTTP/1.1 200 "), text);
        assertTrue(text.toLowerCase().contains("x-anonymization-status: processed"), text);
    }

    @Test
    void aRequestThatOutlastsTheGracePeriodIsCancelledInsideTheBudgetAndNotReportedAsSuccess() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        Served served = serve((docx, ctx) -> {
            inside.countDown();
            return UNTIL_INTERRUPTED.process(docx, ctx);
        }, 2);
        CompletableFuture<String> response = exchangeAsync(served.port(), head(1), new byte[] {1});
        assertTrue(inside.await(5, TimeUnit.SECONDS));
        try (Logs logs = new Logs()) {
            double took = stop(served, budget(1_000, 2_000));
            assertTrue(took >= 0.9 && took < 3.5, "took " + took);
            assertTrue(logs.has("The 1.0 s grace period expired with active=1 request(s) still running"),
                    logs.lines().toString());
            assertTrue(logs.has("outcome=cancelled status=503"), logs.lines().toString());
            assertFalse(logs.has("outcome=provider_failure"), logs.lines().toString());
            assertTrue(logs.has("cancelled=1"), logs.lines().toString());
            assertTrue(logs.has("still_running=0"), logs.lines().toString());
        }
        String text = response.get(5, TimeUnit.SECONDS);
        assertTrue(text.startsWith("HTTP/1.1 503 "), text);
        assertTrue(text.endsWith("{\"detail\":\"the server is shutting down\"}"), text);
        assertEquals(0, served.requests().active());
    }

    @Test
    void aStalledUploadCannotHoldShutdown() throws Exception {
        Served served = serve(ApiHandlerTest.UNREACHABLE, 2);
        try (Socket stalled = new Socket("127.0.0.1", served.port())) {
            stalled.getOutputStream().write(head(100_000).getBytes(StandardCharsets.ISO_8859_1));
            stalled.getOutputStream().write(new byte[10]);
            stalled.getOutputStream().flush();
            awaitTrue(() -> served.requests().active() == 1, 5_000); // inside the handler, reading the body
            try (Logs logs = new Logs()) {
                double took = stop(served, budget(1_000, 2_000));
                assertTrue(took < 3.5, "took " + took);
                assertTrue(logs.has("cancelled=1"), logs.lines().toString());
                assertTrue(logs.has("outcome=cancelled"), logs.lines().toString());
            }
        }
        assertEquals(0, served.requests().active());
    }

    @Test
    void aResponseTheClientDoesNotReadCannotHoldShutdown() throws Exception {
        byte[] big = new byte[64 * 1024 * 1024];
        RequestTracker requests = new RequestTracker();
        Served served = serve(exchange -> {
            exchange.sendResponseHeaders(200, big.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(big);
            }
        }, 2, requests);
        try (Socket reader = new Socket()) {
            reader.setReceiveBufferSize(4096);
            reader.connect(new InetSocketAddress("127.0.0.1", served.port()));
            reader.getOutputStream().write("GET /big HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            reader.getOutputStream().flush();
            Thread.sleep(500);
            assertEquals(1, requests.active()); // still writing: the client reads nothing
            try (Logs logs = new Logs()) {
                double took = stop(served, budget(1_000, 2_000));
                assertTrue(took < 3.5, "took " + took);
                assertTrue(logs.has("cancelled=1"), logs.lines().toString());
            }
            awaitTrue(() -> requests.active() == 0, 2_000);
        }
    }

    /** A document whose response write the shutdown cuts off was not delivered: never logged as a success. */
    @Test
    void aDocumentWhoseResponseIsCutOffIsLoggedAsCancelledNotAsASuccess() throws Exception {
        byte[] big = new byte[64 * 1024 * 1024];
        Served served = serve((docx, ctx) -> {
            dev.filtsiap.ded.anonymizer.AnonymizeResult r = ApiHandlerTest.pipeline(docx, ctx);
            return new dev.filtsiap.ded.anonymizer.AnonymizeResult(r.documentId(), big, r.summary(), r.warnings(),
                    r.model(), r.timings(), r.postcheck(), r.provenance(), r.unresolved(), r.accounting());
        }, 2);
        byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος.").bytes();
        try (Socket reader = new Socket()) {
            reader.setReceiveBufferSize(4096);
            reader.connect(new InetSocketAddress("127.0.0.1", served.port()));
            reader.getOutputStream().write(head(docx.length).getBytes(StandardCharsets.ISO_8859_1));
            reader.getOutputStream().write(docx);
            reader.getOutputStream().flush();
            Thread.sleep(500);
            assertEquals(1, served.requests().active()); // writing the document: the client reads nothing
            try (Logs logs = new Logs()) {
                double took = stop(served, budget(1_000, 2_000));
                assertTrue(took < 3.5, "took " + took);
                assertTrue(logs.has("outcome=cancelled status=200"), logs.lines().toString());
                assertTrue(logs.has("error_code=SHUTTING_DOWN"), logs.lines().toString());
                assertFalse(logs.has("outcome=success"), logs.lines().toString());
            }
            awaitTrue(() -> served.requests().active() == 0, 2_000);
        }
    }

    /** A document's own failure inside the cancel window keeps its status: a retry would fail the same way. */
    @Test
    void aDocumentErrorWhileCancellingKeepsItsOwnStatus() throws Exception {
        RequestTracker requests = new RequestTracker();
        CountDownLatch inside = new CountDownLatch(1);
        Served served = serve(new ApiHandler(ApiHandlerTest.CFG, System::nanoTime, (docx, ctx) -> {
            inside.countDown();
            while (!requests.cancelling()) {
                java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
            }
            throw new InvalidDocumentError("synthetic invalid"); // found by work the interrupt did not stop
        }, requests::cancelling), 2, requests);
        CompletableFuture<String> response = exchangeAsync(served.port(), head(1), new byte[] {1});
        assertTrue(inside.await(5, TimeUnit.SECONDS));
        try (Logs logs = new Logs()) {
            stop(served, budget(500, 2_000));
            assertTrue(logs.has("status=400"), logs.lines().toString());
            assertFalse(logs.has("error_code=SHUTTING_DOWN"), logs.lines().toString());
        }
        String text = response.get(5, TimeUnit.SECONDS);
        assertTrue(text.startsWith("HTTP/1.1 400 "), text);
    }

    static String textHead(int contentLength) {
        return "POST /anonymize-text HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
                + "Authorization: Bearer k3y\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
                + contentLength + "\r\n\r\n";
    }

    private static Served serveText(ApiHandler.TextProcessor text) {
        RequestTracker requests = new RequestTracker();
        return serve(new ApiHandler(ApiHandlerTest.CFG, System::nanoTime, ApiHandlerTest.UNREACHABLE, text,
                requests::cancelling), 2, requests);
    }

    /** A text whose work shutdown interrupts is answered 503 and logged as cancelled, never as a 500. */
    @Test
    void aTextCancelledByShutdownIsAnsweredWithA503NotA500() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        Served served = serveText((text, ctx) -> {
            inside.countDown();
            try {
                new CountDownLatch(1).await();
                throw new AssertionError("unreachable");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted", e);
            }
        });
        CompletableFuture<String> response = exchangeAsync(served.port(), textHead(2),
                "hi".getBytes(StandardCharsets.UTF_8));
        assertTrue(inside.await(5, TimeUnit.SECONDS));
        try (Logs logs = new Logs()) {
            stop(served, budget(500, 2_000));
            assertTrue(logs.has("text_finished"), logs.lines().toString());
            assertTrue(logs.has("outcome=cancelled status=503"), logs.lines().toString());
            assertTrue(logs.has("error_code=SHUTTING_DOWN"), logs.lines().toString());
            assertFalse(logs.has("outcome=internal_error"), logs.lines().toString());
        }
        String text = response.get(5, TimeUnit.SECONDS);
        assertTrue(text.startsWith("HTTP/1.1 503 "), text);
        assertTrue(text.endsWith("{\"detail\":\"the server is shutting down\"}"), text);
    }

    /** A text whose response write the shutdown cuts off was not delivered: never logged as a success. */
    @Test
    void aTextWhoseResponseIsCutOffIsLoggedAsCancelledNotAsASuccess() throws Exception {
        String big = ".".repeat(32 * 1024 * 1024);
        Served served = serveText((text, ctx) -> new ChatPipeline.TextResult(big, ChatPipeline.Status.ANONYMIZED,
                Map.of(), List.of()));
        try (Socket reader = new Socket()) {
            reader.setReceiveBufferSize(4096);
            reader.connect(new InetSocketAddress("127.0.0.1", served.port()));
            reader.getOutputStream().write(textHead(2).getBytes(StandardCharsets.ISO_8859_1));
            reader.getOutputStream().write("hi".getBytes(StandardCharsets.UTF_8));
            reader.getOutputStream().flush();
            Thread.sleep(500);
            assertEquals(1, served.requests().active()); // writing the reply: the client reads nothing
            try (Logs logs = new Logs()) {
                double took = stop(served, budget(1_000, 2_000));
                assertTrue(took < 3.5, "took " + took);
                assertTrue(logs.has("outcome=cancelled status=200"), logs.lines().toString());
                assertTrue(logs.has("error_code=SHUTTING_DOWN"), logs.lines().toString());
                assertFalse(logs.has("outcome=success"), logs.lines().toString());
            }
            awaitTrue(() -> served.requests().active() == 0, 2_000);
        }
    }

    /**
     * The real pipeline and the real OpenAI client against a provider that accepts the connection
     * and never answers: the 60 s call timeout and 300 s document budget do not bound shutdown, and
     * the provider connection is closed rather than left running.
     */
    @Test
    void aProviderThatNeverAnswersCannotHoldShutdownAndItsCallIsAbandoned() throws Exception {
        try (ServerSocket provider = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())) {
            CountDownLatch called = new CountDownLatch(1);
            CountDownLatch hungUp = new CountDownLatch(1);
            Thread.ofVirtual().start(() -> {
                try (Socket call = provider.accept()) {
                    called.countDown();
                    call.getInputStream().readAllBytes(); // never answers; returns when the client hangs up
                } catch (IOException e) {
                    // reset by the client: hung up as well
                }
                hungUp.countDown();
            });
            LlmClient llm = OpenAiLlmClient.openAi("sk-synthetic", 60.0,
                    "http://127.0.0.1:" + provider.getLocalPort() + "/v1", null, null);
            RequestTracker requests = new RequestTracker();
            ApiHandler handler = new ApiHandler(ApiHandlerTest.CFG, System::nanoTime,
                    (docx, ctx) -> Pipeline.anonymizeDocument(docx, ApiHandlerTest.CFG, ApiHandlerTest.FILES, llm, ctx),
                    requests::cancelling);
            ApiServer server = ApiServer.serve(handler, llm, new InetSocketAddress("127.0.0.1", 0), 2, requests);
            byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος υπέβαλε προσφυγή.").bytes();
            CompletableFuture<String> response = exchangeAsync(server.port(), head(docx.length), docx);
            assertTrue(called.await(10, TimeUnit.SECONDS), "the pipeline never called the provider");
            try (Logs logs = new Logs()) {
                long started = System.nanoTime();
                server.stop(budget(1_000, 3_000));
                double took = (System.nanoTime() - started) / 1e9;
                assertTrue(took < 4.5, "took " + took);
                assertTrue(logs.has("cancelled=1"), logs.lines().toString());
                assertTrue(logs.has("outcome=cancelled status=503"), logs.lines().toString());
            }
            assertTrue(hungUp.await(3, TimeUnit.SECONDS), "the provider call was left running");
            String text = response.get(5, TimeUnit.SECONDS);
            assertTrue(text.startsWith("HTTP/1.1 503 ") || text.startsWith("IOException") || text.isEmpty(), text);
            assertEquals(0, requests.active());
        }
    }

    // ------------------------------------------------------------------ queued, immediate, repeated

    @Test
    void aQueuedRequestIsRefusedAndNeverProcessedWhileTheActiveOneFinishes() throws Exception {
        AtomicInteger processed = new AtomicInteger();
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Served served = serve((docx, ctx) -> {
            processed.incrementAndGet();
            inside.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                throw new AssertionError("interrupted inside its grace period", e);
            }
            throw new InvalidDocumentError("synthetic invalid");
        }, 1);
        CompletableFuture<String> active = exchangeAsync(served.port(), head(1), new byte[] {1});
        assertTrue(inside.await(5, TimeUnit.SECONDS));
        CompletableFuture<String> queued = exchangeAsync(served.port(), head(1), new byte[] {1});
        Thread.sleep(300); // the second has reached the worker queue behind the only slot
        try (Logs logs = new Logs()) {
            CompletableFuture<Double> took = CompletableFuture.supplyAsync(() -> stop(served, budget(10_000, 2_000)));
            String refused = queued.get(3, TimeUnit.SECONDS);
            assertTrue(refused.startsWith("HTTP/1.1 503 "), refused);
            assertTrue(refused.endsWith("{\"detail\":\"the server is shutting down\"}"), refused);
            release.countDown();
            assertTrue(active.get(5, TimeUnit.SECONDS).startsWith("HTTP/1.1 400 "));
            assertTrue(took.get(10, TimeUnit.SECONDS) < 3.0);
            assertTrue(logs.has("There are pending requests: active=1, queued=1."), logs.lines().toString());
            assertTrue(logs.has("refused=1"), logs.lines().toString());
        }
        assertEquals(1, processed.get());
    }

    @Test
    void aZeroGracePeriodCancelsAtOnce() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        Served served = serve((docx, ctx) -> {
            inside.countDown();
            return UNTIL_INTERRUPTED.process(docx, ctx);
        }, 2);
        CompletableFuture<String> response = exchangeAsync(served.port(), head(1), new byte[] {1});
        assertTrue(inside.await(5, TimeUnit.SECONDS));
        try (Logs logs = new Logs()) {
            double took = stop(served, ApiServer.ShutdownBudget.of(0));
            assertTrue(took < 1.6, "took " + took);
            assertTrue(logs.has("Immediate shutdown (no grace period): cancelling active=1 request(s)"),
                    logs.lines().toString());
            assertFalse(logs.has("There are pending requests"), logs.lines().toString());
        }
        String text = response.get(5, TimeUnit.SECONDS);
        assertTrue(text.startsWith("HTTP/1.1 503 ") || text.startsWith("IOException") || text.isEmpty(), text);
    }

    @Test
    void repeatedAndConcurrentStopsShareOneDeadline() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        Served served = serve((docx, ctx) -> {
            inside.countDown();
            return UNTIL_INTERRUPTED.process(docx, ctx);
        }, 2);
        exchangeAsync(served.port(), head(1), new byte[] {1});
        assertTrue(inside.await(5, TimeUnit.SECONDS));
        try (Logs logs = new Logs()) {
            ApiServer.ShutdownBudget budget = budget(1_000, 1_000);
            CompletableFuture<Double> first = CompletableFuture.supplyAsync(() -> stop(served, budget));
            Thread.sleep(300);
            CompletableFuture<Double> second = CompletableFuture.supplyAsync(() -> stop(served, budget));
            assertTrue(first.get(10, TimeUnit.SECONDS) < 3.0);
            assertTrue(second.get(10, TimeUnit.SECONDS) < 2.7); // the first deadline, not a fresh one
            assertTrue(stop(served, budget) < 0.5); // after the fact: nothing left to wait for
            assertEquals(1, logs.count("Shutdown complete:"), logs.lines().toString());
        }
        assertEquals(1, served.llm().closed.get());
    }

    /**
     * Requests arriving while shutdown begins: each one is either admitted and answered (or, only
     * once the grace period has expired, cancelled), or refused and never processed; no count is
     * lost, and nothing is processed after stop returns.
     */
    @RepeatedTest(5)
    void admissionCompletionAndShutdownDoNotRace() throws Exception {
        AtomicInteger processed = new AtomicInteger();
        AtomicInteger cancelled = new AtomicInteger();
        AtomicLong lastProcessedAt = new AtomicLong();
        Served served = serve((docx, ctx) -> {
            processed.incrementAndGet();
            try {
                Thread.sleep((long) (Math.random() * 5));
            } catch (InterruptedException e) {
                cancelled.incrementAndGet();
                Thread.currentThread().interrupt();
                throw new AIProviderError("LLM detection interrupted", e);
            }
            lastProcessedAt.set(System.nanoTime());
            throw new InvalidDocumentError("synthetic invalid");
        }, 4);
        AtomicBoolean go = new AtomicBoolean(true);
        ConcurrentHashMap<String, AtomicInteger> outcomes = new ConcurrentHashMap<>();
        // Platform threads, as real clients are other processes: once the listener is closed, a
        // refused connect returns without parking, and on a virtual thread that loop would hold a
        // carrier the server's own (virtual) request threads need.
        ExecutorService clients = Executors.newFixedThreadPool(8);
        for (int i = 0; i < 8; i++) {
            clients.submit(() -> {
                while (go.get()) {
                    String text = exchange(served.port(), head(1), new byte[] {1});
                    String key = text.startsWith("HTTP/1.1 ") ? text.substring(9, 12) : "io";
                    outcomes.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
                }
            });
        }
        Thread.sleep(200);
        stop(served, budget(2_000, 1_000));
        long stoppedAt = System.nanoTime();
        go.set(false);
        clients.shutdown();
        assertTrue(clients.awaitTermination(20, TimeUnit.SECONDS));
        assertEquals(0, served.requests().active());
        assertTrue(lastProcessedAt.get() < stoppedAt, "a document was processed after stop() returned");
        // Every admitted request was answered with its own 400, or cancelled, and only after expiry.
        int answered = outcomes.getOrDefault("400", new AtomicInteger()).get();
        assertEquals(processed.get(), answered + cancelled.get(), outcomes + " cancelled=" + cancelled);
        assertTrue(cancelled.get() == 0 || served.requests().cancelling(), "cancelled inside the grace period");
        List<String> unexpected = new ArrayList<>(outcomes.keySet());
        unexpected.removeAll(List.of("400", "503", "io"));
        assertTrue(unexpected.isEmpty(), outcomes.toString());
    }

    // ------------------------------------------------------------------ configuration

    @Test
    void theGracefulTimeoutIsAValidatedBudgetOfAtMostOneHundredTwentySeconds() {
        assertEquals(0, ApiServer.gracefulTimeout("0"));
        assertEquals(120, ApiServer.gracefulTimeout(ApiServer.DEFAULT_GRACEFUL_TIMEOUT));
        assertEquals(60, ApiServer.gracefulTimeout("60"));
        assertEquals(120, ApiServer.gracefulTimeout("120"));
        try (Logs logs = new Logs()) {
            assertEquals(120, ApiServer.gracefulTimeout("900")); // the value v2 deployments carry
            assertTrue(logs.has("ANON_GRACEFUL_TIMEOUT=900 exceeds the 120 s maximum shutdown budget; using 120"),
                    logs.lines().toString());
        }
        for (String bad : new String[] {"-1", "abc", "", "1.5", "25s", "nine hundred"}) {
            ConfigurationError e = assertThrows(ConfigurationError.class, () -> ApiServer.gracefulTimeout(bad), bad);
            assertTrue(e.getMessage().startsWith("ANON_GRACEFUL_TIMEOUT must"), e.getMessage());
        }
    }

    @Test
    void theBudgetReservesCleanupInsideItAndNeverExceedsItsMaximum() {
        assertEquals(budget(115_000, 5_000), ApiServer.ShutdownBudget.of(120));
        assertEquals(budget(20_000, 5_000), ApiServer.ShutdownBudget.of(25));
        assertEquals(budget(55_000, 5_000), ApiServer.ShutdownBudget.of(60));
        assertEquals(budget(0, 1_000), ApiServer.ShutdownBudget.of(0));
        assertEquals(budget(5_000, 5_000), ApiServer.ShutdownBudget.of(10));
        for (int seconds = 0; seconds <= ApiServer.MAX_GRACEFUL_TIMEOUT_S; seconds++) {
            ApiServer.ShutdownBudget b = ApiServer.ShutdownBudget.of(seconds);
            assertEquals(Math.max(seconds, 1) * 1000L, b.total().toMillis(), "seconds=" + seconds);
            assertTrue(b.cleanup().toMillis() >= 1000 && b.cleanup().toMillis() <= 5000, "seconds=" + seconds);
        }
    }
}
