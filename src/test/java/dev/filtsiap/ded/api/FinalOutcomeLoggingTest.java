package dev.filtsiap.ded.api;

import static dev.filtsiap.ded.anonymizer.LogCapture.await;
import static dev.filtsiap.ded.anonymizer.LogCapture.count;
import static dev.filtsiap.ded.anonymizer.LogCapture.one;
import static dev.filtsiap.ded.anonymizer.llm.FlakyLlm.ok;
import static dev.filtsiap.ded.anonymizer.llm.FlakyLlm.rateLimited;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.AnonymizeResult;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.FileConfig;
import dev.filtsiap.ded.anonymizer.InvalidDocumentError;
import dev.filtsiap.ded.anonymizer.LogCapture;
import dev.filtsiap.ded.anonymizer.Pipeline;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.TestDocx;
import dev.filtsiap.ded.anonymizer.llm.FlakyLlm;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The one final log line per document, through the HTTP service, against a simulated provider: what a
 * document that was absorbed, recovered, timed out, was abandoned by its client, or was cut off by
 * shutdown logs, and that each ends with exactly one {@code document_finished}.
 */
class FinalOutcomeLoggingTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final RuntimeConfig CFG = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
            "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test", "ANON_API_KEY", "k3y", "ANON_LLM_CONCURRENCY", "4"));
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final String DOCX = ApiHandler.DOCX_MEDIA_TYPE;
    /** One short paragraph with no name in it: one chunk, and no pass-2 question. */
    static final String PLAIN_TEXT = "Κείμενο χωρίς στοιχεία.";

    static ApiServer start(RuntimeConfig cfg, LlmClient llm) {
        return ApiServer.start(cfg, FILES, llm, new InetSocketAddress("127.0.0.1", 0), 4);
    }

    static HttpRequest post(ApiServer server, byte[] docx) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/anonymize"))
                .header("Authorization", "Bearer k3y")
                .header("Content-Type", DOCX)
                .POST(HttpRequest.BodyPublishers.ofByteArray(docx))
                .build();
    }

    /** Every provider call is rate-limited at once: discovery gives up, and the document is delivered needs-review. */
    @Test
    void aStormOfRateLimitsAbsorbedByDiscoveryEndsNeedsReviewWithItsRetriesLogged() throws Exception {
        FlakyLlm llm = new FlakyLlm().script("", rateLimited(0L));
        try (LogCapture logs = new LogCapture()) {
            ApiServer server = start(CFG, llm);
            HttpResponse<byte[]> response;
            try {
                response = HTTP.send(post(server, TestDocx.paragraphs(PLAIN_TEXT).bytes()),
                        HttpResponse.BodyHandlers.ofByteArray());
            } finally {
                server.stop(0);
            }
            assertEquals(200, response.statusCode());
            assertEquals("needs-review", response.headers().firstValue("X-Anonymization-Status").orElseThrow());
            List<String> lines = logs.lines();
            assertEquals(1, count(lines, "document_started"));
            one(lines, "llm_retry_exhausted", "chunk=1 pass=1", "attempts=6");
            String finished = one(lines, "document_finished", "outcome=needs_review", "status=200");
            assertEquals(1, count(lines, "document_finished"));
            assertFalse(finished.contains("failed_stage="), finished);
        }
    }

    /** Five rate limits, then success: a success, with the attempts it cost counted and no failure fields. */
    @Test
    void aSuccessAfterFiveRecoveredRateLimitsIsASuccessWithNoFailureFields() throws Exception {
        FlakyLlm llm = new FlakyLlm().script("", rateLimited(0L), rateLimited(0L), rateLimited(0L),
                rateLimited(0L), rateLimited(0L), ok());
        try (LogCapture logs = new LogCapture()) {
            ApiServer server = start(CFG, llm);
            HttpResponse<byte[]> response;
            try {
                response = HTTP.send(post(server, TestDocx.paragraphs(PLAIN_TEXT).bytes()),
                        HttpResponse.BodyHandlers.ofByteArray());
            } finally {
                server.stop(0);
            }
            assertEquals(200, response.statusCode());
            assertEquals("processed", response.headers().firstValue("X-Anonymization-Status").orElseThrow());
            List<String> lines = logs.lines();
            String finished = one(lines, "document_finished", "outcome=success", "status=200",
                    "failed_provider_attempts=5", "chunks_completed=1", "chunks_total=1");
            assertFalse(finished.contains("failed_stage="), finished);
            assertEquals(0, count(lines, "llm_retry_exhausted"));
            one(lines, "llm_retry_succeeded", "chunk=1 pass=1", "transport_attempt=6");
        }
    }

    /**
     * The provider never answers and the document's budget runs out: the request is a timeout, and its
     * final line names the stage it was in and the deadline as the reason.
     */
    @Test
    void aDocumentThatRunsOutOfTimeInTheLlmStageSaysWhereAndWhy() throws Exception {
        RuntimeConfig short1 = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_API_KEY", "k3y", "ANON_DOCUMENT_DEADLINE_S", "1.5"));
        CountDownLatch never = new CountDownLatch(1);
        LlmClient stalled = new LlmClient() {
            @Override
            public LlmClient.Completion complete(LlmClient.ChatRequest request) {
                try {
                    never.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                throw new IllegalStateException("released by the test");
            }

            @Override
            public void close() {
            }
        };
        try (LogCapture logs = new LogCapture()) {
            ApiServer server = start(short1, stalled);
            HttpResponse<byte[]> response;
            try {
                response = HTTP.send(post(server, TestDocx.paragraphs(PLAIN_TEXT).bytes()),
                        HttpResponse.BodyHandlers.ofByteArray());
            } finally {
                never.countDown();
                server.stop(0);
            }
            assertEquals(504, response.statusCode());
            one(logs.lines(), "document_finished", "outcome=timeout", "status=504", "error_code=DOCUMENT_TIMEOUT",
                    "failed_stage=llm_pass_1", "error_reason=deadline_expired", "last_failed_chunk=-",
                    "chunks_completed=0", "chunks_total=1");
        }
    }

    /**
     * The client hangs up while the answer is being written: nothing was delivered, so it is logged as
     * disconnected, never as a success.
     */
    @Test
    void aClientThatHangsUpBeforeTheAnswerIsLoggedAsDisconnectedNotAsASuccess() throws Exception {
        FlakyLlm llm = new FlakyLlm();
        ApiHandler.Processor bigAnswer = (docx, ctx) -> {
            AnonymizeResult r = Pipeline.anonymizeDocument(docx, CFG, FILES, llm, ctx);
            return new AnonymizeResult(r.documentId(), new byte[32 * 1024 * 1024], r.summary(), r.warnings(),
                    r.model(), r.timings(), r.postcheck(), r.provenance(), r.unresolved(), r.accounting());
        };
        try (LogCapture logs = new LogCapture()) {
            ApiServer server = ApiServer.serve(new ApiHandler(CFG, System::nanoTime, bigAnswer), llm,
                    new InetSocketAddress("127.0.0.1", 0), 2);
            try {
                byte[] docx = TestDocx.paragraphs(PLAIN_TEXT).bytes();
                try (Socket client = new Socket("127.0.0.1", server.port())) {
                    OutputStream out = client.getOutputStream();
                    out.write(("POST /anonymize HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
                            + "Authorization: Bearer k3y\r\nContent-Type: " + DOCX + "\r\nContent-Length: "
                            + docx.length + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    out.write(docx);
                    out.flush();
                } // gone before any of the answer is read
                await(() -> logs.lines().stream().anyMatch(l -> l.contains("document_finished")), 20_000);
            } finally {
                server.stop(0);
            }
            one(logs.lines(), "document_finished", "outcome=client_disconnected", "status=200",
                    "error_code=RESPONSE_INCOMPLETE", "failed_stage=respond");
        }
    }

    /**
     * The text endpoint logs its own start and one finish line, as /anonymize does: a text that fails
     * carries the same failure fields.
     */
    @Test
    void aTextRequestLogsItsStartAndOneFinishLineWithItsFailure() throws Exception {
        ApiHandler handler = new ApiHandler(CFG, System::nanoTime, (docx, ctx) -> {
            throw new IllegalStateException("not used by the text endpoint");
        }, (text, ctx) -> {
            throw new InvalidDocumentError("synthetic invalid text");
        }, () -> false);
        try (LogCapture logs = new LogCapture()) {
            ApiServer server = ApiServer.serve(handler, new FlakyLlm(), new InetSocketAddress("127.0.0.1", 0), 2);
            HttpResponse<byte[]> response;
            try {
                HttpRequest request = HttpRequest.newBuilder(
                                URI.create("http://127.0.0.1:" + server.port() + "/anonymize-text"))
                        .header("Authorization", "Bearer k3y")
                        .header("Content-Type", "text/plain; charset=utf-8")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)))
                        .build();
                response = HTTP.send(request, HttpResponse.BodyHandlers.ofByteArray());
            } finally {
                server.stop(0);
            }
            assertEquals(400, response.statusCode());
            List<String> lines = logs.lines();
            one(lines, "text_started", "deadline_s=");
            String finished = one(lines, "text_finished", "outcome=invalid_input", "status=400",
                    "error_reason=InvalidDocumentError");
            assertEquals(1, count(lines, "text_finished"));
            assertTrue(finished.contains(" failed_stage="), finished);
        }
    }

    /**
     * Shutdown arrives while a document waits out a provider's 30 s retry: the wait is interrupted, the
     * shutdown is named with the document's ids and stage, and the document ends cancelled, never as a
     * success or a provider failure.
     */
    @Test
    void aDocumentCaughtByShutdownDuringARetryWaitIsNamedAndEndsCancelled() throws Exception {
        FlakyLlm llm = new FlakyLlm().script("", rateLimited(30_000L));
        try (LogCapture logs = new LogCapture()) {
            ApiServer server = start(CFG, llm);
            CompletableFuture<HttpResponse<byte[]>> answer = HTTP.sendAsync(
                    post(server, TestDocx.paragraphs(PLAIN_TEXT).bytes()), HttpResponse.BodyHandlers.ofByteArray());
            await(() -> logs.lines().stream().anyMatch(l -> l.contains("llm_retry ")), 15_000);
            server.stop(3);
            assertEquals(503, answer.get(20, TimeUnit.SECONDS).statusCode());
            List<String> lines = logs.lines();
            one(lines, "shutdown_inflight", "stage=llm_pass_1", "chunks_total=1");
            one(lines, "llm_retry_interrupted", "chunk=1 pass=1", "waited_ms=0");
            one(lines, "document_finished", "outcome=cancelled", "status=503", "error_code=SHUTTING_DOWN",
                    "failed_stage=llm_pass_1", "error_reason=shutdown");
        }
    }
}
