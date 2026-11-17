package dev.filtsiap.ded.anonymizer.llm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.ChatRequest;
import dev.filtsiap.ded.anonymizer.llm.LlmClient.Completion;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The real SDK client against a local HTTP server: one request is exactly one HTTP attempt. */
class OpenAiLlmClientTest {

    static final ChatRequest REQUEST = new ChatRequest("gpt-test", "system", "user", 10, 5.0);

    HttpServer server;
    final AtomicInteger hits = new AtomicInteger();
    volatile int status;
    volatile String body;
    volatile String requestPath;
    volatile String requestQuery;
    volatile String azureKey;
    /** Response header name and value to send, or null for none. */
    volatile String extraHeader;
    volatile String extraHeaderValue;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            hits.incrementAndGet();
            requestPath = exchange.getRequestURI().getPath();
            requestQuery = exchange.getRequestURI().getQuery();
            azureKey = exchange.getRequestHeaders().getFirst("api-key");
            exchange.getRequestBody().readAllBytes();
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            if (extraHeader != null) {
                exchange.getResponseHeaders().set(extraHeader, extraHeaderValue);
            }
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    OpenAiLlmClient client() {
        return OpenAiLlmClient.openAi("sk-test", 5.0, "http://127.0.0.1:" + server.getAddress().getPort(), null, null);
    }

    static String completion(String finishReason, String content, String refusal) {
        return "{\"id\":\"c\",\"object\":\"chat.completion\",\"created\":0,\"model\":\"gpt-test\",\"choices\":[{"
                + "\"index\":0,\"logprobs\":null,"
                + (finishReason == null ? "" : "\"finish_reason\":\"" + finishReason + "\",")
                + "\"message\":{\"role\":\"assistant\",\"content\":" + (content == null ? "null" : "\"" + content + "\"")
                + ",\"refusal\":" + (refusal == null ? "null" : "\"" + refusal + "\"") + "}}]}";
    }

    @Test
    void theSdkNeverRetriesARetryableStatus() {
        assertEquals(0, OpenAiLlmClient.SDK_MAX_RETRIES);
        for (int s : new int[] {408, 409, 429, 500, 503}) {
            status = s;
            body = "{\"error\":{\"message\":\"busy\",\"type\":\"server_error\"}}";
            hits.set(0);
            try (OpenAiLlmClient client = client()) {
                LlmCallException e = assertThrows(LlmCallException.class, () -> client.complete(REQUEST));
                assertEquals(LlmCallException.Kind.STATUS, e.kind());
                assertEquals(s, e.statusCode());
            }
            assertEquals(1, hits.get(), "HTTP " + s); // the detector's ladder is the only retry layer
        }
    }

    /**
     * The provider's {@code retry-after-ms} reaches the retry controller through the error wrapper:
     * a non-negative integer as given (zero and values above the fixed schedule included), anything else as
     * "none", so the controller falls back to its own backoff. Only that header is read.
     */
    @Test
    void theRetryAfterMsHeaderIsCarriedOnTheFailure() {
        status = 429;
        body = "{\"error\":{\"message\":\"slow down\",\"type\":\"rate_limit\"}}";
        Map<String, Long> cases = new LinkedHashMap<>();
        cases.put("1500", 1500L);
        cases.put("0", 0L);
        cases.put("12345", 12_345L);
        cases.put(" 250 ", 250L);
        cases.put("abc", null);
        cases.put("-5", null);
        cases.put("1.5", null);
        cases.put("99999999999999999999", null);
        cases.forEach((value, expected) -> {
            extraHeader = "retry-after-ms";
            extraHeaderValue = value;
            try (OpenAiLlmClient client = client()) {
                LlmCallException e = assertThrows(LlmCallException.class, () -> client.complete(REQUEST));
                assertEquals(429, e.statusCode());
                assertEquals(expected, e.retryAfterMs(), "retry-after-ms: " + value);
            }
        });
        // Missing, or only a different header (the misspelling and the seconds-based one are not it).
        for (String other : new String[] {null, "relay-after-ms", "retry-after"}) {
            extraHeader = other;
            extraHeaderValue = "1500";
            try (OpenAiLlmClient client = client()) {
                assertNull(assertThrows(LlmCallException.class, () -> client.complete(REQUEST)).retryAfterMs(),
                        String.valueOf(other));
            }
        }
        assertNull(LlmCallException.timeout(null).retryAfterMs());
        assertNull(LlmCallException.status(503, null).retryAfterMs());
    }

    @Test
    void azureUsesTheDeploymentRouteVersionAndApiKey() {
        status = 200;
        body = completion("stop", "[]", null);
        try (OpenAiLlmClient azure = OpenAiLlmClient.azure("synthetic-key",
                "http://127.0.0.1:" + server.getAddress().getPort(), "2024-10-21", 5)) {
            assertEquals("[]", azure.complete(new ChatRequest("test-deployment", "system", "user", 10, 5)).text());
        }
        assertEquals("/openai/deployments/test-deployment/chat/completions", requestPath);
        assertEquals("api-version=2024-10-21", requestQuery);
        assertEquals("synthetic-key", azureKey);
        assertEquals(1, hits.get());
    }

    @Test
    void aTricklingResponseCannotOutliveTheTotalCallBudget() {
        server.removeContext("/");
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 20; i++) {
                    out.write(' ');
                    out.flush();
                    Thread.sleep(50);
                }
                out.write(completion("stop", "[]", null).getBytes(StandardCharsets.UTF_8));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException expectedDisconnect) {
                // A timed-out client closes the stream while this peer is still sending.
            } finally {
                exchange.close();
            }
        });
        try (OpenAiLlmClient client = client()) {
            LlmCallException e = assertThrows(LlmCallException.class,
                    () -> client.complete(new ChatRequest("gpt-test", "system", "user", 10, 0.3)));
            assertEquals(LlmCallException.Kind.TIMEOUT, e.kind());
        }
    }

    /**
     * Surefire runs every test with {@code OPENAI_LOG=debug} (see the pom), the setting under which
     * the SDK's default prints each request and response body to standard output.
     */
    @Test
    void theSdkNeverPrintsARequestOrResponseBody() {
        assertEquals("debug", System.getenv("OPENAI_LOG"), "the pom sets OPENAI_LOG for this test");
        status = 200;
        body = completion("stop", "REPLY_SENTINEL_7f3", null);
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream out = System.out;
        PrintStream err = System.err;
        PrintStream capture = new PrintStream(captured, true, StandardCharsets.UTF_8);
        System.setOut(capture);
        System.setErr(capture);
        try (OpenAiLlmClient client = client()) {
            client.complete(new ChatRequest("gpt-test", "system", "DOCUMENT_SENTINEL_9c1", 10, 5.0));
        } finally {
            System.setOut(out);
            System.setErr(err);
        }
        String printed = captured.toString(StandardCharsets.UTF_8);
        assertFalse(printed.contains("DOCUMENT_SENTINEL_9c1"), "request body printed");
        assertFalse(printed.contains("REPLY_SENTINEL_7f3"), "response body printed");
        assertFalse(printed.contains("sk-test"), "credential printed");
    }

    @Test
    void finishReasonAndRefusalReachTheDetector() {
        status = 200;
        try (OpenAiLlmClient client = client()) {
            body = completion("length", "[]", null);
            Completion truncated = client.complete(REQUEST);
            assertTrue(truncated.truncated());
            assertEquals("[]", truncated.text());

            body = completion("stop", null, "I cannot help with that");
            Completion refused = client.complete(REQUEST);
            assertTrue(refused.refused());
            assertFalse(refused.complete());
            assertEquals("", refused.text());

            body = completion(null, "[]", null);
            Completion unstated = client.complete(REQUEST);
            assertNull(unstated.finishReason());
            assertTrue(unstated.complete()); // no reason reported is not a problem reported
        }
    }

    /** {@link #completion} with a {@code usage} block (raw JSON) appended. */
    static String withUsage(String completion, String usage) {
        return completion.substring(0, completion.length() - 1) + ",\"usage\":" + usage + "}";
    }

    @Test
    void theProvidersTokenUsageIsReadAsReportedAndNeverMadeUp() {
        status = 200;
        try (OpenAiLlmClient client = client()) {
            body = withUsage(completion("stop", "[]", null), "{\"prompt_tokens\":1234,\"completion_tokens\":56,"
                    + "\"total_tokens\":1290,\"prompt_tokens_details\":{\"cached_tokens\":1024},"
                    + "\"completion_tokens_details\":{\"reasoning_tokens\":16}}");
            assertEquals(new LlmClient.TokenUsage(1234L, 56L, 1290L, 1024L, 16L), client.complete(REQUEST).usage());

            body = withUsage(completion("stop", "[]", null),
                    "{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}");
            assertEquals(new LlmClient.TokenUsage(10L, 2L, 12L, null, null), client.complete(REQUEST).usage());

            body = completion("stop", "[]", null); // no usage block at all
            assertNull(client.complete(REQUEST).usage());

            // A usage block the SDK cannot read costs the counts, never the answer.
            body = withUsage(completion("length", "[]", null),
                    "{\"prompt_tokens\":\"many\",\"completion_tokens\":7,\"total_tokens\":null}");
            Completion odd = client.complete(REQUEST);
            assertTrue(odd.truncated());
            assertEquals("[]", odd.text());
            assertEquals(new LlmClient.TokenUsage(null, 7L, null, null, null), odd.usage());
        }
    }
}
