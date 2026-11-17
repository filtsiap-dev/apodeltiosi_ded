package dev.filtsiap.ded.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.FileConfig;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.TestDocx;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The HTTP contract of api.py, over real HTTP on an ephemeral port. */
class ApiServerTest {

    static ApiServer server;
    static String base;
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));

    static RuntimeConfig cfg(String apiKey) {
        Map<String, String> env = new HashMap<>(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_MAX_UPLOAD_BYTES", "1048576"));
        if (apiKey != null) {
            env.put("ANON_API_KEY", apiKey);
        }
        return Config.loadRuntimeConfig(env);
    }

    @BeforeAll
    static void start() {
        server = ApiServer.start(cfg("k3y"), FILES, ScriptedLlm.cooperative(), new InetSocketAddress("127.0.0.1", 0), 4);
        base = "http://127.0.0.1:" + server.port();
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    static HttpResponse<byte[]> send(HttpRequest.Builder b) throws Exception {
        return HTTP.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    static String body(HttpResponse<byte[]> r) {
        return new String(r.body(), StandardCharsets.UTF_8);
    }

    static HttpRequest.Builder post(String path, String contentType, byte[] data, String auth) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).POST(HttpRequest.BodyPublishers.ofByteArray(data))
                .header("Content-Type", contentType);
        return auth == null ? b : b.header("Authorization", auth);
    }

    @Test
    void refusesToStartWithoutKey() {
        assertThrows(ConfigurationError.class,
                () -> ApiServer.start(cfg(null), FILES, ScriptedLlm.cooperative(), new InetSocketAddress("127.0.0.1", 0),
                        4));
    }

    @Test
    void healthzIsUnauthenticated() throws Exception {
        HttpResponse<byte[]> r = send(HttpRequest.newBuilder(URI.create(base + "/healthz")));
        assertEquals(200, r.statusCode());
        assertEquals("{\"status\":\"ok\",\"provider\":\"openai\",\"model\":\"gpt-test\"}", body(r));
    }

    @Test
    void authFailuresAreOneUniform401() throws Exception {
        for (String auth : new String[] {null, "Basic abc", "Bearer wrong", "Bearer"}) {
            HttpResponse<byte[]> r = send(post("/anonymize", "text/plain", new byte[] {1}, auth));
            assertEquals(401, r.statusCode());
            assertEquals("Bearer", r.headers().firstValue("www-authenticate").orElse(""));
            assertEquals("{\"detail\":\"missing or invalid API key\"}", body(r));
        }
    }

    static final String DOCX = ApiHandler.DOCX_MEDIA_TYPE;
    static final String UNSUPPORTED = "{\"error\":\"UnsupportedDocumentFormatError\",\"code\":"
            + "\"UNSUPPORTED_DOCUMENT_FORMAT\",\"detail\":\"unsupported document format; send a .docx file\"}";

    @Test
    void payloadChecks() throws Exception {
        HttpResponse<byte[]> empty = send(post("/anonymize", DOCX, new byte[0], "Bearer k3y"));
        assertEquals(400, empty.statusCode());
        assertEquals("{\"error\":\"InvalidDocumentError\",\"code\":\"INVALID_DOCUMENT\",\"detail\":\"the request body "
                + "is not a readable Word (OOXML) document\"}", body(empty));
        // Declared, not sent: the server answers from the header alone. (Streaming the whole body
        // races the early answer, and the client can see the connection reset instead of the 413.)
        String big = ApiHandlerTest.raw(server, ApiHandlerTest.request("Bearer k3y", DOCX,
                "Content-Length: " + (1024 * 1024 + 1) + "\r\n"), new byte[0]);
        assertTrue(big.startsWith("HTTP/1.1 413 "), big);
        assertTrue(big.endsWith("\r\n\r\n{\"error\":\"ResourceLimitExceededError\",\"code\":\"UPLOAD_TOO_LARGE\",\"detail\":"
                + "\"the document exceeds a configured size or resource limit\"}"), big);
        assertEquals(400, send(post("/anonymize", DOCX, "PK junk".getBytes(), "Bearer k3y")).statusCode());
        // Parameters are ignored and case does not matter; the media type itself must match exactly.
        assertEquals(200, send(post("/anonymize", "Application/VND.openxmlformats-officedocument.wordprocessingml.Document;"
                + " charset=utf-8", TestDocx.paragraphs("κείμενο").bytes(), "Bearer k3y")).statusCode());
    }

    @Test
    void onlyARawDocxBodyIsAccepted() throws Exception {
        byte[] docx = TestDocx.paragraphs("κείμενο").bytes();
        for (String type : new String[] {"multipart/form-data; boundary=BoUnDaRy", "application/octet-stream",
                "text/plain", DOCX + "-ish", "application/vnd.ms-word.document.macroEnabled.12"}) {
            HttpResponse<byte[]> r = send(post("/anonymize", type, docx, "Bearer k3y"));
            assertEquals(415, r.statusCode(), type);
            assertEquals(UNSUPPORTED, body(r), type);
        }
        HttpResponse<byte[]> untyped = send(HttpRequest.newBuilder(URI.create(base + "/anonymize"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(docx)).header("Authorization", "Bearer k3y"));
        assertEquals(415, untyped.statusCode());
        assertEquals(UNSUPPORTED, body(untyped));
    }

    @Test
    void routing() throws Exception {
        assertEquals(404, send(HttpRequest.newBuilder(URI.create(base + "/nope"))).statusCode());
        HttpResponse<byte[]> m = send(HttpRequest.newBuilder(URI.create(base + "/anonymize")));
        assertEquals(405, m.statusCode());
        assertEquals("POST", m.headers().firstValue("allow").orElse(""));
        // Starlette serves HEAD wherever it serves GET.
        HttpResponse<byte[]> head = send(HttpRequest.newBuilder(URI.create(base + "/healthz"))
                .method("HEAD", HttpRequest.BodyPublishers.noBody()));
        assertEquals(200, head.statusCode());
        assertEquals(0, head.body().length);
        HttpResponse<byte[]> post = send(post("/healthz", DOCX, new byte[] {1}, null));
        assertEquals(405, post.statusCode());
        assertEquals("GET, HEAD", post.headers().firstValue("allow").orElse(""));
    }

    /** Transport headers the server adds; everything else on a success is the application's. */
    static final Set<String> TRANSPORT = Set.of("date", "content-length", "content-type", "connection",
            "transfer-encoding");

    @Test
    void aRawDocxBodyReturnsTheRedactedDocxAndOnlyTheV2AndAccountingHeaders() throws Exception {
        HttpResponse<byte[]> r = send(post("/anonymize", DOCX, TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος.").bytes(),
                "Bearer k3y"));
        assertEquals(200, r.statusCode());
        assertEquals(DOCX, r.headers().firstValue("content-type").orElse(""));
        String id = r.headers().firstValue("x-document-id").orElse("");
        assertTrue(id.matches("[0-9a-f]{12}"), id);
        assertEquals("attachment; filename=\"" + id + "_redacted.docx\"",
                r.headers().firstValue("content-disposition").orElse(""));
        assertEquals("processed", r.headers().firstValue("x-anonymization-status").orElse(""));
        assertEquals("0", r.headers().firstValue("x-unresolved-count").orElse(""));
        assertTrue(r.headers().firstValue("x-postcheck-findings").isPresent());
        assertTrue(r.headers().firstValue("x-postcheck-kinds").isPresent());
        // v2's headers, plus the per-document accounting that is known. The scripted model reports no
        // token usage and no price is configured, so no token or cost header is sent: only what is known.
        assertEquals(Set.of("content-disposition", "x-document-id", "x-anonymization-status", "x-unresolved-count",
                "x-postcheck-findings", "x-postcheck-kinds", "x-processing-time-ms", "x-llm-time-ms", "x-llm-calls",
                "x-llm-calls-missing-usage"), r.headers().map().keySet().stream()
                .map(k -> k.toLowerCase(Locale.ROOT)).filter(k -> !TRANSPORT.contains(k)).collect(Collectors.toSet()));
        // The body is the file: a package, and the name is gone from it.
        String xml = TestDocx.part(r.body(), "word/document.xml");
        assertTrue(xml != null && !xml.contains("Παπαδόπουλος"), String.valueOf(xml));
    }

    @Test
    void theQueryStringChangesNothing() throws Exception {
        byte[] docx = TestDocx.paragraphs("Απλό κείμενο.").bytes();
        for (String query : new String[] {"?summary=1", "?summary=yes", "?anything=else"}) {
            HttpResponse<byte[]> r = send(post("/anonymize" + query, DOCX, docx, "Bearer k3y"));
            assertEquals(200, r.statusCode(), query);
            assertEquals(DOCX, r.headers().firstValue("content-type").orElse(""), query);
            assertTrue(TestDocx.part(r.body(), "word/document.xml") != null, query); // a DOCX, never JSON
        }
    }
}
