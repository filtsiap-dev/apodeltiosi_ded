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
import java.util.Map;
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
                "ANON_MODEL", "gpt-test", "ANON_MAX_UPLOAD_MB", "1"));
        if (apiKey != null) {
            env.put("ANON_API_KEY", apiKey);
        }
        return Config.loadRuntimeConfig(env);
    }

    @BeforeAll
    static void start() {
        server = ApiServer.start(cfg("k3y"), FILES, ScriptedLlm.cooperative(), new InetSocketAddress("127.0.0.1", 0));
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
                () -> ApiServer.start(cfg(null), FILES, ScriptedLlm.cooperative(), new InetSocketAddress("127.0.0.1", 0)));
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

    @Test
    void payloadChecks() throws Exception {
        assertEquals(415, send(post("/anonymize", "text/plain", new byte[] {1}, "Bearer k3y")).statusCode());
        HttpResponse<byte[]> empty = send(post("/anonymize", "application/octet-stream", new byte[0], "Bearer k3y"));
        assertEquals("{\"error\":\"InvalidDocumentError\",\"detail\":\"empty request body\"}", body(empty));
        assertEquals(413, send(post("/anonymize", "application/octet-stream", new byte[1024 * 1024 + 1], "Bearer k3y")).statusCode());
        HttpResponse<byte[]> q = send(post("/anonymize?summary=yes", "application/octet-stream", new byte[] {1}, "Bearer k3y"));
        assertEquals(422, q.statusCode());
        assertTrue(body(q).contains("\"type\":\"int_parsing\""));
        assertEquals(400, send(post("/anonymize", "application/octet-stream", "PK junk".getBytes(), "Bearer k3y")).statusCode());
    }

    @Test
    void routing() throws Exception {
        assertEquals(404, send(HttpRequest.newBuilder(URI.create(base + "/nope"))).statusCode());
        HttpResponse<byte[]> m = send(HttpRequest.newBuilder(URI.create(base + "/anonymize")));
        assertEquals(405, m.statusCode());
        assertEquals("POST", m.headers().firstValue("allow").orElse(""));
    }

    @Test
    void multipartUploadReturnsTheRedactedDocx() throws Exception {
        byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος.").bytes();
        String boundary = "BoUnDaRy";
        byte[] head = ("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"d.docx\"\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8);
        byte[] tail = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] body = new byte[head.length + docx.length + tail.length];
        System.arraycopy(head, 0, body, 0, head.length);
        System.arraycopy(docx, 0, body, head.length, docx.length);
        System.arraycopy(tail, 0, body, head.length + docx.length, tail.length);
        HttpResponse<byte[]> r = send(post("/anonymize", "multipart/form-data; boundary=" + boundary, body, "Bearer k3y"));
        assertEquals(200, r.statusCode());
        assertEquals(ApiHandler.DOCX_MEDIA_TYPE, r.headers().firstValue("content-type").orElse(""));
        assertTrue(r.headers().firstValue("content-disposition").orElse("").matches("attachment; filename=\"[0-9a-f]{12}_redacted.docx\""));
        assertTrue(r.headers().firstValue("x-postcheck-findings").isPresent());
        assertTrue(!TestDocx.part(r.body(), "word/document.xml").contains("Παπαδόπουλος"));
    }

    @Test
    void summaryModeReturnsJson() throws Exception {
        HttpResponse<byte[]> r = send(post("/anonymize?summary=1", ApiHandler.DOCX_MEDIA_TYPE,
                TestDocx.paragraphs("Απλό κείμενο.").bytes(), "Bearer k3y"));
        assertEquals(200, r.statusCode());
        String json = body(r);
        assertTrue(json.startsWith("{\"document_id\":\""), json);
        assertTrue(json.contains("\"docx_base64\":\""));
    }
}
