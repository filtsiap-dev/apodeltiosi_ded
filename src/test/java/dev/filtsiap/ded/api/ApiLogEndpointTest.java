package dev.filtsiap.ded.api;

import static dev.filtsiap.ded.api.ApiHandlerTest.CFG;
import static dev.filtsiap.ded.api.ApiHandlerTest.HTTP;
import static dev.filtsiap.ded.api.ApiHandlerTest.SECRET;
import static dev.filtsiap.ded.api.ApiHandlerTest.serve;
import static dev.filtsiap.ded.api.ApiHandlerTest.text;
import static dev.filtsiap.ded.api.ApiTextEndpointTest.real;
import static dev.filtsiap.ded.api.ApiTextEndpointTest.utf8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.PiiType;

class ApiLogEndpointTest {
    static final String JSON = "application/json; charset=utf-8";

    static HttpResponse<byte[]> send(ApiHandler handler, byte[] body, String contentType, boolean auth)
            throws Exception {
        ApiServer server = serve(handler, 2);
        try {
            return post(server, body, contentType, auth);
        } finally {
            server.stop(0);
        }
    }

    static HttpResponse<byte[]> post(ApiServer server, byte[] body, String contentType, boolean auth)
            throws Exception {
        HttpRequest.Builder b = HttpRequest
                .newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/anonymize-log"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).header("Content-Type", contentType);
        if (auth) {
            b.header("Authorization", "Bearer k3y");
        }
        return HTTP.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    static HttpResponse<byte[]> send(String json) throws Exception {
        return send(real(CFG), utf8(json), JSON, true);
    }

    static String header(HttpResponse<byte[]> r, String name) {
        return r.headers().firstValue(name).orElse("");
    }

    static RuntimeConfig withLimits(String uploadBytes, String textChars) {
        return Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_API_KEY", "k3y", "ANON_MAX_UPLOAD_BYTES", uploadBytes,
                "ANON_MAX_TEXT_CHARS", textChars));
    }

    /** A log line of roughly {@code kb} kilobytes: the query, then retrieved text the endpoint must not touch. */
    static String bigLine(String query, int kb) {
        String chunk = "{\"id\":1,\"similarity\":0.8123456789012345,\"textScore\":null,"
                + "\"content\":\"Το επίδομα \\u03b1 δίνεται\\nστους δικαιούχους. ΑΦΜ 090000045\"},";
        StringBuilder sb = new StringBuilder("{\"user_query\":\"").append(query)
                .append("\",\"topk_retrieved_payload\":[");
        while (sb.length() < kb * 1024) {
            sb.append(chunk);
        }
        return sb.append("{}],\"status\":\"success\"}").toString();
    }

    @Test
    void masksTheQueryReturnsTheRestUnchangedAndReportsStatusAndCounts() throws Exception {
        String in = "{\"session_id\":\"s\",\"user_query\":\"ΑΦΜ 090000045\",\"n\":0.50,"
                + "\"final_answer\":\"ΑΦΜ 090000045\"}";
        HttpResponse<byte[]> r = send(in);
        assertEquals(200, r.statusCode());
        assertEquals("{\"session_id\":\"s\",\"user_query\":\"ΑΦΜ .........\",\"n\":0.50,"
                + "\"final_answer\":\"ΑΦΜ 090000045\"}", text(r));
        assertEquals(JSON, header(r, "Content-Type"));
        assertEquals("anonymized", header(r, "x-anonymization-status"));
        assertEquals("AFM=1", header(r, "x-redaction-counts"));
        assertFalse(header(r, "x-document-id").isEmpty());
        assertFalse(header(r, "x-processing-time-ms").isEmpty());
        assertEquals("", header(r, "x-review-reasons"));
    }

    @Test
    void aNumberOfTheWrongLengthAfterACueIsMasked() throws Exception {
        String in = "{\"user_query\":\"με αφμ 1212121\",\"final_answer\":\"αφμ 1212121\"}";
        HttpResponse<byte[]> r = send(in);
        assertEquals("{\"user_query\":\"με αφμ .......\",\"final_answer\":\"αφμ 1212121\"}", text(r));
        assertEquals("anonymized", header(r, "x-anonymization-status"));
        assertEquals("AFM=1", header(r, "x-redaction-counts"));
    }

    @Test
    void aLogWithNoPiiComesBackByteIdentical() throws Exception {
        String in = "{\"session_id\" : \"s\",\n \"user_query\":\"\\u03b1\\u0032\\u0031\", \"n\":1e-7}\n";
        HttpResponse<byte[]> r = send(in);
        assertEquals(in, text(r));
        assertEquals("none", header(r, "x-redaction-counts"));
    }

    @Test
    void aLeadingBomIsAcceptedAndComesBackInTheReply() throws Exception {
        String clean = "\uFEFF{\"user_query\":\"\\u03b1\\u0032\\u0031\", \"n\":1e-7}";
        HttpResponse<byte[]> r = send(clean);
        assertEquals(200, r.statusCode());
        assertEquals(clean, text(r));
        assertEquals("\uFEFF{\"user_query\":\"ΑΦΜ .........\"}",
                text(send("\uFEFF{\"user_query\":\"ΑΦΜ 090000045\"}")));
    }

    @Test
    void aNonStringQueryNeedsReviewAndIsReturnedUnchanged() throws Exception {
        String in = "{\"user_query\":5}";
        HttpResponse<byte[]> r = send(in);
        assertEquals(in, text(r));
        assertEquals("needs-review", header(r, "x-anonymization-status"));
        assertEquals("user_query_not_a_string", header(r, "x-review-reasons"));
    }

    @Test
    void theHeadersCarryTheReviewReasonsOfTheQueryResult() throws Exception {
        ApiHandler handler = new ApiHandler(CFG, System::nanoTime, ApiHandlerTest::pipeline,
                (t, ctx) -> new ChatPipeline.TextResult("...", ChatPipeline.Status.NEEDS_REVIEW,
                        Map.of(PiiType.OTHER, 1), List.of("residual:DIGIT_RUN")));
        HttpResponse<byte[]> r = send(handler, utf8("{\"user_query\":\"abc\"}"), JSON, true);
        assertEquals("{\"user_query\":\"...\"}", text(r));
        assertEquals("needs-review", header(r, "x-anonymization-status"));
        assertEquals("residual:DIGIT_RUN", header(r, "x-review-reasons"));
        assertEquals("OTHER=1", header(r, "x-redaction-counts"));
    }

    @Test
    void aMissingCharsetMeansUtf8() throws Exception {
        assertEquals(200, send(real(CFG), utf8("{}"), "application/json", true).statusCode());
    }

    @Test
    void requiresTheBearerToken() throws Exception {
        assertEquals(401, send(real(CFG), utf8("{}"), JSON, false).statusCode());
    }

    @Test
    void refusesOtherMediaTypesAndCharsets() throws Exception {
        assertEquals(415, send(real(CFG), utf8("{}"), "text/plain", true).statusCode());
        assertEquals(415, send(real(CFG), utf8("{}"), "multipart/form-data", true).statusCode());
        assertEquals(415, send(real(CFG), utf8("{}"), "application/json; charset=iso-8859-7", true).statusCode());
    }

    @Test
    void refusesInvalidUtf8() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), new byte[] {'{', (byte) 0xC3, (byte) 0x28, '}'}, JSON, true);
        assertEquals(400, r.statusCode());
        assertTrue(text(r).contains("INVALID_UTF8"));
    }

    @Test
    void refusesBodiesThatAreNotOneJsonObject() throws Exception {
        for (String body : List.of("not json", "{\"user_query\":\"a\"", "{} {}", "{}x", "")) {
            HttpResponse<byte[]> r = send(body);
            assertEquals(400, r.statusCode(), body);
            assertTrue(text(r).contains("INVALID_JSON"), body);
        }
        for (String body : List.of("[]", "\"x\"", "7")) {
            HttpResponse<byte[]> r = send(body);
            assertEquals(400, r.statusCode(), body);
            assertTrue(text(r).contains("NOT_A_JSON_OBJECT"), body);
        }
    }

    @Test
    void theBodyIsBoundedByTheUploadLimitNotTheTextLimit() throws Exception {
        RuntimeConfig cfg = withLimits("5000", "100");
        String fits = bigLine("ΑΦΜ 090000045", 3);
        assertTrue(fits.length() > 2000 && fits.length() < 5000);
        assertEquals(200, send(real(cfg), utf8(fits), JSON, true).statusCode());
        HttpResponse<byte[]> r = send(real(cfg), utf8(bigLine("ΑΦΜ 090000045", 6)), JSON, true);
        assertEquals(413, r.statusCode());
        assertTrue(text(r).contains("UPLOAD_TOO_LARGE"));
    }

    @Test
    void aQueryOverTheTextLimitIs413() throws Exception {
        RuntimeConfig cfg = withLimits("5000", "10");
        assertEquals(200, send(real(cfg), utf8("{\"user_query\":\"αβγδεζηθικ\"}"), JSON, true).statusCode());
        HttpResponse<byte[]> r = send(real(cfg), utf8("{\"user_query\":\"αβγδεζηθικλ\"}"), JSON, true);
        assertEquals(413, r.statusCode());
        assertTrue(text(r).contains("TEXT_TOO_LARGE"));
    }

    @Test
    void theLimitCountsTheDecodedQueryNotItsEscapedSpelling() throws Exception {
        RuntimeConfig cfg = withLimits("5000", "10");
        assertEquals(200, send(real(cfg), utf8("{\"user_query\":\"\\u03b1\\u03b2\\u03b3\\u03b4\\u03b5\"}"), JSON, true)
                .statusCode());
    }

    @Test
    void anUnconfiguredChatPipelineIs503() throws Exception {
        ApiHandler docxOnly = new ApiHandler(CFG, System::nanoTime, ApiHandlerTest::pipeline);
        assertEquals(503, send(docxOnly, utf8("{\"user_query\":\"x\"}"), JSON, true).statusCode());
    }

    @Test
    void aFiftyKilobyteLogIsFastAndEverythingButTheQueryIsUntouched() throws Exception {
        String in = bigLine("με λένε Γιώργο, ΑΦΜ 090000045", 50);
        HttpResponse<byte[]> r = send(in);
        assertEquals(200, r.statusCode());
        String out = text(r);
        assertEquals(in.length(), out.length());
        assertEquals(in.substring(in.indexOf("\",\"topk_retrieved_payload")),
                out.substring(out.indexOf("\",\"topk_retrieved_payload")));
        assertTrue(Long.parseLong(header(r, "x-processing-time-ms")) < 5000);
    }

    @Test
    void logLinesNeverContainTheQueryOrAnyBodyText() throws Exception {
        Logger api = (Logger) LoggerFactory.getLogger("anonymizer.api");
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        api.addAppender(logs);
        // The server profile logs anonymizer.api at INFO; the test runtime uses the CLI profile.
        Level level = api.getLevel();
        api.setLevel(Level.INFO);
        List<String> lines = List.of();
        ApiServer server = serve(real(CFG), 2);
        try {
            HttpResponse<byte[]> first = post(server,
                    utf8("{\"user_query\":\"με λένε " + SECRET + "\",\"final_answer\":\"BODYTEXT-XYZ\"}"), JSON, true);
            assertEquals(200, first.statusCode(), text(first));
            post(server, utf8("{\"user_query\":\"" + SECRET + "\",\"final_answer\":\"BODYTEXT-XYZ\""), JSON, true);
            post(server, utf8("{\"user_query\":\"" + SECRET + "\"}"), "text/plain", true);
            // The success line is written after its response has gone out, so it can trail the client.
            for (int i = 0; i < 100 && finishedLines(lines).size() < 3; i++) {
                Thread.sleep(50);
                lines = logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
            }
        } finally {
            server.stop(0);
            api.setLevel(level);
            api.detachAppender(logs);
        }
        List<String> finished = finishedLines(lines);
        assertEquals(3, finished.size(), String.join(" | ", lines));
        assertTrue(finished.stream().anyMatch(l -> l.contains("outcome=success") && l.contains("status=200")
                && l.contains("bytes=") && l.contains("chars=")));
        assertTrue(finished.stream().anyMatch(l -> l.contains("status=400") && l.contains("error_code=INVALID_JSON")));
        assertTrue(finished.stream().allMatch(l -> l.contains(" bytes=") && l.contains(" chars=")));
        assertTrue(finished.stream().anyMatch(l -> l.contains("status=415")));
        for (String line : lines) {
            assertFalse(line.contains("Παπαδόπουλος") || line.contains("BODYTEXT") || line.contains("user_query"),
                    line);
        }
    }

    private static List<String> finishedLines(List<String> lines) {
        return lines.stream().filter(l -> l.startsWith("log_finished")).toList();
    }
}
