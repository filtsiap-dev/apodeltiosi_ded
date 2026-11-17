package dev.filtsiap.ded.api;

import static dev.filtsiap.ded.api.ApiHandlerTest.CFG;
import static dev.filtsiap.ded.api.ApiHandlerTest.HTTP;
import static dev.filtsiap.ded.api.ApiHandlerTest.SECRET;
import static dev.filtsiap.ded.api.ApiHandlerTest.serve;
import static dev.filtsiap.ded.api.ApiHandlerTest.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.chat.ChatLists;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.NerDetector;
import dev.filtsiap.ded.anonymizer.chat.PiiType;

class ApiTextEndpointTest {
    static final ChatPipeline CHAT = new ChatPipeline(Config.loadFileConfig(Path.of("config")).rules(),
            ChatLists.of(List.of("Αναστασία"), List.of(), List.of("μίλησα", "με", "χθες"), List.of(), List.of(),
                    List.of("αφμ")),
            NerDetector.NONE, true);

    static HttpRequest postText(ApiServer server, byte[] body, String contentType, boolean auth) {
        HttpRequest.Builder b = HttpRequest
                .newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/anonymize-text"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).header("Content-Type", contentType);
        if (auth) {
            b.header("Authorization", "Bearer k3y");
        }
        return b.build();
    }

    static HttpResponse<byte[]> send(ApiHandler handler, byte[] body, String contentType, boolean auth)
            throws Exception {
        ApiServer server = serve(handler, 2);
        try {
            return HTTP.send(postText(server, body, contentType, auth), HttpResponse.BodyHandlers.ofByteArray());
        } finally {
            server.stop(0);
        }
    }

    static ApiHandler real(RuntimeConfig cfg) {
        return new ApiHandler(cfg, System::nanoTime, ApiHandlerTest::pipeline,
                (text, ctx) -> CHAT.anonymize(text, ctx.deadline()));
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void masksTheTextAndReportsStatusAndCounts() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), utf8("μίλησα με Αναστασία, ΑΦΜ 090000045"),
                "text/plain; charset=utf-8", true);
        assertEquals(200, r.statusCode());
        assertEquals("μίλησα με ........., ΑΦΜ .........", text(r));
        assertEquals("text/plain; charset=utf-8", r.headers().firstValue("Content-Type").orElse(""));
        assertEquals("anonymized", r.headers().firstValue("x-anonymization-status").orElse(""));
        assertEquals("PERSON=1,AFM=1", r.headers().firstValue("x-redaction-counts").orElse(""));
        assertTrue(r.headers().firstValue("x-document-id").isPresent());
        assertTrue(r.headers().firstValue("x-processing-time-ms").isPresent());
        assertFalse(r.headers().firstValue("x-review-reasons").isPresent());
    }

    @Test
    void aNumberOfTheWrongLengthAfterACueIsMasked() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), utf8("ΑΦΜ 1212121"), "text/plain; charset=utf-8", true);
        assertEquals("ΑΦΜ .......", text(r));
        assertEquals("anonymized", r.headers().firstValue("x-anonymization-status").orElse(""));
        assertEquals("AFM=1", r.headers().firstValue("x-redaction-counts").orElse(""));
    }

    @Test
    void aMissingCharsetMeansUtf8() throws Exception {
        assertEquals(200, send(real(CFG), utf8("χθες"), "text/plain", true).statusCode());
    }

    @Test
    void needsReviewCarriesItsReasons() throws Exception {
        ApiHandler handler = new ApiHandler(CFG, System::nanoTime, ApiHandlerTest::pipeline,
                (text, ctx) -> new ChatPipeline.TextResult("...", ChatPipeline.Status.NEEDS_REVIEW,
                        Map.of(PiiType.OTHER, 1), List.of("residual:DIGIT_RUN")));
        HttpResponse<byte[]> r = send(handler, utf8("abc"), "text/plain", true);
        assertEquals("needs-review", r.headers().firstValue("x-anonymization-status").orElse(""));
        assertEquals("residual:DIGIT_RUN", r.headers().firstValue("x-review-reasons").orElse(""));
    }

    @Test
    void crlfAndEmojiSurviveTheRoundTrip() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), utf8("🙏\r\nΑΦΜ 090000045"), "text/plain", true);
        assertEquals("🙏\r\nΑΦΜ .........", text(r));
    }

    @Test
    void anEmptyBodyIsAnEmptyAnswer() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), new byte[0], "text/plain", true);
        assertEquals(200, r.statusCode());
        assertEquals("", text(r));
    }

    @Test
    void requiresTheBearerToken() throws Exception {
        assertEquals(401, send(real(CFG), utf8("χθες"), "text/plain", false).statusCode());
    }

    @Test
    void refusesOtherMediaTypesAndCharsets() throws Exception {
        assertEquals(415, send(real(CFG), utf8("χθες"), "application/json", true).statusCode());
        assertEquals(415, send(real(CFG), "χθες".getBytes(java.nio.charset.Charset.forName("ISO-8859-7")),
                "text/plain; charset=iso-8859-7", true).statusCode());
    }

    @Test
    void refusesInvalidUtf8() throws Exception {
        HttpResponse<byte[]> r = send(real(CFG), new byte[] {(byte) 0xC3, (byte) 0x28}, "text/plain", true);
        assertEquals(400, r.statusCode());
        assertTrue(text(r).contains("INVALID_UTF8"));
    }

    @Test
    void refusesTextOverTheCharacterLimit() throws Exception {
        RuntimeConfig small = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_API_KEY", "k3y", "ANON_MAX_TEXT_CHARS", "10"));
        assertEquals(413, send(real(small), utf8("αβγδεζηθικλ"), "text/plain", true).statusCode());
        assertEquals(200, send(real(small), utf8("αβγδεζηθικ"), "text/plain", true).statusCode());
    }

    @Test
    void anUnconfiguredChatPipelineIs503() throws Exception {
        ApiHandler docxOnly = new ApiHandler(CFG, System::nanoTime, ApiHandlerTest::pipeline);
        assertEquals(503, send(docxOnly, utf8("χθες"), "text/plain", true).statusCode());
    }

    @Test
    void logLinesNeverContainTheText() throws Exception {
        Logger api = (Logger) LoggerFactory.getLogger("anonymizer.api");
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        api.addAppender(logs);
        try {
            send(real(CFG), utf8("με λένε " + SECRET), "text/plain", true);
            send(real(CFG), utf8(SECRET), "application/json", true);
        } finally {
            api.detachAppender(logs);
        }
        assertTrue(logs.list.stream().anyMatch(e -> e.getFormattedMessage().startsWith("text_finished")));
        assertTrue(logs.list.stream().noneMatch(e -> e.getFormattedMessage().contains("Παπαδόπουλος")));
        assertTrue(logs.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(l -> l.startsWith("text_finished")).noneMatch(l -> l.contains("bytes=")));
    }
}
