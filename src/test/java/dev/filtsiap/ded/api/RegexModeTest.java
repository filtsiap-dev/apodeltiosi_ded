package dev.filtsiap.ded.api;

import static dev.filtsiap.ded.api.ApiHandlerTest.HTTP;
import static dev.filtsiap.ded.api.ApiHandlerTest.serve;
import static dev.filtsiap.ded.api.ApiHandlerTest.text;
import static dev.filtsiap.ded.api.ApiTextEndpointTest.utf8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.TestDocx;
import dev.filtsiap.ded.anonymizer.llm.RegexModeLlmClient;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/** ANON_PROVIDER=regex: no model keys, the chat endpoints work, the .docx endpoint refuses. */
class RegexModeTest {

    static final RuntimeConfig REGEX = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "regex", "ANON_API_KEY", "k3y"));

    static ApiHandler handler() {
        return new ApiHandler(REGEX, System::nanoTime, ApiHandlerTest.UNREACHABLE,
                (text, ctx) -> ApiTextEndpointTest.CHAT.anonymize(text, ctx.deadline()));
    }

    @Test
    void healthzReportsTheRegexProviderAndNoModel() throws Exception {
        ApiServer server = serve(handler(), 2);
        try {
            HttpResponse<byte[]> r = HTTP.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port()
                    + "/healthz")).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, r.statusCode());
            assertEquals("{\"status\":\"ok\",\"provider\":\"regex\",\"model\":null}", text(r));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void theDocxEndpointIsRefusedWith503AndLogsTheError() throws Exception {
        ch.qos.logback.classic.Logger api = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger("anonymizer.api");
        Level original = api.getLevel();
        api.setLevel(Level.INFO);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        api.addAppender(logs);
        ApiServer server = serve(handler(), 2);
        HttpResponse<byte[]> r;
        try {
            r = HTTP.send(ApiHandlerTest.post(server, TestDocx.paragraphs("plain text").bytes()),
                    HttpResponse.BodyHandlers.ofByteArray());
        } finally {
            server.stop(0);
            api.detachAppender(logs);
            api.setLevel(original);
        }
        assertEquals(503, r.statusCode());
        assertTrue(text(r).contains("\"code\":\"AI_DISABLED\""), text(r));
        assertTrue(logs.list.stream().anyMatch(e -> e.getLevel() == Level.ERROR
                && e.getFormattedMessage().startsWith(RegexModeLlmClient.ERROR)));
        assertEquals("Error: AI model endpoint called while running in regex mode", RegexModeLlmClient.ERROR);
    }

    @Test
    void theTextEndpointStillMasks() throws Exception {
        HttpResponse<byte[]> r = ApiTextEndpointTest.send(handler(), utf8("ΑΦΜ 090000045"), "text/plain", true);
        assertEquals(200, r.statusCode());
        assertEquals("ΑΦΜ .........", text(r));
    }

    @Test
    void theLogEndpointStillMasks() throws Exception {
        HttpResponse<byte[]> r = ApiLogEndpointTest.send(handler(), utf8("{\"user_query\":\"ΑΦΜ 090000045\"}"),
                ApiLogEndpointTest.JSON, true);
        assertEquals(200, r.statusCode());
        assertEquals("{\"user_query\":\"ΑΦΜ .........\"}", text(r));
    }
}
