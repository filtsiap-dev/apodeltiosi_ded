package dev.filtsiap.ded.anonymizer.llm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.filtsiap.ded.anonymizer.AIDisabledError;
import dev.filtsiap.ded.anonymizer.Config;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class RegexModeLlmClientTest {

    @Test
    void regexModeBuildsAClientThatLogsAndRefusesEveryCall() {
        LlmClient client = LlmClients.build(Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "regex")));
        assertInstanceOf(RegexModeLlmClient.class, client);
        ch.qos.logback.classic.Logger log = (ch.qos.logback.classic.Logger) LoggerFactory
                .getLogger(RegexModeLlmClient.class);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        log.addAppender(logs);
        try {
            assertThrows(AIDisabledError.class,
                    () -> client.complete(new LlmClient.ChatRequest(null, "system", "user", 10, 1.0)));
        } finally {
            log.detachAppender(logs);
        }
        assertEquals(1, logs.list.size());
        assertEquals(Level.ERROR, logs.list.get(0).getLevel());
        assertEquals(RegexModeLlmClient.ERROR, logs.list.get(0).getFormattedMessage());
        client.close();
    }
}
