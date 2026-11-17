package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;
import org.slf4j.LoggerFactory;

/**
 * Every line the code under test logs while this is open, formatted as the service writes it. INFO and
 * up, so the request lifecycle lines are included. The root level is restored on close.
 */
public final class LogCapture implements AutoCloseable {

    private final Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    private final Level originalLevel = root.getLevel();
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    public LogCapture() {
        root.setLevel(Level.INFO);
        appender.start();
        root.addAppender(appender);
    }

    public List<String> lines() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Override
    public void close() {
        root.detachAppender(appender);
        root.setLevel(originalLevel);
    }

    /** The one line that contains every fragment; fails when there is not exactly one. */
    public static String one(List<String> lines, String... fragments) {
        List<String> hits = lines.stream().filter(l -> Arrays.stream(fragments).allMatch(l::contains)).toList();
        assertEquals(1, hits.size(), () -> "lines with " + Arrays.toString(fragments) + ": " + hits);
        return hits.get(0);
    }

    /** How many lines contain {@code fragment}. */
    public static long count(List<String> lines, String fragment) {
        return lines.stream().filter(l -> l.contains(fragment)).count();
    }

    /** Waits until {@code condition} holds, for up to {@code millis}. */
    public static void await(BooleanSupplier condition, long millis) throws InterruptedException {
        long until = System.currentTimeMillis() + millis;
        while (!condition.getAsBoolean()) {
            if (System.currentTimeMillis() > until) {
                throw new AssertionError("condition not reached within " + millis + " ms");
            }
            Thread.sleep(20);
        }
    }
}
