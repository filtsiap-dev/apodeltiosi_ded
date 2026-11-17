package dev.filtsiap.ded.anonymizer;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/** A monotonic nanosecond clock that moves only when a test moves it. */
public final class FakeClock implements LongSupplier {

    private final AtomicLong nanos = new AtomicLong(1_000_000_000L);

    @Override
    public long getAsLong() {
        return nanos.get();
    }

    public void advance(double seconds) {
        nanos.addAndGet((long) (seconds * 1e9));
    }

    /** A document context whose budget of {@code seconds} runs on this clock. */
    public RunContext context(double seconds) {
        return RunContext.start(seconds, null, this);
    }
}
