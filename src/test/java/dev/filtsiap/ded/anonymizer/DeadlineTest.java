package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DeadlineTest {

    @Test
    void theBudgetRunsOnTheInjectedMonotonicClock() {
        FakeClock clock = new FakeClock();
        Deadline deadline = Deadline.after(10, clock);
        assertEquals(10.0, deadline.remaining());
        clock.advance(9.5);
        assertEquals(0.5, deadline.remaining(), 1e-9);
        deadline.check("parse"); // still inside
        clock.advance(0.5);
        assertTrue(deadline.expired());
        DocumentTimeoutError e = assertThrows(DocumentTimeoutError.class, () -> deadline.check("scan"));
        assertEquals("scan", e.stage());
        assertEquals("the document deadline expired during scan", e.getMessage());
        assertEquals("DOCUMENT_TIMEOUT", e.code());
        clock.advance(100);
        assertEquals(0.0, deadline.remaining()); // never negative
    }

    @Test
    void anAttemptGetsTheSmallerOfItsCapAndWhatIsLeftAndNoneBelowTheFloor() {
        FakeClock clock = new FakeClock();
        Deadline deadline = Deadline.after(30, clock);
        assertEquals(30.0, deadline.budget(60, "llm pass 1"));
        assertEquals(20.0, deadline.budget(20, "llm pass 1"));
        clock.advance(28.5);
        assertEquals(1.5, deadline.budget(60, "llm pass 1"), 1e-9);
        clock.advance(0.5); // exactly the floor: a call that cannot finish is not started
        assertEquals("llm pass 2", assertThrows(DocumentTimeoutError.class,
                () -> deadline.budget(60, "llm pass 2")).stage());
    }

    @Test
    void cancellationIsDoneWithoutBeingExpired() {
        Deadline deadline = Deadline.after(300, new FakeClock());
        assertFalse(deadline.done());
        deadline.cancel();
        assertTrue(deadline.cancelled() && deadline.done());
        assertFalse(deadline.expired());
    }

    @Test
    void correlationIdsAreGeneratedNeverBorrowed() {
        RunContext a = RunContext.start(300);
        RunContext b = RunContext.start(300);
        assertTrue(a.requestId().matches("[0-9a-f]{16}"), a.requestId());
        assertTrue(a.documentId().matches("[0-9a-f]{12}"), a.documentId());
        assertNotEquals(a.requestId(), b.requestId());
        assertNotEquals(a.documentId(), b.documentId());
        assertEquals("request_id=" + a.requestId() + " document_id=" + a.documentId(), a.tag());
        assertEquals(a.tag() + " chunk=3 pass=2 attempt=retry", a.chunkTag(2, 2, "retry"));
        assertEquals("fixed", RunContext.start(300, "fixed", System::nanoTime).documentId());
    }
}
