package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.text.Normalizer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.Deadline;
import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.RunContext;

class ChatPipelineTest {
    static final DetectorRules RULES = Config.loadFileConfig(Path.of("config")).rules();
    static final ChatPipeline PIPELINE = new ChatPipeline(RULES, ChatFixtures.LISTS, NerDetector.NONE, true);
    static final ChatPipeline REAL_LISTS_PIPELINE =
            new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, NerDetector.NONE, true);

    private static Deadline deadline() {
        return RunContext.start(60).deadline();
    }

    @Test
    void masksIdsAndNamesTogether() {
        String t = "Καλησπέρα, με λένε γιώργο παπαδόπουλο. ΑΦΜ 090000045. Ο γιώργος μένει στην Πατησίων 25, "
                + "τηλ 6912345678";
        ChatPipeline.TextResult r = PIPELINE.anonymize(t, deadline());
        // The fixture lists lack "Πατησίων", so the name rule masks it as an unknown capitalised word.
        assertEquals(expect(t, "γιώργος", "γιώργο", "παπαδόπουλο", "090000045", "Πατησίων", "6912345678"),
                r.masked());
        assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
        assertEquals(1, r.counts().get(PiiType.AFM));
        assertEquals(1, r.counts().get(PiiType.PHONE));
        assertTrue(r.counts().get(PiiType.PERSON) >= 3);
    }

    // Owner decision 2026-10-14: no location information is masked (area, street address, postal code). The
    // name rule may still mask a place that looks like a name ("Ζωγράφου", "Αθήνα"); the owner accepts that.
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
            "Μένω στην Πλάκα, πάνω από ένα καφέ.",
            "Ζω στη Νίκαια με τους γονείς μου.",
            "Είμαι από το Γαλάτσι αλλά δουλεύω στο Μαρούσι.",
            "Εργάζομαι στην Καλλιθέα και κατοικώ στο Περιστέρι.",
            "μένω στο μαρούσι",
            "μένω στην πατησίων 25",
            "Η διεύθυνσή μου είναι Αμοργού 4, Νέα Σμύρνη.",
            "Η νέα μου διεύθυνση: Αγίου Δημητρίου 8, Τ.Κ. 17341, Άγιος Δημήτριος.",
            "Το σπίτι μου είναι στο 3ο χιλιόμετρο Λεωφόρου Μαραθώνος, Πικέρμι.",
            "οδός ερμού 12, 10563",
            "λεωφ. κηφισιας 100",
            "ΣΤΕΙΛΤΕ ΤΟ ΣΤΗΝ ΠΑΤΗΣΙΩΝ 25 ΠΑΡΑΚΑΛΩ",
            "Συγγρού 100, Μαρούσι 15125",
            "η ΔΟΥ Κηφισιάς με πήρε τηλέφωνο",
            "η δου μου είναι η Α' Αθηνών",
            "Δ.Ο.Υ. Χαλανδρίου, ευχαριστώ",
            "Χρήστης: Μένω στην Πλάκα\r\nBot: Ευχαριστώ"})
    void locationInformationIsKept(String text) {
        assertEquals(text, REAL_LISTS_PIPELINE.anonymize(text, deadline()).masked());
    }

    @Test
    void emojiDoesNotShiftMasks() {
        String t = "🙏 ΑΦΜ 090000045";
        assertEquals(expect(t, "090000045"), PIPELINE.anonymize(t, deadline()).masked());
    }

    @Test
    void nfdInputIsNormalisedBeforeMatching() {
        String nfc = "μίλησα με Αναστασία χθες";
        String nfd = Normalizer.normalize(nfc, Normalizer.Form.NFD);
        assertEquals(expect(nfc, "Αναστασία"), PIPELINE.anonymize(nfd, deadline()).masked());
    }

    @Test
    void aResidualDigitRunIsMaskedAndAsksForReview() {
        String t = "ο αριθμός 1234567890 χθες";
        ChatPipeline.TextResult r = new ChatPipeline(RULES, ChatFixtures.LISTS, NerDetector.NONE, true)
                .anonymize(t, deadline());
        assertEquals(expect(t, "1234567890"), r.masked());
        assertEquals(ChatPipeline.Status.NEEDS_REVIEW, r.status());
        assertEquals(List.of("residual:DIGIT_RUN"), r.reviewReasons());
    }

    @Test
    void nerSpansOnlyAdd() {
        String t = "δεν έχω καμία ελπίδα";
        int at = t.indexOf("ελπίδα");
        NerDetector stub = text -> List.of(new ChatSpan(at, at + 6, PiiType.PERSON, "stub"));
        assertEquals(expect(t, "ελπίδα"),
                new ChatPipeline(RULES, ChatFixtures.LISTS, stub, true).anonymize(t, deadline()).masked());
        assertEquals(expect(t, "ελπίδα"),
                new ChatPipeline(RULES, ChatFixtures.LISTS, stub, false).anonymize(t, deadline()).masked());
    }

    @Test
    void anUnavailableNerFallsBackToTheRulesAndAsksForReview() {
        String t = "ΑΦΜ 090000045";
        NerDetector broken = text -> {
            throw new NerUnavailableException("model down", null);
        };
        ChatPipeline.TextResult r = new ChatPipeline(RULES, ChatFixtures.LISTS, broken, true).anonymize(t, deadline());
        assertEquals(expect(t, "090000045"), r.masked());
        assertEquals(ChatPipeline.Status.NEEDS_REVIEW, r.status());
        assertEquals(List.of("ner_unavailable"), r.reviewReasons());
    }

    @Test
    void longInputStaysFast() {
        String digits = "6 9 1 ".repeat(35_000);
        String word = "α".repeat(50_000);
        String mixed = "με λένε Ξανθίππη, ΑΦΜ 090000045. ".repeat(4_000);
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            PIPELINE.anonymize(digits, deadline());
            PIPELINE.anonymize(word, deadline());
            PIPELINE.anonymize(mixed, deadline());
        });
    }

    @Test
    void aVeryLongCapitalisedRunAfterAResidenceCueCompletes() throws Throwable {
        assertLinearOnSmallStack("ΜΕΝΩ ΣΤΗΝ ", "ΑΘΗΝΑ ", 70_000);   // about 400k characters
    }

    @Test
    void aVeryLongCapitalisedRunAfterABankCueCompletes() throws Throwable {
        assertLinearOnSmallStack("τράπεζα ", "Πειραιώς ", 45_000);
    }

    @Test
    void aVeryLongCapitalisedRunAfterABeneficiaryCueCompletes() throws Throwable {
        assertLinearOnSmallStack("δικαιούχο τον ", "Πειραιώς ", 45_000);
    }

    /**
     * The text of {@code reps} units after {@code prefix} completes on a small stack, and doubling the
     * input takes under three times as long (plus 200 ms): a quadratic run takes four times. Checks scaling,
     * not the speed of the machine, so the only fixed limit is a generous ceiling per run.
     */
    private static void assertLinearOnSmallStack(String prefix, String unit, int reps) throws Throwable {
        nanosOnSmallStack(prefix + unit.repeat(500)); // warm-up on a small input
        String half = prefix + unit.repeat(reps / 2);
        String full = prefix + unit.repeat(reps);
        long halfNanos = Long.MAX_VALUE;
        long fullNanos = Long.MAX_VALUE;
        for (int run = 0; run < 3; run++) {
            halfNanos = Math.min(halfNanos, nanosOnSmallStack(half));
            fullNanos = Math.min(fullNanos, nanosOnSmallStack(full));
            if (fullNanos < 3 * halfNanos + 200_000_000L) {
                break;
            }
        }
        assertTrue(fullNanos < 3 * halfNanos + 200_000_000L, fullNanos / 1_000_000 + " ms for " + full.length()
                + " chars vs " + halfNanos / 1_000_000 + " ms for " + half.length());
    }

    /**
     * A regex group repeated once per word recurses once per word and overflows the stack; whether
     * it does at a given input size depends on JIT warm-up. A 512 KiB thread stack makes it
     * deterministic: a bounded repetition needs a fraction of that.
     */
    private static long nanosOnSmallStack(String text) throws Throwable {
        AtomicReference<Object> result = new AtomicReference<>();
        Thread worker = new Thread(null, () -> {
            try {
                result.set(PIPELINE.anonymize(text, deadline()));
            } catch (Throwable e) {
                result.set(e);
            }
        }, "small-stack", 512 * 1024);
        long start = System.nanoTime();
        worker.start();
        worker.join(Duration.ofSeconds(120));
        long nanos = System.nanoTime() - start;
        assertTrue(!worker.isAlive(), "did not complete within 120 s");
        if (result.get() instanceof Throwable e) {
            throw e;
        }
        assertEquals(text.length(), ((ChatPipeline.TextResult) result.get()).masked().length());
        return nanos;
    }

    @Test
    void emptyTextIsAnonymized() {
        ChatPipeline.TextResult r = PIPELINE.anonymize("", deadline());
        assertEquals("", r.masked());
        assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"πληρωμη στις 27-10-2024", "αιτηση 21-03-2024 και 20-05-2024",
            "ημερομηνια 2024-10-27"})
    void aHyphenatedDateIsKeptAndDoesNotAskForReview(String text) {
        ChatPipeline real = new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, NerDetector.NONE, true);
        ChatPipeline.TextResult r = real.anonymize(text, deadline());
        assertEquals(text, r.masked());
        assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
        assertEquals(List.of(), r.reviewReasons());
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "με αφμ 1212121|1212121|AFM",
            "το ΑΦΜ μου είναι 1212121|1212121|AFM",
            "ΑΜΚΑ 123456|123456|AMKA",
            "τηλ 69123456|69123456|PHONE",
            "ΑΔΤ ΑΚ 12345|ΑΚ 12345|ID_CARD",
            "ΑΜΚΑ 1989992121|1989992121|AMKA"})
    void aNumberOfTheWrongLengthAfterACueIsMaskedWithoutAskingForReview(String text, String value, PiiType type) {
        ChatPipeline.TextResult r = REAL_LISTS_PIPELINE.anonymize(text, deadline());
        assertEquals(expect(text, value), r.masked());
        assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
        assertEquals(List.of(), r.reviewReasons());
        assertEquals(1, r.counts().get(type));
    }
}
