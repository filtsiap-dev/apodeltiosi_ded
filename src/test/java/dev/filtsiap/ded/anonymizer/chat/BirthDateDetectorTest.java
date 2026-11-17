package dev.filtsiap.ded.anonymizer.chat;

import static dev.filtsiap.ded.anonymizer.chat.ChatAsserts.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.RunContext;

class BirthDateDetectorTest {

    private static String masked(String text) {
        return Masker.mask(text, BirthDateDetector.detect(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "γεννηθηκα 3-5-85|3-5-85",
            "Ημερομηνία γέννησης: 27 Οκτωβρίου 1984|27 Οκτωβρίου 1984",
            "γεννήθηκε το 1952|1952",
            "DOB 27.10.1984|27.10.1984",
            "born on October 27, 1984|October 27, 1984",
            "Γεννήθηκα στις 03/05/1985 στο Ηράκλειο.|03/05/1985",
            "ημ. γεν. 27 Οκτ. 1984|27 Οκτ. 1984",
            "Ημ/νία γέννησης 27-10-84|27-10-84",
            "ημερ. γεν.: 1/2/1990|1/2/1990",
            "date of birth: 27 Oct 1984|27 Oct 1984",
            "D.O.B. 5/6/1977|5/6/1977",
            "γεννημένη στις 5 Μαΐου 1977|5 Μαΐου 1977",
            "γεννηθείς την 12/03/1960|12/03/1960",
            "γεννηθήκαμε το 1990|1990",
            "έτος γέννησης 1984|1984",
            "born in 1984|1984",
            "ΓΕΝΝΗΘΗΚΑ ΣΤΙΣ 1984-10-27|1984-10-27"})
    void masksTheDateAfterABirthCue(String text, String date) {
        assertEquals(expect(text, date), masked(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "πλήρωσα στις 27/10/2024",
            "η προθεσμία λήγει 31/12/2026",
            "το 1984 ήταν καλή χρονιά",
            "Γεννήθηκα στην Αθήνα. Στις 27/10/2024 πλήρωσα τον λογαριασμό",
            "γεννήθηκα στην Αθήνα αλλά πλήρωσα αργότερα στις 27/10/2024",
            "γεννήθηκα στην Αθήνα και το 1984 μετακόμισα",
            "γεννήθηκα; 27/10/2024",
            "γεννήθηκα!27/10/2024"})
    void keepsADateWithoutABirthCue(String text) {
        assertEquals(text, masked(text));
    }

    @Test
    void stopsAtALineBreak() {
        String t = "γεννήθηκα στην Αθήνα\n27/10/2024 πλήρωσα";
        assertEquals(t, masked(t));
    }

    @Test
    void masksOnlyTheFirstDateAfterTheCue() {
        String t = "γεννήθηκα το 1984, πλήρωσα 27/10/2024";
        assertEquals(expect(t, "1984"), masked(t));
    }

    @Test
    void reportsDobSpans() {
        List<ChatSpan> spans = BirthDateDetector.detect("γεννήθηκα 3-5-85");
        assertEquals(List.of(new ChatSpan(10, 16, PiiType.DOB, "chat_dob_cue")), spans);
    }

    @Test
    void thePipelineMasksTheBirthDateWithTheNameAndIdAndKeepsTheAddress() {
        ChatPipeline pipeline = new ChatPipeline(Config.loadFileConfig(Path.of("config")).rules(),
                ChatListsRealConfigTest.LISTS, NerDetector.NONE, true);
        String t = "Ονομάζομαι Μιχάλης Κόκκινος, γεννήθηκα στις 27/10/1984, με ΑΦΜ 123123128 και μένω στην "
                + "Αμοργού 4, Κυψέλη.";
        ChatPipeline.TextResult r = pipeline.anonymize(t, RunContext.start(60).deadline());
        assertEquals(expect(t, "Μιχάλης", "Κόκκινος", "27/10/1984", "123123128"), r.masked());
        assertEquals(1, r.counts().get(PiiType.DOB));
    }

    /** Characters of the largest adversarial input; the smaller one is half of it. */
    private static final int ADVERSARIAL_CHARS = 400_000;

    /**
     * Doubling the input must not much more than double the time: a quadratic detector would take four
     * times as long. Checks scaling, not the speed of the machine, so the only fixed limit is a ceiling.
     */
    @Test
    void longCueRunsAreLinear() {
        assertTimeoutPreemptively(Duration.ofSeconds(120), () -> {
            for (String unit : new String[] {"γεννήθηκα ", "dob ", "ημ. γεν. ", "γεννήθηκα 1/", "born on october ",
                    "γεννήθηκα στις στις στις ", "Γεννήθηκα. Στις 27/10/2024 ", "1/1/1984 "}) {
                BirthDateDetector.detect(unit.repeat(500)); // warm-up on a small input
                String half = unit.repeat(ADVERSARIAL_CHARS / 2 / unit.length());
                String full = unit.repeat(ADVERSARIAL_CHARS / unit.length());
                long halfNanos = Long.MAX_VALUE;
                long fullNanos = Long.MAX_VALUE;
                for (int run = 0; run < 3; run++) {
                    halfNanos = Math.min(halfNanos, nanosToDetect(half));
                    fullNanos = Math.min(fullNanos, nanosToDetect(full));
                    if (fullNanos < 3 * halfNanos + 200_000_000L) {
                        break;
                    }
                }
                assertTrue(fullNanos < 3 * halfNanos + 200_000_000L,
                        "'" + unit + "': " + fullNanos / 1_000_000 + " ms for " + full.length() + " chars vs "
                                + halfNanos / 1_000_000 + " ms for " + half.length());
            }
        });
    }

    private static long nanosToDetect(String text) {
        long start = System.nanoTime();
        BirthDateDetector.detect(text);
        return System.nanoTime() - start;
    }
}
