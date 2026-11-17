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
import org.junit.jupiter.params.provider.ValueSource;

import dev.filtsiap.ded.anonymizer.Config;

class IdDetectorTest {
    static final IdDetector IDS = new IdDetector(Config.loadFileConfig(Path.of("config")).rules());

    private static String masked(String text) {
        return Masker.mask(text, IDS.detect(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Καλησπέρα, το ΑΦΜ μου είναι 090000045.|090000045",
            "Σας στέλνω τον ΑΦΜ χωρίς κενά: 801 234 560|801 234 560",
            "ο αριθμός μου είναι 047112234, μπορείτε;|047112234",
            "ΑΜΚΑ: 15038501233|15038501233",
            "IBAN GR39 0110 1250 0000 0123 4567 890 για την επιστροφή|GR39 0110 1250 0000 0123 4567 890",
            "στείλτε τα χρήματα στο gr6801701230000000123456789|gr6801701230000000123456789",
            "Το κινητό μου είναι 6912345678, πάρτε με μετά τις 5.|6912345678",
            "Τηλέφωνο: +30 697 123 4567 ή αλλιώς|+30 697 123 4567",
            "σταθερό 210 6543210 το πρωί|210 6543210",
            "0030 6944 556677 είναι το νούμερο|0030 6944 556677",
            "Τ η λ: 6 9 1 2 3 4 5 6 7 8|6 9 1 2 3 4 5 6 7 8",
            "Το email μου είναι maria.papadopoulou82@gmail.com|maria.papadopoulou82@gmail.com",
            "γράψτε μου στο giorgos_k [at] yahoo.gr|giorgos_k [at] yahoo.gr",
            "Αριθμός ταυτότητας ΑΚ 123456|ΑΚ 123456",
            "η ταυτότητά μου είναι Χ-654321, παλιού τύπου|Χ-654321",
            "Ταυτότητα AB123456 (με λατινικά)|AB123456",
            "Αρ. διαβατηρίου AN1234567, λήγει τον Μάρτιο|AN1234567",
            "αριθμός διαβατηρίου ΑΕ 1234567|ΑΕ 1234567",
            "διαβατήριο μου AE-1234567|AE-1234567",
            "πινακίδα ΙΚΥ-4521 εδώ|ΙΚΥ-4521",
            "το μηχανάκι ΖΗΒ 318 εδώ|ΖΗΒ 318",
            "Πλήρωσα με την κάρτα 4111 1111 1111 1111 και χρεώθηκα 45,90 €|4111 1111 1111 1111",
            "Αριθμός παροχής 1 23456789-01 2, ευχαριστώ|1 23456789-01 2",
            "αριθμός ΓΕΜΗ 123456701000|123456701000",
            "και ο κωδικος πελατη 7788990011|7788990011"})
    void masksTheIdentifier(String text, String id) {
        assertEquals(expect(text, id), masked(text));
    }

    @Test
    void masksLabelValuePairsWithoutSpaces() {
        String text = "ΑΦΜ:998877666,ΑΜΚΑ:01016003111,ΤΗΛ:6900112233";
        assertEquals(expect(text, "998877666", "01016003111", "6900112233"), masked(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "Πλήρωσα 123,45 € στις 15/06/2026 και δεν φαίνεται.",
            "Το τηλεφωνικό κέντρο 11888 δεν απαντά.",
            "Ο κωδικός σφάλματος είναι E-4021 στην εφαρμογή σας.",
            "Η εφαρμογή σας κολλάει σε Android 14 και iPhone 15.",
            "Ο λογαριασμός είναι 89,99 € για 30 ημέρες, δηλαδή 2,99 € την ημέρα.",
            "Το συμβόλαιο έχει διάρκεια 24 μήνες και λήγει στις 31/12/2027.",
            "Η κάρτα μου τελειώνει σε 1111"})
    void leavesOrdinaryNumbersAlone(String text) {
        assertEquals(text, masked(text));
    }

    @Test
    void cueFollowedByLongWhitespaceIsFast() {
        for (String prefix : new String[] {"ταυτοτητα", "αριθμος γεμη ", "κωδικος πελατη ", "cvv",
                "κωδικος ασφαλειας "}) {
            String text = prefix + " ".repeat(200_000) + "x";
            assertTimeoutPreemptively(Duration.ofSeconds(2), () -> IDS.detect(text));
        }
    }

    @Test
    void masksTheCardBeforeAnExpiryOrCvv() {
        String a = "Πλήρωσα με 4111 1111 1111 1111 12/26 χθες";
        assertEquals(expect(a, "4111 1111 1111 1111"), masked(a));
        String b = "η κάρτα 4111 1111 1111 1111 123";
        assertEquals(expect(b, "4111 1111 1111 1111"), masked(b));
    }

    @Test
    void masksTheAfmBeforeATrailingNumber() {
        String a = "ΑΦΜ 090000045 12 ετών";
        assertEquals(expect(a, "090000045"), masked(a));
        String b = "ο αριθμός 801 234 560 12 φορές";
        assertEquals(expect(b, "801 234 560"), masked(b));
    }

    @Test
    void emailStopsAtTheSentenceEnd() {
        String a = "Το email μου είναι foo@bar.com. Ευχαριστώ πολύ";
        assertEquals(expect(a, "foo@bar.com"), masked(a));
        String b = "γράψτε στο giorgos_k [at] yahoo [dot] gr";
        assertEquals(expect(b, "giorgos_k [at] yahoo [dot] gr"), masked(b));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "κάρτα 1 4111 1111 1111 1111|4111 1111 1111 1111",
            "η κάρτα 13 5555 5555 5555 4444 λήγει|5555 5555 5555 4444",
            "ο αριθμός 1 090000045|090000045",
            "ο αριθμός 1 801 234 560|801 234 560",
            "κωδ 7 15038501233 τέλος|15038501233",
            "κωδ 1 1503 8501 233 τέλος|1503 8501 233"})
    void anIdPrecededByAnotherNumberIsMasked(String text, String id) {
        assertEquals(expect(text, id), masked(text));
    }

    @Test
    void aCvvAfterItsCueIsMaskedWithTheCard() {
        String t = "cvv 123 5555 5555 5555 4444";
        assertEquals(expect(t, "123", "5555 5555 5555 4444"), masked(t));
        String u = "cvv 123 4111 1111 1111 1111";
        assertEquals(expect(u, "123", "4111 1111 1111 1111"), masked(u));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "CVC: 4567|4567",
            "το CVV2 - 987 τώρα|987",
            "cid:123|123",
            "ο κωδικός ασφαλείας είναι 321|321",
            "ο κωδικος ασφαλειας: 3210|3210",
            "τον κωδικου ασφαλειας 456 δώστε|456"})
    void aCvvAfterItsCueIsMasked(String text, String cvv) {
        assertEquals(expect(text, cvv), masked(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "ο κωδικός πρόσβασης είναι 1234",
            "cvv 12345",
            "cvv 12",
            "το cvv δεν φαίνεται",
            "ο κωδικός ασφαλείας 12345"})
    void aCvvCueWithoutThreeOrFourDigitsMasksNothing(String text) {
        assertEquals(text, masked(text));
    }

    @Test
    void aCardSplitAcrossTwoGreedyMatchesIsStillMasked() {
        // A 19-digit window from the first "1" ends inside the card: windows from every group start are tried.
        String t = "1 2 3 4 5 6 4111 1111 1111 1111";
        assertTrue(masked(t).endsWith(ChatAsserts.dots("4111 1111 1111 1111")), masked(t));
    }

    /** Characters of the largest adversarial input; the smaller one is half of it. */
    private static final int ADVERSARIAL_CHARS = 400_000;

    /**
     * Doubling the input must not much more than double the time: a quadratic detector would take four
     * times as long. Checks scaling, not the speed of the machine, so the only fixed limit is a ceiling.
     */
    @Test
    void longDigitAndEmailRunsAreLinear() {
        assertTimeoutPreemptively(Duration.ofSeconds(120), () -> {
            for (String unit : new String[] {"1 ", "1", "1-2.", "a @ ", "a@b.", "a . "}) {
                IDS.detect(unit.repeat(500)); // warm-up on a small input
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
        IDS.detect(text);
        return System.nanoTime() - start;
    }

    @Test
    void aSpacedEmailStopsAtANonLatinWordAfterTheSentenceEnd() {
        String t = "γράψτε στο foo @ bar . com. Ευχαριστώ πολύ";
        assertEquals(expect(t, "foo @ bar . com"), masked(t));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "maria.k @ gmail.com είναι το email|maria.k @ gmail.com",
            "γράψτε στο john @ gmail . com ευχαριστώ|john @ gmail . com",
            "nick @ yahoo . gr|nick @ yahoo . gr",
            "το mail: maria.k@ gmail.com|maria.k@ gmail.com",
            "sales @ shop . co . uk, παρακαλώ|sales @ shop . co . uk"})
    void spacedEmailsAreMasked(String text, String email) {
        assertEquals(expect(text, email), masked(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "πινακίδα IKY-1234 εδώ|IKY-1234",
            "το αμάξι ΙKΥ 1234 εδώ|ΙKΥ 1234"})
    void platesTypedWithLatinLookAlikesAreMasked(String text, String plate) {
        assertEquals(expect(text, plate), masked(text));
    }

    @Test
    void theDigitGroupsOfAnIbanAreNotACard() {
        String t = "IBAN GR16 0110 1250 0000 0001 2300 695";
        assertTrue(IDS.detect(t).stream().noneMatch(s -> s.type() == PiiType.CARD), t);
        assertEquals(expect(t, "GR16 0110 1250 0000 0001 2300 695"), masked(t));
    }

    @Test
    void checksums() {
        assertTrue(Checksums.luhn("4111111111111111"));
        assertTrue(Checksums.amka("15038501233"));
        assertEquals("801234560", Checksums.digitsOnly("801 234-560"));
    }

    /** The production wiring: a detector that knows the allowlist (public acronyms such as ΚΕΑ, ΙΚΑ). */
    static final IdDetector IDS_WITH_ALLOWLIST = new IdDetector(Config.loadFileConfig(Path.of("config")).rules(),
            ChatListsRealConfigTest.LISTS.allow());

    private static String maskedWithAllowlist(String text) {
        return Masker.mask(text, IDS_WITH_ALLOWLIST.detect(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "ΚΕΑ 2025 πότε πληρώνεται",
            "ΙΚΑ 2024 σύνταξη",
            "ΟΤΕ 2020 λογαριασμός",
            "το ΙΚΑ-2024 έκλεισε"})
    void anAllowlistedAcronymWithAYearIsNotAPlate(String text) {
        assertEquals(text, maskedWithAllowlist(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "πινακίδα ΙΚΥ-4521 εδώ|ΙΚΥ-4521",
            "το μηχανάκι ΖΗΒ 318 εδώ|ΖΗΒ 318",
            "πινακίδα IKY-1234 εδώ|IKY-1234"})
    void aRealPlateIsStillMaskedWithTheAllowlist(String text, String plate) {
        assertEquals(expect(text, plate), maskedWithAllowlist(text));
    }

    private static List<ChatSpan> cued(String text) {
        return IDS.detect(text).stream().filter(s -> s.detector().equals("chat_cued_number")).toList();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "με αφμ 1212121|1212121|AFM",
            "το ΑΦΜ μου είναι 1212121|1212121|AFM",
            "Α.Φ.Μ.: 12 345|12 345|AFM",
            "afm 1234|1234|AFM",
            "ΑΜΚΑ 123456|123456|AMKA",
            "ΑΜΚΑ 1989992121|1989992121|AMKA",
            "my amka is 12345|12345|AMKA",
            "τηλ 69123456|69123456|PHONE",
            "Τηλέφωνο 21012|21012|PHONE",
            "το κινητό μου: 697-12-34|697-12-34|PHONE",
            "tel +30 69123|+30 69123|PHONE",
            "ΑΔΤ ΑΚ 12345|ΑΚ 12345|ID_CARD",
            "αριθμός ταυτότητας Χ 1234|Χ 1234|ID_CARD",
            "ταυτότητα αριθμ 12345|12345|ID_CARD",
            "διαβατήριο ΑΒ 12345|ΑΒ 12345|PASSPORT",
            "passport 123|123|PASSPORT",
            "iban GR16 0110 125|GR16 0110 125|IBAN"})
    void anyNumberAfterACueIsMaskedAndTheCueStaysVisible(String text, String value, PiiType type) {
        assertEquals(expect(text, value), masked(text));
        int start = text.indexOf(value);
        assertTrue(IDS.detect(text).stream().anyMatch(s -> s.type() == type && s.start() == start
                && s.end() == start + value.length()), () -> IDS.detect(text).toString());
    }

    @Test
    void aNumberAnotherRuleFoundKeepsThatRulesSpan() {
        String t = "ΑΦΜ 090000045 12 ετών";
        assertEquals(List.of(), cued(t));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "η ταυτότητα λήγει το 2030|2030",
            "my iban is 1234|1234",
            "διαβατήριο σε 12345|12345",
            "ταυτότητα ακ 12345|12345"})
    void lowercaseLettersBeforeACuedNumberAreAWordAndStayVisible(String text, String number) {
        assertEquals(expect(text, number), masked(text));
    }

    @Test
    void theCueNearestToTheNumberDecidesItsType() {
        String t = "ΑΦΜ και ΑΜΚΑ 123";
        assertEquals(expect(t, "123"), masked(t));
        assertEquals(List.of(PiiType.AMKA), cued(t).stream().map(ChatSpan::type).toList());
    }

    @Test
    void onlyTheFirstNumberAfterTheCueIsMasked() {
        String t = "ΑΜΚΑ 123456 και 3 παιδιά";
        assertEquals(expect(t, "123456"), masked(t));
    }

    @Test
    void aNumberOnTheNextLineIsNotMasked() {
        String t = "το ΑΜΚΑ μου\n123456";
        assertEquals(t, masked(t));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
            "το 2020 πλήρωσα 1500 ευρώ",
            "στις 10:30, 3 τεμάχια",
            "ΑΦΜ: θα σας το στείλω αύριο το απόγευμα 1234",
            "η τηλεόραση 3 ετών",
            "η κινητικότητα 2 ατόμων",
            "η ταυτότητα λήγει τον Μάιο",
            "Το τηλεφωνικό κέντρο 11888 δεν απαντά."})
    void aNumberWithoutACueIsNotMasked(String text) {
        assertEquals(text, masked(text));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3})
    void aCuedNumberOfAnyShapeStaysFast(int which) {
        String text = new String[] {"αφμ" + " ".repeat(200_000) + "x", "τηλ " + "1 ".repeat(200_000),
                "αμκα ".repeat(100_000), "ταυτοτητα " + "α 1 ".repeat(100_000)}[which];
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> IDS.detect(text));
    }
}
