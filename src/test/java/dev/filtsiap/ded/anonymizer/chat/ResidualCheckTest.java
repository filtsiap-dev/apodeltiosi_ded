package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The residual re-scan flags what slipped past the detectors, but not a date that only looks like a phone. */
class ResidualCheckTest {

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "πληρωμη στις 27-10-2024",
            "αιτηση 21-03-2024 και 20-05-2024",
            "ημερομηνια 2024-10-27",
            "ημερομηνια 2024-10-27 και 2025-01-20"})
    void aHyphenatedDateIsNotAPhone(String text) {
        assertEquals(List.of(), ResidualCheck.find(text));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "τηλ 6912345678|6912345678",
            "τηλ 210 6543 210|210 6543 210",
            "τηλ 210-6543210|210-6543210",
            "τηλ +30 6912345678|+30 6912345678",
            "τηλ 0030 210 6543210|0030 210 6543210"})
    void aPhoneThatSlippedThroughIsStillFlagged(String text, String phone) {
        List<ChatSpan> found = ResidualCheck.find(text).stream().filter(s -> s.type() == PiiType.PHONE).toList();
        assertTrue(!found.isEmpty(), "no residual PHONE in: " + text);
        assertTrue(text.contains(phone) && found.stream().allMatch(s -> s.detector().equals("residual:PHONE")));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "1234567890|residual:DIGIT_RUN",
            "ΑΦΜ 123456789|residual:DIGIT_RUN",
            "μ foo@bar.com μ|residual:EMAIL"})
    void theOtherPatternsAreUnchanged(String text, String detector) {
        assertTrue(ResidualCheck.find(text).stream().anyMatch(s -> s.detector().equals(detector)), text);
    }
}
