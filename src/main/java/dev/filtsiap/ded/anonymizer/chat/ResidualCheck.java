package dev.filtsiap.ded.anonymizer.chat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import dev.filtsiap.ded.anonymizer.PostcheckPatterns;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;

/** The .docx post-check's QA patterns over the MASKED text: anything still matching slipped past every detector. */
final class ResidualCheck {
    private static final Map<String, PiiType> TYPES = Map.of("AFM", PiiType.AFM, "AMKA", PiiType.AMKA,
            "IBAN_GR", PiiType.IBAN, "EMAIL", PiiType.EMAIL, "PHONE", PiiType.PHONE, "DIGIT_RUN", PiiType.OTHER);

    /**
     * A Greek phone number has ten digits. The QA PHONE pattern is looser (a leading 2 or 6, then 8 to 14
     * digits, spaces or hyphens), so it also matches a date such as 27-10-2024, which has eight.
     */
    private static final int PHONE_DIGITS = 10;

    private ResidualCheck() {
    }

    /**
     * Finds what is still personal in {@code masked}.
     *
     * @param masked the text after the detectors' masks were applied
     * @return one span per match of a QA pattern, named "residual:" and the pattern's key; a PHONE match
     *         with fewer than ten digits is a date and is not reported
     */
    static List<ChatSpan> find(String masked) {
        List<ChatSpan> out = new ArrayList<>();
        for (Map.Entry<String, PyPattern> e : PostcheckPatterns.QA_PATTERNS.entrySet()) {
            for (PyMatch m : e.getValue().finditer(masked)) {
                if (e.getKey().equals("PHONE") && digits(m.group()) < PHONE_DIGITS) {
                    continue;
                }
                out.add(new ChatSpan(m.start(), m.end(), TYPES.getOrDefault(e.getKey(), PiiType.OTHER),
                        "residual:" + e.getKey()));
            }
        }
        return out;
    }

    private static long digits(String text) {
        return text.codePoints().filter(Character::isDigit).count();
    }
}
