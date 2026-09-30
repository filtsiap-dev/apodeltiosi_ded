package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyNumber;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.math.BigInteger;
import java.util.Optional;

/**
 * Helpers of the post-redaction audit (port of the functions in {@code postcheck_support.py};
 * its regex constants are in {@link PostcheckPatterns}). No logging.
 */
final class PostcheckSupport {

    private static final PyPattern NON_DIGITS = PyRegex.compile("\\D+");

    private PostcheckSupport() {
    }

    /** True if {@code s} is a valid Greek AFM by its checksum. */
    static boolean afmChecksumOk(String s) {
        if (PyStr.len(s) != 9 || !PyStr.isDigit(s)) {
            return false;
        }
        int[] cps = s.codePoints().toArray();
        int total = 0;
        for (int i = 0; i < 8; i++) {
            total += PyStr.digitValue(cps[i]) * (1 << (8 - i));
        }
        return (total % 11) % 10 == PyStr.digitValue(cps[8]);
    }

    /** True if {@code s} passes the IBAN mod-97 checksum (Python's loose variant, kept as is). */
    static boolean ibanChecksumOk(String s) {
        s = PyStr.upper(s.replace(" ", ""));
        if (PyStr.len(s) < 4) {
            return false;
        }
        String rearranged = PyStr.sliceFrom(s, 4) + PyStr.slice(s, 0, 4);
        StringBuilder numeric = new StringBuilder();
        rearranged.codePoints().forEach(cp -> {
            if (PyUnicode.isAlpha(cp)) {
                numeric.append(cp - 55);
            } else {
                numeric.appendCodePoint(cp);
            }
        });
        Optional<BigInteger> value = PyNumber.parseInt(numeric.toString());
        return value.isPresent() && value.get().mod(BigInteger.valueOf(97)).intValue() == 1;
    }

    /**
     * Normalizes {@code value} to a 10-digit Greek phone number (mobile 69x or landline 2x),
     * stripping non-digits and a +30/0030 prefix; empty if it does not qualify.
     */
    static Optional<String> normalizedGreekPhone(String value) {
        if (value.contains("\n") || value.contains("\t")) {
            return Optional.empty();
        }
        String digits = NON_DIGITS.subLiteral("", value);
        if (digits.startsWith("0030")) {
            digits = PyStr.sliceFrom(digits, 4);
        } else if (digits.startsWith("30") && PyStr.len(digits) == 12) {
            digits = PyStr.sliceFrom(digits, 2);
        }
        if (PyStr.len(digits) != 10) {
            return Optional.empty();
        }
        if (!(digits.startsWith("69") || digits.startsWith("2"))) {
            return Optional.empty();
        }
        return Optional.of(digits);
    }

    /** True when a phone at {@code start} appears on an official authority contact line. */
    static boolean looksLikeOfficialContactPhone(String text, int start) {
        int lineStart = PyStr.rfind(text, "\n", 0, start) + 1;
        int lineEnd = PyStr.find(text, "\n", start);
        if (lineEnd == -1) {
            lineEnd = PyStr.len(text);
        }
        String line = PyStr.slice(text, lineStart, lineEnd);
        if (PostcheckPatterns.OFFICIAL_CONTACT_LABEL_RE.found(line)) {
            return true;
        }
        // Unlabeled phones only count inside the pre-decision authority header block.
        String prefix = PyStr.slice(text, 0, start);
        if (PostcheckPatterns.DECISION_BODY_START_RE.found(prefix)) {
            return false;
        }
        String headerWindow = PyStr.sliceFrom(prefix, -800) + "\n" + line;
        return PostcheckPatterns.OFFICIAL_HEADER_CONTEXT_RE.found(headerWindow);
    }
}
