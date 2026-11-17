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
    private static final PyPattern PRIVATE_OWNER = PyRegex.compile(
            "προσφε[ύυ]γ|προσφε[ύυ]γον|αιτο[ύυ]ν|ιδι[ώω]τ|δικαιο[ύυ]χ|εταιρε[ίι]|επιχε[ίι]ρη", PyRegex.IGNORECASE);

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
        if (PRIVATE_OWNER.found(line)) {
            return false;
        }
        // Unlabeled phones only count inside the pre-decision authority header block.
        String prefix = PyStr.slice(text, 0, start);
        if (PostcheckPatterns.DECISION_BODY_START_RE.found(prefix)
                || PRIVATE_OWNER.found(PyStr.sliceFrom(prefix, -160) + "\n" + line)) {
            return false;
        }
        String headerWindow = PyStr.sliceFrom(prefix, -800) + "\n" + line;
        return PostcheckPatterns.OFFICIAL_HEADER_CONTEXT_RE.found(headerWindow);
    }

    /** Use physical order within ONE package part; extraction lists tables before paragraphs. */
    static boolean looksLikeOfficialContactPhone(DocumentData document, TextUnit unit, int start) {
        var ordered = document.textUnits().stream().filter(u -> u.partName().equals(unit.partName())
                && !u.charMap().isEmpty()).sorted((a, b) -> comparePaths(a.charMap().getFirst().textNodePath(),
                        b.charMap().getFirst().textNodePath())).toList();
        StringBuilder text = new StringBuilder();
        int at = -1;
        for (TextUnit next : ordered) {
            if (next.unitId().equals(unit.unitId())) {
                at = PyStr.len(text.toString()) + start;
            }
            text.append(next.normalizedText()).append('\n');
        }
        return at >= 0 && looksLikeOfficialContactPhone(text.toString(), at);
    }

    private static int comparePaths(String a, String b) {
        String[] left = a.split("/");
        String[] right = b.split("/");
        for (int i = 1; i < Math.min(left.length, right.length); i++) {
            int difference = Integer.compare(Integer.parseInt(left[i]), Integer.parseInt(right[i]));
            if (difference != 0) {
                return difference;
            }
        }
        return Integer.compare(left.length, right.length);
    }
}
