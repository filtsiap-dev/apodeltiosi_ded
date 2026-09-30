package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyNumber;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import dev.filtsiap.ded.anonymizer.pycompat.PyUnicode;
import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IBAN validation, ported from what the Python service actually runs:
 * {@code stdnum.iban.is_valid} (python-stdnum is installed, so {@code detector_support}'s
 * mod-97 fallback is never used in production).
 *
 * <p>Steps: compact, ISO 7064 mod 97-10, country lookup, BBAN structure, then the country
 * checks stdnum has for BE, ES, ME and NO. One known gap: stdnum also requires a Belgian bank
 * code to exist in its bank list; that list is not ported (CLAUDE.md §8).
 */
final class Iban {

    private static final Pattern STRUCT = Pattern.compile("([1-9][0-9]*)!([nac])");

    private Iban() {
    }

    /** {@code stdnum.iban.is_valid(number)}. */
    static boolean isValid(String number) {
        String n = compact(number);
        if (!mod97Valid(PyStr.sliceFrom(n, 4) + PyStr.slice(n, 0, 4))) {
            return false;
        }
        String structure = IbanRegistry.BBAN_STRUCTURE.get(PyStr.slice(n, 0, 2));
        if (structure == null || structure.isEmpty()) {
            return false;
        }
        if (!bbanRegex(structure).matcher(PyStr.sliceFrom(n, 4)).matches()) {
            return false;
        }
        return switch (PyStr.slice(n, 0, 2)) {
            case "BE" -> belgianCheckOk(n);
            case "ES" -> spanishCccOk(PyStr.sliceFrom(n, 4));
            case "ME" -> intOrNull(PyStr.sliceFrom(n, 4)) != null
                    && intOrNull(PyStr.sliceFrom(n, 4)).mod(BigInteger.valueOf(97)).intValue() == 1;
            case "NO" -> norwegianKontonrOk(PyStr.sliceFrom(n, 4));
            default -> true;
        };
    }

    static String compact(String number) {
        StringBuilder sb = new StringBuilder();
        number.codePoints().filter(cp -> cp != ' ' && cp != '-' && cp != '.').forEach(sb::appendCodePoint);
        return PyStr.upper(PyStr.strip(sb.toString()));
    }

    /** ISO 7064 mod 97-10 over base-36 digits; any non-alphanumeric makes it invalid. */
    static boolean mod97Valid(String s) {
        StringBuilder base10 = new StringBuilder();
        for (int cp : s.codePoints().toArray()) {
            int v;
            if (PyUnicode.isDecimal(cp)) {
                v = Character.digit(cp, 10);
            } else if ((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z')) {
                v = Character.toUpperCase(cp) - 'A' + 10;
            } else {
                return false;
            }
            base10.append(v);
        }
        if (base10.isEmpty()) {
            return false;
        }
        return new BigInteger(base10.toString()).mod(BigInteger.valueOf(97)).intValue() == 1;
    }

    private static Pattern bbanRegex(String structure) {
        StringBuilder re = new StringBuilder();
        Matcher m = STRUCT.matcher(structure);
        while (m.find()) {
            String chars = switch (m.group(2)) {
                case "n" -> "[0-9]";
                case "a" -> "[A-Z]";
                default -> "[A-Za-z0-9]";
            };
            re.append(chars).append('{').append(m.group(1)).append('}');
        }
        return Pattern.compile(re.toString());
    }

    private static BigInteger intOrNull(String s) {
        return PyNumber.parseInt(s).orElse(null);
    }

    private static boolean belgianCheckOk(String n) {
        BigInteger body = intOrNull(PyStr.slice(n, 4, -2));
        if (body == null) {
            return false;
        }
        int check = body.mod(BigInteger.valueOf(97)).intValue();
        return PyStr.sliceFrom(n, -2).equals(String.format("%02d", check == 0 ? 97 : check));
    }

    private static boolean isAsciiDigits(String s) {
        return !s.isEmpty() && s.chars().allMatch(c -> c >= '0' && c <= '9');
    }

    private static String cccCheckDigit(String digits) {
        int sum = 0;
        for (int i = 0; i < digits.length(); i++) {
            sum += (digits.charAt(i) - '0') * (1 << i);
        }
        int check = sum % 11;
        return Integer.toString(check < 2 ? check : 11 - check);
    }

    private static boolean spanishCccOk(String ccc) {
        String n = PyStr.upper(PyStr.strip(ccc.replace(" ", "").replace("-", "")));
        if (n.length() != 20 || !isAsciiDigits(n)) {
            return false;
        }
        String expected = cccCheckDigit("00" + n.substring(0, 8)) + cccCheckDigit(n.substring(10));
        return n.substring(8, 10).equals(expected);
    }

    private static boolean norwegianKontonrOk(String kontonr) {
        String n = PyStr.strip(kontonr.replace(" ", "").replace(".", "").replace("-", ""));
        if (n.startsWith("0000")) {
            n = n.substring(4);
        }
        if (!isAsciiDigits(n)) {
            return false;
        }
        if (n.length() == 7) {
            return luhnChecksum(n) == 0;
        }
        if (n.length() == 11) {
            int[] weights = {6, 7, 8, 9, 4, 5, 6, 7, 8, 9};
            int sum = 0;
            for (int i = 0; i < 10; i++) {
                sum += weights[i] * (n.charAt(i) - '0');
            }
            return Integer.toString(sum % 11).equals(n.substring(10));
        }
        return false;
    }

    private static int luhnChecksum(String n) {
        int sum = 0;
        boolean dbl = false;
        for (int i = n.length() - 1; i >= 0; i--) {
            int d = n.charAt(i) - '0';
            if (dbl) {
                d *= 2;
                d = d / 10 + d % 10;
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10;
    }
}
