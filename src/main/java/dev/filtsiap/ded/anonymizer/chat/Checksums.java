package dev.filtsiap.ded.anonymizer.chat;

import dev.filtsiap.ded.anonymizer.DetectorSupport;

/** Check-digit tests for chat IDs; AFM and the AMKA date come from the .docx detectors' DetectorSupport. */
public final class Checksums {
    private Checksums() {
    }

    /**
     * The ASCII digits of {@code s}, in order.
     *
     * @param s any text
     * @return the digits, possibly empty
     */
    public static String digitsOnly(String s) {
        StringBuilder b = new StringBuilder();
        s.codePoints().filter(cp -> cp >= '0' && cp <= '9').forEach(b::appendCodePoint);
        return b.toString();
    }

    /**
     * The Luhn check.
     *
     * @param digits ASCII digits
     * @return true when non-empty and the sum is a multiple of 10
     */
    public static boolean luhn(String digits) {
        int total = 0;
        for (int i = 0; i < digits.length(); i++) {
            int n = digits.charAt(digits.length() - 1 - i) - '0';
            if (i % 2 == 1) {
                n = n * 2 > 9 ? n * 2 - 9 : n * 2;
            }
            total += n;
        }
        return !digits.isEmpty() && total % 10 == 0;
    }

    /**
     * 11 digits, a plausible DDMMYY birth date, and a Luhn check digit.
     *
     * @param digits ASCII digits
     * @return true when {@code digits} is a valid AMKA
     */
    public static boolean amka(String digits) {
        return digits.length() == 11 && DetectorSupport.validAmkaBirthDate(digits) && luhn(digits);
    }

    /**
     * 9 digits with a valid AFM check digit.
     *
     * @param digits ASCII digits
     * @return true when {@code digits} is a valid AFM
     */
    public static boolean afm(String digits) {
        return digits.length() == 9 && DetectorSupport.validAfm(digits);
    }
}
