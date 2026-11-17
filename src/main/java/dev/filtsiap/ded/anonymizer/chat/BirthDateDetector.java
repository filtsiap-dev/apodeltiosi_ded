package dev.filtsiap.ded.anonymizer.chat;

import java.util.ArrayList;
import java.util.List;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;

/**
 * A date of birth: the first date after a birth cue ("γεννήθηκα", "ημ. γέννησης", "date of birth",
 * "DOB"), within about 25 characters of words or punctuation and in the same sentence. Only the date
 * is masked. A date without a cue (a payment, a deadline) is kept. The shapes are d/m/yyyy and
 * dd/mm/yy with '/', '-' or '.', yyyy-mm-dd, "27 Οκτωβρίου 1984", "27 Οκτ. 1984", "October 27, 1984",
 * "27 Oct 1984", and a bare year 1900-2099 right after the cue and an optional article ("γεννήθηκα το
 * 1984"). Every repetition is bounded, so the scan is linear.
 */
public final class BirthDateDetector {
    /** On the FOLDED text: no accents, lowercase, σ for ς. */
    private static final String CUE = "γεννηθ(?:ηκαμε|ηκα|ηκε|εισ)|γεννημεν(?:οσ|η)"
            + "|(?:ημερομηνια|ημ/νια|ημερ\\.|ημ\\.)\\s{0,3}(?:γεννησησ|γεν\\.)|ετοσ\\s{1,3}γεννησησ"
            + "|date\\s{1,3}of\\s{1,3}birth|born\\s{1,3}(?:on|in)|d\\.?o\\.?b\\.?";
    /** A Greek or English month: its first three letters, then the rest of any form ("οκτωβριου", "oct."). */
    private static final String MONTH = "(?:ιαν|φεβ|μαρ|απρ|μα[ιη]|ιου[νλ]|αυγ|σεπ|οκτ|νοε|δεκ"
            + "|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\\w{0,8}\\.?";
    private static final String DATE = "\\d{4}[/.\\-]\\d{1,2}[/.\\-]\\d{1,2}"
            + "|\\d{1,2}[/.\\-]\\d{1,2}[/.\\-](?:\\d{4}|\\d{2})"
            + "|\\d{1,2}\\s{1,3}" + MONTH + ",?\\s{1,3}\\d{4}"
            + "|" + MONTH + "\\s{1,3}\\d{1,2}(?:st|nd|rd|th)?,?\\s{1,3}\\d{4}";
    /**
     * Group 1 is the cue, group 2 a date after up to 25 characters of no digit or sentence end ('!',
     * '?', the Greek question mark ';', a line break), group 3 a bare year right after the cue. A '.'
     * may be in the gap ("ημ. γεν."); one that ends a sentence is found on the original text.
     */
    static final PyPattern CUED_DATE = PyRegex.compile(
            "(?<!\\w)(" + CUE + ")(?!\\w)"
                    + "(?:[^\\d\\n\\r!?;]{0,25}?(?<!\\w)(" + DATE + ")"
                    + "|[\\s:]{0,4}(?:(?:το|στο|in)\\s{1,3})?((?:19|20)\\d{2}))(?!\\d)", 0);

    private BirthDateDetector() {
    }

    /**
     * Finds the dates of birth in {@code text}.
     *
     * @param text the chat text, NFC-normalised
     * @return the DOB spans to mask, in order
     */
    public static List<ChatSpan> detect(String text) {
        List<ChatSpan> out = new ArrayList<>();
        int[] cps = null;
        for (PyMatch m : CUED_DATE.finditer(GreekFold.fold(text))) {
            if (m.start(3) >= 0) {
                out.add(new ChatSpan(m.start(3), m.end(3), PiiType.DOB, "chat_dob_cue"));
                continue;
            }
            if (cps == null) {
                cps = text.codePoints().toArray();
            }
            if (!endsASentence(cps, m.end(1), m.start(2))) {
                out.add(new ChatSpan(m.start(2), m.end(2), PiiType.DOB, "chat_dob_cue"));
            }
        }
        return out;
    }

    /** Whether {@code [from, to)} of the original text has a '.' followed by a space and a capital. */
    private static boolean endsASentence(int[] cps, int from, int to) {
        for (int i = from; i < to && i + 2 < cps.length; i++) {
            if (cps[i] == '.' && Character.isWhitespace(cps[i + 1]) && Character.isUpperCase(cps[i + 2])) {
                return true;
            }
        }
        return false;
    }
}
