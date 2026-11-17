package dev.filtsiap.ded.anonymizer.chat;

import java.text.Normalizer;

/**
 * The matching form of a text: lowercase, no accents or diaeresis, σ for ς. It has EXACTLY the
 * input's code-point length, so a match offset in the fold is the same offset in the input. Each
 * code point is folded alone: the first code point of its NFD decomposition, lowercased. A lone
 * combining mark (one NFC could not compose) is kept as it is. Like DetectorPatterns.foldGreek,
 * but length-preserving, and with Character.toLowerCase instead of casefold (which can expand).
 */
public final class GreekFold {
    private GreekFold() {
    }

    /**
     * Folds {@code text} code point by code point.
     *
     * @param text any text
     * @return the folded text, with the same number of code points
     */
    public static String fold(String text) {
        StringBuilder out = new StringBuilder(text.length());
        text.codePoints().forEach(cp -> out.appendCodePoint(foldCodePoint(cp)));
        return out.toString();
    }

    static int foldCodePoint(int cp) {
        if (cp < 0x80) {
            return Character.toLowerCase(cp);
        }
        if (Character.getType(cp) == Character.NON_SPACING_MARK) {
            return cp;
        }
        String nfd = Normalizer.normalize(new String(Character.toChars(cp)), Normalizer.Form.NFD);
        int base = Character.toLowerCase(nfd.codePointAt(0));
        return base == 'ς' ? 'σ' : base;
    }
}
