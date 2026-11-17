package dev.filtsiap.ded.anonymizer.chat;

/** Builds expected masked strings without counting dots by hand. */
final class ChatAsserts {
    private ChatAsserts() {
    }

    /** {@code s} with every non-whitespace code point replaced by '.', as Masker does. */
    static String dots(String s) {
        StringBuilder b = new StringBuilder();
        s.codePoints().forEach(cp -> b.appendCodePoint(Character.isWhitespace(cp) ? cp : '.'));
        return b.toString();
    }

    /**
     * {@code text} with every occurrence of each part masked. List a longer part before a part it
     * contains ("γιώργος" before "γιώργο"), or the shorter one is replaced inside it first.
     */
    static String expect(String text, String... maskedParts) {
        String out = text;
        for (String part : maskedParts) {
            out = out.replace(part, dots(part));
        }
        return out;
    }
}
