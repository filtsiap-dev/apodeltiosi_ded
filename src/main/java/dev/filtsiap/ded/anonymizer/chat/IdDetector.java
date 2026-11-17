package dev.filtsiap.ded.anonymizer.chat;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntPredicate;

import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.Detectors;
import dev.filtsiap.ded.anonymizer.Span;
import dev.filtsiap.ded.anonymizer.SpanAction;
import dev.filtsiap.ded.anonymizer.TextUnit;
import dev.filtsiap.ded.anonymizer.UnitType;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;

/**
 * Structured identifiers. First the .docx detectors (AFM, AMKA, IBAN, email, phone, bank account),
 * every REDACT and REVIEW proposal kept whatever its confidence (no pass 2 here to settle a REVIEW
 * or a low-confidence REDACT). Then chat shapes the .docx rules do not need: spaced digits,
 * obfuscated emails, ID cards, passports, plates, ΓΕΜΗ, cards, customer numbers, and any number after
 * an ID's name whatever its shape. Cue patterns run on the GreekFold of the text, whose offsets are the text's.
 */
public final class IdDetector {
    private static final String ID_LETTERS = "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧABEZHIKMNOPTYX";
    /** A card number's digits may be separated by one whitespace or '-'. */
    private static final IntPredicate CARD_SEPARATOR = cp -> isBlank(cp) || cp == '-';
    /** An AFM or AMKA's digits may be separated by one whitespace, '.' or '-'. */
    private static final IntPredicate DIGIT_GROUP_SEPARATOR = cp -> isBlank(cp) || cp == '.' || cp == '-';

    /** 10 digits from 2 or 6, single separators allowed, optional +30 / 0030. */
    static final PyPattern PHONE = PyRegex.compile(
            "(?<![\\d+])(?:(?:\\+|00)\\s?30[\\s.\\-]?)?[26](?:[\\s.\\-]?\\d){9}(?!\\d)", 0);
    static final PyPattern IBAN = PyRegex.compile("\\bGR\\d{2}(?:\\s?[0-9A-Z]){23}\\b", PyRegex.IGNORECASE);
    static final PyPattern EMAIL_OBFUSCATED = PyRegex.compile(
            // Whitespace only around the bracketed forms: a bare '@' or '.' must touch both sides,
            // so "foo@bar.com. Ευχαριστώ" stops at "com". Spaced forms are EMAIL_SPACED.
            "[\\w.+\\-]{1,64}(?:@|\\s?(?:\\[at\\]|\\(at\\)|\\{at\\})\\s?)[\\w\\-]{1,63}"
                    + "(?:(?:\\.|\\s?(?:\\[dot\\]|\\(dot\\))\\s?)[\\w\\-]{1,63}){1,4}", PyRegex.IGNORECASE);
    /**
     * Spaces allowed around '@' and '.' ("maria.k @ gmail.com", "nick @ yahoo . gr"). The capture is
     * bounded by a LAST label shaped like a TLD (2 to 6 Latin letters, not followed by a letter), so
     * "foo@bar.com. Ευχαριστώ" still ends at "com"; a following Latin word ("foo@bar.com. Thanks")
     * may be over-masked. An unspaced email with a longer TLD is still found by EMAIL_OBFUSCATED.
     */
    static final PyPattern EMAIL_SPACED = PyRegex.compile(
            "[\\w.+\\-]{1,64}\\s?@\\s?[\\w\\-]{1,63}(?:\\s?\\.\\s?[\\w\\-]{1,63}){0,3}"
                    + "\\s?\\.\\s?[a-zA-Z]{2,6}(?![a-zA-Z])", 0);
    static final PyPattern ID_CARD_NEW = PyRegex.compile(
            "(?<!\\w)[" + ID_LETTERS + "]{2}[\\s\\-]?\\d{6}(?!\\w)", 0);
    static final PyPattern ID_CARD_OLD = PyRegex.compile("(?<!\\w)[" + ID_LETTERS + "]-\\d{6}(?!\\w)", 0);
    /** Letters that look alike in Greek and Latin (uppercase only), so "IKY-1234" is a plate too. */
    static final PyPattern PLATE = PyRegex.compile(
            "(?<!\\w)[" + ID_LETTERS + "]{3}[\\s\\-]?\\d{3,4}(?!\\w)", 0);
    // Cue patterns: matched on the FOLDED text.
    // Every cue starts with (?<!\w): "αρ" must not match inside "καθαρή".
    static final PyPattern ID_CARD_CUED = PyRegex.compile(
            "(?<!\\w)(?:ταυτοτητ\\w*|α\\.?δ\\.?τ\\.?)[\\s:]{0,8}(?:αρ\\w*\\.?\\s{0,8})?"
                    + "([a-zα-ω]{1,2}[\\s\\-]?\\d{6})(?!\\d)", 0);
    static final PyPattern PASSPORT_CUED = PyRegex.compile(
            "(?<!\\w)διαβατηρ\\w*[^\\d\\n]{0,20}?([a-zα-ω]{2}[\\s\\-]?\\d{7})(?!\\d)", 0);
    static final PyPattern GEMI_CUED = PyRegex.compile(
            "(?<!\\w)γ\\.?ε\\.?μ\\.?η\\.?[\\s:]{0,8}(?:αρ\\w*\\.?\\s{0,8})?(\\d{9,12})(?!\\d)", 0);
    static final PyPattern CUSTOMER_CUED = PyRegex.compile(
            "(?<!\\w)(?:αρ\\w*\\.?|κωδικ\\w*)\\s{1,8}(?:παροχ\\w*|πελατ\\w*|συμβασ\\w*|συμβολαι\\w*|μετρητ\\w*"
                    + "|συνδρομητ\\w*|λογαριασμ\\w*)[\\s:]{0,8}(\\d(?:[\\d\\s\\-/]{3,24}\\d)?)", 0);

    /** A card security code ("cvv 123", "κωδικός ασφαλείας είναι 321"); group 1 is the 3 or 4 digits. */
    static final PyPattern CVV_CUED = PyRegex.compile(
            "(?<!\\w)(?:cvv2?|cvc|cv2|cid|κωδικ(?:οσ|ο|ου)\\s{1,8}ασφαλειασ)[\\s:\\-]{0,8}"
                    + "(?:ειναι[\\s:\\-]{1,8})?(\\d{3,4})(?!\\d)", 0);

    // After the cue: not a letter (so "τηλ" is not "τηλεόραση"), then at most 25 characters with no digit
    // and no line break ("ΑΦΜ μου είναι").
    private static final String CUED_GAP = "(?![^\\W\\d])[^\\d\\n]{0,25}?";
    /**
     * Digit groups joined by one space, tab, '.', '-' or '/': "801 234 560", "697-12-34". At most 32 groups (a
     * phone spelled digit by digit has 10): java.util.regex recurses once per repetition of a group.
     */
    private static final String CUED_DIGITS = "\\d+(?:(?:[^\\S\\n]|[.\\-/])\\d+){0,31}";
    /** The one or two letters of an id card or passport ("ΑΚ 12345"); not the end of a word in the gap. */
    private static final String CUED_LETTERS = "(?:(?<!\\w)[a-zα-ω]{1,2}(?:[^\\S\\n]|-)?)?";

    /**
     * The next number after an ID's name, whatever its length or checksum: a mistyped or partial ID is still
     * personal ("ΑΜΚΑ 123456", "τηλ 69123456"). Group 1 is the number, with the letters of an id card or
     * passport, the '+' of a phone or the country of an IBAN; the cue stays visible. Matched on the FOLDED text.
     */
    static final Map<PiiType, PyPattern> CUED_NUMBER = Map.of(
            PiiType.AFM, cuedNumber("α\\.?φ\\.?μ\\.?|afm", ""),
            PiiType.AMKA, cuedNumber("α\\.?μ\\.?κ\\.?α\\.?|amka", ""),
            PiiType.ID_CARD, cuedNumber("ταυτοτητ\\w*|α\\.?δ\\.?τ\\.?|adt", CUED_LETTERS),
            PiiType.PASSPORT, cuedNumber("διαβατηρ\\w*|passport\\w*", CUED_LETTERS),
            PiiType.PHONE, cuedNumber("τηλ\\.?|τηλεφων(?:ο|ου|α|ων)|κινητ(?:ο|ου|α|ων)|tel\\.?|telephone|phone"
                    + "|mobile", "\\+?"),
            PiiType.IBAN, cuedNumber("iban", "(?:(?<!\\w)[a-z]{2})?"));

    /** A number found after a cue, and where that cue starts: the nearest cue names the number. */
    private record CuedNumber(int cueStart, ChatSpan span) {
    }

    private final DetectorRules rules;
    private final WordSet allow;

    /**
     * Creates the detector with no allowlist: every plate-shaped match is a plate.
     *
     * @param rules the regex rules of the .docx detectors it reuses
     */
    public IdDetector(DetectorRules rules) {
        this(rules, WordSet.of(List.of()));
    }

    /**
     * Creates the detector. A plate-shaped match whose three letters are an allowlisted word is not a
     * plate: "ΚΕΑ 2025" and "ΙΚΑ 2024" are a benefit and a year.
     *
     * @param rules the regex rules of the .docx detectors it reuses
     * @param allow the hand-kept words that are never personal data, folded
     */
    public IdDetector(DetectorRules rules, WordSet allow) {
        this.rules = rules;
        this.allow = allow;
    }

    /**
     * Finds the structured identifiers in {@code text}.
     *
     * @param text the chat text, NFC-normalised
     * @return the spans to mask, in no particular order; they may overlap
     */
    public List<ChatSpan> detect(String text) {
        List<ChatSpan> out = new ArrayList<>(reused(text));
        String folded = GreekFold.fold(text);
        for (PyMatch m : PHONE.finditer(text)) {
            out.add(new ChatSpan(m.start(), m.end(), PiiType.PHONE, "chat_phone"));
        }
        int[] cps = text.codePoints().toArray();
        // Cards first: an AFM/AMKA-looking run of digits overlapping a card number is part of the card.
        // A run may carry a leading number, an expiry or a CVV ("κάρτα 1 4111 1111 1111 1111"), so
        // every window that starts and ends at a group boundary is checked, not just the run's prefix.
        // The digit groups of an IBAN are not a card, whatever Luhn says about a window of them.
        List<ChatSpan> ibans = new ArrayList<>(out.stream().filter(s -> s.type() == PiiType.IBAN).toList());
        for (PyMatch m : IBAN.finditer(text)) {
            ibans.add(new ChatSpan(m.start(), m.end(), PiiType.IBAN, "chat_iban"));
        }
        List<ChatSpan> cards = new ArrayList<>();
        for (int[] run : digitRuns(cps, CARD_SEPARATOR)) {
            checkWindows(cps, run, new int[] {19, 18, 17, 16, 15, 14, 13}, (digits, n) -> Checksums.luhn(digits),
                    (s, e, n) -> {
                        if (!overlapsAny(ibans, s, e)) {
                            cards.add(new ChatSpan(s, e, PiiType.CARD, "chat_card_luhn"));
                        }
                    });
        }
        out.addAll(cards);
        for (int[] run : digitRuns(cps, DIGIT_GROUP_SEPARATOR)) {
            checkWindows(cps, run, new int[] {11, 9},
                    (digits, n) -> n == 11 ? Checksums.amka(digits) : Checksums.afm(digits),
                    (s, e, n) -> {
                        if (!overlapsAny(cards, s, e)) {
                            out.add(n == 11 ? new ChatSpan(s, e, PiiType.AMKA, "chat_amka_checksum")
                                    : new ChatSpan(s, e, PiiType.AFM, "chat_afm_checksum"));
                        }
                    });
        }
        add(out, IBAN, text, 0, PiiType.IBAN, "chat_iban");
        // Both email patterns scan up to 64 characters from every start, which is slow on a long run of word
        // characters; an email needs an '@' (or a bracketed "[at]", "(at)" or "{at}"), so skip them without one.
        boolean hasAt = text.indexOf('@') >= 0;
        if (hasAt || hasBracket(text)) {
            add(out, EMAIL_OBFUSCATED, text, 0, PiiType.EMAIL, "chat_email");
        }
        if (hasAt) {
            add(out, EMAIL_SPACED, text, 0, PiiType.EMAIL, "chat_email_spaced");
        }
        add(out, ID_CARD_NEW, text, 0, PiiType.ID_CARD, "chat_id_card");
        add(out, ID_CARD_OLD, text, 0, PiiType.ID_CARD, "chat_id_card_old");
        for (PyMatch m : PLATE.finditer(text)) {
            if (!allow.contains(GreekFold.fold(new String(cps, m.start(), 3)))) {
                out.add(new ChatSpan(m.start(), m.end(), PiiType.PLATE, "chat_plate"));
            }
        }
        add(out, ID_CARD_CUED, folded, 1, PiiType.ID_CARD, "chat_id_card_cue");
        add(out, PASSPORT_CUED, folded, 1, PiiType.PASSPORT, "chat_passport_cue");
        add(out, GEMI_CUED, folded, 1, PiiType.GEMI, "chat_gemi_cue");
        add(out, CUSTOMER_CUED, folded, 1, PiiType.CUSTOMER_NO, "chat_customer_cue");
        add(out, CVV_CUED, folded, 1, PiiType.CARD, "chat_cvv_cue");
        addCuedNumbers(out, folded, cps);
        return out;
    }

    private static PyPattern cuedNumber(String cue, String prefix) {
        return PyRegex.compile("(?<!\\w)(?:" + cue + ")" + CUED_GAP + "(" + prefix + CUED_DIGITS + ")", 0);
    }

    /**
     * Adds the {@link #CUED_NUMBER} spans that no other rule found. A number another rule already found keeps
     * that rule's span, so a valid ID followed by a count stays as it was ("ΑΦΜ 090000045 12 ετών"). When two
     * cues precede one number ("ΑΦΜ και ΑΜΚΑ 123"), the nearer one names it.
     */
    private static void addCuedNumbers(List<ChatSpan> out, String folded, int[] cps) {
        Map<Integer, CuedNumber> nearest = new HashMap<>();
        for (Map.Entry<PiiType, PyPattern> e : CUED_NUMBER.entrySet()) {
            for (PyMatch m : e.getValue().finditer(folded)) {
                int start = numberStart(cps, m.start(1), m.end(1));
                CuedNumber c = new CuedNumber(m.start(), new ChatSpan(start, m.end(1), e.getKey(), "chat_cued_number"));
                nearest.merge(start, c, (a, b) -> a.cueStart() >= b.cueStart() ? a : b);
            }
        }
        BitSet found = new BitSet();
        out.forEach(s -> found.set(s.start(), s.end()));
        for (CuedNumber c : nearest.values()) {
            if (!found.get(c.span().start())) {
                out.add(c.span());
            }
        }
    }

    /**
     * Where a cued number starts in the ORIGINAL text. The letters an id card or passport number may carry belong
     * to it only in capitals ("ΑΚ 12345"); in lowercase they are a word ("λήγει το 2030") and stay visible.
     */
    private static int numberStart(int[] cps, int start, int end) {
        int digits = start;
        while (digits < end && !Character.isDigit(cps[digits]) && cps[digits] != '+') {
            digits++;
        }
        for (int i = start; i < digits; i++) {
            if (Character.isLowerCase(cps[i])) {
                return digits;
            }
        }
        return start;
    }

    interface WindowCheck {
        boolean test(String digits, int length);
    }

    interface WindowSink {
        void accept(int start, int end, int length);
    }

    /**
     * Maximal runs of digits joined by at most one separator code point:
     * each run is the code-point positions of its digits. Hand-written, so a 400k-digit run is linear
     * and recursion-free.
     */
    static List<int[]> digitRuns(int[] cps, IntPredicate separator) {
        List<int[]> runs = new ArrayList<>();
        int i = 0;
        while (i < cps.length) {
            if (!Character.isDigit(cps[i])) {
                i++;
                continue;
            }
            List<Integer> positions = new ArrayList<>();
            positions.add(i);
            int j = i + 1;
            while (j < cps.length) {
                if (Character.isDigit(cps[j])) {
                    positions.add(j++);
                } else if (separator.test(cps[j]) && j + 1 < cps.length && Character.isDigit(cps[j + 1])) {
                    j++;
                } else {
                    break;
                }
            }
            runs.add(positions.stream().mapToInt(Integer::intValue).toArray());
            i = j;
        }
        return runs;
    }

    /**
     * For every digit of {@code run} that starts a group (the run's first digit, or one after a
     * separator), the first of {@code lengths} (longest first) whose window ends at a group end and
     * passes {@code check} goes to {@code sink} as a code-point span; then the next start.
     */
    static void checkWindows(int[] cps, int[] run, int[] lengths, WindowCheck check, WindowSink sink) {
        int shortest = Integer.MAX_VALUE;
        for (int n : lengths) {
            shortest = Math.min(shortest, n);
        }
        if (run.length < shortest) {
            return;
        }
        String digits = digitString(cps, run);
        for (int k = 0; k + shortest <= run.length; k++) {
            if (k > 0 && run[k] == run[k - 1] + 1) {
                continue; // not the first digit of a group
            }
            for (int n : lengths) {
                int last = k + n - 1;
                if (last >= run.length || (last + 1 < run.length && run[last + 1] == run[last] + 1)) {
                    continue; // past the run, or ends inside a group
                }
                if (check.test(digits.substring(k, k + n), n)) {
                    sink.accept(run[k], run[last] + 1, n);
                    break;
                }
            }
        }
    }

    /** The run's digits as ASCII (any Unicode decimal digit counts). */
    private static String digitString(int[] cps, int[] run) {
        StringBuilder b = new StringBuilder(run.length);
        for (int p : run) {
            b.append((char) ('0' + Character.digit(cps[p], 10)));
        }
        return b.toString();
    }

    private static boolean hasBracket(String text) {
        return text.indexOf('[') >= 0 || text.indexOf('(') >= 0 || text.indexOf('{') >= 0;
    }

    private static boolean isBlank(int cp) {
        return Character.isWhitespace(cp) || Character.isSpaceChar(cp);
    }

    private static boolean overlapsAny(List<ChatSpan> spans, int start, int end) {
        for (ChatSpan s : spans) {
            if (start < s.end() && s.start() < end) {
                return true;
            }
        }
        return false;
    }

    private static void add(List<ChatSpan> out, PyPattern p, String text, int group, PiiType type, String name) {
        for (PyMatch m : p.finditer(text)) {
            out.add(new ChatSpan(m.start(group), m.end(group), type, name));
        }
    }

    /** The .docx detectors over the text as one in-memory paragraph; PRESERVE proposals are dropped. */
    private List<ChatSpan> reused(String text) {
        TextUnit unit = new TextUnit("chat", "chat", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
        List<Span> spans = new ArrayList<>();
        spans.addAll(Detectors.detectStructuredIds(unit, rules));
        spans.addAll(Detectors.detectContacts(unit, rules));
        spans.addAll(Detectors.detectBankPaymentIds(unit));
        List<ChatSpan> out = new ArrayList<>();
        for (Span s : spans) {
            if (s.action() == SpanAction.PRESERVE) {
                continue;
            }
            PiiType type = switch (s.category()) {
                case AFM -> PiiType.AFM;
                case AMKA -> PiiType.AMKA;
                case IBAN -> PiiType.IBAN;
                case EMAIL -> PiiType.EMAIL;
                case PHONE -> PiiType.PHONE;
                case BANK_ACCOUNT -> PiiType.BANK_ACCOUNT;
                case PRIVATE_BENEFICIARY -> PiiType.PERSON;
                default -> null; // e.g. a bank's NAME after "Τράπεζα": public in chat
            };
            if (type != null) {
                out.add(new ChatSpan(s.start(), s.end(), type, s.detector()));
            }
        }
        return out;
    }
}
