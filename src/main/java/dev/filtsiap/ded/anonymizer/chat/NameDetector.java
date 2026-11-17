package dev.filtsiap.ded.anonymizer.chat;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyMatch;
import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;

/**
 * Person names in chat text, by four kinds of evidence, strongest first: a cue ("με λένε",
 * "κύριε", "Υπογραφή:"), the name lists, the lexicons (a word that is not ordinary Greek or English
 * is masked: that is how unusual names are caught), and position (next to a masked name, or after
 * an article). A confirmed name is then masked in all its forms across the text.
 */
public final class NameDetector {
    /** On the FOLDED text. */
    static final PyPattern NAME_CUE = PyRegex.compile(
            "(?<!\\w)(?:με\\s+λενε|με\\s+λεν|(?:τον|την|τη)\\s+λενε"
                    + "|(?:ονομα|επωνυμο|ονοματεπωνυμο|αιτων|αιτουσα)\\s?:"
                    + "|λεγομαι|ονομαζομαι|το\\s+ονομα\\s+μου\\s+ειναι|ειμαι\\s+[οη]"
                    + "|κυριε|κυρια|κυριο|κυριου|κυριασ|κοσ|κα\\.?|κ\\.|υπογραφη\\s*:?|εκ\\s+μερουσ\\s+(?:του|τησ)"
                    + "|ευχαριστω|ευχαριστουμε|στο\\s+ονομα|κουδουνι|i['’]?m|my\\s+name\\s+is|mr\\.?|mrs\\.?|ms\\.?)"
                    + "(?=\\s|$)", 0);
    static final PyPattern SURNAME_ENDING = PyRegex.compile(
            "(?:οπουλοσ|οπουλου|οπουλο|ακησ|ακη|ιδησ|ιδη|ιδου|ιαδησ|ιαδη|αδησ|αδη|ογλου|ελλησ|ιωτησ|ιωτη"
                    + "|ουδησ|ουδη|αιοσ|αιου)$", 0);
    /** The endings so rare in ordinary words that a capitalised ordinary word with one is still a surname. */
    static final PyPattern STRONG_SURNAME_ENDING = PyRegex.compile(
            "(?:οπουλοσ|οπουλου|οπουλο|ιαδησ|ιαδη|ογλου)$", 0);
    /**
     * "ΚΩΝ/ΝΟΣ" and "ΚΩΝ/ΝΑ": the usual abbreviation of Κωνσταντίνος and Κωνσταντίνα, in any case ending, on the
     * FOLDED text. The '/' splits it into two words that no name list holds ("ΚΩΝ", "ΝΑ" is even a common word), so
     * it is matched whole. Latin look-alikes (K, N, o, e, a) are accepted for each letter.
     */
    static final PyPattern NAME_ABBREVIATION = PyRegex.compile(
            "(?<!\\w)[κk]ω[νn]\\s?/\\s?[νn](?:[οo][σs]|[οo]υ|[οo]|[εe]|[αa][σs]|[αa])(?!\\w)", 0);
    private static final Set<String> ARTICLES = Set.of("ο", "η", "του", "τησ", "τον", "την", "τη");
    private static final Set<String> SAINT_WORDS = Set.of("αγιοσ", "αγιου", "αγιο", "αγια", "αγιασ", "αγιων",
            "αγιε", "αγ");
    private static final int MAX_CUE_TOKENS = 3;
    private static final int TYPO_MIN_LENGTH = 6;
    /** Longer tokens are never typo-checked: the one-edit search is quadratic in the length. */
    private static final int TYPO_MAX_LENGTH = 30;
    private static final String CLAUSE_BREAKS = ",;:!?()«»\"\r\n";

    /** {@code letters}: code points of {@code folded} (format characters dropped), not end - start. */
    record Token(int start, int end, String folded, int letters, boolean capitalised, boolean allCaps,
                 boolean sentenceInitial, boolean greek) {
        int length() {
            return letters;
        }
    }

    private final ChatLists lists;

    /**
     * Creates the detector.
     *
     * @param lists the name and word lists
     */
    public NameDetector(ChatLists lists) {
        this.lists = lists;
    }

    /**
     * Finds the personal names in {@code text}, in all their forms.
     *
     * @param text the chat text, NFC-normalised
     * @return the spans to mask, in no particular order; they may overlap
     */
    public List<ChatSpan> detect(String text) {
        String folded = GreekFold.fold(text);
        int[] cps = text.codePoints().toArray();
        List<Token> tokens = tokenize(text, folded, cps);
        String[] verdict = new String[tokens.size()];
        boolean[] confident = new boolean[tokens.size()];

        applyNameAbbreviations(folded, tokens, verdict);
        applyCues(folded, cps, tokens, verdict, confident);
        applyLists(cps, tokens, verdict, confident);
        applyNeighbours(cps, tokens, verdict, confident);
        applyPropagation(cps, tokens, verdict, confident);

        List<ChatSpan> out = new ArrayList<>();
        for (int i = 0; i < tokens.size(); i++) {
            if (verdict[i] != null) {
                out.add(new ChatSpan(tokens.get(i).start(), tokens.get(i).end(), PiiType.PERSON, verdict[i]));
            }
        }
        return out;
    }

    /**
     * Tokens are runs of letters in any script, with the combining marks that follow them and any
     * format character (soft hyphen, zero-width space/joiners) BETWEEN two letters: "Παπα­δόπουλος"
     * is one token. The token covers every original code point; its folded form drops the format
     * characters so the lists still match.
     */
    static List<Token> tokenize(String text, String folded, int[] cps) {
        int[] foldedCps = folded.codePoints().toArray();
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        while (i < cps.length) {
            if (!Character.isLetter(cps[i])) {
                i++;
                continue;
            }
            int s = i;
            int e = i + 1;
            while (e < cps.length) {
                if (Character.isLetter(cps[e]) || isMark(cps[e])) {
                    e++;
                    continue;
                }
                int j = e;
                while (j < cps.length && Character.getType(cps[j]) == Character.FORMAT) {
                    j++;
                }
                if (j > e && j < cps.length && Character.isLetter(cps[j])) {
                    e = j;
                } else {
                    break;
                }
            }
            StringBuilder f = new StringBuilder(e - s);
            boolean allCaps = true;
            boolean greek = false;
            for (int k = s; k < e; k++) {
                if (Character.getType(cps[k]) == Character.FORMAT) {
                    continue;
                }
                f.appendCodePoint(foldedCps[k]);
                if (Character.isLetter(cps[k])) {
                    allCaps &= Character.isUpperCase(cps[k]);
                    greek |= Character.UnicodeScript.of(cps[k]) == Character.UnicodeScript.GREEK;
                }
            }
            String foldedToken = f.toString();
            int letters = foldedToken.codePointCount(0, foldedToken.length());
            tokens.add(new Token(s, e, foldedToken, letters, Character.isUpperCase(cps[s]),
                    allCaps && letters > 1, sentenceInitial(cps, s), greek));
            i = e;
        }
        return tokens;
    }

    private static boolean isMark(int cp) {
        int type = Character.getType(cp);
        return type == Character.NON_SPACING_MARK || type == Character.COMBINING_SPACING_MARK
                || type == Character.ENCLOSING_MARK;
    }

    /** No letter or digit before {@code start} since the text began or since . ! ? : ; or a line break. */
    private static boolean sentenceInitial(int[] cps, int start) {
        for (int i = start - 1; i >= 0; i--) {
            int c = cps[i];
            if (c == '.' || c == '!' || c == '?' || c == ':' || c == ';' || c == '\n' || c == '\r') {
                return true;
            }
            if (Character.isLetterOrDigit(c)) {
                return false;
            }
        }
        return true;
    }

    /** Marks both words of every "ΚΩΝ/ΝΟΣ"-style abbreviation; the '/' is not a letter, so it stays visible. */
    private static void applyNameAbbreviations(String folded, List<Token> tokens, String[] verdict) {
        for (PyMatch m : NAME_ABBREVIATION.finditer(folded)) {
            for (int k = firstTokenAtOrAfter(tokens, m.start());
                    k < tokens.size() && tokens.get(k).start() < m.end(); k++) {
                verdict[k] = "name_abbreviation";
            }
        }
    }

    private void applyCues(String folded, int[] cps, List<Token> tokens, String[] verdict, boolean[] confident) {
        for (PyMatch cue : NAME_CUE.finditer(folded)) {
            int k = firstTokenAtOrAfter(tokens, cue.end());
            int prevEnd = cue.end();
            Token prev = null;
            int taken = 0;
            while (k < tokens.size() && taken < MAX_CUE_TOKENS) {
                Token t = tokens.get(k);
                if (breaksBetween(cps, prevEnd, t.start(), prev)) {
                    break;
                }
                if (isInitial(t, cps)) {
                    verdict[k] = "name_cue_initial";
                } else if (t.capitalised() || lists.isName(t.folded()) || !lists.isCommonWord(t.folded())) {
                    verdict[k] = "name_cue";
                    // A capitalised ordinary word is masked here but not propagated elsewhere.
                    confident[k] = lists.isName(t.folded()) || !lists.isCommonWord(t.folded());
                    taken++;
                } else {
                    break;
                }
                prevEnd = t.end();
                prev = t;
                k++;
            }
        }
    }

    private void applyLists(int[] cps, List<Token> tokens, String[] verdict, boolean[] confident) {
        for (int i = 0; i < tokens.size(); i++) {
            Token t = tokens.get(i);
            if (verdict[i] != null || t.length() < 2 || afterSaintWord(cps, tokens, i)) {
                continue;
            }
            String f = t.folded();
            boolean name = lists.isName(f);
            boolean common = lists.isCommonWord(f);
            boolean place = lists.greekProper().contains(f);
            if (name && !common && !place) {
                verdict[i] = "name_list";
                confident[i] = true;
            } else if (hasSurnameEnding(f) && (!common
                    || (t.capitalised() && !isEidisWord(f) && STRONG_SURNAME_ENDING.search(f) != null))) {
                // A surname ending marks a surname even when the word is a place-list entry
                // ("Αγγελάκη"). A capitalised ordinary word needs a strong ending ("Ραφτόπουλος"):
                // the weak ones are common in ordinary words ("Ιδιώτης", "Περιφερειακή").
                verdict[i] = "surname_ending";
                confident[i] = true;
            } else if (name && t.capitalised() && !t.sentenceInitial() && i > 0
                    && ARTICLES.contains(tokens.get(i - 1).folded())
                    && onlySpaces(cps, tokens.get(i - 1).end(), t.start())) {
                verdict[i] = "name_after_article";
                confident[i] = true;
            } else if (!name && !common && !place && !isTypo(t)) {
                verdict[i] = "uncommon_word";
            }
        }
    }

    private boolean isTypo(Token t) {
        return t.greek() && t.length() >= TYPO_MIN_LENGTH && t.length() <= TYPO_MAX_LENGTH
                && !hasSurnameEnding(t.folded())
                && lists.greekCommon().containsWithinOneEdit(t.folded());
    }

    static boolean hasSurnameEnding(String folded) {
        return SURNAME_ENDING.search(folded) != null;
    }

    /**
     * "είδη" and the "-οειδής" adjectives ("σφαιροειδής", "σφαιροειδή") end like "-ίδης": as ordinary
     * words they never count as surnames, even capitalised. A place-list entry ("Μαυροειδή") still does.
     */
    private static boolean isEidisWord(String folded) {
        return folded.endsWith("ειδησ") || folded.endsWith("ειδη");
    }

    /**
     * A capitalised (or initial) token right next to a masked token is masked, and so on outwards.
     * A known name next to a confident name is masked whatever its case or position, so a common-word
     * first name is found in "Σοφία Γεωργίου", "ΣΟΦΙΑ ΓΕΩΡΓΙΟΥ" and at the start of a sentence.
     * Eligibility and adjacency do not depend on the verdicts, so a worklist from every masked
     * token reaches the fixpoint in linear time.
     */
    private void applyNeighbours(int[] cps, List<Token> tokens, String[] verdict, boolean[] confident) {
        Deque<Integer> work = new ArrayDeque<>();
        for (int i = 0; i < tokens.size(); i++) {
            if (verdict[i] != null) {
                work.add(i);
            }
        }
        while (!work.isEmpty()) {
            int i = work.poll();
            for (int j = i - 1; j <= i + 1; j += 2) {
                if (j < 0 || j >= tokens.size() || verdict[j] != null) {
                    continue;
                }
                Token t = tokens.get(j);
                boolean eligible = isInitial(t, cps)
                        || (t.capitalised() && !t.allCaps() && !t.sentenceInitial() && t.length() >= 2)
                        || (confident[i] && t.length() >= 2 && lists.isName(t.folded()));
                if (eligible && !afterSaintWord(cps, tokens, j)
                        && (j < i ? adjacent(cps, t, tokens.get(i)) : adjacent(cps, tokens.get(i), t))) {
                    verdict[j] = "name_adjacent";
                    work.add(j);
                }
            }
        }
    }

    private static void applyPropagation(int[] cps, List<Token> tokens, String[] verdict, boolean[] confident) {
        Set<String> family = new HashSet<>();
        for (int i = 0; i < tokens.size(); i++) {
            if (confident[i] && tokens.get(i).length() >= 3) {
                family.addAll(GreekInflection.family(tokens.get(i).folded()));
            }
        }
        for (int i = 0; i < tokens.size(); i++) {
            Token t = tokens.get(i);
            if (verdict[i] == null && t.length() >= 3 && family.contains(t.folded())
                    && !afterSaintWord(cps, tokens, i)) {
                verdict[i] = "name_propagated";
            }
        }
    }

    /** Binary search: tokens are in text order, so a text with thousands of cues stays linear-ish. */
    private static int firstTokenAtOrAfter(List<Token> tokens, int pos) {
        int lo = 0;
        int hi = tokens.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (tokens.get(mid).start() < pos) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    /** A single capital letter directly followed by '.': "Μ." in "Γιώργος Μ. Παπαδόπουλος". */
    private static boolean isInitial(Token t, int[] cps) {
        return t.length() == 1 && t.capitalised() && t.end() < cps.length && cps[t.end()] == '.';
    }

    /** Between two tokens: only spaces/tabs or one hyphen; or '.' and spaces after an initial. */
    private static boolean adjacent(int[] cps, Token a, Token b) {
        int dots = 0;
        int hyphens = 0;
        for (int i = a.end(); i < b.start(); i++) {
            int c = cps[i];
            if (c == '.') {
                dots++;
            } else if (c == '-') {
                hyphens++;
            } else if (c != ' ' && c != '\t') {
                return false;
            }
        }
        return hyphens <= 1 && (dots == 0 || (dots == 1 && isInitial(a, cps)));
    }

    /** Clause punctuation between {@code from} and {@code to}, or a '.' that does not follow an initial. */
    private static boolean breaksBetween(int[] cps, int from, int to, Token prev) {
        for (int i = from; i < to; i++) {
            int c = cps[i];
            if (CLAUSE_BREAKS.indexOf(c) >= 0) {
                return true;
            }
            if (c == '.' && !(prev != null && isInitial(prev, cps) && i == prev.end())) {
                return true;
            }
        }
        return false;
    }

    private static boolean onlySpaces(int[] cps, int from, int to) {
        for (int i = from; i < to; i++) {
            if (cps[i] != ' ' && cps[i] != '\t') {
                return false;
            }
        }
        return true;
    }

    private static boolean afterSaintWord(int[] cps, List<Token> tokens, int i) {
        if (i == 0 || !SAINT_WORDS.contains(tokens.get(i - 1).folded())) {
            return false;
        }
        for (int c = tokens.get(i - 1).end(); c < tokens.get(i).start(); c++) {
            if (cps[c] != ' ' && cps[c] != '.') {
                return false;
            }
        }
        return true;
    }
}
