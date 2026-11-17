package dev.filtsiap.ded.anonymizer.chat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;

import dev.filtsiap.ded.anonymizer.ConfigurationError;

/**
 * An immutable set of FOLDED words in two flat arrays: every word's chars back to back, and each
 * word's start offset. Sorted in String order, so a lookup is a binary search, and a million words
 * cost about the characters they contain instead of a String object each.
 */
public final class WordSet {
    private static final String GREEK_LETTERS = "αβγδεζηθικλμνξοπρστυφχψω";

    private final char[] chars;
    /** Word i is chars[starts[i] .. starts[i + 1]); starts.length == size() + 1. */
    private final int[] starts;

    private WordSet(char[] chars, int[] starts) {
        this.chars = chars;
        this.starts = starts;
    }

    /**
     * Folds, drops blanks, dedupes and sorts {@code words}. For small lists and tests.
     *
     * @param words the words, in any form
     * @return the set
     */
    public static WordSet of(Collection<String> words) {
        TreeSet<String> sorted = new TreeSet<>();
        for (String w : words) {
            String folded = GreekFold.fold(w.strip());
            if (!folded.isEmpty()) {
                sorted.add(folded);
            }
        }
        Builder b = new Builder();
        sorted.forEach(b::add);
        return b.build();
    }

    /**
     * A generated list: one word per line, already folded, strictly increasing in String order (so
     * no duplicates). Streams the file, so loading never holds a String per word. A violation is a
     * ConfigurationError: the file was edited by hand or built by an older builder.
     *
     * @param path the list file, plain or gzip (by its .gz name)
     * @return the set
     * @throws ConfigurationError when the file cannot be read, is not folded or is not strictly sorted
     */
    public static WordSet loadSorted(Path path) {
        Builder b = new Builder();
        String previous = null;
        try (BufferedReader in = reader(path)) {
            String line;
            int lineNo = 0;
            while ((line = in.readLine()) != null) {
                lineNo++;
                if (line.isEmpty()) {
                    continue;
                }
                if (!GreekFold.fold(line).equals(line)) {
                    throw new ConfigurationError(path + ":" + lineNo + " is not folded; rebuild the chat lists");
                }
                if (previous != null && previous.compareTo(line) >= 0) {
                    throw new ConfigurationError(path + ":" + lineNo + " is out of order; rebuild the chat lists");
                }
                b.add(line);
                previous = line;
            }
        } catch (IOException e) {
            throw new ConfigurationError("cannot read " + path + ": " + e.getMessage(), e);
        }
        return b.build();
    }

    /**
     * A hand-kept list: '#' starts a comment, blank lines are skipped, any order, folded on load.
     *
     * @param path the list file
     * @return the set
     * @throws ConfigurationError when the file cannot be read
     */
    public static WordSet loadList(Path path) {
        List<String> words = new ArrayList<>();
        try (BufferedReader in = reader(path)) {
            String line;
            while ((line = in.readLine()) != null) {
                int hash = line.indexOf('#');
                String word = (hash < 0 ? line : line.substring(0, hash)).strip();
                if (!word.isEmpty()) {
                    words.add(word);
                }
            }
        } catch (IOException e) {
            throw new ConfigurationError("cannot read " + path + ": " + e.getMessage(), e);
        }
        return of(words);
    }

    private static BufferedReader reader(Path path) throws IOException {
        InputStream raw = Files.newInputStream(path);
        InputStream in = path.getFileName().toString().endsWith(".gz") ? new GZIPInputStream(raw, 1 << 16) : raw;
        return new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 1 << 16);
    }

    /**
     * The number of words.
     *
     * @return the count
     */
    public int size() {
        return starts.length - 1;
    }

    /**
     * Whether the set has the word.
     *
     * @param folded the word, folded
     * @return true when present
     */
    public boolean contains(String folded) {
        int lo = 0;
        int hi = size() - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            int c = compareAt(mid, folded);
            if (c < 0) {
                lo = mid + 1;
            } else if (c > 0) {
                hi = mid - 1;
            } else {
                return true;
            }
        }
        return false;
    }

    /** Sign of (word i − s) in String order. */
    private int compareAt(int i, String s) {
        int a = starts[i];
        int aEnd = starts[i + 1];
        int b = 0;
        while (a < aEnd && b < s.length()) {
            int d = chars[a++] - s.charAt(b++);
            if (d != 0) {
                return d;
            }
        }
        return (aEnd - a) - (s.length() - b);
    }

    /**
     * Whether a word within one substitution, insertion, deletion or adjacent swap (Greek letters)
     * is in the set.
     *
     * @param w the word, folded
     * @return true when {@code w} or a word one edit away is present
     */
    public boolean containsWithinOneEdit(String w) {
        if (contains(w)) {
            return true;
        }
        for (int i = 0; i < w.length(); i++) {
            if (contains(w.substring(0, i) + w.substring(i + 1))) {
                return true;
            }
        }
        for (int i = 0; i + 1 < w.length(); i++) {
            char[] c = w.toCharArray();
            char t = c[i];
            c[i] = c[i + 1];
            c[i + 1] = t;
            if (contains(new String(c))) {
                return true;
            }
        }
        for (int i = 0; i <= w.length(); i++) {
            for (int k = 0; k < GREEK_LETTERS.length(); k++) {
                char ch = GREEK_LETTERS.charAt(k);
                if (contains(w.substring(0, i) + ch + w.substring(i))) {
                    return true;
                }
                if (i < w.length() && w.charAt(i) != ch && contains(w.substring(0, i) + ch + w.substring(i + 1))) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Bytes held by the two arrays (object headers aside).
     *
     * @return the byte count
     */
    public long footprintBytes() {
        return chars.length * 2L + starts.length * 4L;
    }

    /** Every word, in order. Allocates a String per word: for small lists only. */
    List<String> words() {
        List<String> out = new ArrayList<>(size());
        for (int i = 0; i < size(); i++) {
            out.add(new String(chars, starts[i], starts[i + 1] - starts[i]));
        }
        return out;
    }

    /** Appends words in order into growing arrays. */
    private static final class Builder {
        private char[] chars = new char[1 << 12];
        private int[] starts = new int[1 << 10];
        private int size;
        private int used;

        void add(String w) {
            if (used + w.length() > chars.length) {
                chars = Arrays.copyOf(chars, Math.max(chars.length * 2, used + w.length()));
            }
            if (size + 2 > starts.length) {
                starts = Arrays.copyOf(starts, starts.length * 2);
            }
            starts[size++] = used;
            w.getChars(0, w.length(), chars, used);
            used += w.length();
        }

        WordSet build() {
            starts[size] = used;
            return new WordSet(Arrays.copyOf(chars, used), Arrays.copyOf(starts, size + 1));
        }
    }
}
