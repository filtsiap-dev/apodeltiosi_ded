package dev.filtsiap.ded.anonymizer.pycompat;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Compiles Python {@code re} patterns (str patterns, Python 3 semantics) into Java patterns
 * that match the same text, and reports match offsets in code points.
 *
 * <p>Why a translator instead of {@code Pattern.UNICODE_CHARACTER_CLASS}: Java's Unicode
 * {@code \w} includes combining marks and excludes superscript/other digits, while Python's
 * {@code \w} is exactly {@code str.isalnum() or "_"} = categories L* and N* plus underscore.
 * {@code \s} is Python's {@code isspace()} set, which includes U+001C..U+001F. Rewriting the
 * escapes to explicit classes gives identical behaviour. Also handled: {@code (?P<name>)},
 * {@code (?P=name)}, {@code \Z}, literal {@code [}/{@code &} inside classes, literal
 * {@code {}} that is not a quantifier, and {@code {,m}}.
 *
 * <p>All patterns get {@code UNICODE_CASE} (so {@code (?i)} and {@code IGNORECASE} fold Greek
 * like Python) and {@code UNIX_LINES} (so {@code .} and {@code $} treat only {@code \n} as a
 * line terminator, like Python).
 */
public final class PyRegex {

    /** Python {@code re.IGNORECASE}. */
    public static final int IGNORECASE = 2;
    /** Python {@code re.DOTALL}. */
    public static final int DOTALL = 16;

    private static final String WORD = "\\p{L}\\p{N}_";
    private static final String WORD_CLASS = "[" + WORD + "]";
    private static final String NON_WORD_CLASS = "[^" + WORD + "]";
    private static final String SPACE_CLASS = "[" + PyUnicode.SPACE_CLASS_BODY + "]";
    private static final String NON_SPACE_CLASS = "[^" + PyUnicode.SPACE_CLASS_BODY + "]";
    private static final String BOUNDARY =
            "(?:(?<=" + WORD_CLASS + ")(?!" + WORD_CLASS + ")|(?<!" + WORD_CLASS + ")(?=" + WORD_CLASS + "))";
    private static final String NON_BOUNDARY =
            "(?:(?<=" + WORD_CLASS + ")(?=" + WORD_CLASS + ")|(?<!" + WORD_CLASS + ")(?!" + WORD_CLASS + "))";
    private static final Pattern QUANTIFIER = Pattern.compile("\\{(\\d*)(,(\\d*))?}");

    private PyRegex() {
    }

    /** Python {@code re.compile(pattern, flags)}. */
    public static PyPattern compile(String pattern, int flags) {
        int javaFlags = Pattern.UNICODE_CASE | Pattern.UNIX_LINES;
        if ((flags & IGNORECASE) != 0) {
            javaFlags |= Pattern.CASE_INSENSITIVE;
        }
        if ((flags & DOTALL) != 0) {
            javaFlags |= Pattern.DOTALL;
        }
        try {
            return new PyPattern(pattern, flags, Pattern.compile(translate(pattern), javaFlags));
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("invalid regular expression: " + e.getDescription(), e);
        }
    }

    /** Python {@code re.compile(pattern)}. */
    public static PyPattern compile(String pattern) {
        return compile(pattern, 0);
    }

    /** Python {@code re.escape(s)}. */
    public static String escape(String s) {
        StringBuilder out = new StringBuilder();
        s.codePoints().forEach(cp -> {
            // Python escapes exactly this ASCII set; everything else is literal.
            if (cp < 128 && "()[]{}?*+-|^$\\.&~# \t\n\r\u000B\u000C".indexOf(cp) >= 0) {
                out.append('\\');
            }
            out.appendCodePoint(cp);
        });
        return out.toString();
    }

    /** Rewrites a Python pattern into equivalent Java syntax. Package-private for tests. */
    static String translate(String p) {
        StringBuilder out = new StringBuilder(p.length() + 16);
        int i = 0;
        int n = p.length();
        boolean inClass = false;
        boolean classJustOpened = false;
        while (i < n) {
            char c = p.charAt(i);
            if (c == '\\') {
                if (i + 1 >= n) {
                    throw new IllegalArgumentException("bad escape (end of pattern)");
                }
                char d = p.charAt(i + 1);
                out.append(inClass ? classEscape(d) : escape(d));
                i += 2;
                classJustOpened = false;
                continue;
            }
            if (inClass) {
                if (c == ']' && !classJustOpened) {
                    inClass = false;
                    out.append(']');
                } else if (c == ']' || c == '[' || c == '&') {
                    out.append('\\').append(c);
                } else {
                    out.append(c);
                }
                classJustOpened = false;
                i++;
                continue;
            }
            switch (c) {
                case '[' -> {
                    inClass = true;
                    classJustOpened = true;
                    out.append('[');
                    if (i + 1 < n && p.charAt(i + 1) == '^') {
                        out.append('^');
                        i++;
                    }
                    i++;
                }
                case '(' -> {
                    if (p.startsWith("(?P<", i)) {
                        int close = p.indexOf('>', i);
                        out.append("(?<").append(javaGroupName(p.substring(i + 4, close))).append('>');
                        i = close + 1;
                    } else if (p.startsWith("(?P=", i)) {
                        int close = p.indexOf(')', i);
                        out.append("\\k<").append(javaGroupName(p.substring(i + 4, close))).append('>');
                        i = close + 1;
                    } else {
                        out.append('(');
                        i++;
                    }
                }
                case '{' -> {
                    Matcher q = QUANTIFIER.matcher(p).region(i, n);
                    if (q.lookingAt() && !(q.group(1).isEmpty() && q.group(2) == null)) {
                        String min = q.group(1).isEmpty() ? "0" : q.group(1);
                        out.append('{').append(min);
                        if (q.group(2) != null) {
                            out.append(',').append(q.group(3));
                        }
                        out.append('}');
                        i = q.end();
                    } else {
                        out.append("\\{");
                        i++;
                    }
                }
                case '}' -> {
                    out.append("\\}");
                    i++;
                }
                default -> {
                    out.append(c);
                    i++;
                }
            }
        }
        if (inClass) {
            throw new IllegalArgumentException("unterminated character set");
        }
        return out.toString();
    }

    private static String escape(char d) {
        return switch (d) {
            case 'w' -> WORD_CLASS;
            case 'W' -> NON_WORD_CLASS;
            case 'd' -> "\\p{Nd}";
            case 'D' -> "\\P{Nd}";
            case 's' -> SPACE_CLASS;
            case 'S' -> NON_SPACE_CLASS;
            case 'b' -> BOUNDARY;
            case 'B' -> NON_BOUNDARY;
            case 'Z' -> "\\z";
            default -> "\\" + d;
        };
    }

    private static String classEscape(char d) {
        return switch (d) {
            case 'w' -> WORD;
            case 'W' -> NON_WORD_CLASS;
            case 'd' -> "\\p{Nd}";
            case 'D' -> "\\P{Nd}";
            case 's' -> PyUnicode.SPACE_CLASS_BODY;
            case 'S' -> NON_SPACE_CLASS;
            case 'b' -> "\\x08";
            default -> "\\" + d;
        };
    }

    private static String javaGroupName(String pythonName) {
        // Java group names are [A-Za-z][A-Za-z0-9]*; Python allows underscores.
        return "g" + pythonName.replace("_", "U");
    }

    // ------------------------------------------------------------------ results

    /**
     * Java can report an empty match between the two halves of a surrogate pair, a position
     * that does not exist in Python's code-point string. Such matches are skipped.
     */
    static boolean splitsSurrogatePair(String text, int utf16Start) {
        return utf16Start > 0 && utf16Start < text.length()
                && Character.isLowSurrogate(text.charAt(utf16Start))
                && Character.isHighSurrogate(text.charAt(utf16Start - 1));
    }

    /** A compiled Python pattern. */
    public static final class PyPattern {
        private final String source;
        private final int flags;
        private final Pattern pattern;

        PyPattern(String source, int flags, Pattern pattern) {
            this.source = source;
            this.flags = flags;
            this.pattern = pattern;
        }

        /** The original Python pattern text. */
        public String pattern() {
            return source;
        }

        /** The Python flags it was compiled with. */
        public int flags() {
            return flags;
        }

        /** Python {@code pattern.finditer(text)}, fully materialized. */
        public List<PyMatch> finditer(String text) {
            List<PyMatch> matches = new ArrayList<>();
            Matcher m = pattern.matcher(text);
            while (m.find()) {
                if (!splitsSurrogatePair(text, m.start())) {
                    matches.add(PyMatch.of(text, m));
                }
            }
            return matches;
        }

        /** Python {@code pattern.search(text)}. */
        public PyMatch search(String text) {
            Matcher m = pattern.matcher(text);
            while (m.find()) {
                if (!splitsSurrogatePair(text, m.start())) {
                    return PyMatch.of(text, m);
                }
            }
            return null;
        }

        /** True when {@code search(text)} finds a match. */
        public boolean found(String text) {
            return search(text) != null;
        }

        /** Python {@code pattern.match(text)}: anchored at the start. */
        public PyMatch match(String text) {
            Matcher m = pattern.matcher(text);
            return m.lookingAt() ? PyMatch.of(text, m) : null;
        }

        /** Python {@code pattern.fullmatch(text)}. */
        public PyMatch fullmatch(String text) {
            Matcher m = pattern.matcher(text);
            return m.matches() ? PyMatch.of(text, m) : null;
        }

        /** Python {@code len(pattern.findall(text))}. */
        public int countAll(String text) {
            int count = 0;
            Matcher m = pattern.matcher(text);
            while (m.find()) {
                if (!splitsSurrogatePair(text, m.start())) {
                    count++;
                }
            }
            return count;
        }

        /** Python {@code pattern.findall(text)} for a pattern without groups: the matched strings. */
        public List<String> findallStrings(String text) {
            List<String> found = new ArrayList<>();
            Matcher m = pattern.matcher(text);
            while (m.find()) {
                if (!splitsSurrogatePair(text, m.start())) {
                    found.add(m.group());
                }
            }
            return found;
        }

        /** Python {@code pattern.sub(literal, text)} with a replacement that has no backslashes. */
        public String subLiteral(String replacement, String text) {
            return pattern.matcher(text).replaceAll(Matcher.quoteReplacement(replacement));
        }

        /** Python {@code pattern.sub(fn, text)}. */
        public String sub(Function<PyMatch, String> fn, String text) {
            Matcher m = pattern.matcher(text);
            return m.replaceAll(r -> Matcher.quoteReplacement(fn.apply(PyMatch.of(text, r))));
        }
    }

    /** A Python match object; every offset is a code-point index. */
    public static final class PyMatch {
        private final String[] groups;
        private final int[] starts;
        private final int[] ends;

        private PyMatch(String[] groups, int[] starts, int[] ends) {
            this.groups = groups;
            this.starts = starts;
            this.ends = ends;
        }

        static PyMatch of(String text, java.util.regex.MatchResult m) {
            int count = m.groupCount() + 1;
            String[] groups = new String[count];
            int[] starts = new int[count];
            int[] ends = new int[count];
            for (int g = 0; g < count; g++) {
                groups[g] = m.group(g);
                if (m.start(g) < 0) {
                    starts[g] = -1;
                    ends[g] = -1;
                } else {
                    starts[g] = PyStr.toCodePoint(text, m.start(g));
                    ends[g] = PyStr.toCodePoint(text, m.end(g));
                }
            }
            return new PyMatch(groups, starts, ends);
        }

        /** Python {@code m.group(0)}. */
        public String group() {
            return groups[0];
        }

        /** Python {@code m.group(g)}; null when the group did not participate. Throws for a missing group. */
        public String group(int g) {
            checkGroup(g);
            return groups[g];
        }

        /** Python {@code m.start()}. */
        public int start() {
            return starts[0];
        }

        /** Python {@code m.end()}. */
        public int end() {
            return ends[0];
        }

        /** Python {@code m.start(g)}; -1 when the group did not participate. */
        public int start(int g) {
            checkGroup(g);
            return starts[g];
        }

        /** Python {@code m.end(g)}; -1 when the group did not participate. */
        public int end(int g) {
            checkGroup(g);
            return ends[g];
        }

        /** Number of capture groups (Python {@code len(m.groups())}). */
        public int groupCount() {
            return groups.length - 1;
        }

        private void checkGroup(int g) {
            if (g < 0 || g >= groups.length) {
                // Python raises IndexError("no such group").
                throw new IndexOutOfBoundsException("no such group");
            }
        }

        @Override
        public String toString() {
            return "PyMatch[" + starts[0] + ", " + ends[0] + ")";
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof PyMatch other && java.util.Arrays.equals(starts, other.starts)
                    && java.util.Arrays.equals(ends, other.ends);
        }

        @Override
        public int hashCode() {
            return Objects.hash(java.util.Arrays.hashCode(starts), java.util.Arrays.hashCode(ends));
        }
    }
}
