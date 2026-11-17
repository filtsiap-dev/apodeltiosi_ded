package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import dev.filtsiap.ded.anonymizer.pycompat.PyRegex.PyPattern;

/**
 * Whitespace on both sides of an optional character ({@code \s*[:.]?\s*}) makes a regex try every split of a long
 * whitespace run between the two {@code \s*} before it fails: n² steps, 23 s for "ΑΦΜ" and 20,000 spaces.
 * {@code \s*(?:[:.]\s*)?} matches the same text in linear time.
 */
class RegexBacktrackingTest {
    /** The quadratic shape as written in a Java string literal ({@code \\s*:?\\s*}) or in YAML ({@code \s*:?\s*}). */
    private static final Pattern SPLIT_WHITESPACE =
            Pattern.compile("(\\\\{1,2})s[*+](?:\\[[^\\]]+\\]|\\\\{1,2}.|[^\\\\\\[(])\\?\\1s[*+]");
    private static final int SPACES = 50_000;

    @Test
    void noPatternPutsWhitespaceOnBothSidesOfAnOptionalCharacter() throws IOException {
        List<String> found = new ArrayList<>();
        for (Path root : List.of(Path.of("src", "main", "java"), Path.of("config"))) {
            try (Stream<Path> files = Files.walk(root)) {
                for (Path f : files.filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".yaml"))
                        .toList()) {
                    List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
                    for (int i = 0; i < lines.size(); i++) {
                        if (SPLIT_WHITESPACE.matcher(lines.get(i)).find()) {
                            found.add(f + ":" + (i + 1));
                        }
                    }
                }
            }
        }
        assertEquals(List.of(), found);
    }

    @Test
    void theShapeCheckFindsTheQuadraticForms() {
        for (String bad : List.of("\\\\s*[:.]?\\\\s*", "\\s*[:.]?\\s*", "\\\\s*:?\\\\s*", "\\\\s*,?\\\\s*",
                "\\\\s*[:.\\\\-]?\\\\s*")) {
            assertEquals(true, SPLIT_WHITESPACE.matcher(bad).find(), bad);
        }
        for (String good : List.of("\\\\s*(?:[:.]\\\\s*)?", "[\\\\s:]{0,8}", "\\\\s?(?:\\\\[at\\\\])\\\\s?")) {
            assertEquals(false, SPLIT_WHITESPACE.matcher(good).find(), good);
        }
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ΑΦΜ", "ΑΜΚΑ", "αρ. πρωτ.", "Συναλλαγή", "ΚΑΕΚ", "ΑΤΑΚ", "Ο.Τ.", "Α.Χ.Κ.", "Τ.Κ.",
            "αριθμό ειδοποίησης", "ΓΕΜΗ", "οδός", "κάτοικος", "με έδρα", "οδός Ερμού", "οδός Ερμού αρ.",
            "με έδρα επί της Ερμού", "κάτοικος Αθηνών,"})
    void aLabelBeforeALongWhitespaceRunIsFast(String label) {
        String text = label + " ".repeat(SPACES) + "x";
        DocumentData doc = new DocumentData("d", List.of(DetectorsTest.unit(text)), List.of(), List.of());
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> Detectors.detectAll(doc, DetectorsTest.RULES));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ΑΦΜ", "ΑΜΚΑ", "ΓΕΜΗ", "αριθμό φύλλου"})
    void thePostCheckIsFastOnALongWhitespaceRun(String label) {
        String text = label + " ".repeat(SPACES) + "x";
        List<PyPattern> patterns = new ArrayList<>(PostcheckPatterns.QA_PATTERNS.values());
        patterns.add(PostcheckPatterns.REGISTRY_LEAK_RE);
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> patterns.forEach(p -> p.finditer(text)));
    }
}
