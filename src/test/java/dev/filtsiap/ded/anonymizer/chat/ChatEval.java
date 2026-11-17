package dev.filtsiap.ded.anonymizer.chat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dev.filtsiap.ded.anonymizer.RunContext;

/** Loads eval/chat-anonymization/dataset.jsonl and scores a pipeline on it (README: "Scoring"). */
final class ChatEval {
    static final Path DATASET = Path.of("eval", "chat-anonymization", "dataset.jsonl");
    static final Path REPORT_DIR = Path.of("target", "chat-eval");

    record Item(String text, String type) {
    }

    record Entry(String id, String group, String text, List<Item> mustMask, List<String> mustKeep,
                 List<String> mayMask) {
    }

    record Leak(Entry entry, Item item) {
    }

    record OverMask(Entry entry, String keep) {
    }

    record Report(String mode, int mustMaskTotal, int mustKeepTotal, List<Leak> leaks, List<OverMask> overMasks,
                  long maskedChars, long maskedCharsExpected, Map<String, int[]> byType, Map<String, int[]> byGroup,
                  Map<String, String> outputs) {

        double leakRate() {
            return mustMaskTotal == 0 ? 0 : (double) leaks.size() / mustMaskTotal;
        }

        double overMaskRate() {
            return mustKeepTotal == 0 ? 0 : (double) overMasks.size() / mustKeepTotal;
        }

        double charPrecision() {
            return maskedChars == 0 ? 1 : (double) maskedCharsExpected / maskedChars;
        }

        String markdown() {
            StringBuilder b = new StringBuilder();
            b.append("# Chat eval: ").append(mode).append("\n\n");
            b.append(String.format("| Metric | Value |%n|---|---|%n| Leak rate | %d / %d (%.1f%%) |%n"
                            + "| Over-mask rate | %d / %d (%.1f%%) |%n| Character precision | %.1f%% |%n%n",
                    leaks.size(), mustMaskTotal, 100 * leakRate(), overMasks.size(), mustKeepTotal,
                    100 * overMaskRate(), 100 * charPrecision()));
            b.append("## Recall by type\n\n| Type | Caught | Total |\n|---|---|---|\n");
            byType.forEach((t, v) -> b.append("| ").append(t).append(" | ").append(v[0]).append(" | ")
                    .append(v[1]).append(" |\n"));
            b.append("\n## Recall by group\n\n| Group | Caught | Total |\n|---|---|---|\n");
            byGroup.forEach((g, v) -> b.append("| ").append(g).append(" | ").append(v[0]).append(" | ")
                    .append(v[1]).append(" |\n"));
            b.append("\n## Leaks\n\n");
            leaks.forEach(l -> b.append("- ").append(l.entry().id()).append(" ").append(l.item().type())
                    .append(" `").append(l.item().text()).append("` → `").append(outputs.get(l.entry().id()))
                    .append("`\n"));
            b.append("\n## Over-masked\n\n");
            overMasks.forEach(o -> b.append("- ").append(o.entry().id()).append(" `").append(o.keep())
                    .append("` → `").append(outputs.get(o.entry().id())).append("`\n"));
            return b.toString();
        }
    }

    private ChatEval() {
    }

    static List<Entry> load(Path path) {
        ObjectMapper json = new ObjectMapper();
        List<Entry> out = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode n = json.readTree(line);
                List<Item> mustMask = new ArrayList<>();
                n.get("must_mask").forEach(i -> mustMask.add(new Item(i.get("text").asText(), i.get("type").asText())));
                out.add(new Entry(n.get("id").asText(), n.get("group").asText(), n.get("text").asText(), mustMask,
                        strings(n.get("must_keep")), strings(n.get("may_mask"))));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out;
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(s -> out.add(s.asText()));
        return out;
    }

    /**
     * Code-point ranges of every occurrence of {@code needle} (case-sensitive).
     *
     * @throws IllegalArgumentException when {@code needle} is empty: it would match between every character
     */
    static List<int[]> occurrences(String text, String needle) {
        if (needle.isEmpty()) {
            throw new IllegalArgumentException("empty needle");
        }
        List<int[]> out = new ArrayList<>();
        for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + 1)) {
            int start = text.codePointCount(0, at);
            out.add(new int[] {start, start + needle.codePointCount(0, needle.length())});
        }
        return out;
    }

    static Report run(String mode, ChatPipeline pipeline, List<Entry> entries) {
        List<Leak> leaks = new ArrayList<>();
        List<OverMask> overMasks = new ArrayList<>();
        Map<String, int[]> byType = new TreeMap<>();
        Map<String, int[]> byGroup = new TreeMap<>();
        Map<String, String> outputs = new TreeMap<>();
        int mustMaskTotal = 0;
        int mustKeepTotal = 0;
        long maskedChars = 0;
        long maskedExpected = 0;
        for (Entry e : entries) {
            String masked = pipeline.anonymize(e.text(), RunContext.start(60).deadline()).masked();
            outputs.put(e.id(), masked);
            int[] orig = e.text().codePoints().toArray();
            int[] out = masked.codePoints().toArray();
            if (orig.length != out.length) {
                throw new AssertionError(e.id() + ": output length differs from input");
            }
            boolean[] expected = new boolean[orig.length];
            for (Item item : e.mustMask()) {
                mustMaskTotal++;
                boolean caught = true;
                for (int[] r : occurrences(e.text(), item.text())) {
                    for (int i = r[0]; i < r[1]; i++) {
                        expected[i] = true;
                        if (Character.isLetterOrDigit(orig[i]) && out[i] != Masker.MASK) {
                            caught = false;
                        }
                    }
                }
                if (!caught) {
                    leaks.add(new Leak(e, item));
                }
                tally(byType, item.type(), caught);
                tally(byGroup, e.group(), caught);
            }
            for (String may : e.mayMask()) {
                for (int[] r : occurrences(e.text(), may)) {
                    for (int i = r[0]; i < r[1]; i++) {
                        expected[i] = true;
                    }
                }
            }
            for (String keep : e.mustKeep()) {
                mustKeepTotal++;
                boolean touched = false;
                for (int[] r : occurrences(e.text(), keep)) {
                    for (int i = r[0]; i < r[1]; i++) {
                        touched |= out[i] == Masker.MASK && orig[i] != Masker.MASK;
                    }
                }
                if (touched) {
                    overMasks.add(new OverMask(e, keep));
                }
            }
            for (int i = 0; i < orig.length; i++) {
                if (out[i] == Masker.MASK && orig[i] != Masker.MASK) {
                    maskedChars++;
                    if (expected[i]) {
                        maskedExpected++;
                    }
                }
            }
        }
        return new Report(mode, mustMaskTotal, mustKeepTotal, leaks, overMasks, maskedChars, maskedExpected,
                byType, byGroup, outputs);
    }

    private static void tally(Map<String, int[]> map, String key, boolean caught) {
        int[] v = map.computeIfAbsent(key, k -> new int[2]);
        v[1]++;
        if (caught) {
            v[0]++;
        }
    }

    static void write(Report report) {
        try {
            Files.createDirectories(REPORT_DIR);
            Files.writeString(REPORT_DIR.resolve(report.mode() + ".md"), report.markdown(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
