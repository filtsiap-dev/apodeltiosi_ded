package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

/** The dataset itself is consistent: Java port of the former validate_dataset.py. */
class ChatDatasetTest {
    static final Set<String> GROUPS = Set.of("ids", "names_typical", "names_tricky", "locations_tricky",
            "overmask_traps", "multi_turn", "format_extremes", "controls");

    @Test
    void everyEntryIsConsistent() {
        List<ChatEval.Entry> entries = ChatEval.load(ChatEval.DATASET);
        List<String> problems = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            ChatEval.Entry e = entries.get(i);
            if (!e.id().equals(String.format("T%03d", i + 1))) {
                problems.add(e.id() + ": ids must be T001..Tnnn in order");
            }
            if (!GROUPS.contains(e.group())) {
                problems.add(e.id() + ": unknown group " + e.group());
            }
            List<int[]> maskRanges = new ArrayList<>();
            for (ChatEval.Item item : e.mustMask()) {
                List<int[]> found = ChatEval.occurrences(e.text(), item.text());
                if (found.isEmpty()) {
                    problems.add(e.id() + ": must_mask '" + item.text() + "' not in text");
                }
                maskRanges.addAll(found);
                try {
                    PiiType.valueOf(item.type());
                } catch (IllegalArgumentException x) {
                    problems.add(e.id() + ": unknown type " + item.type());
                }
                String digits = Checksums.digitsOnly(item.text());
                boolean ok = switch (item.type()) {
                    case "AFM" -> Checksums.afm(digits);
                    case "AMKA" -> Checksums.amka(digits);
                    // A CVV (3 or 4 digits) is card data with no checksum.
                    case "CARD" -> digits.length() <= 4 || Checksums.luhn(digits);
                    case "IBAN" -> ibanValid(item.text());
                    default -> true;
                };
                if (!ok) {
                    problems.add(e.id() + ": " + item.type() + " '" + item.text() + "' fails its checksum");
                }
            }
            for (String keep : concat(e.mustKeep(), e.mayMask())) {
                if (ChatEval.occurrences(e.text(), keep).isEmpty()) {
                    problems.add(e.id() + ": '" + keep + "' not in text");
                }
            }
            for (String keep : e.mustKeep()) {
                for (int[] k : ChatEval.occurrences(e.text(), keep)) {
                    for (int[] m : maskRanges) {
                        if (k[0] < m[1] && m[0] < k[1]) {
                            problems.add(e.id() + ": must_keep '" + keep + "' overlaps a must_mask item");
                        }
                    }
                }
            }
        }
        assertEquals(List.of(), problems);
        assertEquals(120, entries.size());
    }

    static boolean ibanValid(String s) {
        String v = s.replaceAll("\\s", "").toUpperCase(java.util.Locale.ROOT);
        StringBuilder num = new StringBuilder();
        for (char c : (v.substring(4) + v.substring(0, 4)).toCharArray()) {
            num.append(Character.getNumericValue(c));
        }
        return v.matches("GR\\d{25}") && new java.math.BigInteger(num.toString()).mod(java.math.BigInteger.valueOf(97))
                .intValue() == 1;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    @Test
    void theDatasetPathExists() {
        assertTrue(java.nio.file.Files.isRegularFile(Path.of("eval", "chat-anonymization", "dataset.jsonl")));
    }
}
