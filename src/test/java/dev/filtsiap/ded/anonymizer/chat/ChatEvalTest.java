package dev.filtsiap.ded.anonymizer.chat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.RunContext;

/**
 * The dataset in three modes (eval/chat-anonymization/README.md). Only "rules" runs until a NER
 * model exists; the invariant that NER only adds is checked with a stub model.
 */
class ChatEvalTest {
    static final DetectorRules RULES = Config.loadFileConfig(Path.of("config")).rules();
    static final List<ChatEval.Entry> DATASET = ChatEval.load(ChatEval.DATASET);

    /**
     * Pinned on 2026-10-12; re-measured on 2026-10-13 on the 118-entry dataset, after the final-review fixes
     * and the owner-review fixes (3 / 125 must-mask, 2 / 97 must-keep);
     * re-measured on 2026-10-14 after the owner's label decisions (T002, T085, T088), the tax-office rule and the
     * CVV rule (3 / 128 must-mask, 2 / 96 must-keep);
     * re-measured on 2026-10-14 after T119 and T120 (3 / 131 must-mask, 2 / 98 must-keep);
     * re-measured on 2026-10-14 after the date-of-birth rule (2 / 131 must-mask, 2 / 98 must-keep);
     * re-measured on 2026-10-14 after the owner dropped every location rule and the ADDRESS, POSTAL_CODE and
     * LOCATION labels moved to may_mask (3 / 99 must-mask, 2 / 98 must-keep): T096's "ΟΕ" was masked only by
     * the old work-cue rule.
     * A change that leaks or over-masks more fails.
     */
    static final int MAX_RULES_LEAKS = 3; // measured 2026-10-14: T090, T095, T096
    static final int MAX_RULES_OVER_MASKS = 2; // measured 2026-10-14: T036, T047

    /** These types are checksum- or shape-certain: the rules must catch every one in the dataset. */
    static final Set<String> MUST_NEVER_LEAK = Set.of("AFM", "AMKA", "IBAN", "CARD", "ID_CARD", "PASSPORT", "PLATE",
            "GEMI", "EMAIL");

    /** The NER model to evaluate; none in v1. */
    static NerDetector configuredNer() {
        return null;
    }

    @Test
    void anEmptyNeedleIsRejectedNotMatchedEverywhere() {
        assertThrows(IllegalArgumentException.class, () -> ChatEval.occurrences("abc", ""));
    }

    @Test
    void rulesMode() {
        ChatEval.Report report = ChatEval.run("rules",
                new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, NerDetector.NONE, true), DATASET);
        ChatEval.write(report);
        System.out.println(report.markdown());
        List<String> certainLeaks = new ArrayList<>();
        report.leaks().stream().filter(l -> MUST_NEVER_LEAK.contains(l.item().type()))
                .forEach(l -> certainLeaks.add(l.entry().id() + " " + l.item().type()));
        assertEquals(List.of(), certainLeaks);
        assertTrue(report.leaks().size() <= MAX_RULES_LEAKS, "leaks " + report.leaks().size());
        assertTrue(report.overMasks().size() <= MAX_RULES_OVER_MASKS, "over-masks " + report.overMasks().size());
    }

    @Test
    void nerAndBothModes() {
        NerDetector ner = configuredNer();
        Assumptions.assumeTrue(ner != null, "no NER model configured: ner and both modes skipped");
        ChatEval.write(ChatEval.run("ner",
                new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, ner, false), DATASET));
        ChatEval.write(ChatEval.run("both",
                new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, ner, true), DATASET));
    }

    @Test
    void bothModeNeverMasksLessThanRulesMode() {
        // A stub "model" that flags every capitalised word: whatever it says, both ⊇ rules.
        NerDetector stub = text -> {
            List<ChatSpan> out = new ArrayList<>();
            int[] cps = text.codePoints().toArray();
            for (int i = 0; i < cps.length; i++) {
                if (Character.isUpperCase(cps[i]) && (i == 0 || !Character.isLetter(cps[i - 1]))) {
                    int j = i;
                    while (j < cps.length && Character.isLetter(cps[j])) {
                        j++;
                    }
                    out.add(new ChatSpan(i, j, PiiType.OTHER, "stub"));
                }
            }
            return out;
        };
        ChatPipeline rules = new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, NerDetector.NONE, true);
        ChatPipeline both = new ChatPipeline(RULES, ChatListsRealConfigTest.LISTS, stub, true);
        for (ChatEval.Entry e : DATASET) {
            int[] r = rules.anonymize(e.text(), RunContext.start(60).deadline()).masked().codePoints().toArray();
            int[] b = both.anonymize(e.text(), RunContext.start(60).deadline()).masked().codePoints().toArray();
            for (int i = 0; i < r.length; i++) {
                if (r[i] == Masker.MASK) {
                    assertEquals(Masker.MASK, b[i], e.id() + " position " + i);
                }
            }
        }
    }
}
