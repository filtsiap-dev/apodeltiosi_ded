package dev.filtsiap.ded.anonymizer.chat;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import dev.filtsiap.ded.anonymizer.Deadline;
import dev.filtsiap.ded.anonymizer.DetectorRules;
import dev.filtsiap.ded.anonymizer.FileConfig;

/**
 * POST /anonymize-text: NFC, every detector, union mask, residual re-scan. No LLM. The output is
 * the NFC text with masked code points, so its code-point length is the NFC input's.
 */
public final class ChatPipeline {

    /** Whether the masked text is complete as far as the pipeline can tell. */
    public enum Status {
        ANONYMIZED("anonymized"), NEEDS_REVIEW("needs-review");

        private final String wire;

        Status(String wire) {
            this.wire = wire;
        }

        /**
         * The value of the {@code x-anonymization-status} header.
         *
         * @return "anonymized" or "needs-review"
         */
        public String wire() {
            return wire;
        }
    }

    /**
     * The answer of {@link #anonymize}.
     *
     * @param masked        the masked text, NFC, with the input's code-point length
     * @param status        whether a person should look at it
     * @param counts        the number of masked regions per type
     * @param reviewReasons fixed strings only ("ner_unavailable", "residual:AFM"), never text
     */
    public record TextResult(String masked, Status status, Map<PiiType, Integer> counts, List<String> reviewReasons) {
    }

    private final IdDetector ids;
    private final NameDetector names;
    private final NerDetector ner;
    private final boolean rulesEnabled;

    /**
     * {@code rulesEnabled} false runs the NER alone (the eval's "ner" mode); production always runs
     * the rules. The residual re-scan belongs to the rules.
     *
     * @param rules        the regex rules of the .docx detectors the ID detector reuses
     * @param lists        the word lists
     * @param ner          the NER slot
     * @param rulesEnabled false to run only {@code ner}
     */
    public ChatPipeline(DetectorRules rules, ChatLists lists, NerDetector ner, boolean rulesEnabled) {
        this.ids = new IdDetector(rules, lists.allow());
        this.names = new NameDetector(lists);
        this.ner = ner;
        this.rulesEnabled = rulesEnabled;
    }

    /**
     * ChatSettings.load has already refused an enabled NER, so this is the rules with NER off.
     *
     * @param files    the loaded file configuration
     * @param lists    the word lists
     * @param settings the chat settings, already validated (v1 has nothing to read from them)
     * @return the production pipeline
     */
    public static ChatPipeline production(FileConfig files, ChatLists lists, ChatSettings settings) {
        return new ChatPipeline(files.rules(), lists, NerDetector.NONE, true);
    }

    /**
     * Masks {@code input}: NFC, every detector, the union, then the residual re-scan.
     *
     * @param input    the chat text
     * @param deadline the request's time budget, checked between stages
     * @return the masked text with its status and counts
     * @throws dev.filtsiap.ded.anonymizer.DocumentTimeoutError when the budget is gone at a stage boundary
     */
    public TextResult anonymize(String input, Deadline deadline) {
        String text = Normalizer.normalize(input, Normalizer.Form.NFC);
        List<ChatSpan> spans = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        if (rulesEnabled) {
            spans.addAll(ids.detect(text));
            spans.addAll(BirthDateDetector.detect(text));
            deadline.check("chat_ids");
            spans.addAll(names.detect(text));
            deadline.check("chat_names");
        }
        try {
            spans.addAll(ner.detect(text));
        } catch (NerUnavailableException e) {
            reasons.add("ner_unavailable");
        }
        String masked = Masker.mask(text, spans);
        if (rulesEnabled) {
            List<ChatSpan> residual = ResidualCheck.find(masked);
            if (!residual.isEmpty()) {
                masked = Masker.mask(masked, residual);
                spans.addAll(residual);
                TreeSet<String> kinds = new TreeSet<>();
                residual.forEach(s -> kinds.add(s.detector()));
                reasons.addAll(kinds);
            }
        }
        Status status = reasons.isEmpty() ? Status.ANONYMIZED : Status.NEEDS_REVIEW;
        return new TextResult(masked, status, Masker.counts(spans), List.copyOf(reasons));
    }
}
