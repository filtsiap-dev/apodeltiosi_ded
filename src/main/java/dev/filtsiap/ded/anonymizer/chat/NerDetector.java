package dev.filtsiap.ded.anonymizer.chat;

import java.util.List;

/**
 * The NER slot. A model's spans are ADDED to the rules' spans and never remove one, so turning a
 * model on can only mask more. v1 ships only {@link #NONE}; an ONNX or HTTP adapter implements this
 * interface later and is selected in config/chat/chat.yaml.
 */
@FunctionalInterface
public interface NerDetector {
    /**
     * Finds the entities a model sees in {@code text}.
     *
     * @param text the chat text, NFC-normalised
     * @return the spans to ADD to the rules' spans
     * @throws NerUnavailableException when the model cannot answer
     */
    List<ChatSpan> detect(String text) throws NerUnavailableException;

    /** The detector of v1: finds nothing. */
    NerDetector NONE = text -> List.of();
}
