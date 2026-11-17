package dev.filtsiap.ded.anonymizer.llm;

import dev.filtsiap.ded.anonymizer.AIDisabledError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The client of {@code ANON_PROVIDER=regex}: there is no model, so every call is logged and
 * refused. The endpoints refuse before they get here; this is the net under them.
 */
public final class RegexModeLlmClient implements LlmClient {

    /** The line logged whenever something asks for the model in regex mode. */
    public static final String ERROR = "Error: AI model endpoint called while running in regex mode";

    private static final Logger LOG = LoggerFactory.getLogger(RegexModeLlmClient.class);

    @Override
    public Completion complete(ChatRequest request) {
        LOG.error(ERROR);
        throw new AIDisabledError(ERROR);
    }

    @Override
    public void close() {
    }
}
