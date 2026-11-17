package dev.filtsiap.ded.anonymizer.llm;

import com.openai.azure.AzureOpenAIServiceVersion;
import com.openai.azure.AzureUrlPathMode;
import com.openai.azure.credential.AzureApiKeyCredential;
import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.core.LogLevel;
import com.openai.core.RequestOptions;
import com.openai.core.Timeout;
import com.openai.errors.OpenAIException;
import com.openai.errors.OpenAIInvalidDataException;
import com.openai.errors.OpenAIIoException;
import com.openai.errors.OpenAIServiceException;
import com.openai.models.chat.completions.ChatCompletion;
import com.openai.models.chat.completions.ChatCompletion.Choice.FinishReason;
import com.openai.models.chat.completions.ChatCompletionCreateParams;
import com.openai.models.chat.completions.ChatCompletionMessage;
import com.openai.models.completions.CompletionUsage;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * {@link LlmClient} over the official openai-java SDK, for OpenAI and Azure OpenAI
 * (port of {@code llm/client.py}).
 *
 * <p>Timeouts mirror the Python SDK, where {@code timeout=60.0} becomes an httpx timeout of 60 s
 * per phase (connect, read, write), plus a total request cap. The latter prevents a peer
 * that keeps sending bytes from extending remediation beyond the remaining document budget.
 *
 * <p>THE SDK DOES NOT RETRY: {@code maxRetries(0)}, as Python's {@code max_retries=0}. The
 * detector owns the retry policy, and two layers would multiply rather than cooperate: the SDK's
 * default of two silent retries inside each of the detector's six attempts would be up to eighteen
 * calls per request, with the delays and failures invisible in the logs. (The SDK's OkHttp
 * transport is built with {@code retryOnConnectionFailure(false)}, so with this setting one
 * request is exactly one HTTP attempt.)
 *
 * <p>THE SDK DOES NOT LOG: {@code logLevel(OFF)}. Left at its default, the SDK reads
 * {@code OPENAI_LOG} from the environment, and at {@code debug} it prints every request and
 * response body to standard output, bypassing logback. Those bodies are document text.
 */
public final class OpenAiLlmClient implements LlmClient {

    /** Retries are the detector's job ({@code LlmDetector.callWithRetries}). */
    static final int SDK_MAX_RETRIES = 0;

    /** Never the environment's choice: a request body is document text. */
    static final LogLevel SDK_LOG_LEVEL = LogLevel.OFF;

    private final OpenAIClient client;

    private OpenAiLlmClient(OpenAIClient client) {
        this.client = client;
    }

    /**
     * Python {@code openai.OpenAI(api_key=..., timeout=...)}. Like the Python SDK, it also picks
     * up {@code OPENAI_BASE_URL}, {@code OPENAI_ORG_ID} and {@code OPENAI_PROJECT_ID} from the
     * environment (a proxy or gateway configured that way keeps working after the port).
     */
    public static OpenAiLlmClient openAi(String apiKey, double timeoutSeconds, String baseUrl, String organization,
                                         String project) {
        OpenAIOkHttpClient.Builder builder = OpenAIOkHttpClient.builder()
                .apiKey(apiKey)
                .timeout(perPhase(timeoutSeconds))
                .maxRetries(SDK_MAX_RETRIES)
                .logLevel(SDK_LOG_LEVEL);
        if (baseUrl != null && !baseUrl.isEmpty()) {
            builder.baseUrl(baseUrl);
        }
        if (organization != null) {
            builder.organization(organization);
        }
        if (project != null) {
            builder.project(project);
        }
        return new OpenAiLlmClient(builder.build());
    }

    /**
     * Python {@code openai.AzureOpenAI(api_key, azure_endpoint, api_version, timeout)}: requests
     * go to {@code {endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...},
     * the deployment being the request's {@code model}.
     */
    public static OpenAiLlmClient azure(String apiKey, String endpoint, String apiVersion, double timeoutSeconds) {
        return new OpenAiLlmClient(OpenAIOkHttpClient.builder()
                .baseUrl(endpoint)
                .credential(AzureApiKeyCredential.create(apiKey))
                .azureServiceVersion(AzureOpenAIServiceVersion.fromString(apiVersion))
                .azureUrlPathMode(AzureUrlPathMode.LEGACY)
                .timeout(perPhase(timeoutSeconds))
                .maxRetries(SDK_MAX_RETRIES)
                .logLevel(SDK_LOG_LEVEL)
                .build());
    }

    private static Timeout perPhase(double seconds) {
        Duration d = Duration.ofNanos(Math.round(seconds * 1_000_000_000L));
        return Timeout.builder().connect(d).read(d).write(d).request(d).build();
    }

    @Override
    public Completion complete(ChatRequest request) {
        ChatCompletionCreateParams params = ChatCompletionCreateParams.builder()
                .model(request.model())
                .addSystemMessage(request.systemPrompt())
                .addUserMessage(request.userMessage())
                .maxCompletionTokens((long) request.maxCompletionTokens())
                .build();
        ChatCompletion completion;
        try {
            // Per request: the detector cuts the timeout to what is left of the document's budget.
            completion = client.chat().completions().create(params,
                    RequestOptions.builder().timeout(perPhase(request.timeoutSeconds())).build());
        } catch (OpenAIIoException e) {
            // Timeouts surface as I/O failures whose cause is an InterruptedIOException
            // (SocketTimeoutException, OkHttp's call timeout); everything else is connectivity.
            if (hasCause(e, InterruptedIOException.class)) {
                throw LlmCallException.timeout(e);
            }
            throw LlmCallException.connection(e);
        } catch (OpenAIServiceException e) {
            throw LlmCallException.status(e.statusCode(), retryAfterMs(e), e);
        } catch (OpenAIException e) {
            // A timeout while decoding a streamed response can be wrapped by the SDK's
            // JSON handler instead of OpenAIIoException. Keep the timeout classification.
            if (hasCause(e, InterruptedIOException.class)) {
                throw LlmCallException.timeout(e);
            }
            throw LlmCallException.other(e);
        }
        return toCompletion(completion);
    }

    /**
     * The first choice's content, finish reason and refusal, and the response's token usage.
     * Defensive on purpose: an unfamiliar response shape is a provider returning something
     * unusable, and it must reach the detector's policy as an empty answer rather than as an
     * exception from inside the SDK's accessors.
     */
    static Completion toCompletion(ChatCompletion completion) {
        // Read first and separately: a usage block the SDK cannot parse costs the accounting,
        // never the answer.
        TokenUsage usage = tokenUsage(completion);
        try {
            List<ChatCompletion.Choice> choices = completion.choices();
            if (choices.isEmpty()) {
                return new Completion("", null, false, usage);
            }
            ChatCompletion.Choice first = choices.get(0);
            String finishReason = first._finishReason().asKnown().map(FinishReason::asString).orElse(null);
            Optional<ChatCompletionMessage> message = first._message().asKnown();
            String text = message.flatMap(ChatCompletionMessage::content).orElse("");
            boolean refused = message.flatMap(ChatCompletionMessage::refusal)
                    .map(r -> !PyStr.strip(r).isEmpty()).orElse(false);
            return new Completion(text, finishReason, refused, usage);
        } catch (OpenAIInvalidDataException e) {
            return new Completion("", null, false, usage);
        }
    }

    /**
     * The response's {@code usage} block, each count as reported or null. Read through the raw
     * {@code _field().asKnown()} accessors, which never throw: the typed ones raise on a missing
     * required field, and accounting must not be able to fail a document. Null when the response
     * carried no usable block at all.
     */
    static TokenUsage tokenUsage(ChatCompletion completion) {
        try {
            Optional<CompletionUsage> block = completion._usage().asKnown();
            if (block.isEmpty()) {
                return null;
            }
            CompletionUsage u = block.get();
            Long cached = u._promptTokensDetails().asKnown()
                    .flatMap(d -> d._cachedTokens().asKnown()).orElse(null);
            Long reasoning = u._completionTokensDetails().asKnown()
                    .flatMap(d -> d._reasoningTokens().asKnown()).orElse(null);
            return new TokenUsage(u._promptTokens().asKnown().orElse(null),
                    u._completionTokens().asKnown().orElse(null), u._totalTokens().asKnown().orElse(null), cached,
                    reasoning);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * The failed response's {@code retry-after-ms} header, parsed by
     * {@link LlmCallException#parseRetryAfterMs}; null when absent or unusable. Never raises: a
     * header the SDK cannot hand over costs the hint, not the classification of the failure.
     */
    static Long retryAfterMs(OpenAIServiceException e) {
        try {
            List<String> values = e.headers().values(LlmCallException.RETRY_AFTER_MS_HEADER);
            return values.isEmpty() ? null : LlmCallException.parseRetryAfterMs(values.get(0));
        } catch (RuntimeException unreadable) {
            return null;
        }
    }

    private static boolean hasCause(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause() == c ? null : c.getCause()) {
            if (type.isInstance(c)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void close() {
        client.close();
    }
}
