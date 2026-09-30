package dev.filtsiap.ded.anonymizer.llm;

import com.openai.azure.AzureOpenAIServiceVersion;
import com.openai.azure.AzureUrlPathMode;
import com.openai.azure.credential.AzureApiKeyCredential;
import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.core.Timeout;
import com.openai.errors.OpenAIException;
import com.openai.errors.OpenAIIoException;
import com.openai.errors.OpenAIServiceException;
import com.openai.models.chat.completions.ChatCompletion;
import com.openai.models.chat.completions.ChatCompletionCreateParams;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.List;

/**
 * {@link LlmClient} over the official openai-java SDK, for OpenAI and Azure OpenAI
 * (port of {@code llm/client.py}).
 *
 * <p>Timeouts mirror the Python SDK, where {@code timeout=60.0} becomes an httpx timeout of 60 s
 * per phase (connect, read, write) with no overall cap. The SDK's built-in retries (2, as in
 * Python) stay active; there is no local retry loop.
 */
public final class OpenAiLlmClient implements LlmClient {

    private static final int SDK_MAX_RETRIES = 2;

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
                .maxRetries(SDK_MAX_RETRIES);
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
                .build());
    }

    private static Timeout perPhase(double seconds) {
        Duration d = Duration.ofNanos(Math.round(seconds * 1_000_000_000L));
        return Timeout.builder().connect(d).read(d).write(d).request(Duration.ZERO).build();
    }

    @Override
    public String complete(ChatRequest request) {
        ChatCompletionCreateParams params = ChatCompletionCreateParams.builder()
                .model(request.model())
                .addSystemMessage(request.systemPrompt())
                .addUserMessage(request.userMessage())
                .maxCompletionTokens((long) request.maxCompletionTokens())
                .build();
        ChatCompletion completion;
        try {
            completion = client.chat().completions().create(params);
        } catch (OpenAIIoException e) {
            // Timeouts surface as I/O failures whose cause is an InterruptedIOException
            // (SocketTimeoutException, OkHttp's call timeout); everything else is connectivity.
            if (hasCause(e, InterruptedIOException.class)) {
                throw LlmCallException.timeout(e);
            }
            throw LlmCallException.connection(e);
        } catch (OpenAIServiceException e) {
            throw LlmCallException.status(e.statusCode(), e);
        } catch (OpenAIException e) {
            throw LlmCallException.other(e);
        }
        List<ChatCompletion.Choice> choices = completion.choices();
        if (choices.isEmpty()) {
            return null;
        }
        return choices.get(0).message().content().orElse(null);
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
