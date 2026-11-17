package dev.filtsiap.ded.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import dev.filtsiap.ded.anonymizer.AIDisabledError;
import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.AITimeoutError;
import dev.filtsiap.ded.anonymizer.AIUnavailableError;
import dev.filtsiap.ded.anonymizer.AnonymizeResult;
import dev.filtsiap.ded.anonymizer.AnonymizerError;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.Deadline;
import dev.filtsiap.ded.anonymizer.DocumentAccounting;
import dev.filtsiap.ded.anonymizer.DocumentProcessingError;
import dev.filtsiap.ded.anonymizer.DocumentTimeoutError;
import dev.filtsiap.ded.anonymizer.FileConfig;
import dev.filtsiap.ded.anonymizer.InternalError;
import dev.filtsiap.ded.anonymizer.InvalidDocumentError;
import dev.filtsiap.ded.anonymizer.Pipeline;
import dev.filtsiap.ded.anonymizer.PostcheckSummary;
import dev.filtsiap.ded.anonymizer.PromptInjectionError;
import dev.filtsiap.ded.anonymizer.RequestProgress;
import dev.filtsiap.ded.anonymizer.ResidualPIIError;
import dev.filtsiap.ded.anonymizer.ResourceLimitExceededError;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.UnsupportedDocumentFormatError;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.Masker;
import dev.filtsiap.ded.anonymizer.chat.PiiType;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.RegexModeLlmClient;
import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.anonymizer.pycompat.PyNumber;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;

/**
 * HTTP transport (port of {@code anonymizer/api.py}). Transport only: it reads the body, calls
 * the same {@link Pipeline} the CLI calls, and returns its bytes.
 *
 * <pre>
 * POST /anonymize   the DOCX bytes as the request body
 *                   Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document
 *                   Authorization: Bearer &lt;ANON_API_KEY&gt;
 *                   -&gt; the redacted DOCX bytes as the response body
 * POST /anonymize-text  plain text (text/plain; charset=utf-8) in, the masked text out; the chat
 *                   pipeline, no LLM, same Authorization header
 * POST /anonymize-log  one chatbot log entry (application/json) in, the same entry out with only the
 *                   top-level user_query string masked; see {@link LogBody}
 * GET  /healthz     unauthenticated liveness probe
 * </pre>
 *
 * <p>THE BODY IS THE DOCUMENT, IN BOTH DIRECTIONS: no form, no field name and no envelope in;
 * no JSON, no base64, no path and no wrapper out (on /anonymize-log the document is itself a JSON
 * log entry, and it comes back as that same entry). {@code multipart/form-data} and
 * {@code application/octet-stream} are refused with 415, as in v2: one accepted shape is one code
 * path. Everything else the endpoint has to say travels in response headers (ids, an enum and
 * counts, never document text).
 *
 * <p>AUTHENTICATION HAPPENS BEFORE THE BODY IS TOUCHED, then the document's deadline starts, then
 * the media type is checked (still before any body byte), then the body is streamed and counted.
 *
 * <p>Errors reproduce FastAPI's: compact JSON, {@code {"detail": ...}} for HTTP errors (401, 503,
 * routing), {@code {"error", "code", "detail"}} for anonymizer errors (the fixed public detail,
 * never the message), and 404/405/307 routing answers.
 */
final class ApiHandler implements HttpHandler {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.api");
    private static final Logger ACCESS = LoggerFactory.getLogger("anonymizer.api.access");

    static final String DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

    /**
     * As {@code _ERROR_STATUS_CODES}, looked up along the class hierarchy so a subclass inherits its
     * parent's status. 504 is reserved for ONE thing, the document deadline, so a caller seeing it
     * knows which limit they hit; one provider call timing out is a provider failure like any other.
     */
    private static final Map<Class<? extends AnonymizerError>, Integer> ERROR_STATUS = Map.ofEntries(
            Map.entry(InvalidDocumentError.class, 400),
            Map.entry(UnsupportedDocumentFormatError.class, 415),
            Map.entry(ResourceLimitExceededError.class, 413),
            // The document carries text shaped like an instruction to the model.
            Map.entry(PromptInjectionError.class, 422),
            Map.entry(ResidualPIIError.class, 422),
            // Valid input this service could not turn into valid output: ours, not the caller's.
            Map.entry(DocumentProcessingError.class, 500),
            Map.entry(AIProviderError.class, 502),
            Map.entry(AITimeoutError.class, 502),
            Map.entry(ConfigurationError.class, 503),
            Map.entry(AIUnavailableError.class, 503),
            Map.entry(AIDisabledError.class, 503),
            Map.entry(DocumentTimeoutError.class, 504),
            Map.entry(InternalError.class, 500));

    private static final Map<String, String> ROUTES = Map.of("/anonymize", "POST", "/anonymize-text", "POST",
            "/anonymize-log", "POST", "/healthz", "GET");

    /**
     * The media types a request may declare, compared after {@link #mediaType}. v2 also takes
     * .docm, .dotx and .dotm and normalizes them to .docx; this pipeline cannot (a template would
     * come back still a template, a macro document would be refused by the scan), so it takes the
     * one type it can return correctly and refuses the others with the same 415.
     */
    private static final Set<String> ACCEPTED_MEDIA_TYPES = Set.of(DOCX_MEDIA_TYPE);

    /** The body is read, counted and deadline-checked in pieces of this size. */
    private static final int READ_CHUNK_BYTES = 64 * 1024;

    /** One document's work, given its bytes and its budget: the pipeline, or a stand-in in tests. */
    @FunctionalInterface
    interface Processor {
        AnonymizeResult process(byte[] docx, RunContext ctx);
    }

    /** One text's work: the chat pipeline, or a stand-in in tests. */
    @FunctionalInterface
    interface TextProcessor {
        ChatPipeline.TextResult process(String text, RunContext ctx);
    }

    /** A handler built without a chat pipeline answers /anonymize-text with 503, as a missing API key does. */
    static final TextProcessor NO_TEXT_PIPELINE = (text, ctx) -> {
        throw new ConfigurationError("POST /anonymize-text is not configured on this server");
    };

    static final String TEXT_MEDIA_TYPE = "text/plain";
    static final String JSON_MEDIA_TYPE = "application/json";

    private final RuntimeConfig cfg;
    private final LongSupplier clock;
    private final Processor processor;
    private final TextProcessor textProcessor;
    private final BooleanSupplier cancelled;
    /** Where each running document is reported to shutdown; null where no server tracks them (tests). */
    private final RequestTracker requests;

    /** {@code cancelled}: the server's shutdown is cancelling the requests still running. */
    ApiHandler(RuntimeConfig cfg, FileConfig files, LlmClient client, ChatPipeline chat, BooleanSupplier cancelled) {
        this(cfg, System::nanoTime, (docx, ctx) -> Pipeline.anonymizeDocument(docx, cfg, files, client, ctx),
                chat == null ? NO_TEXT_PIPELINE : (text, ctx) -> chat.anonymize(text, ctx.deadline()), cancelled, null);
    }

    /** The served handler: cancelled by the tracker's shutdown, and reporting each document to it. */
    ApiHandler(RuntimeConfig cfg, FileConfig files, LlmClient client, ChatPipeline chat, RequestTracker requests) {
        this(cfg, System::nanoTime, (docx, ctx) -> Pipeline.anonymizeDocument(docx, cfg, files, client, ctx),
                chat == null ? NO_TEXT_PIPELINE : (text, ctx) -> chat.anonymize(text, ctx.deadline()),
                requests::cancelling, requests);
    }

    /** {@code clock} is the monotonic nanosecond clock every document's budget runs on. */
    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor) {
        this(cfg, clock, processor, NO_TEXT_PIPELINE, () -> false, null);
    }

    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor, TextProcessor textProcessor) {
        this(cfg, clock, processor, textProcessor, () -> false, null);
    }

    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor, BooleanSupplier cancelled) {
        this(cfg, clock, processor, NO_TEXT_PIPELINE, cancelled, null);
    }

    ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor, TextProcessor textProcessor,
               BooleanSupplier cancelled) {
        this(cfg, clock, processor, textProcessor, cancelled, null);
    }

    private ApiHandler(RuntimeConfig cfg, LongSupplier clock, Processor processor, TextProcessor textProcessor,
                       BooleanSupplier cancelled, RequestTracker requests) {
        this.cfg = cfg;
        this.clock = clock;
        this.processor = processor;
        this.textProcessor = textProcessor;
        this.cancelled = cancelled;
        this.requests = requests;
    }

    /** A FastAPI {@code HTTPException}: status, {@code {"detail": detail}}, extra headers. */
    private static final class HttpError extends Exception {
        private static final long serialVersionUID = 1L;
        final int status;
        final transient Object detail;
        final transient Map<String, String> headers;

        HttpError(int status, Object detail, Map<String, String> headers) {
            super(null, null, false, false);
            this.status = status;
            this.detail = detail;
            this.headers = headers;
        }

        HttpError(int status, Object detail) {
            this(status, detail, Map.of());
        }
    }

    private record Reply(int status, String contentType, byte[] body, Map<String, String> headers) {
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Reply reply;
        try {
            reply = route(exchange);
        } catch (HttpError e) {
            reply = json(e.status, Map.of("detail", e.detail), e.headers);
        } catch (AnonymizerError e) {
            // publicDetail, NEVER the message: the message is raised from deep in the document path
            // and can quote what it found there (a ZIP member name, a parser error, measured sizes).
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", e.getClass().getSimpleName());
            body.put("code", e.code());
            body.put("detail", e.publicDetail());
            reply = json(statusFor(e), body, Map.of());
        } catch (RuntimeException | Error e) {
            // An Error too (a StackOverflowError from a hostile document): left to the JDK it would
            // close the connection with no response at all. Frames only, never the message, which
            // can quote the document.
            LOG.error("unhandled_exception method={} path={} error={} cause={}\n{}", methodLabel(exchange),
                    routeLabel(exchange), e.getClass().getSimpleName(),
                    e.getCause() == null ? "-" : e.getCause().getClass().getSimpleName(), frames(e));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", "InternalServerError");
            body.put("detail", "internal error");
            reply = json(500, body, Map.of());
        }
        if (reply == null) {
            return; // POST /anonymize has already sent its document
        }
        if (cancelled.getAsBoolean()) {
            // The shutdown's interrupt has stopped the work; cleared so the reply can still be
            // written if the connection is open (an interrupted thread cannot write to a channel).
            Thread.interrupted();
        }
        send(exchange, reply);
    }

    /** The reply to send; null when the route has already sent it (a document, see {@link #anonymize}). */
    private Reply route(HttpExchange exchange) throws HttpError, IOException {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();
        String allowed = ROUTES.get(path);
        if (allowed == null) {
            // Starlette's redirect_slashes: "/healthz/" -> 307 to "/healthz".
            if (path.length() > 1 && path.endsWith("/") && ROUTES.containsKey(path.substring(0, path.length() - 1))) {
                String host = exchange.getRequestHeaders().getFirst("Host");
                String query = exchange.getRequestURI().getRawQuery();
                String location = "http://" + (host == null ? "localhost" : host) + path.substring(0, path.length() - 1)
                        + (query == null ? "" : "?" + query);
                return new Reply(307, null, new byte[0], Map.of("location", location));
            }
            throw new HttpError(404, "Not Found");
        }
        // Starlette serves HEAD wherever it serves GET.
        boolean get = allowed.equals("GET");
        if (!(allowed.equals(method) || get && method.equals("HEAD"))) {
            throw new HttpError(405, "Method Not Allowed", Map.of("allow", get ? "GET, HEAD" : allowed));
        }
        if (path.equals("/healthz")) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", "ok");
            body.put("provider", cfg.provider().wire());
            body.put("model", cfg.modelHandle());
            return json(200, body, Map.of());
        }
        if (path.equals("/anonymize-text")) {
            return anonymizeText(exchange);
        }
        if (path.equals("/anonymize-log")) {
            return anonymizeLog(exchange);
        }
        return anonymize(exchange);
    }

    // ------------------------------------------------------------------ POST /anonymize

    /** The status for a domain failure, honouring subclasses; 500 for anything unmapped. */
    static int statusFor(AnonymizerError e) {
        for (Class<?> c = e.getClass(); AnonymizerError.class.isAssignableFrom(c); c = c.getSuperclass()) {
            Integer status = ERROR_STATUS.get(c);
            if (status != null) {
                return status;
            }
        }
        return 500;
    }

    /** File, line and method for every frame: the shape of a failure, and nothing that can quote a document. */
    static String frames(Throwable e) {
        StringBuilder out = new StringBuilder();
        for (StackTraceElement frame : e.getStackTrace()) {
            out.append("  at ").append(frame).append('\n');
        }
        return out.toString();
    }

    /**
     * The one POST /anonymize flow. The document's clock starts after authentication has passed and
     * before a byte of the body is read, so everything the document costs (receiving it included) is
     * inside the budget. Exactly one {@code document_finished} line is logged per request, on every
     * path, carrying ids, codes and the document's accounting (counts, times and cost) only. A
     * document that FAILED still reports what it spent: the ledger lives on its context.
     *
     * <p>The document is sent from here, and the line is logged only once the write has ended, so
     * a response that never fully went out (the client hung up, or shutdown cancelled the write)
     * is never logged as a success. Returns null: the reply is already sent. Errors are thrown
     * for {@link #handle} to send.
     */
    private Reply anonymize(HttpExchange exchange) throws HttpError, IOException {
        requireApiKey(exchange.getRequestHeaders()); // before the body is read
        RunContext ctx = RunContext.start(cfg.documentDeadlineS(), null, clock);
        // Correlate failures too, including validation failures before the pipeline starts.
        exchange.getResponseHeaders().set("x-document-id", ctx.documentId());
        long started = System.nanoTime();
        String outcome = "internal_error";
        int status = 500;
        String errorCode = "INTERNAL_ERROR";
        int unresolved = 0;
        AnonymizeResult result = null;
        boolean responding = false;
        Throwable failure = null;
        // The request-start marker: a document with this line and no document_finished is one that never ended.
        LOG.info("document_started {} deadline_s={}", ctx.tag(), PyFloat.fixed(cfg.documentDeadlineS(), 1));
        if (requests != null) {
            requests.trackDocument(ctx);
        }
        try {
            if (cfg.provider() == RuntimeConfig.Provider.REGEX) { // no model to send the document to
                LOG.error("{} {}", RegexModeLlmClient.ERROR, ctx.tag());
                throw new AIDisabledError(RegexModeLlmClient.ERROR);
            }
            byte[] payload = readUpload(exchange, ctx.deadline());
            result = processor.process(payload, ctx);
            // A document finished after the deadline is still a document nobody finished in time.
            ctx.deadline().check("respond");
            Reply reply = docxReply(result);
            if (cancelled.getAsBoolean()) {
                // Finished although shutdown is cancelling: still delivered if the connection is open.
                Thread.interrupted();
            }
            responding = true;
            send(exchange, reply);
            outcome = result.needsReview() ? "needs_review" : "success";
            status = 200;
            errorCode = "-";
            unresolved = result.unresolvedCount();
            return null;
        } catch (RuntimeException | IOException | Error e) {
            failure = e;
            if (responding) {
                // The 200 was (partly) on its way: nothing else can be sent on this exchange.
                boolean shutdown = cancelled.getAsBoolean();
                outcome = shutdown ? "cancelled" : "client_disconnected";
                status = 200;
                errorCode = shutdown ? "SHUTTING_DOWN" : "RESPONSE_INCOMPLETE";
                unresolved = result.unresolvedCount();
                throw e;
            }
            if (cancelled.getAsBoolean() && stoppedByShutdown(e)) {
                // Stopped by the server's shutdown (an interrupted read, provider wait or write):
                // not the document's failure, and never reported as a provider or internal error.
                outcome = "cancelled";
                status = 503;
                errorCode = "SHUTTING_DOWN";
                throw shuttingDown();
            }
            if (e instanceof AnonymizerError ae) {
                outcome = ae.outcome();
                status = statusFor(ae);
                errorCode = ae.code();
                throw ae;
            }
            if (e instanceof IOException io) {
                throw io;
            }
            // Logged here, where the ids are, and never with its message, which can quote the
            // document; it then leaves by the typed path with the fixed body.
            LOG.error("unhandled_exception {} error={} cause={}\n{}", ctx.tag(), e.getClass().getSimpleName(),
                    e.getCause() == null ? "-" : e.getCause().getClass().getSimpleName(), frames(e));
            throw new InternalError(e);
        } finally {
            if (requests != null) {
                requests.untrackDocument();
            }
            long elapsedNanos = System.nanoTime() - started;
            DocumentAccounting accounting = result != null ? result.accounting()
                    : DocumentAccounting.of(ctx.usage().snapshot(), elapsedNanos / 1_000_000, null, cfg.pricing());
            RequestProgress.Snapshot progress = ctx.progress().snapshot();
            // A document that finished (success or needs-review, fallbacks included) carries no failure fields:
            // a provider failure it recovered from, or absorbed, is in the counts above, not a cause of failure.
            boolean finished = outcome.equals("success") || outcome.equals("needs_review");
            String failureText = finished ? "" : failureFields(failure, outcome, ctx, progress);
            String line = "document_finished {} outcome={} status={} elapsed_s={} unresolved_count={} error_code={} "
                    + "chunks_completed={} chunks_total={} {}{}";
            Object[] fields = {ctx.tag(), outcome, status, PyFloat.fixed(elapsedNanos / 1e9, 2), unresolved, errorCode,
                    progress.chunksCompleted(), progress.chunksTotal(), accounting.logFields(), failureText};
            if (errorCode.equals("-")) {
                LOG.info(line, fields);
            } else if (status < 500 || outcome.equals("cancelled")) { // the caller's or a shutdown, not a fault
                LOG.warn(line, fields);
            } else {
                LOG.error(line, fields);
            }
        }
    }

    // ------------------------------------------------------------------ POST /anonymize-text, /anonymize-log

    /** What one chat request has counted so far, for its one finished line: never any text. */
    private final class TextFlow {
        final long started = clock.getAsLong();
        /** Whether the finished line reports the body's size: /anonymize-log does, /anonymize-text not. */
        final boolean reportsBytes;
        int chars;
        /** The body's size; stays 0 when the body was refused unread. */
        long bytes;

        TextFlow(boolean reportsBytes) {
            this.reportsBytes = reportsBytes;
        }

        long elapsedMs() {
            return (clock.getAsLong() - started) / 1_000_000;
        }

        String counted() {
            return (reportsBytes ? "bytes=" + bytes + " " : "") + "chars=" + chars;
        }
    }

    /** One chat request's work after authentication: read, mask, build the reply. */
    @FunctionalInterface
    private interface TextJob {
        TextDone run(RunContext ctx, TextFlow flow) throws IOException;
    }

    private record TextDone(Reply reply, boolean needsReview) {
    }

    /** The one POST /anonymize-text flow: the body is plain text, the answer is the masked text. */
    private Reply anonymizeText(HttpExchange exchange) throws HttpError, IOException {
        return textFlow(exchange, "text_finished", false, (ctx, flow) -> {
            String text = readText(exchange, ctx.deadline());
            flow.chars = text.codePointCount(0, text.length());
            ChatPipeline.TextResult result = textProcessor.process(text, ctx);
            return new TextDone(textReply(ctx.documentId(), result, flow.elapsedMs()),
                    result.status() == ChatPipeline.Status.NEEDS_REVIEW);
        });
    }

    /**
     * The one POST /anonymize-log flow: the body is one JSON log entry, the answer is the same entry
     * with only its {@code user_query} masked (see {@link LogBody}). The text limit applies to each
     * decoded query, the upload limit to the whole body.
     */
    private Reply anonymizeLog(HttpExchange exchange) throws HttpError, IOException {
        return textFlow(exchange, "log_finished", true, (ctx, flow) -> {
            byte[] data = readJson(exchange, ctx.deadline(), flow);
            String json = decodeUtf8(data);
            long maxChars = cfg.limits().maxTextChars();
            LogBody.Result result = LogBody.anonymizeUserQuery(json, query -> {
                int chars = query.codePointCount(0, query.length());
                if (chars > maxChars) {
                    throw textTooLarge(maxChars);
                }
                flow.chars += chars;
                return textProcessor.process(query, ctx);
            });
            Map<String, String> headers = textHeaders(ctx.documentId(), result.status(), result.counts(),
                    result.reviewReasons(), flow.elapsedMs());
            // Nothing masked (the common case): LogBody returns json itself, and the bytes that came in go back.
            byte[] body = result.body() == json ? data : result.body().getBytes(StandardCharsets.UTF_8);
            return new TextDone(new Reply(200, JSON_MEDIA_TYPE + "; charset=utf-8", body, headers),
                    result.status() == ChatPipeline.Status.NEEDS_REVIEW);
        });
    }

    /**
     * The flow both chat endpoints share: auth, the document clock, {@code job}, the reply. Exactly
     * one {@code event} line per request with ids, codes, counts and timings, NEVER any text.
     * Errors are thrown for {@link #handle} to send, as on /anonymize. {@code reportsBytes} adds the
     * body's size to that line.
     */
    private Reply textFlow(HttpExchange exchange, String event, boolean reportsBytes, TextJob job)
            throws HttpError, IOException {
        requireApiKey(exchange.getRequestHeaders());
        RunContext ctx = RunContext.start(cfg.documentDeadlineS(), null, clock);
        exchange.getResponseHeaders().set("x-document-id", ctx.documentId());
        TextFlow flow = new TextFlow(reportsBytes);
        String outcome = "internal_error";
        int status = 500;
        String errorCode = "INTERNAL_ERROR";
        boolean responding = false;
        Throwable failure = null;
        // The request-start marker, as document_started is for /anonymize: a request with this line and no finish line never ended.
        LOG.info(event.replace("_finished", "_started") + " {} deadline_s={}", ctx.tag(),
                PyFloat.fixed(cfg.documentDeadlineS(), 1));
        if (requests != null) {
            requests.trackDocument(ctx);
        }
        try {
            TextDone done = job.run(ctx, flow);
            ctx.deadline().check("respond");
            Reply reply = done.reply();
            if (cancelled.getAsBoolean()) {
                // Finished although shutdown is cancelling: still delivered if the connection is open.
                Thread.interrupted();
            }
            responding = true;
            send(exchange, reply);
            outcome = done.needsReview() ? "needs_review" : "success";
            status = 200;
            errorCode = "-";
            return null;
        } catch (RuntimeException | IOException | Error e) {
            failure = e;
            if (responding) {
                // The 200 was (partly) on its way: nothing else can be sent on this exchange.
                boolean shutdown = cancelled.getAsBoolean();
                outcome = shutdown ? "cancelled" : "client_disconnected";
                status = 200;
                errorCode = shutdown ? "SHUTTING_DOWN" : "RESPONSE_INCOMPLETE";
                throw e;
            }
            if (cancelled.getAsBoolean() && stoppedByShutdown(e)) {
                // Stopped by the server's shutdown (an interrupted read or write): not the text's failure.
                outcome = "cancelled";
                status = 503;
                errorCode = "SHUTTING_DOWN";
                throw shuttingDown();
            }
            if (e instanceof AnonymizerError ae) {
                outcome = ae.outcome();
                status = statusFor(ae);
                errorCode = ae.code();
                throw ae;
            }
            if (e instanceof IOException io) {
                outcome = "io_error";
                errorCode = "IO_ERROR";
                throw io;
            }
            LOG.error("unhandled_exception {} error={} cause={}\n{}", ctx.tag(), e.getClass().getSimpleName(),
                    e.getCause() == null ? "-" : e.getCause().getClass().getSimpleName(), frames(e));
            throw new InternalError(e);
        } finally {
            if (requests != null) {
                requests.untrackDocument();
            }
            // A text that finished carries no failure fields; a provider failure it recovered from is in the counts.
            boolean finished = outcome.equals("success") || outcome.equals("needs_review");
            String failureText = finished ? "" : failureFields(failure, outcome, ctx, ctx.progress().snapshot());
            String line = event + " {} outcome={} status={} elapsed_s={} {} error_code={}{}";
            Object[] fields = {ctx.tag(), outcome, status,
                    PyFloat.fixed((clock.getAsLong() - flow.started) / 1e9, 2), flow.counted(), errorCode, failureText};
            if (errorCode.equals("-")) {
                LOG.info(line, fields);
            } else if (status < 500 || outcome.equals("cancelled")) { // the caller's or a shutdown, not a fault
                LOG.warn(line, fields);
            } else {
                LOG.error(line, fields);
            }
        }
    }

    /**
     * The body as text: text/plain, charset absent or UTF-8, valid UTF-8, at most
     * ANON_MAX_TEXT_CHARS code points (so at most four times that in bytes). A leading BOM is dropped.
     */
    private String readText(HttpExchange exchange, Deadline deadline) throws IOException {
        String contentType = headerValue(exchange.getRequestHeaders(), "Content-Type");
        if (!mediaType(contentType).equals(TEXT_MEDIA_TYPE) || !utf8Charset(contentType)) {
            throw new UnsupportedDocumentFormatError(
                    "send the text as the request body with Content-Type: text/plain; charset=utf-8");
        }
        long maxChars = cfg.limits().maxTextChars();
        long limit = maxChars * 4;
        checkDeclaredLength(exchange.getRequestHeaders().getFirst("Content-Length"), limit);
        String text = decodeUtf8(readBody(exchange.getRequestBody(), limit, deadline));
        if (text.startsWith("\uFEFF")) {
            text = text.substring(1);
        }
        if (text.codePointCount(0, text.length()) > maxChars) {
            throw textTooLarge(maxChars);
        }
        return text;
    }

    /**
     * The raw body of POST /anonymize-log: application/json, charset absent or UTF-8, at most
     * ANON_MAX_UPLOAD_BYTES (a log entry carries pages of retrieved text, so the text limit does not
     * apply to the body). The caller decodes it as strict UTF-8 and keeps the bytes to send back when
     * nothing is masked. A leading BOM is not dropped: {@link LogBody} skips it and the body comes back
     * byte for byte.
     */
    private byte[] readJson(HttpExchange exchange, Deadline deadline, TextFlow flow) throws IOException {
        String contentType = headerValue(exchange.getRequestHeaders(), "Content-Type");
        if (!mediaType(contentType).equals(JSON_MEDIA_TYPE) || !utf8Charset(contentType)) {
            throw new UnsupportedDocumentFormatError(
                    "send the log entry as the request body with Content-Type: application/json; charset=utf-8");
        }
        long limit = cfg.limits().maxUploadBytes();
        checkDeclaredLength(exchange.getRequestHeaders().getFirst("Content-Length"), limit);
        byte[] data = readBody(exchange.getRequestBody(), limit, deadline);
        flow.bytes = data.length;
        return data;
    }

    /** Strict UTF-8: a malformed or unmappable byte is a 400, never a replacement character. */
    private static String decodeUtf8(byte[] data) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            throw new InvalidDocumentError("request body is not valid UTF-8", "INVALID_UTF8");
        }
    }

    private static ResourceLimitExceededError textTooLarge(long maxChars) {
        return new ResourceLimitExceededError("text exceeds the " + maxChars + "-character limit", "TEXT_TOO_LARGE");
    }

    /** True when the Content-Type has no charset parameter or says utf-8 / utf8. */
    static boolean utf8Charset(String contentType) {
        String[] parts = contentType.split(";");
        for (int i = 1; i < parts.length; i++) {
            String[] kv = parts[i].split("=", 2);
            if (kv.length == 2 && PyStr.casefold(PyStr.strip(kv[0])).equals("charset")) {
                String value = PyStr.casefold(PyStr.strip(kv[1]).replace("\"", ""));
                return value.equals("utf-8") || value.equals("utf8");
            }
        }
        return true;
    }

    /** Every header value is an id, an enum, a fixed reason string or an integer: never the text. */
    private static Reply textReply(String documentId, ChatPipeline.TextResult result, long elapsedMs) {
        Map<String, String> headers = textHeaders(documentId, result.status(), result.counts(),
                result.reviewReasons(), elapsedMs);
        return new Reply(200, "text/plain; charset=utf-8", result.masked().getBytes(StandardCharsets.UTF_8), headers);
    }

    private static Map<String, String> textHeaders(String documentId, ChatPipeline.Status status,
            Map<PiiType, Integer> counts, List<String> reviewReasons, long elapsedMs) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-document-id", documentId);
        headers.put("x-anonymization-status", status.wire());
        headers.put("x-redaction-counts", Masker.countsHeader(counts));
        if (!reviewReasons.isEmpty()) {
            headers.put("x-review-reasons", String.join(",", reviewReasons));
        }
        headers.put("x-processing-time-ms", Long.toString(elapsedMs));
        return headers;
    }

    /**
     * The fields that say where a document that did not finish stopped, and why: the stage it had begun
     * last, the class of what failed it (or the provider failure's label), and the most recent provider
     * failure that did not recover (else the last one) with its chunk, pass, status and recovery. Names,
     * labels and counts only; never a message, which can quote the document.
     */
    static String failureFields(Throwable failure, String outcome, RunContext ctx, RequestProgress.Snapshot progress) {
        RequestProgress.Failure last = progress.failure();
        String reason;
        if (outcome.equals("cancelled")) {
            reason = "shutdown";
        } else if (failure instanceof DocumentTimeoutError) {
            reason = "deadline_expired";
        } else if (failure instanceof AIProviderError || failure instanceof AITimeoutError
                || failure instanceof AIUnavailableError) {
            reason = last != null && !last.recovered() ? last.label() : failure.getClass().getSimpleName();
        } else {
            reason = failure == null ? "-" : failure.getClass().getSimpleName();
        }
        return " failed_stage=" + ctx.deadline().lastStage().replace(' ', '_') + " error_reason=" + reason
                + " provider_http_status=" + (last == null || last.httpStatus() == null ? "-" : last.httpStatus())
                + " last_failed_chunk=" + (last == null ? "-" : last.chunk())
                + " last_failed_pass=" + (last == null ? "-" : last.pass())
                + " last_failure_recovered=" + (last == null ? "-" : last.recovered() ? "yes" : "no");
    }

    /**
     * The success response: the bytes, and what the caller has to know, in headers. THE ONE A
     * CALLER MUST NOT IGNORE is X-Anonymization-Status: a needs-review 200 is a complete file a
     * person has to check at X-Unresolved-Count locations before publishing. Every value is an id,
     * an enum or an integer; the filename is the generated document id, never anything the caller
     * sent.
     */
    private static Reply docxReply(AnonymizeResult result) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("content-disposition", "attachment; filename=\"" + result.documentId() + "_redacted.docx\"");
        headers.put("x-document-id", result.documentId());
        headers.put("x-anonymization-status", result.status());
        headers.put("x-unresolved-count", Integer.toString(result.unresolvedCount()));
        if (result.fallbackUsed()) {
            // Only when true, so a clean response carries exactly the headers it always did. Implies
            // needs-review: LLM pass 2 was unavailable for some candidates and the documented fallback
            // decided them (or left them for a person).
            headers.put("x-llm-fallback-used", "true");
        }
        headers.putAll(postcheckHeaders(result.postcheck()));
        headers.putAll(accountingHeaders(result.accounting()));
        return new Reply(200, DOCX_MEDIA_TYPE, result.redactedDocx(), headers);
    }

    /**
     * The document's totals, one integer or decimal per header, and ONLY WHAT IS KNOWN: a token
     * total is sent only when every response reported its usage (otherwise it is a partial sum,
     * and {@code X-LLM-Calls-Missing-Usage} says why it is absent), cached and reasoning tokens only
     * when the provider reported them, and the cost only when prices are configured. The full
     * breakdown is in the {@code document_finished} log line and the CLI's {@code --summary-json}.
     */
    static Map<String, String> accountingHeaders(DocumentAccounting accounting) {
        Map<String, String> h = new LinkedHashMap<>();
        if (accounting == null) {
            return h;
        }
        h.put("x-processing-time-ms", Long.toString(accounting.totalElapsedMs()));
        if (accounting.llmElapsedMs() != null) {
            h.put("x-llm-time-ms", Long.toString(accounting.llmElapsedMs()));
        }
        h.put("x-llm-calls", Integer.toString(accounting.calls()));
        h.put("x-llm-calls-missing-usage", Integer.toString(accounting.callsMissingUsage()));
        if (accounting.callsMissingUsage() == 0) {
            h.put("x-llm-input-tokens", Long.toString(accounting.inputTokens()));
            if (accounting.cachedInputTokens() != null) {
                h.put("x-llm-cached-input-tokens", Long.toString(accounting.cachedInputTokens()));
            }
            h.put("x-llm-output-tokens", Long.toString(accounting.outputTokens()));
            if (accounting.reasoningTokens() != null) {
                h.put("x-llm-reasoning-tokens", Long.toString(accounting.reasoningTokens()));
            }
            h.put("x-llm-total-tokens", Long.toString(accounting.totalTokens()));
        }
        if (accounting.estimatedCost() != null) {
            h.put("x-llm-estimated-cost", accounting.estimatedCostText());
            h.put("x-llm-cost-currency", accounting.currency());
        }
        return h;
    }

    /**
     * One 401 for a missing, malformed or wrong credential. Constant-time comparison over UTF-8
     * bytes; the expected key never appears in a response or a log line.
     */
    private void requireApiKey(Headers headers) throws HttpError {
        String expected = cfg.anonApiKey();
        if (expected == null || expected.isEmpty()) {
            LOG.error("ANON_API_KEY is not configured; refusing every request");
            throw new HttpError(503, "server authentication is not configured");
        }
        String header = headerValue(headers, "Authorization");
        int space = header.indexOf(' ');
        String scheme = space < 0 ? header : header.substring(0, space);
        String token = space < 0 ? "" : header.substring(space + 1);
        if (!PyStr.casefold(PyStr.strip(scheme)).equals("bearer")) {
            LOG.warn("rejected request with missing or non-bearer Authorization header");
            throw unauthorized();
        }
        if (!MessageDigest.isEqual(PyStr.strip(token).getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8))) {
            LOG.warn("rejected request with an incorrect API key");
            throw unauthorized();
        }
    }

    private static HttpError unauthorized() {
        return new HttpError(401, "missing or invalid API key", Map.of("www-authenticate", "Bearer"));
    }

    /** The same answer the server gives a request it refused during shutdown. */
    private static HttpError shuttingDown() {
        return new HttpError(503, "the server is shutting down", Map.of("connection", "close"));
    }

    /**
     * Whether a failure seen while shutdown is cancelling was caused by it: any I/O failure (the
     * interrupt closes the channel), or an error raised by the interrupt itself. A document's own
     * failure (invalid, too large, prompt injection, timed out) keeps its status: a caller told to
     * retry it elsewhere would only fail the same way again.
     */
    private static boolean stoppedByShutdown(Throwable e) {
        if (e instanceof IOException) {
            return true;
        }
        for (Throwable c = e; c != null; c = c.getCause() == c ? null : c.getCause()) {
            if (c instanceof InterruptedException || c instanceof InterruptedIOException
                    || c instanceof ClosedByInterruptException) {
                return true;
            }
        }
        return false;
    }

    /** First header value, leading/trailing HTTP whitespace removed (as uvicorn delivers it); "" when absent. */
    private static String headerValue(Headers headers, String name) {
        String v = headers.getFirst(name);
        if (v == null) {
            return "";
        }
        int start = 0;
        int end = v.length();
        while (start < end && (v.charAt(start) == ' ' || v.charAt(start) == '\t')) {
            start++;
        }
        while (end > start && (v.charAt(end - 1) == ' ' || v.charAt(end - 1) == '\t')) {
            end--;
        }
        return v.substring(start, end);
    }

    /**
     * The request body as the DOCX to anonymize (port of {@code _read_upload}). THE BODY IS THE
     * DOCUMENT: anything not declared as a DOCX is refused with 415 before the body is read at all.
     * Then the body is streamed and counted against {@code ANON_MAX_UPLOAD_BYTES} within the
     * document's budget.
     */
    private byte[] readUpload(HttpExchange exchange, Deadline deadline) throws IOException {
        if (!ACCEPTED_MEDIA_TYPES.contains(mediaType(headerValue(exchange.getRequestHeaders(), "Content-Type")))) {
            throw new UnsupportedDocumentFormatError("send the Word document as the request body with one of these "
                    + "content types: " + String.join(", ", new TreeSet<>(ACCEPTED_MEDIA_TYPES)));
        }
        long limit = cfg.limits().maxUploadBytes();
        checkDeclaredLength(exchange.getRequestHeaders().getFirst("Content-Length"), limit);
        byte[] data = readBody(exchange.getRequestBody(), limit, deadline);
        if (data.length == 0) {
            throw new InvalidDocumentError("empty request body");
        }
        return data;
    }

    /**
     * The bare media type of a Content-Type header: parameters off, stripped, casefolded. The type
     * itself must then match EXACTLY; a prefix test would accept "...wordprocessingml.document-ish".
     */
    static String mediaType(String contentType) {
        int semicolon = contentType.indexOf(';');
        return PyStr.casefold(PyStr.strip(semicolon < 0 ? contentType : contentType.substring(0, semicolon)));
    }

    private static ResourceLimitExceededError tooLarge(long limit) {
        return new ResourceLimitExceededError("upload exceeds the " + limit + "-byte limit", "UPLOAD_TOO_LARGE");
    }

    /**
     * The cheap case, refused before any body is read: an honest client that sent too much learns
     * so having transferred nothing. A length that is not a length is a malformed request.
     */
    static void checkDeclaredLength(String declared, long limit) {
        if (declared == null) {
            return;
        }
        BigInteger announced = PyNumber.parseInt(declared).orElseThrow(
                () -> new InvalidDocumentError("malformed Content-Length header", "MALFORMED_CONTENT_LENGTH"));
        if (announced.signum() < 0) {
            throw new InvalidDocumentError("negative Content-Length header", "MALFORMED_CONTENT_LENGTH");
        }
        if (announced.compareTo(BigInteger.valueOf(limit)) > 0) {
            throw new ResourceLimitExceededError("declared upload size " + announced + " exceeds the " + limit
                    + "-byte limit", "UPLOAD_TOO_LARGE");
        }
    }

    /**
     * Reads the body piece by piece, counting as it goes and checking the deadline after each
     * piece. Stops at the first piece that crosses {@code limit}: the rest of the body is never
     * read, so an oversized upload costs one piece of memory rather than all of it.
     */
    static byte[] readBody(InputStream in, long limit, Deadline deadline) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] piece = new byte[READ_CHUNK_BYTES];
        int n;
        while ((n = in.read(piece)) >= 0) {
            deadline.check("upload");
            if (buffer.size() + (long) n > limit) {
                throw tooLarge(limit);
            }
            buffer.write(piece, 0, n);
        }
        return buffer.toByteArray();
    }

    /** Advisory scan results as headers: kind names and counts only, sorted by kind. */
    static Map<String, String> postcheckHeaders(PostcheckSummary postcheck) {
        if (postcheck == null) {
            return Map.of();
        }
        TreeMap<String, Integer> sorted = new TreeMap<>(PyStr.CODE_POINT_ORDER);
        sorted.putAll(postcheck.byKind());
        List<String> kinds = new ArrayList<>();
        sorted.forEach((k, v) -> kinds.add(k + "=" + v));
        Map<String, String> h = new LinkedHashMap<>();
        h.put("x-postcheck-findings", Integer.toString(postcheck.findingsTotal()));
        h.put("x-postcheck-kinds", kinds.isEmpty() ? "none" : String.join(",", kinds));
        return h;
    }

    // ------------------------------------------------------------------ responses

    private static Reply json(int status, Object body, Map<String, String> headers) {
        byte[] bytes = PyJson.dumps(body, PyJson.COMPACT_SEPARATORS, false).getBytes(StandardCharsets.UTF_8);
        return new Reply(status, "application/json", bytes, headers);
    }

    private static final DateTimeFormatter CLF = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ROOT);

    private static void send(HttpExchange exchange, Reply reply) throws IOException {
        Headers out = exchange.getResponseHeaders();
        if (reply.contentType() != null) {
            out.set("content-type", reply.contentType());
        }
        reply.headers().forEach(out::set);
        boolean head = exchange.getRequestMethod().equals("HEAD");
        try {
            if (head || reply.body().length == 0) {
                exchange.sendResponseHeaders(reply.status(), -1);
            } else {
                exchange.sendResponseHeaders(reply.status(), reply.body().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(reply.body());
                }
            }
        } finally {
            exchange.close();
            // URLs, Referer and User-Agent are caller-controlled and can contain document PII.
            ACCESS.info("[{}] method={} route={} status={} bytes={}", CLF.format(ZonedDateTime.now()),
                    methodLabel(exchange), routeLabel(exchange), reply.status(), head ? 0 : reply.body().length);
        }
    }

    private static String routeLabel(HttpExchange exchange) {
        String path = exchange.getRequestURI().getPath();
        return ROUTES.containsKey(path) ? path : "unmatched";
    }

    private static String methodLabel(HttpExchange exchange) {
        String method = exchange.getRequestMethod();
        return Set.of("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS").contains(method) ? method : "OTHER";
    }
}
