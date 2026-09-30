package dev.filtsiap.ded.api;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import dev.filtsiap.ded.anonymizer.AIProviderError;
import dev.filtsiap.ded.anonymizer.AITimeoutError;
import dev.filtsiap.ded.anonymizer.AIUnavailableError;
import dev.filtsiap.ded.anonymizer.AnonymizeResult;
import dev.filtsiap.ded.anonymizer.AnonymizerError;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.DocumentProcessingError;
import dev.filtsiap.ded.anonymizer.FileConfig;
import dev.filtsiap.ded.anonymizer.InvalidDocumentError;
import dev.filtsiap.ded.anonymizer.Pipeline;
import dev.filtsiap.ded.anonymizer.PostcheckSummary;
import dev.filtsiap.ded.anonymizer.ResidualPIIError;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.anonymizer.pycompat.PyStr;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP transport (rewrite of {@code anonymizer/api.py}). Transport only: it parses the upload,
 * calls the same {@link Pipeline} the CLI calls, and serializes the result.
 *
 * <pre>
 * POST /anonymize   multipart field "file", or a raw DOCX / octet-stream body; bearer auth
 * GET  /healthz     unauthenticated liveness probe
 * </pre>
 *
 * Responses reproduce FastAPI's: compact JSON, {@code {"detail": ...}} for HTTP errors,
 * {@code {"error", "detail"}} for anonymizer errors, 404/405/307 routing answers and the 422
 * query-validation body.
 */
final class ApiHandler implements HttpHandler {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.api");
    private static final Logger ACCESS = LoggerFactory.getLogger("anonymizer.api.access");

    static final String DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

    /** Exact-class mapping, as {@code _ERROR_STATUS_CODES.get(type(exc), 500)}. */
    private static final Map<Class<? extends AnonymizerError>, Integer> ERROR_STATUS = Map.of(
            InvalidDocumentError.class, 400,
            DocumentProcessingError.class, 422,
            ResidualPIIError.class, 422,
            AIProviderError.class, 502,
            ConfigurationError.class, 503,
            AIUnavailableError.class, 503,
            AITimeoutError.class, 504);

    private static final Map<String, String> ROUTES = Map.of("/anonymize", "POST", "/healthz", "GET");
    private static final Pattern PYDANTIC_INT = Pattern.compile("[+-]?[0-9]+(?:_[0-9]+)*(?:\\.0*)?");
    /** Headroom for multipart framing and extra fields, so memory stays bounded. */
    private static final long MULTIPART_OVERHEAD_BYTES = 1024L * 1024;

    private final RuntimeConfig cfg;
    private final FileConfig files;
    private final LlmClient client;

    ApiHandler(RuntimeConfig cfg, FileConfig files, LlmClient client) {
        this.cfg = cfg;
        this.files = files;
        this.client = client;
    }

    /** A FastAPI {@code HTTPException}: status, {@code {"detail": detail}}, extra headers. */
    private static final class HttpError extends Exception {
        private static final long serialVersionUID = 1L;
        final int status;
        final Object detail;
        final Map<String, String> headers;

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
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", e.getClass().getSimpleName());
            body.put("detail", e.getMessage());
            reply = json(ERROR_STATUS.getOrDefault(e.getClass(), 500), body, Map.of());
        } catch (RuntimeException e) {
            LOG.error("unhandled error serving {} {}", exchange.getRequestMethod(), exchange.getRequestURI().getPath(), e);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", "InternalServerError");
            body.put("detail", "internal error");
            reply = json(500, body, Map.of());
        }
        send(exchange, reply);
    }

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
        if (!allowed.equals(method)) {
            throw new HttpError(405, "Method Not Allowed", Map.of("allow", allowed));
        }
        if (path.equals("/healthz")) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", "ok");
            body.put("provider", cfg.provider().wire());
            body.put("model", cfg.modelHandle());
            return json(200, body, Map.of());
        }
        return anonymize(exchange);
    }

    // ------------------------------------------------------------------ POST /anonymize

    private Reply anonymize(HttpExchange exchange) throws HttpError, IOException {
        requireApiKey(exchange.getRequestHeaders()); // before the body is read
        byte[] payload = readPayload(exchange);
        boolean summary = summaryFlag(exchange.getRequestURI().getRawQuery());

        AnonymizeResult result = Pipeline.anonymizeDocument(payload, cfg, files, client);
        if (!summary) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("content-disposition", "attachment; filename=\"" + result.documentId() + "_redacted.docx\"");
            headers.putAll(postcheckHeaders(result.postcheck()));
            return new Reply(200, DOCX_MEDIA_TYPE, result.redactedDocx(), headers);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("document_id", result.documentId());
        body.put("summary", result.summary().asMap());
        body.put("warnings", result.warnings());
        body.put("model", result.model());
        body.put("postcheck", result.postcheck() == null ? null : result.postcheck().asMap());
        body.put("provenance", result.provenance());
        body.put("docx_base64", Base64.getEncoder().encodeToString(result.redactedDocx()));
        return json(200, body, Map.of());
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

    private byte[] readPayload(HttpExchange exchange) throws HttpError, IOException {
        String contentType = headerValue(exchange.getRequestHeaders(), "Content-Type");
        long limit = (long) cfg.maxUploadMb() * 1024 * 1024;
        byte[] data;
        if (contentType.startsWith("multipart/form-data")) {
            byte[] body = readCapped(exchange.getRequestBody(), limit + MULTIPART_OVERHEAD_BYTES);
            List<Multipart.Part> parts;
            try {
                parts = Multipart.parse(contentType, body);
            } catch (Multipart.MultiPartException e) {
                throw new HttpError(400, e.getMessage());
            }
            Multipart.Part upload = null;
            for (Multipart.Part p : parts) {
                if (p.name().equals("file")) {
                    upload = p; // FormData.get: last value wins
                }
            }
            if (upload == null) {
                throw new InvalidDocumentError("multipart form is missing the 'file' field");
            }
            if (upload.filename() == null) {
                throw new InvalidDocumentError("multipart field 'file' must be a file part");
            }
            data = upload.data();
        } else if (contentType.startsWith(DOCX_MEDIA_TYPE) || contentType.startsWith("application/octet-stream")) {
            data = readCapped(exchange.getRequestBody(), limit);
        } else {
            throw new HttpError(415, "unsupported content type");
        }
        if (data.length == 0) {
            throw new InvalidDocumentError("empty request body");
        }
        if (data.length > limit) {
            throw new HttpError(413, "upload exceeds ANON_MAX_UPLOAD_MB");
        }
        return data;
    }

    /** Reads at most {@code cap + 1} bytes: anything past the cap is already a 413. */
    private static byte[] readCapped(InputStream in, long cap) throws IOException, HttpError {
        byte[] data = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, cap + 1));
        if (data.length > cap) {
            throw new HttpError(413, "upload exceeds ANON_MAX_UPLOAD_MB");
        }
        return data;
    }

    /**
     * The {@code summary: int = 0} query parameter: last value wins; Pydantic's lax int parsing
     * (surrounding whitespace, sign, underscores, a zero fraction such as "1.0"); anything else
     * is FastAPI's 422.
     */
    static boolean summaryFlag(String rawQuery) throws HttpError {
        String value = null;
        if (rawQuery != null) {
            for (String pair : rawQuery.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String k = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
                if (k.equals("summary")) {
                    value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                }
            }
        }
        if (value == null) {
            return false;
        }
        String stripped = PyStr.strip(value);
        if (!PYDANTIC_INT.matcher(stripped).matches()) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("type", "int_parsing");
            err.put("loc", List.of("query", "summary"));
            err.put("msg", "Input should be a valid integer, unable to parse string as an integer");
            err.put("input", value);
            err.put("url", "https://errors.pydantic.dev/2.13/v/int_parsing");
            throw new HttpError(422, List.of(err));
        }
        String digits = stripped.replace("_", "").replaceFirst("\\..*$", "").replaceFirst("^[+-]", "");
        return !digits.chars().allMatch(c -> c == '0');
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
            // gunicorn's access-log format: host, request line, status, size, referer, user agent.
            Headers in = exchange.getRequestHeaders();
            ACCESS.info("{} - - [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
                    exchange.getRemoteAddress().getAddress().getHostAddress(), CLF.format(ZonedDateTime.now()),
                    exchange.getRequestMethod(), exchange.getRequestURI(), exchange.getProtocol(), reply.status(),
                    head ? 0 : reply.body().length, orDash(in.getFirst("Referer")), orDash(in.getFirst("User-Agent")));
        }
    }

    private static String orDash(String s) {
        return s == null ? "-" : s;
    }
}
