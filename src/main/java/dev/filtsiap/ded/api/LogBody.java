package dev.filtsiap.ded.api;

import java.io.IOException;
import java.io.StringReader;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import dev.filtsiap.ded.anonymizer.InvalidDocumentError;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.PiiType;

/**
 * POST /anonymize-log: one chatbot log entry (a JSON object) in, the same bytes out except the
 * value of the top-level {@code "user_query"} string, which is masked by the chat pipeline.
 *
 * <p>The value is found with Jackson's streaming parser, which reports where its token starts and
 * ends, and the masked text is spliced into the original text at that range. The body is never
 * read into a tree and written back, so field order, whitespace, number formatting, escapes and
 * unknown fields stay exactly as they arrived. Only the top-level key counts: a nested
 * {@code user_query} is skipped like any other value. A leading BOM is hidden from the parser and
 * kept in the body.
 */
final class LogBody {

    static final String QUERY_KEY = "user_query";

    private static final String NOT_A_STRING = "user_query_not_a_string";
    private static final JsonFactory JSON = new JsonFactory();

    /**
     * The spliced body and what the masked values reported.
     *
     * @param body          the request body with the query value(s) masked
     * @param status        needs-review when any value needed it, or a query was not a string
     * @param counts        masked regions per type, summed over every masked value
     * @param reviewReasons fixed strings only, without repeats
     */
    record Result(String body, ChatPipeline.Status status, Map<PiiType, Integer> counts, List<String> reviewReasons) {
    }

    /** The original range of one string token, quotes included, and its decoded text. */
    private record Value(int start, int end, String text) {
    }

    private LogBody() {
    }

    /**
     * Masks the top-level {@code user_query} string(s) of {@code json} and returns the rest as is.
     * A missing or null query is not an error (nothing to mask); a query that is not a string is
     * left alone and reported as {@code user_query_not_a_string}. A value the mask leaves unchanged
     * (apart from NFC normalisation) keeps its original token, so even its escapes are untouched; a
     * changed value is written as the pipeline's NFC output.
     *
     * @param json the whole request body: exactly one JSON object
     * @param mask the chat pipeline, given the decoded query text
     * @return the new body ({@code json} itself when nothing changed), the merged status, counts and
     *         review reasons
     * @throws InvalidDocumentError {@code NOT_A_JSON_OBJECT} when the body is JSON but not an object,
     *                              {@code INVALID_JSON} when it is not exactly one JSON value
     */
    static Result anonymizeUserQuery(String json, Function<String, ChatPipeline.TextResult> mask) {
        List<Value> values = new ArrayList<>();
        boolean notAString = scan(json, values);
        Map<PiiType, Integer> counts = new EnumMap<>(PiiType.class);
        Set<String> reasons = new LinkedHashSet<>();
        boolean review = false; // a status without reasons still counts
        StringBuilder out = null; // built only when a value changes: most queries carry no PII
        int copied = 0;
        for (Value v : values) {
            ChatPipeline.TextResult r = mask.apply(v.text());
            r.counts().forEach((type, n) -> counts.merge(type, n, Integer::sum));
            reasons.addAll(r.reviewReasons());
            review |= r.status() == ChatPipeline.Status.NEEDS_REVIEW;
            // The pipeline answers in NFC: a value that differs only by normalisation is unchanged.
            if (!r.masked().equals(Normalizer.normalize(v.text(), Normalizer.Form.NFC))) {
                if (out == null) {
                    out = new StringBuilder(json.length());
                }
                out.append(json, copied, v.start()).append(encode(r.masked()));
                copied = v.end();
            }
        }
        if (notAString) {
            reasons.add(NOT_A_STRING);
        }
        String body = out == null ? json : out.append(json, copied, json.length()).toString();
        return new Result(body, review || !reasons.isEmpty() ? ChatPipeline.Status.NEEDS_REVIEW
                : ChatPipeline.Status.ANONYMIZED, counts, List.copyOf(reasons));
    }

    /**
     * Walks the top-level members, collecting the string values of {@link #QUERY_KEY}; every other
     * value is skipped without being built. Jackson's own limits (nesting depth, string length)
     * bound the work.
     *
     * @return true when a {@code user_query} was present that is neither a string nor null
     */
    private static boolean scan(String json, List<Value> found) {
        boolean notAString = false;
        // Jackson refuses a BOM: it is skipped here, so every offset the parser reports is short by it.
        int bom = json.startsWith("\uFEFF") ? 1 : 0;
        StringReader reader = new StringReader(json);
        try (JsonParser p = JSON.createParser(reader)) {
            reader.skip(bom);
            JsonToken first = p.nextToken();
            if (first == null) {
                throw invalid("the body is empty");
            }
            if (first != JsonToken.START_OBJECT) {
                throw new InvalidDocumentError("the body is JSON but not an object", "NOT_A_JSON_OBJECT");
            }
            while (p.nextToken() == JsonToken.FIELD_NAME) {
                boolean query = QUERY_KEY.equals(p.currentName());
                JsonToken value = p.nextToken();
                if (query && value == JsonToken.VALUE_STRING) {
                    int start = bom + (int) p.currentTokenLocation().getCharOffset();
                    String text = p.getText(); // reads the token to its end: only then is the end known
                    found.add(new Value(start, bom + (int) p.currentLocation().getCharOffset(), text));
                } else {
                    notAString |= query && value != JsonToken.VALUE_NULL;
                    p.skipChildren();
                }
            }
            if (p.nextToken() != null) {
                throw invalid("the body has more than one JSON value");
            }
        } catch (IOException e) {
            // Jackson's message quotes the body: it is dropped here, never logged or sent.
            throw invalid("the body is not valid JSON");
        }
        return notAString;
    }

    private static InvalidDocumentError invalid(String message) {
        return new InvalidDocumentError(message, "INVALID_JSON");
    }

    /**
     * The text as a JSON string token: quote and backslash escaped, a newline, carriage return or
     * tab as its short escape, any other control character and any unpaired surrogate (which has no
     * UTF-8 form) as a four-digit hex escape, everything else as it is.
     */
    private static String encode(String text) {
        StringBuilder sb = new StringBuilder(text.length() + 2).append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (Character.isHighSurrogate(c) && i + 1 < text.length()
                            && Character.isLowSurrogate(text.charAt(i + 1))) {
                        sb.append(c).append(text.charAt(++i));
                    } else if (c < 0x20 || Character.isSurrogate(c)) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
