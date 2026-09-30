package dev.filtsiap.ded.api;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * multipart/form-data parsing with Starlette 0.27 / python-multipart semantics: a part is a
 * file part when its Content-Disposition carries a {@code filename} parameter (even an empty
 * one); a missing {@code name} is an error; duplicate names resolve to the last part
 * ({@code FormData.get}).
 */
final class Multipart {

    /** A client error Starlette reports as HTTP 400 with {@code {"detail": message}}. */
    static final class MultiPartException extends Exception {
        private static final long serialVersionUID = 1L;

        MultiPartException(String message) {
            super(message);
        }
    }

    /** One form part: {@code filename} is null for a plain text field. */
    record Part(String name, String filename, byte[] data) {
    }

    private static final int MAX_FILES = 1000;
    private static final int MAX_FIELDS = 1000;

    private Multipart() {
    }

    /** Parses a header value like {@code form-data; name="file"; filename="a.docx"} into lower-cased params. */
    static Map<String, String> options(String headerValue) {
        Map<String, String> out = new LinkedHashMap<>();
        if (headerValue == null) {
            return out;
        }
        int i = headerValue.indexOf(';');
        if (i < 0) {
            return out;
        }
        String rest = headerValue.substring(i + 1);
        int pos = 0;
        while (pos < rest.length()) {
            while (pos < rest.length() && (rest.charAt(pos) == ';' || Character.isWhitespace(rest.charAt(pos)))) {
                pos++;
            }
            int eq = rest.indexOf('=', pos);
            int semi = rest.indexOf(';', pos);
            if (eq < 0 || (semi >= 0 && semi < eq)) {
                int end = semi < 0 ? rest.length() : semi;
                String key = rest.substring(pos, end).trim().toLowerCase(Locale.ROOT);
                if (!key.isEmpty()) {
                    out.put(key, "");
                }
                pos = end + 1;
                continue;
            }
            String key = rest.substring(pos, eq).trim().toLowerCase(Locale.ROOT);
            pos = eq + 1;
            String value;
            if (pos < rest.length() && rest.charAt(pos) == '"') {
                StringBuilder sb = new StringBuilder();
                pos++;
                while (pos < rest.length() && rest.charAt(pos) != '"') {
                    char c = rest.charAt(pos);
                    if (c == '\\' && pos + 1 < rest.length()) {
                        c = rest.charAt(++pos);
                    }
                    sb.append(c);
                    pos++;
                }
                pos++;
                value = sb.toString();
            } else {
                int end = rest.indexOf(';', pos);
                end = end < 0 ? rest.length() : end;
                value = rest.substring(pos, end).trim();
                pos = end;
            }
            out.put(key, value);
        }
        return out;
    }

    /** Parses the body; {@code contentType} is the request's Content-Type header. */
    static List<Part> parse(String contentType, byte[] body) throws MultiPartException {
        Map<String, String> params = options(contentType);
        String boundary = params.get("boundary");
        if (boundary == null) {
            throw new MultiPartException("Missing boundary in multipart.");
        }
        Charset charset;
        try {
            charset = Charset.forName(params.getOrDefault("charset", "utf-8"));
        } catch (RuntimeException e) {
            charset = StandardCharsets.UTF_8;
        }
        byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        List<Part> parts = new ArrayList<>();
        int files = 0;
        int fields = 0;

        int pos = indexOf(body, delimiter, 0);
        if (pos < 0) {
            return parts; // no parts: python-multipart yields an empty form
        }
        while (true) {
            pos += delimiter.length;
            if (pos + 1 < body.length && body[pos] == '-' && body[pos + 1] == '-') {
                break; // closing delimiter
            }
            pos = skipLineEnd(body, pos);
            int headersEnd = indexOf(body, new byte[] {'\r', '\n', '\r', '\n'}, pos);
            if (headersEnd < 0) {
                break; // truncated: python-multipart finalizes without the incomplete part
            }
            String disposition = null;
            for (String line : new String(body, pos, headersEnd - pos, StandardCharsets.ISO_8859_1).split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("content-disposition")) {
                    disposition = line.substring(colon + 1).trim();
                }
            }
            int dataStart = headersEnd + 4;
            byte[] next = new byte[delimiter.length + 2];
            next[0] = '\r';
            next[1] = '\n';
            System.arraycopy(delimiter, 0, next, 2, delimiter.length);
            int dataEnd = indexOf(body, next, dataStart);
            if (dataEnd < 0) {
                break;
            }
            Map<String, String> opts = options(disposition);
            if (!opts.containsKey("name")) {
                throw new MultiPartException("The Content-Disposition header field \"name\" must be provided.");
            }
            String name = decode(opts.get("name"), charset);
            String filename = null;
            if (opts.containsKey("filename")) {
                if (++files > MAX_FILES) {
                    throw new MultiPartException("Too many files. Maximum number of files is " + MAX_FILES + ".");
                }
                filename = decode(opts.get("filename"), charset);
            } else if (++fields > MAX_FIELDS) {
                throw new MultiPartException("Too many fields. Maximum number of fields is " + MAX_FIELDS + ".");
            }
            parts.add(new Part(name, filename, Arrays.copyOfRange(body, dataStart, dataEnd)));
            pos = dataEnd + 2;
        }
        return parts;
    }

    /** Header params arrive as latin-1 text; Starlette decodes their bytes with the form charset. */
    private static String decode(String latin1, Charset charset) {
        return new String(latin1.getBytes(StandardCharsets.ISO_8859_1), charset);
    }

    private static int skipLineEnd(byte[] b, int pos) {
        while (pos < b.length && (b[pos] == ' ' || b[pos] == '\t')) {
            pos++;
        }
        if (pos + 1 < b.length && b[pos] == '\r' && b[pos + 1] == '\n') {
            return pos + 2;
        }
        return pos;
    }

    static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = Math.max(0, from); i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
