package dev.filtsiap.ded.anonymizer.chat.build;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dev.filtsiap.ded.anonymizer.chat.GreekFold;
import dev.filtsiap.ded.anonymizer.chat.GreekInflection;

/**
 * Dev-time tool, never run by the service: downloads the sources into a cache, expands and folds
 * them, and writes config/chat. Usage (from the repo root, after `mvn -q test-compile`):
 *
 * <pre>
 * java -Xmx2g -cp "target/test-classes;target/classes"
 *     dev.filtsiap.ded.anonymizer.chat.build.BuildChatLists config/chat .cache/chat-lists
 * </pre>
 *
 * (One command, wrapped here. Use ':' instead of ';' in the classpath on Linux/macOS.)
 */
public final class BuildChatLists {
    static final String LO = "https://raw.githubusercontent.com/LibreOffice/dictionaries/master/";
    static final Map<String, String> DOWNLOADS = Map.of(
            "el_GR.aff", LO + "el_GR/el_GR.aff",
            "el_GR.dic", LO + "el_GR/el_GR.dic",
            "en_US.aff", LO + "en/en_US.aff",
            "en_US.dic", LO + "en/en_US.dic");
    /** The head of the dictionaries repository: its SHA and date say which snapshot the lists come from. */
    static final String LO_HEAD = "https://api.github.com/repos/LibreOffice/dictionaries/commits/master";
    static final String WDQS = "https://query.wikidata.org/sparql?query=";
    static final String GIVEN_QUERY = "SELECT DISTINCT ?l WHERE { VALUES ?t {wd:Q12308941 wd:Q11879590} "
            + "?n wdt:P31 ?t ; wdt:P1705 ?l . FILTER(LANG(?l)=\"el\") }";
    /** Given names (P735) of Greek citizens: catches common names that carry no native-label (P1705) statement. */
    static final String GIVEN_PEOPLE_QUERY = "SELECT DISTINCT ?l WHERE { ?p wdt:P27 wd:Q41 ; wdt:P735 ?g . "
            + "?g rdfs:label ?l . FILTER(LANG(?l)=\"el\") }";
    /** A folded form made only of the basic Greek letters; drops quirks such as U+03D1 or U+03F0. */
    static final Pattern BASIC_GREEK = Pattern.compile("[α-ω]+");
    static final String SURNAME_QUERY = "SELECT DISTINCT ?l WHERE { ?p wdt:P27 wd:Q41 ; wdt:P734 ?f . "
            + "?f rdfs:label ?l . FILTER(LANG(?l)=\"el\") }";
    /** One Greek word, optionally hyphenated; labels with spaces or other scripts are skipped. */
    static final Pattern GREEK_NAME = Pattern.compile("[\\p{IsGreek}]+(?:-[\\p{IsGreek}]+)?");

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NORMAL).build();

    private BuildChatLists() {
    }

    public static void main(String[] args) throws Exception {
        Path out = Path.of(args.length > 0 ? args[0] : "config/chat");
        Path cache = Path.of(args.length > 1 ? args[1] : ".cache/chat-lists");
        Files.createDirectories(cache);
        for (Map.Entry<String, String> d : DOWNLOADS.entrySet()) {
            fetch(d.getValue(), cache.resolve(d.getKey()), "*/*");
        }
        fetch(LO_HEAD, cache.resolve("dictionaries_commit.json"), "application/vnd.github+json");
        fetch(WDQS + URLEncoder.encode(GIVEN_QUERY, StandardCharsets.UTF_8), cache.resolve("given.csv"), "text/csv");
        fetch(WDQS + URLEncoder.encode(GIVEN_PEOPLE_QUERY, StandardCharsets.UTF_8),
                cache.resolve("given_people.csv"), "text/csv");
        fetch(WDQS + URLEncoder.encode(SURNAME_QUERY, StandardCharsets.UTF_8),
                cache.resolve("surnames.csv"), "text/csv");

        Set<String> given = names(cache.resolve("given.csv"));
        given.addAll(names(cache.resolve("given_people.csv")));
        Set<String> surnames = names(cache.resolve("surnames.csv"));
        Set<String> elCommon = new TreeSet<>();
        Set<String> elProper = new TreeSet<>();
        expandDictionary(cache.resolve("el_GR.aff"), cache.resolve("el_GR.dic"), elCommon, elProper);
        Set<String> enCommon = new TreeSet<>();
        expandDictionary(cache.resolve("en_US.aff"), cache.resolve("en_US.dic"), enCommon, new TreeSet<>());
        elProper.removeAll(given);
        elProper.removeAll(surnames);

        Files.createDirectories(out);
        write(out.resolve("given_names.txt"), given, false);
        write(out.resolve("surnames.txt"), surnames, false);
        write(out.resolve("el_common.txt.gz"), elCommon, true);
        write(out.resolve("el_proper.txt.gz"), elProper, true);
        write(out.resolve("en_common.txt.gz"), enCommon, true);

        Map<String, String> p = new TreeMap<>();
        p.put("built", LocalDate.now().toString());
        DOWNLOADS.forEach((k, v) -> p.put("source." + k, v));
        p.putAll(parseCommit(Files.readString(cache.resolve("dictionaries_commit.json"), StandardCharsets.UTF_8)));
        p.put("source.given_names", "Wikidata SPARQL: " + GIVEN_QUERY);
        p.put("source.given_names_people", "Wikidata SPARQL: " + GIVEN_PEOPLE_QUERY);
        p.put("source.surnames", "Wikidata SPARQL: " + SURNAME_QUERY);
        p.put("count.given_names", Integer.toString(given.size()));
        p.put("count.surnames", Integer.toString(surnames.size()));
        p.put("count.el_common", Integer.toString(elCommon.size()));
        p.put("count.el_proper", Integer.toString(elProper.size()));
        p.put("count.en_common", Integer.toString(enCommon.size()));
        writeProperties(out.resolve("lists.properties"), p);
        System.out.println(p);
    }

    /**
     * The commit SHA and committer date from a GitHub "get a commit" answer, as
     * source.dictionaries_commit and source.dictionaries_commit_date.
     *
     * @throws IllegalArgumentException when the answer has no commit
     */
    static Map<String, String> parseCommit(String json) {
        try {
            JsonNode root = new ObjectMapper().readTree(json);
            String sha = root.path("sha").asText("");
            String date = root.path("commit").path("committer").path("date").asText("");
            if (sha.isEmpty() || date.isEmpty()) {
                throw new IllegalArgumentException("no commit in the GitHub answer");
            }
            return Map.of("source.dictionaries_commit", sha, "source.dictionaries_commit_date", date);
        } catch (IOException e) {
            throw new IllegalArgumentException("not JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Writes {@code key=value} lines in key order, with LF line ends, no comment and no timestamp
     * (unlike {@code Properties.store}), so a rebuild changes only what changed. Readable by
     * {@code Properties.load}: ':' '=' '#' '!' and backslash are escaped, and non-ASCII characters
     * are written as backslash-u escapes.
     */
    static void writeProperties(Path file, Map<String, String> entries) throws IOException {
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, String> e : new TreeMap<>(entries).entrySet()) {
            b.append(escape(e.getKey(), true)).append('=').append(escape(e.getValue(), false)).append('\n');
        }
        Files.writeString(file, b, StandardCharsets.US_ASCII);
    }

    private static String escape(String s, boolean key) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == ':' || c == '=' || c == '#' || c == '!' || (c == ' ' && (key || i == 0))) {
                b.append('\\').append(c);
            } else if (c == '\n') {
                b.append("\\n");
            } else if (c == '\r') {
                b.append("\\r");
            } else if (c == '\t') {
                b.append("\\t");
            } else if (c < 0x20 || c > 0x7e) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** Downloads once; a cached file is reused, so a rebuild with the same cache is reproducible. */
    static void fetch(String url, Path target, String accept) throws IOException, InterruptedException {
        if (Files.isRegularFile(target) && Files.size(target) > 0) {
            return;
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMinutes(3))
                .header("Accept", accept)
                .header("User-Agent", "ded-anonymizer-list-builder/1.0 (internal build tool)").GET().build();
        HttpResponse<Path> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofFile(target));
        if (resp.statusCode() != 200) {
            Files.deleteIfExists(target);
            throw new IOException("GET " + url + " -> HTTP " + resp.statusCode());
        }
    }

    /** CSV with header "l": each Greek single-word label, folded, expanded through GreekInflection. */
    static Set<String> names(Path csv) throws IOException {
        Set<String> out = new TreeSet<>();
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        for (String line : lines.subList(1, lines.size())) {
            String label = line.strip().replace("\"", "");
            if (GREEK_NAME.matcher(label).matches()) {
                for (String part : label.split("-")) {
                    for (String form : GreekInflection.forms(GreekFold.fold(part))) {
                        if (BASIC_GREEK.matcher(form).matches()) {
                            out.add(form);
                        }
                    }
                }
            }
        }
        return out;
    }

    /** Lowercase-initial entries go to {@code common}, capitalised ones to {@code proper}; every form, folded. */
    static void expandDictionary(Path aff, Path dic, Collection<String> common, Collection<String> proper)
            throws IOException {
        HunspellAffixes affixes = HunspellAffixes.parse(Files.readAllBytes(aff));
        List<String> lines = Files.readAllLines(dic, affixes.charset());
        for (String line : lines.subList(1, lines.size())) {   // line 1 is the entry count
            if (line.isBlank()) {
                continue;
            }
            for (String form : affixes.expand(line)) {
                if (form.isEmpty() || !Character.isLetter(form.codePointAt(0))) {
                    continue;
                }
                (Character.isUpperCase(form.codePointAt(0)) ? proper : common).add(GreekFold.fold(form));
            }
        }
    }

    static void write(Path path, Collection<String> sortedFolded, boolean gzip) throws IOException {
        try (OutputStream raw = Files.newOutputStream(path);
             OutputStream o = gzip ? new GZIPOutputStream(raw, 1 << 16) : raw;
             BufferedWriter w = new BufferedWriter(new OutputStreamWriter(o, StandardCharsets.UTF_8))) {
            for (String word : sortedFolded) {
                w.write(word);
                w.write('\n');
            }
        }
    }
}
