package dev.filtsiap.ded.anonymizer.chat.build;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BuildChatListsTest {
    @TempDir
    Path dir;

    @Test
    void propertiesAreWrittenSortedWithoutACommentOrTimestampAndWithLineFeeds() throws IOException {
        Path file = dir.resolve("lists.properties");
        BuildChatLists.writeProperties(file, new TreeMap<>(Map.of("b", "2", "built", "2026-10-12", "a", "1")));
        assertEquals("a=1\nb=2\nbuilt=2026-10-12\n", Files.readString(file, StandardCharsets.UTF_8));
    }

    @Test
    void propertiesRoundTripThroughPropertiesLoad() throws IOException {
        Map<String, String> in = Map.of("source.q", "SELECT ?l WHERE { ?p wdt:P27 wd:Q41 . } # x!", "k", "  lead",
                "u", "κ");
        Path file = dir.resolve("p.properties");
        BuildChatLists.writeProperties(file, in);
        Properties p = new Properties();
        try (InputStream s = Files.newInputStream(file)) {
            p.load(s);
        }
        assertEquals(in.size(), p.size());
        in.forEach((k, v) -> assertEquals(v, p.getProperty(k)));
    }

    @Test
    void theHeadCommitIsReadFromTheGithubApiAnswer() {
        String json = """
                {"sha":"67032ee957631908098a72edf48dc81cac27e369","node_id":"x","commit":{"author":
                {"name":"A","email":"a@x","date":"2026-09-21T21:35:49Z"},"committer":{"name":"B","email":"b@x",
                "date":"2026-10-12T12:58:15Z"},"message":"m"},"committer":{"login":"b","id":1}}
                """;
        Map<String, String> c = BuildChatLists.parseCommit(json);
        assertEquals("67032ee957631908098a72edf48dc81cac27e369", c.get("source.dictionaries_commit"));
        assertEquals("2026-10-12T12:58:15Z", c.get("source.dictionaries_commit_date"));
    }

    @Test
    void anAnswerWithoutACommitIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> BuildChatLists.parseCommit("{\"message\":\"Not Found\"}"));
    }
}
