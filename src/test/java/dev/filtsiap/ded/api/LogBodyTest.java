package dev.filtsiap.ded.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.text.Normalizer;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.InvalidDocumentError;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.chat.ChatLists;
import dev.filtsiap.ded.anonymizer.chat.ChatPipeline;
import dev.filtsiap.ded.anonymizer.chat.NerDetector;
import dev.filtsiap.ded.anonymizer.chat.PiiType;

class LogBodyTest {
    static final ChatPipeline CHAT = new ChatPipeline(Config.loadFileConfig(Path.of("config")).rules(),
            ChatLists.of(List.of("Γιώργος"), List.of("Παπαδόπουλος"),
                    List.of("με", "λένε", "έχω", "παιδια", "τι", "επιδομα", "θα", "παρω", "και", "είπε",
                            "τέλος", "ευχαριστώ"),
                    List.of(), List.of(), List.of("αφμ")),
            NerDetector.NONE, true);

    static final String PII = "με λένε Γιώργο Παπαδόπουλο, ΑΦΜ 090000045";

    static LogBody.Result real(String json) {
        return LogBody.anonymizeUserQuery(json, t -> CHAT.anonymize(t, RunContext.start(60).deadline()));
    }

    /** A stand-in for the pipeline: returns {@code replacement} for any input, with no findings. */
    static LogBody.Result fake(String json, String replacement) {
        return LogBody.anonymizeUserQuery(json,
                t -> new ChatPipeline.TextResult(replacement, ChatPipeline.Status.ANONYMIZED, Map.of(), List.of()));
    }

    /** A log line with the whole documented structure around the given {@code user_query} JSON token. */
    static String line(String queryToken) {
        return "{\"session_id\":\"s-1\", \"timestamp\" : \"2026-10-14T10:00:00Z\",\"mode\":\"rag 🙏\",\"user_query\":"
                + queryToken + ",\n"
                + "  \"topk_retrieved_payload\":[{\"id\":1,\"chunkNo\":2,\"carrierId\":3,"
                + "\"similarity\":0.8123456789012345,\"textScore\":null,\"extractedFacts\":[\"α\\nβ\"],"
                + "\"thematicChain\":[{\"level\":1,\"id\":7,\"label\":\"Επίδομα\",\"type\":\"t\"}],"
                + "\"content\":\"γραμμή1\\nγραμμή2 \\u03b1 \\/ \\\"q\\\"\"},"
                + "{\"id\":2,\"chunkNo\":1,\"carrierId\":3,\"similarity\":1e-7,\"textScore\":null,"
                + "\"user_query\":\"nested ΑΦΜ 090000045\",\"content\":\"x\"}],"
                + "\"retrieved_information_for_final_answer\":{\"context\":\"κείμενο\"},"
                + "\"final_answer\":\"ok\",\"status\":\"success\"}\n";
    }

    static String quoted(String s) {
        return "\"" + s + "\"";
    }

    @Test
    void masksOnlyTheUserQueryValueAndKeepsEveryOtherByte() {
        String in = line(quoted(PII));
        LogBody.Result r = real(in);
        int start = in.indexOf(PII);
        int tail = in.length() - (start + PII.length());
        String out = r.body();
        assertEquals(in.substring(0, start), out.substring(0, start));
        assertEquals(in.substring(in.length() - tail), out.substring(out.length() - tail));
        assertEquals("με λένε ...... ..........., ΑΦΜ .........", out.substring(start, out.length() - tail));
        assertTrue(out.contains("\"user_query\":\"nested ΑΦΜ 090000045\""));
        assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
        assertEquals(1, r.counts().get(PiiType.AFM));
        assertEquals(2, r.counts().get(PiiType.PERSON));
    }

    @Test
    void aQueryWithNothingToMaskComesBackByteIdenticalEvenWhenItsEscapesWereUnusual() {
        for (String token : List.of("\"επιδομα α21\"", "\"α21\"",
                "\"\\u03b5\\u03c0\\u03b9\\u03b4\\u03bf\\u03bc\\u03b1 \\/\"",
                "\"έχω 3 παιδια τι επιδομα θα παρω?\"", "\"\"")) {
            String in = line(token);
            assertEquals(in, real(in).body(), token);
        }
    }

    @Test
    void aDecomposedQueryWithNothingToMaskIsNotRewrittenToNfc() {
        String nfd = Normalizer.normalize("έχω 3 παιδια τι επίδομα θα παρω", Normalizer.Form.NFD);
        String in = line(quoted(nfd));
        LogBody.Result r = real(in);
        assertEquals(in, r.body());
        assertTrue(r.counts().isEmpty());
    }

    @Test
    void aDecomposedQueryWithPiiIsMaskedAndComesBackAsNfc() {
        String nfd = Normalizer.normalize("είπε ΑΦΜ 090000045 τέλος", Normalizer.Form.NFD);
        assertEquals("{\"user_query\":\"είπε ΑΦΜ ......... τέλος\"}", real("{\"user_query\":\"" + nfd + "\"}").body());
    }

    @Test
    void aResultThatNeedsReviewWithoutReasonsStillNeedsReview() {
        LogBody.Result r = LogBody.anonymizeUserQuery("{\"user_query\":\"x\"}",
                t -> new ChatPipeline.TextResult(t, ChatPipeline.Status.NEEDS_REVIEW, Map.of(), List.of()));
        assertEquals(ChatPipeline.Status.NEEDS_REVIEW, r.status());
        assertTrue(r.reviewReasons().isEmpty());
    }

    @Test
    void anUnchangedBodyIsReturnedAsTheSameStringNotACopy() {
        String in = line(quoted("επιδομα α21"));
        assertSame(in, real(in).body());
        String none = "{\"a\":1}";
        assertSame(none, real(none).body());
    }

    @Test
    void aMissingOrNullQueryIsReturnedUnchangedAsAnonymizedWithNoCounts() {
        AtomicInteger calls = new AtomicInteger();
        for (String in : List.of("{\"a\":1}", "{\"user_query\":null,\"a\":1}", "{}",
                " { \"x\" : { \"user_query\" : \"ΑΦΜ 090000045\" } } ")) {
            LogBody.Result r = LogBody.anonymizeUserQuery(in, t -> {
                calls.incrementAndGet();
                return null;
            });
            assertEquals(in, r.body());
            assertEquals(ChatPipeline.Status.ANONYMIZED, r.status());
            assertTrue(r.counts().isEmpty());
            assertTrue(r.reviewReasons().isEmpty());
        }
        assertEquals(0, calls.get());
    }

    @Test
    void aNonStringQueryIsReturnedUnchangedAndNeedsReview() {
        for (String value : List.of("42", "{\"a\":\"ΑΦΜ 090000045\"}", "[\"ΑΦΜ 090000045\"]", "true", "1.5e3")) {
            String in = "{\"user_query\":" + value + ",\"b\":2}";
            LogBody.Result r = real(in);
            assertEquals(in, r.body(), value);
            assertEquals(ChatPipeline.Status.NEEDS_REVIEW, r.status());
            assertEquals(List.of("user_query_not_a_string"), r.reviewReasons());
        }
    }

    @Test
    void aDuplicatedQueryKeyIsMaskedAtBothPlacesAndTheResultsAreMerged() {
        String in = "{\"user_query\":\"ΑΦΜ 090000045\",\"k\":\"ΑΦΜ 090000045\","
                + "\"user_query\":\"ΑΦΜ 090000045 και 090000045\"}";
        LogBody.Result r = real(in);
        assertEquals("{\"user_query\":\"ΑΦΜ .........\",\"k\":\"ΑΦΜ 090000045\","
                + "\"user_query\":\"ΑΦΜ ......... και .........\"}", r.body());
        assertEquals(3, r.counts().get(PiiType.AFM));
    }

    @Test
    void aStringAndANonStringDuplicateMaskTheStringAndAskForReview() {
        LogBody.Result r = real("{\"user_query\":\"ΑΦΜ 090000045\",\"user_query\":7}");
        assertEquals("{\"user_query\":\"ΑΦΜ .........\",\"user_query\":7}", r.body());
        assertEquals(ChatPipeline.Status.NEEDS_REVIEW, r.status());
        assertEquals(List.of("user_query_not_a_string"), r.reviewReasons());
        assertEquals(1, r.counts().get(PiiType.AFM));
    }

    @Test
    void theKeyIsMatchedAfterDecodingItsEscapes() {
        assertEquals("{\"user\\u005fquery\":\"ΑΦΜ .........\"}",
                real("{\"user\\u005fquery\":\"ΑΦΜ 090000045\"}").body());
    }

    @Test
    void escapedQuotesAndNewlinesInTheQuerySurviveAndStayEscaped() {
        String in = "{\"user_query\":\"είπε \\\"ΑΦΜ\\\"\\n090000045\\tτέλος\",\"z\":1}";
        assertEquals("{\"user_query\":\"είπε \\\"ΑΦΜ\\\"\\n.........\\tτέλος\",\"z\":1}", real(in).body());
    }

    @Test
    void anEmojiBeforeThePiiKeepsEveryOffsetRight() {
        String in = line(quoted("🙏🙏 ΑΦΜ 090000045 ευχαριστώ"));
        String out = real(in).body();
        assertEquals(in.replace("🙏🙏 ΑΦΜ 090000045 ευχαριστώ", "🙏🙏 ΑΦΜ ......... ευχαριστώ"), out);
    }

    @Test
    void queriesPastTheParsersFirstBufferAreSplicedAtTheRightOffsets() {
        // Real lines are over 32K chars, where Jackson reads the String through a buffered reader.
        String pad = "\"pad\":\"" + "x".repeat(40_000) + "\",";
        String in = "{" + pad + "\"user_query\":\"ΑΦΜ 090000045\"," + pad + "\"user_query\":\"ΑΦΜ 090000045\"}";
        assertEquals(in.replace("ΑΦΜ 090000045", "ΑΦΜ ........."), real(in).body());
    }

    @Test
    void anEscapedEmojiIsReEncodedAsTheEmojiItselfWhenTheValueChanges() {
        assertEquals("{\"user_query\":\"🙏 ΑΦΜ .........\"}",
                real("{\"user_query\":\"\\ud83d\\ude4f ΑΦΜ 090000045\"}").body());
    }

    @Test
    void theReplacementIsEncodedAsAJsonString() {
        LogBody.Result r = fake("{\"user_query\":\"x\",\"n\":1}", "a\"b\\c\nd\re\tf\u0001g\u001fé");
        assertEquals("{\"user_query\":\"a\\\"b\\\\c\\nd\\re\\tf\\u0001g\\u001fé\",\"n\":1}", r.body());
    }

    @Test
    void aLeadingBomIsAcceptedAndKeptInTheBody() {
        String in = "\uFEFF" + line(quoted(PII));
        assertEquals(in.replace(PII, "με λένε ...... ..........., ΑΦΜ ........."), real(in).body());
        String clean = "\uFEFF" + line(quoted("επιδομα α21"));
        assertEquals(clean, real(clean).body());
        assertEquals("\uFEFF{\"user_query\":\"ΑΦΜ .........\"}",
                real("\uFEFF{\"user_query\":\"ΑΦΜ 090000045\"}").body());
    }

    @Test
    void aLoneSurrogateEscapeInAMaskedQueryIsWrittenBackAsTheSameEscape() {
        assertEquals("{\"user_query\":\"\\ud83d ΑΦΜ ......... \\ude4f\"}",
                real("{\"user_query\":\"\\ud83d ΑΦΜ 090000045 \\ude4f\"}").body());
        assertEquals("{\"user_query\":\"a\\udc00🙏\\ud800\"}",
                fake("{\"user_query\":\"x\"}", "a\udc00🙏\ud800").body());
    }

    @Test
    void refusesAnythingButOneJsonObject() {
        assertCode("NOT_A_JSON_OBJECT", "[]");
        assertCode("NOT_A_JSON_OBJECT", "[{\"user_query\":\"a\"}]");
        assertCode("NOT_A_JSON_OBJECT", "\"text\"");
        assertCode("NOT_A_JSON_OBJECT", "42");
        assertCode("NOT_A_JSON_OBJECT", "null");
        assertCode("INVALID_JSON", "{\"user_query\":\"a\"} x");
        assertCode("INVALID_JSON", "{\"user_query\":\"a\"}{\"user_query\":\"b\"}");
        assertCode("INVALID_JSON", "{\"user_query\":\"a\"}\n{\"user_query\":\"b\"}\n");
        assertCode("INVALID_JSON", "{\"user_query\":");
        assertCode("INVALID_JSON", "{\"user_query\":\"a\"");
        assertCode("INVALID_JSON", "{user_query:\"a\"}");
        assertCode("INVALID_JSON", "{'user_query':'a'}");
        assertCode("INVALID_JSON", "{\"user_query\":\"a\",}");
        assertCode("INVALID_JSON", "{\"user_query\":\"a\nb\"}");
        assertCode("INVALID_JSON", "");
        assertCode("INVALID_JSON", "   \n");
        assertCode("INVALID_JSON", "not json");
    }

    @Test
    void aVeryDeepDocumentIsRefusedNotCrashed() {
        assertCode("INVALID_JSON", "{\"a\":" + "[".repeat(5000) + "]".repeat(5000) + "}");
    }

    @Test
    void jacksonsDepthAndNumberLimitsAreTheDocumentedOnes() {
        // README: nesting deeper than 1000 levels, or a number longer than about 1000 digits, is INVALID_JSON.
        String deepest = "{\"a\":" + "[".repeat(999) + "]".repeat(999) + "}";
        assertEquals(deepest, real(deepest).body());
        assertCode("INVALID_JSON", "{\"a\":" + "[".repeat(1000) + "]".repeat(1000) + "}");
        String longest = "{\"n\":" + "1".repeat(1000) + ",\"f\":0." + "1".repeat(999) + "}";
        assertEquals(longest, real(longest).body());
        assertCode("INVALID_JSON", "{\"n\":" + "1".repeat(1001) + "}");
        assertCode("INVALID_JSON", "{\"f\":0." + "1".repeat(5000) + "}");
    }

    private static void assertCode(String code, String json) {
        InvalidDocumentError e = assertThrows(InvalidDocumentError.class, () -> real(json));
        assertEquals(code, e.code());
        assertFalse(e.getMessage().contains("user_query"), "the message must not quote the body");
    }
}
