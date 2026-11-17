package dev.filtsiap.ded;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.AnonymizeResult;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.Pipeline;
import dev.filtsiap.ded.anonymizer.RunContext;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.TestDocx;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.ScriptedLlm;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** argparse-compatible parsing, the usage-error exit paths, and the per-document summary line. */
class RunAnonymizerTest {

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    PrintStream o() {
        return new PrintStream(out, true, StandardCharsets.UTF_8);
    }

    PrintStream e() {
        return new PrintStream(err, true, StandardCharsets.UTF_8);
    }

    @Test
    void abbreviationsAndInlineValues() throws Exception {
        RunAnonymizer.Args a = RunAnonymizer.parseArgs(new String[] {"--fi=x.docx", "--out", "o", "--sum", "--q"}, o(), e());
        assertEquals("x.docx", a.file());
        assertEquals("o", a.outDir());
        assertTrue(a.summaryJson() && a.qa());
    }

    @Test
    void helpExitsZeroWithPythonText() {
        RunAnonymizer.ArgExit x = assertThrows(RunAnonymizer.ArgExit.class,
                () -> RunAnonymizer.parseArgs(new String[] {"-h"}, o(), e()));
        assertEquals(0, x.code);
        String help = out.toString(StandardCharsets.UTF_8);
        assertTrue(help.startsWith("usage: run_anonymizer [-h] [--file FILE]"));
        // Same line-break style throughout (CRLF on Windows, LF elsewhere), as Python prints it.
        assertFalse(help.replace(System.lineSeparator(), "").contains("\n"));
    }

    @Test
    void usageErrorsExitTwo() {
        RunAnonymizer.ArgExit x = assertThrows(RunAnonymizer.ArgExit.class,
                () -> RunAnonymizer.parseArgs(new String[] {"a", "b"}, o(), e()));
        assertEquals(2, x.code);
        assertTrue(err.toString(StandardCharsets.UTF_8).endsWith("run_anonymizer: error: unrecognized arguments: b" + System.lineSeparator()));
        assertEquals(2, RunAnonymizer.run(new String[] {"--file", "a.docx", "b.docx"}, o(), e()));
        assertEquals(2, RunAnonymizer.run(new String[] {}, o(), e()));
    }

    @Test
    void regexModeRefusesTheCliWithTheRegexModeError() {
        assertTrue(RunAnonymizer.refusedInRegexMode(Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "regex")), e()));
        assertEquals("Error: AI model endpoint called while running in regex mode" + System.lineSeparator(),
                err.toString(StandardCharsets.UTF_8));
        assertFalse(RunAnonymizer.refusedInRegexMode(Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai",
                "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test")), e()));
    }

    /**
     * One synthetic document that makes every kind of call (pass 1, pass 2, its corrective retry, the
     * post-redaction remediation), with usage reported per call, cached and reasoning tokens on one,
     * and synthetic prices configured. Pass 2 first leaves the phone undecided, its retry PRESERVEs it,
     * the scan finds it (MEDIUM), and the remediation REDACTs it.
     */
    static AnonymizeResult pricedDocument() {
        Map<String, String> env = new HashMap<>(Map.of("ANON_PROVIDER", "openai",
                "OPENAI_API_KEY", "sk-test", "ANON_MODEL", "gpt-test"));
        env.put("ANON_INPUT_COST_PER_1M_TOKENS", "2.50");
        env.put("ANON_CACHED_INPUT_COST_PER_1M_TOKENS", "0.25");
        env.put("ANON_OUTPUT_COST_PER_1M_TOKENS", "10.00");
        RuntimeConfig cfg = Config.loadRuntimeConfig(env);
        ScriptedLlm llm = ScriptedLlm.completions(r -> {
            if (ScriptedLlm.isPass1(r)) {
                return ScriptedLlm.finished("[]", ScriptedLlm.usage(1500, 20));
            }
            if (ScriptedLlm.isRemediation(r)) {
                return ScriptedLlm.finished(PyJson.dumps(ScriptedLlm.candidates(r).stream()
                        .map(c -> ScriptedLlm.answer((String) c.get("id"), "REDACT", "PHONE")).toList()),
                        ScriptedLlm.usage(1800, 12));
            }
            List<Object> answers = new ArrayList<>();
            for (Map<String, Object> c : ScriptedLlm.candidates(r)) {
                boolean phone = ((String) c.get("text")).startsWith("69");
                if (ScriptedLlm.isRetry(r) || !phone) {
                    answers.add(ScriptedLlm.answer((String) c.get("id"), phone ? "PRESERVE" : "REDACT",
                            phone ? "PHONE" : "POSSIBLE_PERSON"));
                }
            }
            return ScriptedLlm.isRetry(r) ? ScriptedLlm.finished(PyJson.dumps(answers), ScriptedLlm.usage(2600, 15))
                    : ScriptedLlm.finished(PyJson.dumps(answers), new LlmClient.TokenUsage(2400L, 60L, 2460L, 1024L, 8L));
        });
        return Pipeline.anonymizeDocument(TestDocx.paragraphs("Ο Σπύρος Λάμπρου με κινητό 6912345678.").bytes(), cfg,
                Config.loadFileConfig(Path.of("config")), llm, RunContext.start(300, "acct", System::nanoTime));
    }

    @Test
    void theSummaryJsonCarriesTheDocumentsWholeAccountingAndNoText() {
        AnonymizeResult result = pricedDocument();
        assertEquals("processed", result.status());
        Map<String, Object> line = RunAnonymizer.summaryJson(result);
        @SuppressWarnings("unchecked")
        Map<String, Object> a = (Map<String, Object>) line.get("accounting");
        Map<String, Object> counts = new LinkedHashMap<>(a);
        List.of("total_time_ms", "llm_time_ms", "provider_time_ms", "pricing").forEach(counts::remove);
        Map<String, Object> expected = new LinkedHashMap<>();
        expected.put("llm_calls", 4);
        expected.put("pass1_calls", 1);
        expected.put("pass2_calls", 2);
        expected.put("pass2_retry_calls", 1);
        expected.put("corrective_retry_calls", 1);
        expected.put("failed_provider_attempts", 0);
        expected.put("remediation_calls", 1);
        expected.put("remediation_retry_calls", 0);
        expected.put("input_tokens", 8300L); // 1500 + 2400 + 2600 + 1800
        expected.put("cached_input_tokens", 1024L);
        expected.put("output_tokens", 107L); // 20 + 60 + 15 + 12
        expected.put("reasoning_tokens", 8L);
        expected.put("total_tokens", 8407L);
        expected.put("calls_missing_usage", 0);
        // ((8300 - 1024) x 2.50 + 1024 x 0.25 + 107 x 10.00) / 1 000 000
        expected.put("estimated_cost", "0.019516");
        expected.put("currency", "USD");
        expected.put("cost_unavailable_reason", null);
        expected.put("cached_input_rate", "cached");
        assertEquals(expected, counts);
        assertTrue(((Number) a.get("total_time_ms")).longValue() >= ((Number) a.get("llm_time_ms")).longValue());
        assertTrue(line.containsKey("llm_usage") && line.containsKey("timings"));
        String json = PyJson.dumps(line);
        for (String text : List.of("Σπύρος", "Λάμπρου", "6912345678")) {
            assertFalse(json.contains(text), json);
        }
        // The human-readable line says the same, in one place.
        ByteArrayOutputStream printed = new ByteArrayOutputStream();
        RunAnonymizer.printUsage(new PrintStream(printed, true, StandardCharsets.UTF_8), result.accounting());
        assertEquals("  llm_calls=4 tokens_in=8300 tokens_out=107 tokens_total=8407 cost=0.019516 USD"
                + System.lineSeparator(), printed.toString(StandardCharsets.UTF_8));
    }

    @Test
    void folderInputSkipsPriorOutputsAndSortsLikePython(@TempDir Path dir) throws Exception {
        for (String n : new String[] {"b.docx", "a.docx", "a_redacted.docx", "notes.txt"}) {
            Files.writeString(dir.resolve(n), "x");
        }
        assertEquals(java.util.List.of("a.docx", "b.docx"), RunAnonymizer.collectInputs(dir).stream()
                .map(p -> p.getFileName().toString()).toList());
        assertEquals(Path.of("x", "d_redacted.docx"), RunAnonymizer.outputPath(Path.of("x", "d.docx"), null));
    }
}
