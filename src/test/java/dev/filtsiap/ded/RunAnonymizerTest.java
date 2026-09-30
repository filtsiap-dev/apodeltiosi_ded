package dev.filtsiap.ded;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** argparse-compatible parsing and the usage-error exit paths (no LLM needed). */
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
        assertTrue(out.toString(StandardCharsets.UTF_8).startsWith("usage: run_anonymizer [-h] [--file FILE]"));
    }

    @Test
    void usageErrorsExitTwo() {
        RunAnonymizer.ArgExit x = assertThrows(RunAnonymizer.ArgExit.class,
                () -> RunAnonymizer.parseArgs(new String[] {"a", "b"}, o(), e()));
        assertEquals(2, x.code);
        assertTrue(err.toString(StandardCharsets.UTF_8).endsWith("run_anonymizer: error: unrecognized arguments: b\n"));
        assertEquals(2, RunAnonymizer.run(new String[] {"--file", "a.docx", "b.docx"}, o(), e()));
        assertEquals(2, RunAnonymizer.run(new String[] {}, o(), e()));
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
