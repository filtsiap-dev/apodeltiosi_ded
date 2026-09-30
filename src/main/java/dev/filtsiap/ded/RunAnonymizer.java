package dev.filtsiap.ded;

import dev.filtsiap.ded.anonymizer.AnonymizeResult;
import dev.filtsiap.ded.anonymizer.AnonymizerError;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.FileConfig;
import dev.filtsiap.ded.anonymizer.Pipeline;
import dev.filtsiap.ded.anonymizer.PlanSummary;
import dev.filtsiap.ded.anonymizer.PostcheckFinding;
import dev.filtsiap.ded.anonymizer.PostcheckSummary;
import dev.filtsiap.ded.anonymizer.ResidualPIIError;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.LlmClients;
import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Command-line runner (rewrite of {@code run_anonymizer.py}): same arguments, output lines and
 * exit codes. Uses only the public pipeline API.
 *
 * <p>Exit codes: 0 all processed; 1 at least one failed; 2 usage error; 3 configuration error;
 * 4 otherwise successful but at least one document blocked by the mandatory post-redaction scan;
 * 130 interrupted (Ctrl+C).
 */
public final class RunAnonymizer {

    static final int EXIT_OK = 0;
    static final int EXIT_PROCESSING_FAILED = 1;
    static final int EXIT_USAGE = 2;
    static final int EXIT_CONFIG = 3;
    static final int EXIT_QA_HIGH = 4;

    private static final String REDACTED_SUFFIX = "_redacted.docx";
    private static final String PROG = "run_anonymizer";

    static final String USAGE = """
            usage: run_anonymizer [-h] [--file FILE] [--out-dir OUT_DIR]
                                  [--config-dir CONFIG_DIR] [--qa] [--summary-json]
                                  [input]
            """;

    static final String HELP = USAGE + """

            Anonymize one Greek DED decision DOCX, or every .docx in a folder, via the v2
            pipeline (deterministic detectors + mandatory two-pass LLM).

            positional arguments:
              input                 Path to a .docx file, or a folder containing .docx
                                    files (non-recursive). Alternative to --file; give
                                    exactly one of the two.

            options:
              -h, --help            show this help message and exit
              --file FILE           Path to a .docx file, or a folder containing .docx
                                    files (non-recursive). Alternative to the positional
                                    argument; give exactly one of the two.
              --out-dir OUT_DIR     Directory for redacted outputs. Default: next to each
                                    input file. Outputs are named <stem>_redacted.docx.
              --config-dir CONFIG_DIR
                                    Directory holding policy.yaml / regex_patterns.yaml /
                                    allowlists/. Default: the config/ folder next to this
                                    script.
              --qa                  Print every finding of the post-redaction residual-
                                    leak scan. The scan itself always runs — this flag
                                    only makes it verbose.
              --summary-json        Print each document's counts-only summary as one JSON
                                    line.
            """;

    private RunAnonymizer() {
    }

    // ------------------------------------------------------------------ argument parsing

    /** Parsed arguments. */
    record Args(String input, String file, String outDir, String configDir, boolean qa, boolean summaryJson) {
    }

    /** Signals an argparse exit (help or usage error) with its code. */
    static final class ArgExit extends Exception {
        private static final long serialVersionUID = 1L;
        final int code;

        ArgExit(int code) {
            super(null, null, false, false);
            this.code = code;
        }
    }

    private static final List<String> LONG_OPTIONS =
            List.of("--help", "--file", "--out-dir", "--config-dir", "--qa", "--summary-json");

    /** argparse semantics: unique-prefix abbreviations, {@code --opt=value}, {@code --}, last value wins. */
    static Args parseArgs(String[] argv, PrintStream out, PrintStream err) throws ArgExit {
        String input = null;
        String file = null;
        String outDir = null;
        String configDir = null;
        boolean qa = false;
        boolean summaryJson = false;
        List<String> unrecognized = new ArrayList<>();
        boolean positionalOnly = false;

        for (int i = 0; i < argv.length; i++) {
            String tok = argv[i];
            if (!positionalOnly && tok.equals("--")) {
                positionalOnly = true;
                continue;
            }
            if (!positionalOnly && tok.startsWith("--") && tok.length() > 2) {
                int eq = tok.indexOf('=');
                String name = eq < 0 ? tok : tok.substring(0, eq);
                String inlineValue = eq < 0 ? null : tok.substring(eq + 1);
                List<String> matches = LONG_OPTIONS.contains(name) ? List.of(name)
                        : LONG_OPTIONS.stream().filter(o -> o.startsWith(name)).toList();
                if (matches.isEmpty()) {
                    unrecognized.add(tok);
                    continue;
                }
                if (matches.size() > 1) {
                    usageError(err, "ambiguous option: " + name + " could match " + String.join(", ", matches));
                }
                String opt = matches.get(0);
                switch (opt) {
                    case "--help", "--qa", "--summary-json" -> {
                        if (inlineValue != null) {
                            usageError(err, "argument " + opt + ": ignored explicit argument "
                                    + PyRepr.repr(inlineValue));
                        }
                        if (opt.equals("--help")) {
                            out.print(HELP);
                            throw new ArgExit(0);
                        }
                        if (opt.equals("--qa")) {
                            qa = true;
                        } else {
                            summaryJson = true;
                        }
                    }
                    default -> {
                        String value = inlineValue;
                        if (value == null) {
                            if (i + 1 >= argv.length || looksLikeOption(argv[i + 1])) {
                                usageError(err, "argument " + opt + ": expected one argument");
                            }
                            value = argv[++i];
                        }
                        switch (opt) {
                            case "--file" -> file = value;
                            case "--out-dir" -> outDir = value;
                            default -> configDir = value;
                        }
                    }
                }
                continue;
            }
            if (!positionalOnly && tok.equals("-h")) {
                out.print(HELP);
                throw new ArgExit(0);
            }
            if (!positionalOnly && looksLikeOption(tok)) {
                unrecognized.add(tok);
                continue;
            }
            if (input == null) {
                input = tok;
            } else {
                unrecognized.add(tok);
            }
        }
        if (!unrecognized.isEmpty()) {
            usageError(err, "unrecognized arguments: " + String.join(" ", unrecognized));
        }
        return new Args(input, file, outDir, configDir, qa, summaryJson);
    }

    private static boolean looksLikeOption(String tok) {
        return tok.startsWith("-") && tok.length() > 1 && !tok.matches("-\\d+(\\.\\d*)?|-\\.\\d+");
    }

    private static void usageError(PrintStream err, String message) throws ArgExit {
        err.print(USAGE);
        err.println(PROG + ": error: " + message);
        throw new ArgExit(EXIT_USAGE);
    }

    // ------------------------------------------------------------------ inputs and outputs

    private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("win");

    /** A file yields itself; a folder its non-recursive .docx children minus prior outputs, sorted like Python paths. */
    static List<Path> collectInputs(Path inputPath) {
        if (Files.isRegularFile(inputPath)) {
            return List.of(inputPath);
        }
        if (!Files.isDirectory(inputPath)) {
            return List.of();
        }
        List<Path> found = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(inputPath, "*.docx")) {
            for (Path p : stream) {
                if (Files.isRegularFile(p) && !p.getFileName().toString().endsWith(REDACTED_SUFFIX)) {
                    found.add(p);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        // PurePosixPath compares by code point; PureWindowsPath case-insensitively.
        Comparator<Path> order = WINDOWS
                ? Comparator.comparing(p -> p.toString().toLowerCase(Locale.ROOT))
                : Comparator.comparing(Path::toString, dev.filtsiap.ded.anonymizer.pycompat.PyStr.CODE_POINT_ORDER);
        found.sort(order);
        return found;
    }

    /** Python {@code str(Path(s))}: "." segments and duplicate separators collapsed, trailing separator dropped. */
    static String pyPath(Path p) {
        Path out = p.getRoot();
        for (Path part : p) {
            if (!part.toString().equals(".")) {
                out = out == null ? part : out.resolve(part);
            }
        }
        return out == null ? "." : out.toString();
    }

    static String stem(Path p) {
        String name = p.getFileName().toString();
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    static Path outputPath(Path source, Path outDir) {
        Path dir = outDir != null ? outDir : (source.getParent() != null ? source.getParent() : Path.of(""));
        return dir.resolve(stem(source) + REDACTED_SUFFIX);
    }

    private static void printQa(PrintStream out, PostcheckSummary qa, String sourceName) {
        if (qa == null) {
            return;
        }
        out.println("  qa[" + sourceName + "]: " + (qa.clean() ? "CLEAN" : "FINDINGS") + " total=" + qa.findingsTotal()
                + " by_severity=" + PyRepr.repr(qa.bySeverity()) + " by_kind=" + PyRepr.repr(qa.byKind()));
        for (PostcheckFinding f : qa.findings()) {
            out.println("    " + String.format("%-6s", f.severity().name()) + " " + String.format("%-28s", f.kind())
                    + " " + f.location() + ": " + f.detail());
        }
    }

    // ------------------------------------------------------------------ main

    /** Runs the CLI and returns its exit code; never throws to the caller for expected failures. */
    public static int run(String[] argv, PrintStream out, PrintStream err) {
        Args args;
        try {
            args = parseArgs(argv, out, err);
        } catch (ArgExit e) {
            return e.code;
        }

        Path home = AppHome.resolve();
        Config.loadEnvFile(home.resolve(".env"));

        if (args.file() != null && !args.file().isEmpty() && args.input() != null && !args.input().isEmpty()) {
            err.println("error: pass the input as either the positional argument or --file, not both");
            return EXIT_USAGE;
        }
        String inputArg = args.file() != null && !args.file().isEmpty() ? args.file() : args.input();
        if (inputArg == null || inputArg.isEmpty()) {
            err.println("error: no input given (pass a path, or use --file <path>)");
            return EXIT_USAGE;
        }
        Path inputPath = Path.of(inputArg);
        List<Path> sources = collectInputs(inputPath);
        if (sources.isEmpty()) {
            err.println("error: no .docx input found at " + pyPath(inputPath));
            return EXIT_USAGE;
        }
        Path outDir = args.outDir() != null && !args.outDir().isEmpty() ? Path.of(args.outDir()) : null;
        if (outDir != null) {
            try {
                Files.createDirectories(outDir);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        Path configDir = args.configDir() != null && !args.configDir().isEmpty()
                ? Path.of(args.configDir()) : home.resolve("config");

        RuntimeConfig runtime;
        FileConfig files;
        LlmClient client;
        try {
            runtime = Config.loadRuntimeConfig();
            files = Config.loadFileConfig(configDir);
            client = LlmClients.build(runtime);
        } catch (ConfigurationError e) {
            err.println("configuration error: " + e.getMessage());
            return EXIT_CONFIG;
        }

        int failures = 0;
        int needsReview = 0;
        try (client) {
            for (Path source : sources) {
                Path target = outputPath(source, outDir);
                String name = source.getFileName().toString();
                out.println("started: " + name);
                AnonymizeResult result;
                try {
                    result = Pipeline.anonymizeDocument(Files.readAllBytes(source), runtime, files, client, stem(source));
                } catch (ResidualPIIError e) {
                    // Nothing is written: a document that failed its own check must not look like a result.
                    needsReview++;
                    err.println("NEEDS MANUAL REVIEW  " + name + ": " + e.getMessage());
                    err.println("  no file written to " + pyPath(target));
                    continue;
                } catch (AnonymizerError e) {
                    failures++;
                    err.println("FAILED  " + name + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    continue;
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                try {
                    Files.write(target, result.redactedDocx());
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                PlanSummary summary = result.summary();
                out.println("done: " + pyPath(target));
                out.println("  spans=" + summary.spansTotal() + " by_action=" + PyRepr.repr(summary.byAction())
                        + " model=" + result.model() + " elapsed="
                        + PyFloat.fixed(result.timings().getOrDefault("total", 0.0), 1) + "s");
                for (String warning : result.warnings()) {
                    out.println("  warning: " + warning);
                }
                if (args.summaryJson()) {
                    Map<String, Object> line = new LinkedHashMap<>(summary.asMap());
                    line.put("provenance", result.provenance());
                    out.println(PyJson.dumps(line));
                }
                if (args.qa()) {
                    printQa(out, result.postcheck(), name);
                }
            }
        }
        if (failures > 0) {
            return EXIT_PROCESSING_FAILED;
        }
        if (needsReview > 0) {
            return EXIT_QA_HIGH;
        }
        return EXIT_OK;
    }

    public static void main(String[] argv) {
        AtomicBoolean finished = new AtomicBoolean(false);
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(System.err, true, StandardCharsets.UTF_8);
        // Ctrl+C: the JVM runs shutdown hooks and exits with 130 (128 + SIGINT), as the Python CLI does.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (!finished.get()) {
                err.println();
                err.println("interrupted by user");
            }
        }));
        int code = run(argv, out, err);
        finished.set(true);
        System.exit(code);
    }
}
