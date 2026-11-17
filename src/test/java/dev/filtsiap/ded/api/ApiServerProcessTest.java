package dev.filtsiap.ded.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.filtsiap.ded.anonymizer.TestDocx;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * The server as a real process, ended the way a platform ends it: SIGTERM, the JVM's shutdown
 * hook, process exit. Only where {@link Process#destroy()} IS SIGTERM: on Windows it is
 * TerminateProcess, which runs no hook and would prove nothing. Synthetic configuration in a
 * directory of its own (never the checkout's {@code .env}) and a local provider that never
 * answers.
 */
@DisabledOnOs(value = OS.WINDOWS, disabledReason = "Process.destroy() is TerminateProcess on Windows, not SIGTERM")
class ApiServerProcessTest {

    /** 128 + SIGTERM: the JVM exited through its shutdown sequence, not killed. */
    static final int EXIT_SIGTERM = 143;

    @TempDir
    Path home;

    record Running(Process process, Path log, int port) {
        String output() {
            try {
                return Files.readString(log, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    Running launch(String gracefulTimeout, int providerPort) throws Exception {
        Path config = home.resolve("config");
        try (Stream<Path> files = Files.walk(Path.of("config"))) {
            for (Path source : files.toList()) {
                Path target = config.resolve(Path.of("config").relativize(source).toString());
                if (Files.isDirectory(source)) {
                    Files.createDirectories(target);
                } else {
                    Files.copy(source, target);
                }
            }
        }
        int port;
        try (ServerSocket free = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = free.getLocalPort();
        }
        Path log = home.resolve("server.log");
        ProcessBuilder pb = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), "-Danonymizer.home=" + home,
                "dev.filtsiap.ded.api.ApiServer");
        pb.directory(home.toFile()).redirectErrorStream(true).redirectOutput(log.toFile());
        Map<String, String> env = pb.environment();
        env.keySet().removeIf(k -> k.startsWith("ANON_") || k.startsWith("OPENAI_") || k.startsWith("AZURE_"));
        env.putAll(Map.of("ANON_API_KEY", "k3y", "ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-synthetic",
                "ANON_MODEL", "gpt-synthetic", "OPENAI_BASE_URL", "http://127.0.0.1:" + providerPort + "/v1",
                "ANON_HOST", "127.0.0.1", "ANON_PORT", Integer.toString(port),
                "ANON_GRACEFUL_TIMEOUT", gracefulTimeout));
        Running running = new Running(pb.start(), log, port);
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (!running.output().contains("listening on")) {
            assertTrue(running.process().isAlive(), running.output());
            assertTrue(System.nanoTime() < end, "did not start: " + running.output());
            Thread.sleep(50);
        }
        return running;
    }

    /** Sends SIGTERM and times the exit; a process still alive after {@code limitS} is killed and fails. */
    static double terminate(Running running, long limitS) throws Exception {
        long started = System.nanoTime();
        running.process().destroy();
        boolean exited = running.process().waitFor(limitS, TimeUnit.SECONDS);
        double took = (System.nanoTime() - started) / 1e9;
        if (!exited) {
            running.process().destroyForcibly(); // test cleanup, never counted as a graceful exit
            throw new AssertionError("still running " + limitS + " s after SIGTERM:\n" + running.output());
        }
        return took;
    }

    /**
     * The reported deployment value, and the state that used to make an idle server wait it out:
     * one upload the client abandoned. The 900 is capped, and with nothing pending the process
     * exits at once.
     */
    @Test
    void anIdleServerConfiguredWith900ExitsPromptlyOnSigterm() throws Exception {
        try (ServerSocket provider = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Running running = launch("900", provider.getLocalPort());
            try (Socket aborted = new Socket("127.0.0.1", running.port())) {
                aborted.getOutputStream().write(ApiServerShutdownTest.head(100_000).getBytes(StandardCharsets.ISO_8859_1));
                aborted.getOutputStream().write(new byte[10]);
                aborted.getOutputStream().flush();
                Thread.sleep(300);
            }
            Thread.sleep(300);
            double took = terminate(running, 15);
            String out = running.output();
            assertTrue(took < 5.0, "took " + took + "\n" + out);
            assertEquals(EXIT_SIGTERM, running.process().exitValue(), out);
            assertTrue(out.contains("ANON_GRACEFUL_TIMEOUT=900 exceeds the 120 s maximum shutdown budget; using 120"), out);
            assertTrue(out.contains("No pending requests: active=0"), out);
            assertTrue(out.contains("Shutdown complete:"), out);
        }
    }

    /** A document stuck on a provider that never answers: drained for 2 s, cancelled, exited inside 4 s. */
    @Test
    void aBusyServerCancelsWhatOutlastsTheGracePeriodAndExitsInsideItsBudget() throws Exception {
        try (ServerSocket provider = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            CountDownLatch called = new CountDownLatch(1);
            CountDownLatch hungUp = new CountDownLatch(1);
            Thread.ofVirtual().start(() -> {
                try (Socket call = provider.accept()) {
                    called.countDown();
                    call.getInputStream().readAllBytes();
                } catch (IOException e) {
                    // reset: hung up too
                }
                hungUp.countDown();
            });
            Running running = launch("4", provider.getLocalPort());
            byte[] docx = TestDocx.paragraphs("Ο Γεώργιος Παπαδόπουλος υπέβαλε προσφυγή.").bytes();
            CompletableFuture<String> response = ApiServerShutdownTest.exchangeAsync(running.port(),
                    ApiServerShutdownTest.head(docx.length), docx);
            assertTrue(called.await(20, TimeUnit.SECONDS), "never reached the provider:\n" + running.output());
            double took = terminate(running, 15);
            String out = running.output();
            assertTrue(took >= 1.5 && took < 6.0, "took " + took + "\n" + out);
            assertEquals(EXIT_SIGTERM, running.process().exitValue(), out);
            assertTrue(out.contains("There are pending requests: active=1, queued=0. Waiting up to 2.0 seconds before "
                    + "shutdown."), out);
            assertTrue(out.contains("The 2.0 s grace period expired with active=1 request(s) still running"), out);
            assertTrue(out.contains("outcome=cancelled status=503"), out);
            assertTrue(out.contains("cancelled=1"), out);
            assertTrue(hungUp.await(1, TimeUnit.SECONDS), "the provider call outlived the process");
            String text = response.get(5, TimeUnit.SECONDS);
            assertTrue(List.of("HTTP/1.1 503 ", "IOException").stream().anyMatch(text::startsWith) || text.isEmpty(), text);
        }
    }
}
