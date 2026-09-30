package dev.filtsiap.ded.api;

import com.sun.net.httpserver.HttpServer;
import dev.filtsiap.ded.AppHome;
import dev.filtsiap.ded.anonymizer.Config;
import dev.filtsiap.ded.anonymizer.ConfigurationError;
import dev.filtsiap.ded.anonymizer.FileConfig;
import dev.filtsiap.ded.anonymizer.ProcessEnv;
import dev.filtsiap.ded.anonymizer.RuntimeConfig;
import dev.filtsiap.ded.anonymizer.llm.LlmClient;
import dev.filtsiap.ded.anonymizer.llm.LlmClients;
import dev.filtsiap.ded.anonymizer.pycompat.PyNumber;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * HTTP service entry point: replaces the FastAPI app plus {@code gunicorn.conf.py}, on the
 * JDK's built-in HTTP server with one virtual thread per request.
 *
 * <p>Startup mirrors the Python lifespan: {@code .env} next to the application and in the
 * working directory fill in the environment; the service refuses to start without
 * {@code ANON_API_KEY}; file config comes from {@code ./config}. Server knobs:
 * {@code ANON_HOST} (0.0.0.0), {@code ANON_PORT} (8000), {@code ANON_GRACEFUL_TIMEOUT} (900 s,
 * how long shutdown waits for in-flight requests). Keep-alive is 5 s, as gunicorn's.
 */
public final class ApiServer {

    private final HttpServer server;
    private final LlmClient client;

    private ApiServer(HttpServer server, LlmClient client) {
        this.server = server;
        this.client = client;
    }

    /** Starts serving; the caller owns the returned handle. */
    public static ApiServer start(RuntimeConfig cfg, FileConfig files, LlmClient client, InetSocketAddress address) {
        if (cfg.anonApiKey() == null || cfg.anonApiKey().isEmpty()) {
            // Fail closed: there is no unauthenticated mode for the HTTP transport.
            throw new ConfigurationError("ANON_API_KEY is required to serve the HTTP API "
                    + "(POST /anonymize is bearer-authenticated)");
        }
        try {
            HttpServer server = HttpServer.create(address, 0);
            server.createContext("/", new ApiHandler(cfg, files, client));
            server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
            server.start();
            return new ApiServer(server, client);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /** Stops accepting, waits up to {@code graceSeconds} for in-flight requests, closes the LLM client. */
    public void stop(int graceSeconds) {
        server.stop(graceSeconds);
        client.close();
    }

    /** Python logging level names; logback has no WARNING/CRITICAL. Unknown names fail startup, as in Python. */
    static String logbackLevel(String pythonLevel) {
        Map<String, String> levels = Map.of("DEBUG", "DEBUG", "INFO", "INFO", "WARNING", "WARN", "WARN", "WARN",
                "ERROR", "ERROR", "CRITICAL", "ERROR", "FATAL", "ERROR", "NOTSET", "ALL");
        String level = levels.get(pythonLevel);
        if (level == null) {
            throw new ConfigurationError("Unknown level: '" + pythonLevel + "'");
        }
        return level;
    }

    private static int intKnob(String name, String defaultValue) {
        String raw = ProcessEnv.get(name, defaultValue);
        return PyNumber.parseInt(raw).filter(v -> v.bitLength() < 32).map(v -> v.intValue())
                .orElseThrow(() -> new ConfigurationError(name + " must be an integer"));
    }

    public static void main(String[] args) {
        // Before any logger exists: server logging profile and gunicorn's keep-alive.
        System.setProperty("logback.configurationFile", "logback-server.xml");
        System.setProperty("sun.net.httpserver.idleInterval", "5");
        try {
            Config.loadEnvFile(AppHome.resolve().resolve(".env")); // gunicorn.conf.py
            RuntimeConfig cfg = Config.loadRuntimeConfig();        // also ./.env
            System.setProperty("anonymizer.logLevel", logbackLevel(cfg.logLevel()));
            if (cfg.anonApiKey() == null) {
                throw new ConfigurationError("ANON_API_KEY is required to serve the HTTP API "
                        + "(POST /anonymize is bearer-authenticated)");
            }
            FileConfig files = Config.loadFileConfig(Path.of("config"));
            String host = ProcessEnv.get("ANON_HOST", "0.0.0.0");
            int port = intKnob("ANON_PORT", "8000");
            int grace = intKnob("ANON_GRACEFUL_TIMEOUT", "900");
            ApiServer server = start(cfg, files, LlmClients.build(cfg), new InetSocketAddress(host, port));
            org.slf4j.LoggerFactory.getLogger("anonymizer.api").info("listening on {}:{}", host, server.port());
            Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(grace)));
        } catch (ConfigurationError e) {
            System.err.println("configuration error: " + e.getMessage());
            System.exit(3);
        }
    }
}
