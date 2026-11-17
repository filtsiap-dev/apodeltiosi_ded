package dev.filtsiap.ded.anonymizer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The process environment as Python's mutable {@code os.environ}: the real environment plus
 * values filled in from {@code .env}. Java cannot modify its own environment, so
 * {@link Config#loadEnvFile} writes here and every reader of "the environment" reads here.
 * Real variables always win: the file only fills in missing names.
 */
public final class ProcessEnv {

    private static final Map<String, String> ENV = new LinkedHashMap<>(System.getenv());

    private ProcessEnv() {
    }

    /** Python {@code os.environ.get(name)}. */
    public static synchronized String get(String name) {
        return ENV.get(name);
    }

    /** Python {@code os.getenv(name, default)}. */
    public static synchronized String get(String name, String defaultValue) {
        return ENV.getOrDefault(name, defaultValue);
    }

    static synchronized boolean contains(String name) {
        return ENV.containsKey(name);
    }

    static synchronized void put(String name, String value) {
        ENV.put(name, value);
    }

    /** A snapshot of the current environment. */
    public static synchronized Map<String, String> snapshot() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(ENV));
    }
}
