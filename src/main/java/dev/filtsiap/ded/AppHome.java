package dev.filtsiap.ded;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The application directory, standing in for Python's "folder next to this script" (where
 * {@code .env} and {@code config/} live). Resolution: system property {@code anonymizer.home};
 * else the directory of the running JAR when it contains {@code config/}; else the working
 * directory.
 */
public final class AppHome {

    private AppHome() {
    }

    public static Path resolve() {
        String prop = System.getProperty("anonymizer.home");
        if (prop != null && !prop.isBlank()) {
            return Path.of(prop).toAbsolutePath().normalize();
        }
        try {
            Path code = Path.of(AppHome.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            Path dir = Files.isRegularFile(code) ? code.getParent() : code;
            for (Path candidate = dir; candidate != null; candidate = candidate.getParent()) {
                if (Files.isDirectory(candidate.resolve("config"))) {
                    return candidate;
                }
                if (candidate.equals(dir.getParent())) {
                    break; // look at the JAR's directory and its parent (target/ → project root), no further
                }
            }
        } catch (URISyntaxException | RuntimeException e) {
            // fall through
        }
        return Path.of("").toAbsolutePath();
    }
}
