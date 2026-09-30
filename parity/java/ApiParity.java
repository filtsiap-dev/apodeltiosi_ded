import dev.filtsiap.ded.anonymizer.*;
import dev.filtsiap.ded.anonymizer.pycompat.PyJson;
import dev.filtsiap.ded.api.ApiServer;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;

/** Starts the Java API with recorded LLM responses (keyed by prompt hash) for the live HTTP diff. */
public class ApiParity {
    public static void main(String[] a) throws Exception {
        ParityProbe.RECORDING = (Map<String, Object>) PyJson.loads(Files.readString(Path.of(a[0])));
        RuntimeConfig cfg = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER", "openai", "OPENAI_API_KEY", "sk-test",
                "ANON_MODEL", "gpt-test", "ANON_API_KEY", "s3cret-key", "ANON_CHUNK_SIZE_CHARS", "900", "ANON_MAX_UPLOAD_MB", "1"));
        FileConfig files = Config.loadFileConfig(Path.of(System.getProperty("cfg", "../config")));
        ApiServer s = ApiServer.start(cfg, files, new ParityProbe.ReplayClient(), new InetSocketAddress("127.0.0.1", Integer.parseInt(a[1])));
        System.out.println("READY " + s.port());
        Thread.currentThread().join();
    }
}
