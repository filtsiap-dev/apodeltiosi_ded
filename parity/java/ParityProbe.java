import dev.filtsiap.ded.anonymizer.*;
import dev.filtsiap.ded.anonymizer.pycompat.*;
import java.nio.file.Path;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Reads one JSON request per line, answers one JSON line. Mirrors probe.py. */
public class ParityProbe {
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        String line;
        while ((line = in.readLine()) != null) {
            @SuppressWarnings("unchecked") Map<String,Object> req = (Map<String,Object>) PyJson.loads(line);
            out.println(PyJson.dumps(handle(req)));
        }
    }
    static FileConfig CFG = Config.loadFileConfig(Path.of(System.getProperty("cfg", "../config")));
    @SuppressWarnings("unchecked")
    static DocumentData toDoc(Map<String,Object> d) {
        List<TextUnit> units = new ArrayList<>();
        for (Object o : (List<Object>) d.get("units")) {
            Map<String,Object> u = (Map<String,Object>) o;
            Map<String,Object> loc = (Map<String,Object>) u.get("location");
            TextUnit.Location location = loc.containsKey("paragraph_index")
                ? new TextUnit.ParagraphLocation(((Number) loc.get("paragraph_index")).intValue())
                : new TextUnit.TableCellLocation(((Number) loc.get("table_index")).intValue(), ((Number) loc.get("row_index")).intValue(),
                    ((Number) loc.get("col_index")).intValue(), (String) loc.get("column_header"), (Boolean) loc.get("is_header_row"));
            UnitType type = UnitType.valueOf(((String) u.get("unit_type")).toUpperCase());
            units.add(new TextUnit((String) u.get("unit_id"), (String) u.get("part_name"), type, (String) u.get("text"), (String) u.get("text"), List.of(), location));
        }
        return new DocumentData((String) d.get("document_id"), units, List.of(), List.of());
    }
    static List<Object> sd(Span s) { return new ArrayList<>(Arrays.asList(s.unitId(), s.start(), s.end(), s.text(), s.category().wire(), s.detector(), s.confidence(), s.action().wire(), s.reason())); }
    static Comparator<List<Object>> ROWS = (a, b) -> PyStr.compare(PyJson.dumps(a), PyJson.dumps(b));
    @SuppressWarnings("unchecked")
    static Object detect(Map<String,Object> r) {
        DocumentData doc = toDoc((Map<String,Object>) r.get("doc"));
        var det = Detectors.detectAll(doc, CFG.rules());
        var plan = Resolver.resolveRedactions(doc, det.resolverSpans(), CFG.policy());
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("resolver", sortRows(det.resolverSpans()));
        out.put("review", sortRows(det.reviewHints()));
        List<Object> order = new ArrayList<>();
        for (Span s : det.resolverSpans()) order.add(List.of(s.unitId(), s.start(), s.end(), s.detector()));
        out.put("resolver_order", order);
        List<Object> ps = new ArrayList<>(); for (Span s : plan.spans()) ps.add(sd(s));
        out.put("plan", ps);
        out.put("warnings", plan.warnings());
        out.put("summary", Summary.buildSummary(plan).asMap());
        return out;
    }
    static List<Object> sortRows(List<Span> spans) {
        List<List<Object>> rows = new ArrayList<>(); for (Span s : spans) rows.add(sd(s));
        rows.sort(ROWS);
        return new ArrayList<>(rows);
    }
    static Object docx(Map<String,Object> r) {
        try {
            byte[] data = java.nio.file.Files.readAllBytes(Path.of((String) r.get("path")));
            DocumentData doc = DocxEngine.parseDocx(data, "doc");
            var det = Detectors.detectAll(doc, CFG.rules());
            var plan = Resolver.resolveRedactions(doc, det.resolverSpans(), CFG.policy());
            byte[] red = DocxEngine.writeRedactedDocx(data, doc, plan);
            java.nio.file.Files.write(Path.of((String) r.get("out")), red);
            Map<String,Object> out = new LinkedHashMap<>();
            List<Object> units = new ArrayList<>();
            for (TextUnit u : doc.textUnits()) {
                List<Object> cm = new ArrayList<>();
                for (XmlCharRef c : u.charMap()) cm.add(List.of(c.partName(), c.textNodePath(), c.charIndex()));
                units.add(Arrays.asList(u.unitId(), u.partName(), u.unitType().wire(), u.text(), cm, u.location().asMap()));
            }
            out.put("units", units);
            out.put("inventory", doc.partsInventory());
            List<Object> ps = new ArrayList<>();
            for (Span s : plan.spans()) ps.add(Arrays.asList(s.unitId(), s.start(), s.end(), s.text(), s.category().wire(), s.action().wire()));
            out.put("plan", ps);
            return out;
        } catch (AnonymizerError e) {
            Map<String,Object> out = new LinkedHashMap<>();
            out.put("error", e.getClass().getSimpleName());
            out.put("msg", e.getMessage().split(":")[0]);
            return out;
        } catch (java.io.IOException e) { throw new java.io.UncheckedIOException(e); }
    }
    static Map<String,Object> RECORDING;
    static final java.util.concurrent.atomic.AtomicInteger MISSES = new java.util.concurrent.atomic.AtomicInteger();
    /** Replays recorded Python responses keyed by sha256(system + NUL + user): a prompt difference is a miss. */
    static final class ReplayClient implements dev.filtsiap.ded.anonymizer.llm.LlmClient {
        @SuppressWarnings("unchecked")
        public String complete(ChatRequest req) {
            String k = sha(req.systemPrompt() + "\u0000" + req.userMessage());
            Map<String,Object> e = (Map<String,Object>) RECORDING.get(k);
            if (e == null) { MISSES.incrementAndGet(); try { java.nio.file.Files.writeString(Path.of("/tmp/miss_" + MISSES.get() + ".txt"), req.userMessage()); } catch (Exception x) {} throw new IllegalStateException("no recording for request (prompt mismatch)"); }
            if (e.containsKey("error")) {
                switch ((String) e.get("error")) {
                    case "timeout": throw dev.filtsiap.ded.anonymizer.llm.LlmCallException.timeout(null);
                    case "connection": throw dev.filtsiap.ded.anonymizer.llm.LlmCallException.connection(null);
                    default: throw dev.filtsiap.ded.anonymizer.llm.LlmCallException.status(((Number) e.get("code")).intValue(), null);
                }
            }
            return (String) e.get("content");
        }
        public void close() {}
    }
    static String sha(String s) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    @SuppressWarnings("unchecked")
    static Object pipeline(Map<String,Object> r) {
        try {
            if (RECORDING == null) RECORDING = (Map<String,Object>) PyJson.loads(java.nio.file.Files.readString(Path.of("pipe/recording.json")));
            RuntimeConfig cfg = Config.loadRuntimeConfig(Map.of("ANON_PROVIDER","openai","OPENAI_API_KEY","sk-test","ANON_MODEL","gpt-test","ANON_CHUNK_SIZE_CHARS","900","ANON_LLM_CONCURRENCY","4"));
            byte[] data = java.nio.file.Files.readAllBytes(Path.of((String) r.get("path")));
            Map<String,Object> o = new LinkedHashMap<>();
            try {
                AnonymizeResult res = Pipeline.anonymizeDocument(data, cfg, CFG, new ReplayClient(), "doc");
                java.nio.file.Files.write(Path.of((String) r.get("out")), res.redactedDocx());
                o.put("summary", res.summary().asMap());
                o.put("warnings", res.warnings());
                o.put("model", res.model());
                o.put("postcheck", res.postcheck().asMap());
                Map<String,Object> prov = new LinkedHashMap<>(res.provenance()); prov.remove("package_version");
                o.put("provenance", prov);
                List<String> tk = new ArrayList<>(res.timings().keySet()); java.util.Collections.sort(tk);
                o.put("timings", tk);
            } catch (AnonymizerError e) {
                o.put("error", e.getClass().getSimpleName());
                o.put("msg", e.getMessage());
            }
            return o;
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    static Object handle(Map<String,Object> r) {
        String op = (String) r.get("op");
        String s = (String) r.get("s");
        switch (op) {
            case "casefold": return PyStr.casefold(s);
            case "strip": return PyStr.strip(s);
            case "split": return PyStr.split(s);
            case "splitlines": return PyStr.splitlines(s);
            case "repr": return PyRepr.repr(s);
            case "upper": return PyStr.upper(s);
            case "lower": return PyStr.lower(s);
            case "isdigit": return PyStr.isDigit(s);
            case "len": return PyStr.len(s);
            case "dumps": return PyJson.dumps(s);
            case "floatrepr": return PyFloat.repr(((Number) r.get("f")).doubleValue());
            case "fixed": return PyFloat.fixed(((Number) r.get("f")).doubleValue(), ((Number) r.get("n")).intValue());
            case "finditer": {
                var p = PyRegex.compile((String) r.get("p"), ((Number) r.get("flags")).intValue());
                List<Object> res = new ArrayList<>();
                for (var m : p.finditer(s)) {
                    List<Object> gs = new ArrayList<>();
                    for (int g = 0; g <= m.groupCount(); g++) gs.add(List.of(m.start(g), m.end(g)));
                    res.add(gs);
                }
                return res;
            }
            case "detect": return detect(r);
            case "docx": return docx(r);
            case "pipeline": return pipeline(r);
            case "scan": try {
                    return Postcheck.scanRedactedDocxBytes(java.nio.file.Files.readAllBytes(Path.of((String) r.get("path"))), CFG).asMap();
                } catch (AnonymizerError e) { return Map.of("error", e.getClass().getSimpleName()); }
                  catch (java.io.IOException e) { throw new java.io.UncheckedIOException(e); }
            default: throw new IllegalArgumentException(op);
        }
    }
}
