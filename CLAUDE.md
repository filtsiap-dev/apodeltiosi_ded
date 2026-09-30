# CLAUDE.md — Python → Java port: apodeltiosi_ded (ded-anonymizer)

Rulebook for the Java port. Read it **first** in every session. The initial port is complete
and verified (§6); from now on the job is keeping Java in step with Python changes (§2).

---

## 1. Project context

- **Repo**: `filtsiap-dev/apodeltiosi_ded`, branch `java`. Python ≥3.11 (`anonymizer/`, CLI,
  FastAPI app) and the Java port (Maven, JDK 21, base package `dev.filtsiap.ded`) live side by side.
- **What it does**: anonymizes Greek ΑΑΔΕ/ΔΕΔ tax-decision DOCX files. Pipeline: validate →
  parse DOCX → deterministic detectors → two-pass LLM → resolver → length-preserving write-back
  → metadata cleanup → mandatory residual-PII scan.
- **Redaction is one-way**: every code point of a REDACT span becomes `REDACTION_GLYPH = "."`.
  No tokens, no reversible mapping. sha256 appears only in warnings and provenance.
- **Target**: idiomatic Java source, same outputs. Verified by differential tests (§7), not by
  inspection.

---

## 2. Workflow (maintenance)

When a Python file changes:
1. If it is `detector_patterns.py`, `postcheck_support.py` (constants) or `llm/prompts.py`
   (prompt text), regenerate: `PYTHONPATH=. python3 tools/gen_constants.py`. Never hand-edit
   the generated files (`DetectorPatterns`, `PostcheckPatterns`, `llm/PromptText`, `IbanRegistry`).
2. Port the logic change into the Java class listed in §6, following §3–§5.
3. Record any new decision or deviation in §8 **before** moving on.
4. `mvn package`, then `parity/run_all.sh` (§7). Every tier must stay at 0 mismatches except the
   informational recovery tier and the documented API case.
5. Update §6 and §7 figures if they changed.

---

## 3. Type mapping (as applied)

| Python | Java | Notes |
|---|---|---|
| `@dataclass(frozen=True)` | `record` | `RuntimeConfig`, `PolicySettings`, `DetectorRules`, `FileConfig`, `XmlCharRef` |
| mutable `@dataclass` never mutated after construction | `record` with defensive copies | `TextUnit`, `DocumentData`, `Span`, `RedactionPlan`, `PlanSummary`, `AnonymizeResult`, `PostcheckFinding/Summary` |
| `Literal[...]` | `enum` with UPPERCASE constants; `wire()` gives the Python string; `fromWire()` → `Optional`, unknown → empty | `SpanCategory`, `SpanAction` (wire = name); `UnitType` (wire lowercase, e.g. `table_cell`); `RuntimeConfig.Provider` |
| free-form `location` dict | sealed `TextUnit.Location` (`ParagraphLocation`, `TableCellLocation`) with `asMap()` | `asMap()` restores the Python dict (key order kept) for JSON |
| `dataclasses.asdict` | `asMap()` on records that reach JSON | insertion-ordered `LinkedHashMap` |
| `dict` / `Counter` / `defaultdict(list)` | `LinkedHashMap`, `merge(k,1,Integer::sum)`, `computeIfAbsent` | output order = Python insertion order |
| `set` | `Set` for membership only | never iterated into output; where Python iterates a set, Java sorts (D12) |
| `str` | `String` indexed by **code point** via `PyStr` | §5.3 |
| module of functions | `final class`, private constructor, static methods | Python `_private` → package-private |
| `errors.py` | `AnonymizerError extends RuntimeException` + 7 subclasses, same simple names | the API returns `{"error": "<SimpleName>"}` |
| Python `str(x)` / `repr(x)` of values | `PyRepr.str` / `PyRepr.repr` | dict/list/float reprs appear in warnings and CLI output |

---

## 4. Library mapping (final)

| Python | Java | Notes |
|---|---|---|
| `re` | `pycompat.PyRegex` over `java.util.regex` | translator, not a flag — D9 |
| `lxml.etree` | `LxmlDom` over JDK DOM (strict) + jsoup (recovery) | D11 |
| `zipfile` | Commons Compress `ZipFile` / `ZipArchiveOutputStream` in memory | D10 |
| `unicodedata`, `str.casefold/strip/split/lower/isdigit…` | `pycompat.PyUnicode`, `PyStr` | table from CPython 3.12 / Unicode 15 in `pyunicode.txt` |
| `json` | `pycompat.PyJson`: Jackson-based `loads`, own `dumps` | `dumps` byte-identical to `json.dumps` incl. `ensure_ascii=False`, separators, float repr; JSON goes into prompts and hashes |
| float formatting | `pycompat.PyFloat` (`repr`, fixed-point half-even) | |
| `int()/float()` parsing | `pycompat.PyNumber` | Unicode digits, underscores, `inf`/`nan` |
| `yaml.safe_load` | SnakeYAML `SafeConstructor` | |
| `openai` SDK | openai-java 4.72.0 behind `llm.LlmClient` | D15 |
| `python-stdnum` IBAN | `Iban` + generated `IbanRegistry` | D14 |
| `ThreadPoolExecutor` | fixed pool of `llm_concurrency` virtual threads | results in chunk order; first failure (in chunk order) wins |
| `logging` | SLF4J + logback (`logback.xml` CLI, `logback-server.xml` API) | D17 |
| `importlib.metadata.version` | JAR manifest `Implementation-Version` | provenance `package_version` |
| FastAPI / uvicorn / gunicorn | `api.ApiServer` + `api.ApiHandler` on JDK `HttpServer` | D13 |
| argparse CLI | `RunAnonymizer` | help/usage/error text verbatim |

---

## 5. Parity-critical semantics and PII rules

### 5.1 Regex
Every pattern goes through `PyRegex.compile`, which rewrites Python syntax/semantics into Java:
`\w`→`[\p{L}\p{N}_]`, `\d`→`\p{Nd}`, `\s`→Python's `isspace` set (incl. `\x1c-\x1f`), `\b`/`\B`
as lookarounds on that `\w`, `\Z`→`\z`, `(?P<n>)`→`(?<n>)`, literal `[ & { }` in classes, `{,m}`.
Flags are always `UNICODE_CASE | UNIX_LINES` (+ `IGNORECASE`/`DOTALL` when Python sets them).
Match offsets are code points; empty matches between surrogate halves are skipped. Never call
`Pattern.compile` directly on a Python pattern.

### 5.2 String helpers
Use `PyStr` for everything Python does to strings: `strip` (strips NBSP), `split`/
`collapseWhitespace`, `casefold` (full folding, `ς→σ`), `lower` (CPython Final_Sigma rule),
`upper`, `find/rfind/slice` (code points), `isdigit/isalnum`, `CODE_POINT_ORDER` (Python string
ordering; `"u10" < "u2"`).

### 5.3 Offsets are code points
Span `start/end`, `char_map` indexes and `XmlCharRef.charIndex` count code points. Write-back
replaces one code point with one `"."`.

### 5.4 PII rules and fail-closed contracts
- Fixtures and harness inputs are **synthetic only** (`parity/corpus.py`, `docx_corpus.py`).
- Messages and logs name kinds and locations, never matched text; filenames are not echoed.
- Contracts (all verified by the harness):
  1. `word/document.xml` parsed strictly (valid XML, root `w:document`, has `w:body`).
  2. Pass-2 completeness: every REVIEW hint needs REDACT/PRESERVE; one retry, then `AIProviderError`.
  3. Deterministic REDACT spans stay in the plan whatever pass 2 says.
  4. Post-redaction scan: any HIGH finding → `ResidualPIIError`, no output.
  5. HTTP service refuses to start without `ANON_API_KEY`; constant-time compare; auth before body read.
  6. **(Java addition, D19)** a Word text part, `word/comments.xml`, `docProps/core.xml` or
     `docProps/app.xml` that cannot be parsed even by recovery rejects the document instead of
     being copied verbatim.

---

## 6. Tracker

Status: `V` = verified by the differential harness (§7).

| Python file | Java | Status |
|---|---|---|
| `errors.py` | `AnonymizerError` + `InvalidDocumentError`, `DocumentProcessingError`, `ResidualPIIError`, `ConfigurationError`, `AIUnavailableError`, `AIProviderError`, `AITimeoutError` | V |
| `models.py` | `Models`, `SpanCategory`, `SpanAction`, `UnitType`, `XmlCharRef`, `TextUnit`, `DocumentData`, `Span`, `RedactionPlan`, `PlanSummary`, `AnonymizeResult`, `PostcheckFinding`, `PostcheckSummary` | V |
| `config.py` | `Config`, `RuntimeConfig`, `PolicySettings`, `DetectorRules`, `FileConfig`, `ProcessEnv` | V |
| `summary.py` | `Summary` | V |
| `resolver.py` | `Resolver` | V |
| `detector_patterns.py` | `DetectorPatterns` (generated) | V |
| `detector_support.py` | `DetectorSupport`, `Iban`, `IbanRegistry` (generated) | V |
| `detectors.py` | `Detectors` | V |
| `docx_engine.py` | `DocxEngine`, `LxmlDom`, `ZipPackage` | V |
| `postcheck_support.py` | `PostcheckSupport`, `PostcheckPatterns` (generated) | V |
| `postcheck.py` | `Postcheck` | V |
| `llm/prompts.py` | `llm.Prompts`, `llm.PromptText` (generated) | V |
| `llm/client.py` | `llm.LlmClient`, `llm.LlmCallException`, `llm.OpenAiLlmClient`, `llm.LlmClients` | V (replay seam; live SDK path compile-checked against SDK source) |
| `llm/detector.py` | `llm.LlmDetector` | V |
| `pipeline.py` | `Pipeline` | V |
| `run_anonymizer.py` | `RunAnonymizer`, `AppHome` | V |
| `api.py` + `gunicorn.conf.py` | `api.ApiServer`, `api.ApiHandler`, `api.Multipart` | V (42/43; the one difference is deviation 7) |
| `examples/anonymize_client.py` | not ported (stays Python) | — |
| helpers | `pycompat.*` (`PyUnicode`, `PyStr`, `PyRegex`, `PyJson`, `PyFloat`, `PyRepr`, `PyNumber`) | V (10,000-case fuzz) |

Resources copied as-is: `config/policy.yaml`, `config/regex_patterns.yaml`,
`config/allowlists/*.txt`, `.env.example`.

---

## 7. Differential verification

`parity/run_all.sh` runs every tier through both implementations and diffs. Python's
hash-seed-dependent set order is pinned to Java's order first (`pin_python_order.py`, D12).

| Tier | Inputs | Compared | Last result |
|---|---|---|---|
| compat layer | 10,000 generated string/regex/JSON/float ops | exact results | 0 mismatches |
| detectors + resolver + summary | 300 synthetic decisions (25k spans, 14k plan spans) | spans incl. order, plan, warnings, summary | 0 (identical under 3 hash seeds) |
| DOCX engine | 208 packages (tables, nested tables, tracked changes, hidden runs, comments, PIs, CDATA, oxia, emoji, NBSP, `\r`, damaged headers, stored entries) + 8 invalid | units, char maps, plans, every output part **byte for byte**, ZIP entry order/method/time, error class + message prefix | 0; 1,970/1,970 parts byte-identical |
| post-redaction scan | 802 scans (raw inputs + redacted outputs) | full `PostcheckSummary` | 0 |
| recovery of damaged parts | 400 headers mutated 7 ways | extracted units | informational: truncation, unclosed, mismatched tags, bare `&`, undefined entities identical; deleted `>` / stray `<` partly differ (O6). An lxml-based audit finds 0 residual HIGH PII in Java outputs. |
| pipeline with LLM | 150 documents; scripted fake model (valid, aliased, junk, fenced, unparseable, incomplete pass 2, timeouts, connection errors, HTTP 429); Java replays by sha256(system+user) | outcome, summary, warnings, postcheck, provenance, exact error messages, output parts | 0; a prompt byte difference would be a replay miss |
| HTTP API | 43 raw HTTP requests to uvicorn/FastAPI and to the Java server | status, relevant headers, JSON bodies, DOCX parts | 42/43 (deviation 7) |

DOCX outputs are compared per part, never as raw ZIP bytes (compression differs by design).

---

## 8. Decisions log

**Decided**
- D1. Repo `filtsiap-dev/apodeltiosi_ded`, branch `java`.
- D2. Redaction one-way, length-preserving (`"."` per code point).
- D3. Python `tests/` set aside; the differential harness is the verification. JUnit tests not yet written.
- D4. Maven, single module, standard layout; `config/` at repo root.
- D5. JDK 21.
- D6. Jackson 2.x (`com.fasterxml`, BOM-pinned to the line openai-java uses), never Jackson 3. Used only by `PyJson.loads` (LLM output, configured for Python `json.loads` leniency: NaN/Infinity, duplicate keys last-wins, big numbers); serialization is `PyJson`'s own writer.
- D7. `pom.xml` version = `pyproject.toml` version (2.0.0) → provenance via the manifest.
- D8. Packages: `dev.filtsiap.ded` (CLI), `.anonymizer` (core), `.anonymizer.pycompat`, `.anonymizer.llm`, `.api`.
- D9. Regex via the `PyRegex` translator (§5.1), replacing the earlier "UNICODE_CHARACTER_CLASS" idea, which differs from Python for `\d`, `\s`, `\b`.
- D10. ZIP via Commons Compress: central-directory order, CP437 names unless the UTF-8 flag is set, duplicate names resolve to the last entry, every CRC verified (as `testzip`); written entries copy name, time, method, attributes, extra fields.
- D11. XML: JDK DOM strict (namespace-aware, coalescing, entity refs not expanded, no external entities/DTDs). Recovery = jsoup XML parser plus libxml2 rules (truncated tag, malformed/undefined references, invalid `<`, `<` inside tag names) and an own jsoup→DOM converter that never throws. lxml text/tail and child indexing emulated in `LxmlDom`; attribute order recorded with StAX so serialization is byte-identical to lxml.
- D12. Where Python iterates a set into output (medical terms; equal-length allowlist entries), Java sorts by code point. Python's order depends on `PYTHONHASHSEED`, so Python itself is not reproducible there.
- D13. HTTP on JDK `HttpServer`, one virtual thread per request; FastAPI contract reproduced (routing 404/405/307, `{"detail"}` vs `{"error","detail"}`, exact-class status map, Pydantic lax int for `summary`, 422 body, multipart per Starlette 0.27: last `file` wins, `filename` param marks a file part).
- D14. IBAN: native port of `stdnum.iban.is_valid` (mod 97, BBAN structure from generated registry of 89 countries, BE/ES/ME/NO national checks).
- D15. `LlmClient` seam; `OpenAiLlmClient` over openai-java (per-phase timeouts like httpx, 2 SDK retries, Azure legacy URL mode); `OPENAI_BASE_URL`, `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID` honoured as the Python SDK does. Exception classes map in Python's order (timeout → `AITimeoutError`, connection → `AIUnavailableError`, HTTP status / other → `AIProviderError`).
- D16. Regex constants, prompt text and the IBAN registry are generated from the live Python modules (`tools/gen_constants.py`).
- D17. Logging: CLI prints bare messages on stderr (root WARN; pipeline and LLM progress INFO); API logs `LEVEL:logger:message` on stdout at `ANON_LOG_LEVEL` (Python level names; unknown names fail startup).
- D18. "Next to the script" = app home: `-Danonymizer.home`, else the JAR's directory or its parent if it has `config/`, else the working directory. The API keeps Python's cwd-relative `config/`.
- D19. Fail closed on unparseable must-parse parts (§5.4 contract 6).

**Deviations from Python (deliberate, all documented)**
1. Unsupported compression / unreadable member → 400 `InvalidDocumentError` (Python: uncaught → 500).
2. XML syntax-error `detail` wording after the common prefix differs (Xerces vs libxml2 messages).
3. Malformed config values (non-mapping YAML, non-numeric thresholds) → `ConfigurationError` (Python: uncaught exception).
4. Must-parse part unrecoverable → rejected (Python copies it verbatim, a latent leak).
5. Damaged-part recovery approximates libxml2 (O6).
6. Provider response with no `choices` → `AIProviderError` "empty completion" (Python: `IndexError` → 500).
7. `Authorization: Bearer<TAB>key` is accepted: the JDK header parser turns the tab into a space (Python: 401). Still requires the correct key.
8. Multipart bodies are read up to `ANON_MAX_UPLOAD_MB` + 1 MB (then 413) instead of unbounded; malformed multipart framing may give 400 where python-multipart raises (500).
9. CLI `.env`/`config/` resolve from app home (D18) instead of the script's folder.
10. `WEB_CONCURRENCY` and `ANON_GUNICORN_TIMEOUT` have no equivalent (one process, virtual threads); `ANON_HOST`, `ANON_PORT`, `ANON_GRACEFUL_TIMEOUT`, 5 s keep-alive are honoured.
11. `OPENAI_CUSTOM_HEADERS` is not honoured.
12. Belgian IBANs: stdnum's bank-code existence check is not ported (structure and check digits are).
13. The 422 body's `url` is fixed to the Pydantic 2.13 form.
14. Access log uses gunicorn's combined format; Python server log layout is approximated.

**Open**
- O6. Policy for non-well-formed Word text parts. Now: recover (libxml2 emulation, parity-oriented). In the 400-case fuzz Java extracts more text than Python in 28 differing cases and less in 9, where 1–2 characters can end up inside a tag name (e.g. a 9-digit AFM leaving a 7-digit fragment). Python has its own leak here: a deleted `>` can close a paragraph early, leaving runs outside any `w:p` that are neither redacted nor scanned. Word never writes such XML. **Recommendation**: reject non-well-formed must-parse parts in both implementations. Decide, then change Python and Java together.
- O7. Upstream Python fixes recommended by the port: sort the medical terms and allowlist ties (prompt reproducibility, D12); fail closed on unparseable must-parse parts (D19); O6.
- O8. JUnit tests (D3) and CI wiring of `parity/run_all.sh`.

---

## 9. Build and run

```
mvn package                                   # target/ded-anonymizer-2.0.0.jar
java -jar target/ded-anonymizer-2.0.0.jar decision.docx --out-dir redacted --qa     # CLI
java -cp target/ded-anonymizer-2.0.0.jar dev.filtsiap.ded.api.ApiServer                          # HTTP service
```
`package` copies runtime dependencies to `target/lib`; the JAR manifest references them, so
`java -jar` works in place (ship the JAR together with `lib/` and `config/`). For the parity
harness also run `mvn dependency:build-classpath -Dmdep.outputFile=target/cp.txt`. Exit codes,
arguments and environment variables are the Python ones (`.env.example`).
