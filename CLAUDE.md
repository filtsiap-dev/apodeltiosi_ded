# CLAUDE.md — Python → Java migration: apodeltiosi_ded (ded-anonymizer)

Living rulebook for porting this repo from Python to Java. Read it **first** in
every session; update it **before** moving to the next file.

---

## 1. Project context

- **Source**: `filtsiap-dev/apodeltiosi_ded`, branch `java`. Python ≥3.11,
  package `anonymizer/` (~5.4k lines, 17 modules) + CLI + FastAPI app.
- **What it does**: anonymizes Greek ΑΑΔΕ/ΔΕΔ tax-decision DOCX files. Pipeline:
  parse DOCX → deterministic detectors → two-pass LLM detection → resolver →
  length-preserving write-back → metadata cleanup → mandatory residual-PII scan.
- **Target**: idiomatic Java source (not GraalPy). Same pipeline, same outputs.
- **Redaction is one-way**: every character of a REDACT span is replaced by
  `REDACTION_GLYPH = "."`. No tokens, no reversible mapping. `sha256` is used
  only in warnings and provenance fields.
- `tests/` is git-ignored and **out of scope for now** (see §8).

---

## 2. Workflow

1. Pick the next file from §6 (lowest tier whose dependencies are all Ported).
2. Supply: this file + the Python source + Java signatures of its dependencies.
3. Translate. List every decision not already covered in §3–§5.
4. Fold those decisions into §3/§4/§5/§8 **before** the next file.
5. Compile locally; paste errors back into the same session.
6. Mark the file **Ported** in §6. Mark **Verified** only after §7.

---

## 3. Type mapping

| Python | Java | Notes |
|---|---|---|
| `@dataclass(frozen=True)` | `record` | `RuntimeConfig`, `PolicySettings`, `DetectorRules`, `FileConfig`, `XmlCharRef` |
| `@dataclass` (mutable) | `record` if never mutated after construction, else `final class` | Check per file: `TextUnit`, `DocumentData`, `Span`, `RedactionPlan`, `PlanSummary`, `AnonymizeResult` |
| `field(default_factory=list)` | `new ArrayList<>()` in canonical/compact constructor | Never share a default list instance |
| `Literal["A","B"]` (`SpanAction`, `SpanCategory`, `UnitType`) | `enum` with constants spelled exactly as the Python strings | Parsing from LLM/YAML via `static Optional<E> fromWire(String)`; unknown → `Optional.empty()`, never an exception |
| `dict` | `LinkedHashMap` | Python dicts keep insertion order; output order must match |
| `defaultdict(list)` | `map.computeIfAbsent(k, x -> new ArrayList<>())` | |
| `collections.Counter` | `LinkedHashMap<String,Integer>` + `merge(k, 1, Integer::sum)` | |
| `set` / `frozenset` | `Set.copyOf(...)` for membership only | Set iteration order must never reach output; sort first |
| `list` | `List` (`ArrayList`; `List.copyOf` when exposed immutably) | |
| `tuple` return / element | small `record` | e.g. `(path, char_index, replacement)` edits |
| `X \| None` field | nullable field | Return types: `Optional<X>` |
| `int` / `float` / `bool` | `int` (`long` if it can exceed 2³¹) / `double` / `boolean` | `confidence` is `double` |
| `bytes` | `byte[]` | |
| `str` | `String`, **indexed by code point** — see §5.3 | |
| module of functions | `final class` + private constructor + static methods | `_private` → package-private (keeps tests possible) |
| `__all__` | the class's `public` surface | |
| exception classes (`errors.py`) | same hierarchy, `AnonymizerError extends RuntimeException` | Class simple names must match Python exactly: the API returns `{"error": "<ClassName>"}` |

---

## 4. Library / stdlib mapping

| Python | Java | Notes |
|---|---|---|
| `re` | `java.util.regex` **with `Pattern.UNICODE_CHARACTER_CLASS`** on every pattern | See §5.1. `(?P<n>…)` → `(?<n>…)`; `finditer` → `Matcher.find()` loop; `re.sub(fn)` → `Matcher.replaceAll(Function)` |
| `lxml.etree` | **OPEN** (§8) | Needs a recovering parser for non-main parts and a strict one for `word/document.xml`. lxml `.text`/`.tail` → DOM `Text` nodes; `_append_tail`/`_unwrap_element` need care |
| `zipfile` | Apache Commons Compress `ZipFile` over `SeekableInMemoryByteChannel` | Reads the central directory like Python; `java.util.zip.ZipInputStream` does not. `_copy_zipinfo` → copy name, time, method, extra fields |
| `unicodedata.normalize` | `java.text.Normalizer` | Same form (NFC/NFKC) as the Python call |
| `str.casefold()` | `Text.casefold(String)` helper | §5.2 |
| `str.split()` (no arg), `str.strip()` | `Text.pySplit`, `Text.pyStrip` helpers | §5.2 |
| `json` | Jackson | Where JSON goes into a prompt or a hash, use a Python-compatible writer: `", "` / `": "` separators, `ensure_ascii=False` |
| `hashlib.sha256().hexdigest()` | `MessageDigest` + `HexFormat.of().formatHex` | Must hash identical bytes (UTF-8) |
| `yaml` | SnakeYAML, safe constructor | |
| `openai` (`OpenAI`, `AzureOpenAI`) | openai-java SDK behind a project interface `LlmClient` | `LlmClient` is the record/replay seam for §7. Map `APITimeoutError→AITimeoutError`, `APIConnectionError→AIUnavailableError`, `APIStatusError`/`OpenAIError→AIProviderError` |
| `concurrent.futures.ThreadPoolExecutor` | `ExecutorService` (virtual threads) | Collect results in chunk-index order; the first failure aborts the document |
| `python-stdnum` IBAN | **OPEN** (§8) | Already an optional import with a fallback in Python |
| `datetime.date` | `LocalDate` | AMKA birth-date check |
| `bisect` | `Collections.binarySearch` + insertion-point conversion | `bisect_left` vs `bisect_right` semantics must be kept |
| `secrets.compare_digest` | `MessageDigest.isEqual` over UTF-8 bytes | |
| `base64`, `uuid`, `time.monotonic` | `java.util.Base64`, `UUID`, `System.nanoTime` | `uuid4().hex` → UUID without dashes |
| `os.environ` / `Mapping` env param | `Map<String,String>` param, default `System.getenv()` | Keep `load_runtime_config(env)` injectable |
| `pathlib.Path` | `java.nio.file.Path` | |
| `logging` | SLF4J | Never log matched text (§5.4) |
| `importlib.metadata.version` | JAR manifest `Implementation-Version` | Provenance field |
| FastAPI / uvicorn / gunicorn | **OPEN** (§8) | `api.py` and `gunicorn.conf.py` are rewritten, not translated |

---

## 5. Parity-critical semantics and PII rules

### 5.1 Regex Unicode semantics
Python `str` patterns are Unicode-aware by default: `\w`, `\d`, `\s`, `\b`
match Greek letters, Unicode digits, NBSP. `re.I` is Unicode-aware too.
Java is ASCII-only unless `UNICODE_CHARACTER_CLASS` is set (it also implies
`UNICODE_CASE`). **Every** `Pattern.compile` gets this flag. Missing it compiles
fine and silently under-redacts. Patterns live in `detector_patterns`,
`detectors`, `detector_support`, `postcheck_support`, `postcheck`, and are
overridable from `config/regex_patterns.yaml`.

### 5.2 String helpers (one class, `Text`, used everywhere)
- `casefold`: must fold final sigma `ς → σ`; `toLowerCase(Locale.ROOT)` does not.
- `pyStrip`: Python strips every char where `isspace()` is true, including
  U+00A0 (NBSP, common in Word). Java `String.strip()` does **not** strip NBSP.
- `pySplit`: Python `split()` splits on any Unicode whitespace run and drops
  empties. Java `split("\\s+")` keeps a leading empty string.
- `" ".join(s.split())` → `String.join(" ", pySplit(s))`.

### 5.3 Offsets are code points
All span `start`/`end`, `char_map` indices, and `XmlCharRef.char_index` count
**code points** (Python semantics). Java `String` indexes UTF-16 units, so use
`codePoints()` / `offsetByCodePoints` or an `int[]` code-point array.
Write-back replaces one code point with one `"."`. Naively replacing a `char`
in a surrogate pair would corrupt text and shift every later offset.

### 5.4 PII rules
- Test fixtures: **synthetic data only**. Never a real decision, name, AFM, AMKA.
- Exception messages and logs name finding kinds and locations, never the
  matched text. The uploaded filename is never echoed back.
- Fail-closed contracts that must survive the port unchanged:
  1. `word/document.xml` parsed strictly (valid XML, root `w:document`, has `w:body`).
  2. Pass-2 completeness: every rule-flagged REVIEW hint needs REDACT/PRESERVE;
     one retry, then `AIProviderError`.
  3. Deterministic REDACT spans stay in the plan whatever pass 2 says.
  4. Post-redaction scan: any HIGH finding → `ResidualPIIError`, no output.
  5. HTTP service refuses to start without `ANON_API_KEY`; constant-time compare.

---

## 6. Dependency map and tracker

Status: `—` not started · `P` ported (compiles) · `V` verified (§7)

| Tier | Python file | Lines | Internal deps | Java class | Status |
|---|---|---|---|---|---|
| 0 | `anonymizer/errors.py` | 35 | — | | — |
| 0 | `anonymizer/detector_patterns.py` | 185 | — | | — |
| 0 | `anonymizer/postcheck_support.py` | 149 | — | | — |
| 0 | `anonymizer/llm/prompts.py` | 212 | — | | — |
| 0 | `anonymizer/models.py` | 194 | (type-only: postcheck — see §8) | | — |
| 1 | `anonymizer/config.py` | 350 | errors | | — |
| 1 | `anonymizer/summary.py` | 18 | models | | — |
| 2 | `anonymizer/resolver.py` | 202 | config, models | | — |
| 2 | `anonymizer/docx_engine.py` | 641 | errors, models | | — |
| 2 | `anonymizer/detector_support.py` | 275 | config, detector_patterns, models | | — |
| 2 | `anonymizer/llm/client.py` | 15 | config | | — |
| 3 | `anonymizer/detectors.py` | 966 | config, detector_support, models | | — |
| 3 | `anonymizer/postcheck.py` | 328 | config, docx_engine, postcheck_support | | — |
| 3 | `anonymizer/llm/detector.py` | 726 | config, errors, llm/prompts, models | | — |
| 4 | `anonymizer/pipeline.py` | 186 | all of the above | | — |
| 5 | `run_anonymizer.py` (CLI) | 284 | config, errors, llm/client, pipeline | rewrite | — |
| 5 | `anonymizer/api.py` (HTTP) | 228 | config, errors, llm/client, pipeline, postcheck | rewrite | — |
| — | `gunicorn.conf.py` | 18 | config | server config, no class | — |
| — | `examples/anonymize_client.py` | 115 | — | not ported (stays Python) | — |

Non-code resources copied as-is: `config/policy.yaml`,
`config/regex_patterns.yaml`, `config/allowlists/*.txt`, `.env.example`.

---

## 7. Differential verification

Compiling is not verification. A file is **V** only when Python and Java give
the same output for the same synthetic input.

- **Pure modules (tiers 0–3 except `llm/detector`)**: run the same inputs through
  both, serialize outputs to JSON (spans as `unit_id, start, end, category,
  action, confidence`), diff.
- **LLM-dependent code**: the LLM is non-deterministic, so live runs never
  compare. Record Python's pass-1/pass-2 responses per (chunk index, pass,
  attempt) and replay them into Java through `LlmClient`. Separately assert the
  prompt text sent is identical.
- **DOCX output**: compare per part — extracted text and C14N-canonicalized XML.
  Do **not** compare raw ZIP bytes (compression and serializer differences).
- **Also compare**: `PostcheckSummary`, warnings list, `config_sha256`,
  `prompts_sha256`, exit codes / HTTP status codes.
- Harness construction is deferred (§8).

---

## 8. Decisions log

**Decided**
- D1. Target repo `filtsiap-dev/apodeltiosi_ded`, branch `java`.
- D2. Redaction is one-way, length-preserving (`"."` per code point).
- D3. Python tests (`tests/`, git-ignored) are set aside for now; revisit
  before the first file is marked V.

**Proposed — confirm or change**
- P1. JDK 21 LTS (records, sealed types, pattern switch, virtual threads).
- P2. Offsets in code points (§5.3).
- P3. Unchecked exception hierarchy mirroring `errors.py` names exactly.
- P4. `LlmClient` interface wrapping openai-java, as the replay seam.
- P5. Move `PostcheckSummary` (and its finding type) into the models package
  to break the type-only `models ↔ postcheck` cycle.
- P6. Commons Compress for ZIP reading/writing.

**Open**
- O1. Build tool: Maven or Gradle.
- O2. XML library, and how to reproduce lxml `recover=True` for non-main parts
  (candidates: JDK DOM strict + jsoup XML mode for recovery).
- O3. HTTP framework for `api.py` (Spring Boot, Javalin, Helidon, …).
- O4. IBAN validation: commons-validator vs porting the existing mod-97 fallback.
- O5. Base Java package name.