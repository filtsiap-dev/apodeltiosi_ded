# ded-anonymizer v2 — Complete Codebase Guide

*Generated 2026-07-20 against the current state of the code (all fixes through the
invoice-regex hardening included). The companion high-level docs are `README.md` (how to run)
and `BUILDER_REPORT.md` (historical build/audit record). This guide explains **how the code
actually works**, file by file and function by function.*

---

## 1. What this application is

**Purpose.** It takes a Greek tax-appeal decision document (a Microsoft Word `.docx` file from
ΑΑΔΕ/ΔΕΔ — the Greek tax authority's Dispute Resolution Directorate), finds every piece of
personal or case-identifying information in it, and produces a copy where each such character is
replaced by a dot (`.`) so the decision can be published without exposing the taxpayer.

**The problem it solves.** These decisions must be published, but they are full of PII —
taxpayer names, tax IDs (ΑΦΜ), social-security numbers (ΑΜΚΑ), IBANs, addresses, phone numbers,
invoice numbers. At the same time, lots of look-alike content must **stay visible**: law
citations (ν. 4174/2013), dates, money amounts, the names of public institutions, the official
signatory. Telling these apart requires both rigid pattern matching (a valid ΑΦΜ has a checksum)
and judgment (is this phone number the tax office's or the taxpayer's?). The app combines both:
**deterministic regex detectors** for the rigid cases and a **two-pass LLM** (large language
model — an AI text model called over the OpenAI API) for the judgment calls. A final
**resolver** arbitrates every conflict with fixed, auditable rules.

**Inputs.** One `.docx` file (or a folder of them via the CLI). Nothing else — the document
never needs pre-processing.

**Outputs.** A new `.docx` (`<name>_redacted.docx` on the CLI; a download or base64 JSON on the
API) that is byte-identical to the original except: (a) each redacted character is replaced by
`.` **in place** (layout, fonts, tables all survive), and (b) risky metadata is scrubbed
(author name, comments, tracked changes, hidden text). Plus a counts-only summary (how many
spans, by action/category/detector — never the text itself) and warnings.

**Supported actions.**
- CLI: anonymize one file or a folder; optional residual-leak audit (`--qa`); optional JSON
  summary (`--summary-json`).
- HTTP API: `POST /anonymize` (file in → redacted file or JSON out), `GET /healthz`.

---

## 2. Architecture in one picture

The code is a strict **layered pipeline**. Lower layers never import higher ones; only `api.py`
knows HTTP exists; only `docx_engine.py` knows what a DOCX is; only the `llm/` package talks to
OpenAI.

```
  ENTRY POINTS                          CORE PIPELINE (transport-neutral)
┌───────────────────┐
│ run_anonymizer.py │ CLI               anonymize_document()  (pipeline.py)
│ anonymizer/api.py │ HTTP    ──────►     │
└───────────────────┘                     │ 1. validate_docx_bytes()  ┐
        │  uses                           │ 2. parse_docx()           │ docx_engine.py
        ▼                                 │        │ DocumentData     ┘
┌───────────────────┐                     │ 3. detect_all()           ┐ detectors.py
│ config.py         │                     │        │ DetectionResult  │ (+ detector_support,
│  .env → env vars  │                     │ 4. run_llm_detection()    ┘  detector_patterns)
│  policy.yaml      │                     │        │ llm spans        ┐ llm/detector.py
│  regex_patterns   │                     │ 5. resolve_redactions()   │ (+ prompts, client)
│  allowlists/*.txt │                     │        │ RedactionPlan    ┘ resolver.py
└───────────────────┘                     │ 6. write_redacted_docx()  ─ docx_engine.py
        │                                 │ 7. build_summary()        ─ summary.py
        ▼                                 ▼
┌───────────────────┐                  AnonymizeResult (bytes + counts)
│ models.py         │  ◄── every stage passes these shared dataclasses
│ errors.py         │  ◄── every failure is one of these typed exceptions
└───────────────────┘
   postcheck.py / postcheck_support.py: OUT-OF-BAND auditor — re-scans the OUTPUT for leaks;
   nothing in the pipeline calls it (only the CLI --qa flag does).
```

Key architectural rules (all enforced by the code, verified by audit):
- **`models.py` is the shared vocabulary** — pure dataclasses, zero behavior, bottom of the
  import graph.
- **Typed errors, HTTP mapping only at the edge** — core raises `InvalidDocumentError`,
  `AIProviderError` etc. (`errors.py`); only `api.py` converts them to status codes.
- **No `asyncio` outside `api.py`** — LLM concurrency uses a thread pool instead.
- **The LLM never has the last word** — deterministic spans go to the resolver *directly* as
  well as into the LLM prompt, so the model cannot suppress a regex detection; the resolver's
  fixed priority rules decide every character.
- **The writer never re-renders text** — it follows per-character pointers (`char_map`) back
  into the original XML and swaps single characters, which is why formatting survives perfectly.

---

## 3. Complete execution flow

### 3.1 Start-up — CLI path

Command: `python run_anonymizer.py --file "C:\...\decision.docx" [--qa]`

1. Python executes `run_anonymizer.py`; the `if __name__ == "__main__":` block calls `main()`
   inside a `try/except KeyboardInterrupt` (Ctrl+C → clean exit 130).
2. `main()` parses arguments with `argparse` (`_build_arg_parser()`), configures quiet logging
   (root WARNING, bare messages; only `anonymizer.pipeline` and `anonymizer.llm.detector` at
   INFO so you see stage/chunk progress).
3. `load_env_file(<script dir>/.env)` (from `anonymizer.config`) copies `KEY=VALUE` lines from
   `.env` into the process environment — **only for keys not already set** (real environment
   variables always win).
4. Input resolution: exactly one of `--file` or the positional path must be given;
   `_collect_inputs()` turns it into a list of `.docx` files (a folder is globbed
   non-recursively, skipping `*_redacted.docx`). Empty list → exit 2.
5. `load_runtime_config()` reads the environment (loading CWD `.env` first, same fill-in-only
   rule) → a frozen `RuntimeConfig` (provider, key, model, timeouts, chunk size, concurrency…).
   Missing provider variables → `ConfigurationError` → exit 3.
6. `load_file_config(config/)` reads `policy.yaml` (thresholds + hard category lists),
   `regex_patterns.yaml` (regex overrides), and the three `allowlists/*.txt` gazetteers →
   a `FileConfig` (holding `PolicySettings` + `DetectorRules`).
7. `build_client(runtime)` constructs the OpenAI SDK client — `openai.OpenAI` or
   `openai.AzureOpenAI` depending on `cfg.provider`.
8. For each input file: read bytes → `anonymize_document(...)` (section 3.3) → write
   `<stem>_redacted.docx` → print summary line → optionally `scan_redacted_docx_bytes()` for
   `--qa`. Exit code 0/1/4 depending on failures and QA findings.

### 3.2 Start-up — API path

Command: `uvicorn anonymizer.api:app --reload` (dev) or `gunicorn anonymizer.api:app -c
gunicorn.conf.py` (production, Linux/Docker only — gunicorn does not run on Windows).

1. (gunicorn only) `gunicorn.conf.py` executes first: loads `.env` via `load_env_file`, then
   reads `ANON_HOST/ANON_PORT/WEB_CONCURRENCY/...` to configure bind address, worker count
   (`uvicorn_worker.UvicornWorker`), and the 900-second timeouts.
2. The server imports `anonymizer.api`, which builds `app = FastAPI(lifespan=lifespan)`.
3. On startup FastAPI runs `lifespan(app)`: `load_runtime_config()` (auto-loads CWD `.env`),
   `load_file_config(Path("config"))`, `build_client(cfg)` — all stored on `app.state`. This is
   why the server **must start from the project root** (or the Docker `WORKDIR /app`): `config/`
   is resolved relative to the current directory. A missing key fails startup here.
4. Per request `POST /anonymize`: the `payload: bytes = Depends(_read_payload)` dependency reads
   the body — multipart `file` field, or raw body for the two accepted content types; rejects
   others with 415, empty bodies with 400, oversize with 413 (`ANON_MAX_UPLOAD_MB`). Then
   `anonymize_document(payload, config=app.state.cfg, files=app.state.files,
   client=app.state.client)` runs (synchronously; FastAPI executes sync endpoints on its own
   thread pool). Response: the redacted DOCX as an attachment, or (`?summary=1`) a JSON object
   with `docx_base64`. Typed errors are converted by `handle_anonymizer_error` using
   `_ERROR_STATUS_CODES` (400/422/502/503/504); anything unexpected becomes a fixed 500 body
   that never leaks exception text.

### 3.3 Per-document flow — `anonymize_document()` (the heart)

Location: `anonymizer/pipeline.py`. Five timed stages; catches nothing (errors propagate to the
entry point); logs one counts-only line per stage.

1. **validate** — `validate_docx_bytes(docx_bytes)`: is it a real ZIP, no corrupt members, and
   does it contain `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`? If not →
   `InvalidDocumentError` (HTTP 400 / CLI "FAILED").
2. **parse** — `parse_docx(docx_bytes, document_id)`: unzips in memory, parses every XML part
   with `lxml`, and walks the Word text parts (`word/document.xml`, headers, footers,
   footnotes, endnotes). Tables first: each table cell becomes a `TextUnit` with row/column
   metadata (including the column header text, which the table detectors use). Then every
   remaining paragraph becomes a `TextUnit`. For every visible character it records an
   `XmlCharRef(part_name, text_node_path, char_index)` in the unit's `char_map`, normalizing
   each character to NFC **individually** (whole-string normalization would shift offsets and
   desynchronize the map — this is the single most load-bearing invariant in the codebase).
   Output: `DocumentData` (~211 units for the test decision).
3. **detect** — `detect_all(document, files.rules)`: runs 14 deterministic detectors in a fixed
   order (document-level signatory/header detectors first, low-confidence review candidates
   last) over every unit, then splits the results strictly by action:
   - `resolver_spans`: REDACT/PRESERVE spans (e.g. AFM with valid checksum → REDACT 1.0; a law
     citation → PRESERVE 0.95),
   - `review_hints`: REVIEW spans the LLM must adjudicate (e.g. a phone number — official or
     private?).
4. **llm** — `run_llm_detection(document, resolver_spans, review_hints, client, cfg)`:
   - `split_into_chunks()` — each table is one chunk; paragraphs accumulate into chunks of
     ≤ `chunk_size_chars` (default 3000). Test doc → 19 chunks.
   - A `ThreadPoolExecutor` with `min(llm_concurrency, chunks)` workers (default 8) processes
     chunks **concurrently**; per chunk, strictly in order:
     - **Pass 1 (blind):** send `SYSTEM_PROMPT_PASS1` + just the chunk text. The model proposes
       findings from scratch. Parsed **leniently** by `parse_pass1_findings` (garbage → empty
       list + warning; the run continues).
     - **KNOWN SPANS assembly:** deterministic REDACT/PRESERVE spans + REVIEW hints +
       located pass-1 findings, all rendered as `{"text", "category", "action", "context"}`
       (±40 characters of context).
     - **Pass 2 (informed validation):** send `SYSTEM_PROMPT_PASS2` + chunk text + the KNOWN
       SPANS array. The model must confirm/correct/decide-REVIEW/add/drop every entry. Parsed
       **strictly** by `parse_pass2_spans` (unparseable → `AIProviderError`, run aborts):
       category validated first (aliases like `PERSON`→`POSSIBLE_PERSON` applied, unknown
       categories dropped), then the action (REVIEW coerced to REDACT with a warning only if
       the entry locates), then every occurrence of the text is located in the chunk's units by
       string search → `Span(detector="llm_pass2", confidence=0.9)`.
   - Results collected in chunk order (deterministic output); first failure cancels queued
     chunks and aborts.
5. **resolve** — `resolve_redactions(document, llm_spans + resolver_spans, files.policy)`: for
   each unit builds an `owners` array (one slot per character) and lets spans compete for each
   character using a fixed priority ladder — 6: high-confidence PRESERVE (≥0.8); 5: structured
   high-confidence REDACT (AFM/AMKA/IBAN/EMAIL ≥0.9); 4: REDACT ≥0.7; 3: weak PRESERVE; 0:
   ignored — plus hard-override rules (`hard_redact_categories` beat `hard_preserve_categories`
   etc. from `policy.yaml`). Contiguous same-owner runs become the final spans →
   `RedactionPlan` (REDACT/PRESERVE only — a REVIEW reaching here raises `RuntimeError`, a
   deliberate "programming bug" tripwire). A consistency sweep warns when the same text is
   redacted in one place and preserved in another.
6. **apply** — `write_redacted_docx(docx_bytes, document, plan)`: re-reads the original ZIP,
   and for every REDACT span follows each character's `XmlCharRef` to the exact XML text node
   and replaces that one character with `.` (never inserting/deleting — lengths are
   preserved, so layout is untouched). Then `clean_sensitive_parts()` scrubs document metadata
   (author, lastModifiedBy, dates → 2000-01-01), deletes custom properties, empties comments,
   flattens tracked changes (accepts insertions, drops deletions), and removes hidden text.
   Finally the ZIP is rewritten entry-by-entry — untouched parts are copied **byte-verbatim**
   with their original `ZipInfo` metadata. The output is validated again before returning.
7. **summarize** — `build_summary(plan)`: counts by action/category/detector → `PlanSummary`.
   Everything is wrapped in `AnonymizeResult(document_id, redacted_docx, summary, warnings,
   model, timings)`.

---

## 4. Complete data flow

| # | Data | Comes from | Format | Received by | What happens to it | Becomes |
|---|------|-----------|--------|-------------|--------------------|---------|
| 1 | **User input**: the DOCX | disk (CLI) / HTTP body (API) | `bytes` (a ZIP archive of XML files — that's all a `.docx` is) | `validate_docx_bytes`, then `parse_docx` | validated (ZIP integrity, required members), unzipped in memory, XML-parsed | `DocumentData` |
| 2 | **Internal**: parsed document | stage 1 | `DocumentData{document_id, text_units: [TextUnit], parts_inventory, warnings}`; each `TextUnit` has `normalized_text` + `char_map: [XmlCharRef]` (character-level pointer back into the XML) | `detect_all`, `run_llm_detection`, `resolve_redactions`, `write_redacted_docx` | read-only from here on — every later stage indexes into `normalized_text` | span offsets that are always convertible back to XML positions |
| 3 | **Configuration**: `.env` → env vars | `.env` file, auto-loaded (real env wins) | `KEY=VALUE` lines → `os.environ` → frozen `RuntimeConfig` | `load_runtime_config` | validated per provider (missing key → `ConfigurationError`); numeric knobs parsed | `RuntimeConfig` (immutable) |
| 4 | **Configuration**: rules | `config/policy.yaml`, `config/regex_patterns.yaml`, `config/allowlists/*.txt` | YAML mappings + line-per-entry text files | `load_file_config` | thresholds → floats, category lists → frozensets, allowlist lines → frozensets (comments/blanks dropped) | `FileConfig(PolicySettings, DetectorRules)` |
| 5 | **Internal**: deterministic detections | stage 3 (regex over each unit) | `Span{unit_id, start, end, text, category, detector, confidence, action, reason}` | `detect_all` → split by action | REDACT/PRESERVE → `resolver_spans`; REVIEW → `review_hints` | `DetectionResult` |
| 6 | **API request data** (to OpenAI): pass-1 prompt | chunk text only | JSON chat payload: `SYSTEM_PROMPT_PASS1` + `"DOCUMENT EXCERPT:\n"+text` | OpenAI `chat.completions.create` (via `_call`) | model reads blind, proposes candidates | raw JSON-array string |
| 7 | **API response data**: pass-1 findings | OpenAI | JSON array of `{text, action, category}` | `parse_pass1_findings` | lenient parse; SKIP dropped; aliases normalized; invalid categories dropped; **never become Spans** | advisory `list[dict]` |
| 8 | **Temporary**: KNOWN SPANS payload | stages 5+7 | uniform list `{"text","category","action","context"}` (context = ±40 chars) | `build_pass2_message` | serialized with `json.dumps(ensure_ascii=False)` into the pass-2 prompt | part of prompt 6' |
| 9 | **API response data**: pass-2 decisions | OpenAI | JSON array of `{text, action, category}` | `parse_pass2_spans` | **strict** parse (failure aborts); category-first validation; REVIEW→REDACT coercion; every text occurrence located via `str.find` in unit `normalized_text` | `list[Span]` with `detector="llm_pass2"`, confidence 0.9 |
| 10 | **Internal**: merged candidates | stages 5+9 (`llm_spans + resolver_spans`) | `list[Span]` | `resolve_redactions` | per-character ownership contest (priority ladder + hard rules); runs recovered; consistency sweep | `RedactionPlan{spans (final only), warnings}` |
| 11 | **Final output**: redacted DOCX | stage 6 | `bytes` — original ZIP with edited XML text nodes + scrubbed metadata | `write_redacted_docx` → entry point | REDACT chars → `.` via `char_map`; metadata cleaned; ZIP rebuilt verbatim; re-validated | file on disk (CLI) / HTTP attachment or base64 (API) |
| 12 | **Final output**: summary | stage 7 | `PlanSummary{spans_total, by_action, by_category, by_detector, warnings}` — counts only, never text | `build_summary` | tallied with `Counter` | printed (CLI) / JSON field (API) |
| 13 | **Optional audit**: QA findings | `--qa` (CLI only) | `PostcheckSummary{clean, findings_total, by_severity, by_kind, findings}` | `scan_redacted_docx_bytes` re-parses the OUTPUT with independent regexes | leak kinds/locations reported; details never echo document text (2 safe exceptions) | console report + exit code 4 if HIGH |

---

## 5. Technologies used

| Technology | Where | Why |
|---|---|---|
| **Python 3.11+** | everything | required by `pyproject.toml`; modern `X \| None` syntax used throughout |
| **FastAPI** | `anonymizer/api.py` only | the HTTP layer: routing, dependency injection (`Depends(_read_payload)`), lifespan startup, exception handlers |
| **uvicorn** | dev server / worker class | runs the FastAPI app (ASGI server) |
| **gunicorn + uvicorn-worker** | `gunicorn.conf.py` | production process manager (multiple workers, timeouts). **Linux-only** — use uvicorn on Windows, gunicorn in Docker |
| **openai** (SDK) | `llm/client.py`, `llm/detector.py` | the only LLM dependency; provides `OpenAI` and `AzureOpenAI` clients + typed exceptions the error mapping relies on |
| **lxml** | `docx_engine.py`, `postcheck.py` | fast, robust XML parsing/serialization of the DOCX parts (with entity resolution disabled — an XXE defense) |
| **zipfile** (stdlib) | `docx_engine.py`, `postcheck.py` | a `.docx` IS a ZIP; entries are read/rewritten directly, preserving metadata |
| **PyYAML** | `config.py` | parses `policy.yaml` and `regex_patterns.yaml` (`yaml.safe_load` only) |
| **python-stdnum** | `detector_support.py` (guarded import) | authoritative IBAN checksum validation, with a built-in mod-97 fallback if absent |
| **re** (stdlib) | `detector_patterns.py` + all detectors | the entire deterministic detection layer is regex |
| **concurrent.futures.ThreadPoolExecutor** (stdlib) | `llm/detector.py` | parallel chunk processing (8 workers) without introducing asyncio into the core |
| **dataclasses / typing.Literal** (stdlib) | `models.py`, `config.py` | typed, immutable-ish records; closed string enums for categories/actions |
| **argparse / logging / pathlib / unicodedata / json / base64 / uuid / time** (stdlib) | CLI, everywhere | argument parsing, structured progress logs, path handling, NFC normalization, JSON, encoding, IDs, timings |
| **`.env` + custom loader** | `config.load_env_file` | dependency-free configuration file (python-dotenv deliberately NOT used); real env vars always win |
| **setuptools / pyproject.toml / requirements.txt** | packaging | `pip install -e .` or `pip install -r requirements.txt` |
| **Docker (Dockerfile, docker-compose.yml, .dockerignore)** | deployment | see section 8 |

---

## 6. Module-by-module reference (execution order)

*Every file, every function, every class — what it does, who calls it, what it returns, and what happens when it fails. Generated from the current on-disk code.*

## anonymizer/models.py — Shared data model: the dataclasses, category taxonomy, and constants every pipeline stage passes between each other

**Purpose:** Defines the "vocabulary" of the whole anonymizer: the dataclasses that carry a document through the pipeline (parsed text units, detected spans, the final redaction plan, the counts-only summary, the end result) plus the fixed taxonomy of detection categories and the redaction glyph. It has zero behavior — no functions, no I/O — which lets every other module (parser, detectors, LLM stage, resolver, writer, summary) share one set of types without circular imports. In pipeline terms it is the contract between stages: `parse_docx` produces `DocumentData`, detectors produce `Span`s, the resolver produces a `RedactionPlan`, the writer consumes it, and `anonymize_document` returns an `AnonymizeResult`.

**Imports:**
- stdlib: `dataclasses.dataclass` / `dataclasses.field` (declarative record types with defaults), `typing.Literal` (closed string-enum type aliases for unit types, categories, and actions).
- third-party: none.
- project: none (deliberately — this is the bottom of the import graph).

**Imported by (verified by grep):** `anonymizer/detectors.py`, `anonymizer/docx_engine.py`, `anonymizer/detector_support.py`, `anonymizer/pipeline.py`, `anonymizer/resolver.py`, `anonymizer/summary.py`, `anonymizer/llm/detector.py`.

### Functions & classes

**`class XmlCharRef` (frozen dataclass)**
- What it does: A pointer from one visible character of extracted text back to its exact byte-level home inside the DOCX package's XML. This is what makes "byte-verbatim redaction write-back" possible: the writer never re-renders text, it follows these pointers to overwrite individual characters with the dot glyph.
- Why it exists: DOCX text is scattered across many `<w:t>` XML nodes in many package parts; detection happens on flat extracted strings, so every character needs a reverse map to its XML origin.
- Attributes: `part_name: str` — the ZIP member (XML part) the character lives in, e.g. `word/document.xml`; `text_node_path: str` — the path identifying the specific text node inside that part (special markers `<w:tab/>`, `<w:br/>`, `<w:cr/>` are used for tab/break/carriage-return pseudo-characters); `char_index: int` — the character's index inside that node's text (0 for the pseudo-characters).
- How instances are created: exclusively in `anonymizer/docx_engine.py` inside `_extract_para_chars(...)` (lines 159, 162, 165, 168), one per extracted character, appended to a `char_map` list parallel to the character list.
- How state changes: never — the dataclass is `frozen=True`, so instances are immutable (and hashable).
- Consumed by: `docx_engine` write-back (line 320: `edits.append((ref.text_node_path, ref.char_index, REDACTION_GLYPH))`).
- Side effects / on failure: none; attempting to mutate raises `dataclasses.FrozenInstanceError`.

**`UnitType` (type alias, `Literal[...]`)**
- What it does: The closed set of places text can come from in a DOCX: `"paragraph"`, `"table_cell"`, `"header"`, `"footer"`, `"footnote"`, `"endnote"`, `"comment"`, `"textbox"`. Used as the type of `TextUnit.unit_type`. A type-checker-only construct — at runtime it is just a `typing.Literal` object, not enforced.

**`class TextUnit` (dataclass)**
- What it does: One extracted block of document text (a paragraph, table cell, header, etc.) together with everything needed to detect PII in it and write redactions back. This is the unit the detectors and the LLM chunker operate on.
- Attributes: `unit_id: str` — unique identifier for the unit within the document (spans reference units by this id); `part_name: str` — which XML part it came from; `unit_type: UnitType` — which structural kind of block it is; `text: str` — the raw extracted text; `normalized_text: str` — the NFC-normalized text that detection actually runs on (span offsets index into this string); `char_map: list[XmlCharRef]` — a list parallel to the text, one `XmlCharRef` per character, mapping each character back to its XML node; `location: dict` — free-form contextual metadata about where the unit sits.
- How instances are created: only in `anonymizer/docx_engine.py` inside `parse_docx` (lines 226 and 251 — table-cell and paragraph paths).
- How state changes: the dataclass is mutable in principle, but pipeline code treats units as read-only after parsing; detectors read `normalized_text` and `char_map` without mutating them.
- Side effects / on failure: none (pure data).

**`class DocumentData` (dataclass)**
- What it does: The full parsed document — the output of the DOCX parsing stage and the input to both detection stages and the resolver. Bundles all text units with package-level bookkeeping.
- Attributes: `document_id: str` — caller-supplied identifier threaded through logs, the plan, and the result; `text_units: list[TextUnit]` — every extracted text block; `parts_inventory: list[str]` — the names of the XML parts found in the package (used for warnings/coverage checks); `warnings: list[str]` — parse-time warnings, defaults to a fresh empty list (`field(default_factory=list)`).
- How instances are created: returned by `parse_docx(data, document_id)` in `anonymizer/docx_engine.py` (line 264).
- How state changes: `warnings` may be appended to during parsing; downstream stages read it into the plan/result warnings.
- Side effects / on failure: none (pure data).

**`SpanCategory` (type alias, `Literal[...]`)**
- What it does: The closed taxonomy of 37 detection categories, covering Greek tax-domain identifiers (`AFM` — tax ID, `AMKA` — social-security number, `DOU` — local tax office), generic PII (`IBAN`, `EMAIL`, `PHONE`, `PRIVATE_ADDRESS`), case metadata (`PROTOCOL_NUMBER`, `ACT_NUMBER`, `CHALLENGED_ACT_NUMBER`, `CASE_REF_NUMBER`, ...), values to keep (`DATE`, `MONEY`, `LEGAL_REF`, `PERCENTAGE`, ...), and uncertain LLM guesses (`POSSIBLE_PERSON`, `POSSIBLE_COMPANY`, `POSSIBLE_PRIVATE_LOCATION`, `MEDICAL_TERM`). Every `Span.category` must be one of these; the runtime-enforced version is `ALL_CATEGORIES` below.

**`SpanAction` (type alias, `Literal["REDACT", "PRESERVE", "REVIEW"]`)**
- What it does: The three verdicts a span can carry. Its attached docstring states the invariant: `REVIEW` exists only *before* resolution (deterministic review hints and LLM pass-1 findings) and must never appear in a `RedactionPlan`. The pipeline enforces this (`anonymizer/pipeline.py:91` rejects plans containing non-final actions).

**`class Span` (dataclass)**
- What it does: One detected stretch of text with a verdict — the atom of the whole detection/resolution machinery. Both the regex detectors and the LLM detector emit these; the resolver merges them by character ownership into a final plan.
- Attributes: `unit_id: str` — which `TextUnit` it belongs to; `start: int` / `end: int` — half-open character offsets into that unit's `normalized_text` (`normalized_text[start:end]`); `text: str` — the exact matched text; `category: SpanCategory` — what kind of thing it is; `detector: str` — which detector produced it (provenance, counted in the summary); `confidence: float` — the detector's confidence score, compared against `PolicySettings` thresholds during resolution; `action: SpanAction` — REDACT / PRESERVE / REVIEW verdict; `reason: str` — human-readable justification.
- How instances are created (verified): `anonymizer/detector_support.py` `_make_span(...)` (deterministic detectors), `anonymizer/resolver.py` `_make_span_from_run(...)` (resolver re-slicing spans after character-ownership resolution), `anonymizer/llm/detector.py` `parse_pass2_spans(...)` (validated LLM output).
- How state changes: instances are not mutated in place — the resolver builds *new* spans (`_make_span_from_run`) rather than editing existing ones; other stages only read fields.
- Side effects / on failure: none (pure data).

**`class RedactionPlan` (dataclass)**
- What it does: The final, conflict-resolved list of spans for a document — every span carries only `REDACT` or `PRESERVE`. It is what the DOCX writer executes and what the summary is computed from.
- Attributes: `document_id: str`; `spans: list[Span]` — the resolved spans; `warnings: list[str]` — accumulated warnings, defaults to a fresh empty list.
- How instances are created: only by `resolve_redactions(...)` in `anonymizer/resolver.py` (line 190).
- How state changes: effectively read-only after creation; consumed by `docx_engine` (write-back), `summary.build_summary`, and `pipeline.anonymize_document` (which validates the no-REVIEW invariant).

**`class PlanSummary` (dataclass)**
- What it does: The counts-only view of a plan — the *only* detection information returned to API/CLI callers (no span text ever leaves the service, by design).
- Attributes: `spans_total: int` — total span count; `by_action: dict[str, int]` — counts keyed by action; `by_category: dict[str, int]` — counts keyed by category; `by_detector: dict[str, int]` — counts keyed by detector name; `warnings: list[str]` — warnings carried forward from the plan.
- How instances are created: only by `build_summary(plan)` in `anonymizer/summary.py` (line 12).
- How state changes: none after creation.

**`class AnonymizeResult` (dataclass)**
- What it does: The complete return value of one end-to-end pipeline run — what both entry points (CLI and HTTP API) receive from `anonymize_document`.
- Attributes: `document_id: str`; `redacted_docx: bytes` — the full redacted DOCX file as bytes; `summary: PlanSummary` — the counts-only summary; `warnings: list[str]` — combined warnings; `model: str` — the LLM model/deployment handle used (from `RuntimeConfig.model_handle`); `timings: dict[str, float]` — per-stage wall-clock timings.
- How instances are created: only by `anonymize_document(...)` in `anonymizer/pipeline.py` (line 114).
- How state changes: none after creation.

**`REDACTION_GLYPH = "."` (module constant)**
- What it does: The single character every redacted character is replaced with (each hidden character becomes one dot, preserving length and layout). Used exactly once outside this file: `anonymizer/docx_engine.py:320`, where the writer builds per-character edits.

**`REDACT_CATEGORIES`, `PRESERVE_CATEGORIES`, `REVIEW_CATEGORIES` (module constants, `set[str]`)**
- What they do: Partition the category taxonomy by default disposition — 21 categories that identify parties/identifiers (always hidden), 13 categories that are legally-safe context (dates, money, legal references — kept), and 4 uncertain LLM-only categories that start as `REVIEW` and must be resolved. Grep confirms no other module imports these three sets directly; inside this file their union builds `ALL_CATEGORIES`. (Actual per-run REDACT/PRESERVE policy comes from `config/policy.yaml` via `PolicySettings`; these sets are the canonical taxonomy grouping.)

**`ALL_CATEGORIES: frozenset[str]` (module constant)**
- What it does: The frozen union of the three sets above — the runtime-checkable version of `SpanCategory`. Used by `anonymizer/llm/detector.py` (lines 228 and 266) to reject LLM output whose category is not in the taxonomy (unknown categories are filtered/refused rather than trusted).

---

## anonymizer/errors.py — The service's exception hierarchy: one base class and six failure flavors

**Purpose:** Defines every error the anonymizer deliberately raises, all inheriting from a single base `AnonymizerError`. This gives the two entry points one catch-all: the CLI catches `AnonymizerError` to print a clean message instead of a traceback, and the FastAPI app maps each subclass to a specific HTTP status code via a single exception handler. Keeping the hierarchy in a dependency-free leaf module means any layer (config, DOCX engine, LLM client) can raise them without import cycles.

**Imports:** none at all — stdlib `Exception` is a builtin. (No third-party, no project imports.)

**Imported by (verified by grep):** `run_anonymizer.py`, `anonymizer/config.py`, `anonymizer/api.py`, `anonymizer/docx_engine.py`, `anonymizer/llm/detector.py`.

### Functions & classes

All seven classes are bodyless (`docstring only`): they add no attributes or methods beyond `Exception`, and instances are created the standard way — `raise SomeError("message")` — with the message retrievable via `str(exc)`. State never changes after construction. "Side effects" are none for the classes themselves; the interesting facts are who raises and who catches each one, verified by grep below.

**`class AnonymizerError(Exception)`**
- What it does: Base class for all anonymizer errors; never raised directly, only caught. Exists so callers can distinguish "expected, well-described anonymizer failure" from a genuine bug (any other exception).
- Caught by: `run_anonymizer.py:232` (per-file CLI loop — prints the error and continues/exits nonzero) and `anonymizer/api.py:116-118` (`@app.exception_handler(AnonymizerError)` → JSON error response with the mapped status code).
- HTTP mapping: subclasses are looked up in `_ERROR_STATUS_CODES` in `anonymizer/api.py:42-48`.

**`class InvalidDocumentError(AnonymizerError)`**
- What it does: The upload is not a usable DOCX — wrong format, corrupt ZIP, or missing required parts. Also covers malformed HTTP uploads (missing `file` field, empty body).
- Raised by (verified): `anonymizer/docx_engine.py:44, 47, 52` (inside `validate_docx_bytes`) and `anonymizer/api.py:59, 68` (upload parsing).
- Downstream: HTTP **400**; CLI prints the message via the `AnonymizerError` catch.

**`class DocumentProcessingError(AnonymizerError)`**
- What it does: The DOCX was valid, but producing or applying the redaction plan failed partway (e.g. the write-back stage hit an unexpected condition). Distinguishes "your file is bad" (400) from "we choked on a good file" (422).
- Raised by (verified): `anonymizer/docx_engine.py:571` (`write_redacted_docx` wraps any unexpected exception as `DocumentProcessingError(f'failed during {stage}')`; line 568 deliberately re-raises existing `InvalidDocumentError`/`DocumentProcessingError` unwrapped).
- Downstream: HTTP **422**.

**`class ConfigurationError(AnonymizerError)`**
- What it does: The service cannot start or run because runtime or file configuration is missing or invalid — a required env var absent for the chosen provider, a non-numeric tuning knob, an invalid `ANON_PROVIDER`, or a missing `policy.yaml`/`regex_patterns.yaml`.
- Raised by (verified): `anonymizer/config.py:96` (`_require`), `:114` (`_optional_number`), `:162` (`load_runtime_config` provider check), `:225` (`_load_yaml_mapping`).
- Caught by: `run_anonymizer.py:215` (startup — prints and exits before any file is processed).
- Downstream: HTTP **503** (service not usable, not the client's fault).

**`class AIUnavailableError(AnonymizerError)`**
- What it does: The LLM provider could not be reached at all (connection-level failure). Separated from `AIProviderError` because "network down" and "provider returned garbage" call for different operator responses.
- Raised by (verified): `anonymizer/llm/detector.py:421` (wrapping `openai.APIConnectionError`).
- Downstream: HTTP **503**. Because the LLM stage is mandatory, this aborts the whole document run.

**`class AIProviderError(AnonymizerError)`**
- What it does: The provider was reachable but the call failed at the API level or returned output the service cannot use (e.g. pass-2 output that is not a JSON array).
- Raised by (verified): `anonymizer/llm/detector.py:252` (unparseable pass-2 output), `:425, :430, :436` (API/status/output errors).
- Downstream: HTTP **502** (bad gateway — the upstream AI misbehaved).

**`class AITimeoutError(AnonymizerError)`**
- What it does: A single LLM call exceeded the configured per-call timeout (`RuntimeConfig.llm_timeout_s`).
- Raised by (verified): `anonymizer/llm/detector.py:416` (message includes the configured timeout).
- Downstream: HTTP **504** (gateway timeout).

---

## anonymizer/config.py — Two-source configuration layer: env-based runtime config and file-based policy/rules config

**Purpose:** Centralizes all configuration for the service in two deliberately separate loaders: `load_runtime_config` reads the process environment (which LLM provider, secrets, timeouts, concurrency, upload limits), and `load_file_config` reads a `config/` directory (policy confidence thresholds, regex detector patterns, Greek-domain allowlists). It also owns `load_env_file`, the project's dependency-free `.env` loader shared by every entry point — real environment variables always win over the file. Nothing is read at import time; every read happens inside a loader call, so tests can inject an explicit `env` mapping or `config_dir` and stay hermetic. In the pipeline, the resulting `RuntimeConfig` drives the LLM stage and API limits while `FileConfig` drives the deterministic detectors and the resolver.

**Imports:**
- stdlib: `logging` (module logger for the missing-allowlist warning), `os` (reads/writes `os.environ`), `dataclasses.dataclass` (the four frozen config records), `pathlib.Path` (all file paths), `typing.Callable/Literal/Mapping` (type hints); `from __future__ import annotations` for postponed annotation evaluation.
- third-party: `yaml` (PyYAML) — `yaml.safe_load` parses `policy.yaml` and `regex_patterns.yaml`.
- project: `anonymizer.errors.ConfigurationError` — the single error type this module raises.

**Imported by (verified by grep):** `gunicorn.conf.py`, `run_anonymizer.py`, `anonymizer/api.py`, `anonymizer/detector_support.py`, `anonymizer/detectors.py`, `anonymizer/pipeline.py`, `anonymizer/postcheck.py`, `anonymizer/resolver.py`, `anonymizer/llm/client.py`, `anonymizer/llm/detector.py`.

### Functions & classes

**`class RuntimeConfig` (frozen dataclass)**
- Why it exists: One immutable record of everything read from the environment, so the pipeline, LLM client, and API never touch `os.environ` themselves.
- Attributes: `provider: Literal["openai", "azure"]` — which LLM backend to use; `openai_api_key: str | None` and `openai_model: str | None` — OpenAI credentials/model (populated only when `provider == "openai"`); `azure_api_key`, `azure_endpoint`, `azure_deployment`, `azure_api_version` (all `str | None`) — Azure OpenAI settings (populated only for `provider == "azure"`); `llm_timeout_s: float = 60.0` — per-LLM-call timeout; `chunk_size_chars: int = 3000` — target chunk size for splitting document text before LLM calls; `max_completion_tokens: int = 2000` — cap on LLM completion length; `llm_concurrency: int = 8` — thread-pool worker count for concurrent chunk processing; `log_level: str = "INFO"` — logging level (applied in `api.py:30`); `max_upload_mb: int = 20` — HTTP upload size limit (enforced in `api.py:69`).
- How instances are created: only via `load_runtime_config` (line 204); tests could construct one directly.
- How state changes: never — `frozen=True`.
- Consumers (verified): `anonymizer/llm/client.py` (builds the OpenAI/AzureOpenAI client from `provider`, keys, endpoint, `llm_timeout_s`), `anonymizer/llm/detector.py` (`chunk_size_chars`, `max_completion_tokens`, `llm_concurrency`, `model_handle`), `anonymizer/pipeline.py` (`model_handle`), `anonymizer/api.py` (`log_level`, `max_upload_mb`, `provider`, `model_handle`).

**`RuntimeConfig.model_handle -> str`** (property)
- What it does: Returns the provider-appropriate model identifier the LLM client should pass on each call — the OpenAI model name (`openai_model`) when `provider == "openai"`, otherwise the Azure deployment name (`azure_deployment`). `load_runtime_config` guarantees the relevant field is non-None for the selected provider (hence the `# type: ignore` comments).
- Called by (verified): `anonymizer/pipeline.py:119` (recorded in `AnonymizeResult.model`), `anonymizer/api.py:112` (health/info endpoint payload), `anonymizer/llm/detector.py:408` (the actual LLM call).
- Parameters: none (property). Returns: `str`. Side effects: none. On failure: if constructed by hand with the relevant field `None`, it would return `None` despite the annotation — the loaders prevent this.

**`class PolicySettings` (frozen dataclass)**
- Why it exists: Holds the resolver's decision thresholds and hard-category overrides, loaded from `config/policy.yaml` — policy is data, not code.
- Attributes: `preserve_high_confidence_threshold: float` — confidence at/above which a PRESERVE span is trusted; `redact_high_confidence_threshold: float` — confidence for "high-confidence redact" treatment; `redact_threshold: float` — minimum confidence for a REDACT span to stand; `hard_preserve_categories: frozenset[str]` and `hard_redact_categories: frozenset[str]` — categories whose action is forced regardless of confidence.
- Created only inside `load_file_config` (line 258); immutable thereafter. Consumer (verified): `anonymizer/resolver.py` (threshold and hard-category checks during conflict resolution).

**`class DetectorRules` (frozen dataclass)**
- Why it exists: Bundles everything the deterministic regex detection stage needs, keeping Greek-domain knowledge (tax offices, agency names) in editable config files instead of code.
- Attributes: `patterns: dict[str, dict[str, str]]` — named regex pattern specs from `regex_patterns.yaml` (pattern name → spec fields, all stringified); `dou_allowlist: frozenset[str]` — known DOY (local tax office) names from `allowlists/dou.txt`; `public_services: frozenset[str]` — public-service names from `allowlists/public_services.txt`; `legal_refs: frozenset[str]` — legal-reference strings from `allowlists/legal_refs.txt`; `preserve_email_domains: frozenset[str]` — casefolded email domains (from `policy.yaml`'s `preserve_email_domains`) whose addresses are institutional and kept.
- Created only inside `load_file_config` (line 291); immutable. Consumers (verified): `anonymizer/detectors.py`, `anonymizer/detector_support.py`.

**`class FileConfig` (frozen dataclass)**
- Why it exists: The single return value of `load_file_config`, pairing `policy: PolicySettings` with `rules: DetectorRules` so callers pass one object into the pipeline.
- Created at line 299; immutable. Consumers (verified): `anonymizer/pipeline.py`, `anonymizer/postcheck.py` (both accept a `FileConfig`), created by `run_anonymizer.py:213` and `anonymizer/api.py:29`.

**`_require(env: Mapping[str, str], name: str, provider: str) -> str`**
- What it does: Fetches a mandatory environment variable and fails loudly if it is missing or empty, with a message that names both the variable and the provider that requires it.
- Called by (verified): `load_runtime_config` only (six call sites, lines 174-180).
- Parameters: `env` — the mapping to read from (real environ or injected test dict); `name` — the variable name; `provider` — the selected provider, used only in the error message.
- Returns: the non-empty string value.
- Steps: `env.get(name)` → falsy check → return or raise.
- Side effects: none.
- On failure: raises `ConfigurationError(f"{name} is required when ANON_PROVIDER={provider}")`; the CLI prints it and exits, the API returns 503.

**`_optional_number(env: Mapping[str, str], name: str, caster: Callable[[str], float]) -> float | None`**
- What it does: Reads an optional numeric tuning variable, returning `None` when absent so the dataclass default survives, and converting with the supplied caster (`float` or `int`) when present.
- Called by (verified): `load_runtime_config` only (five call sites, lines 185-197).
- Parameters: `env` — source mapping; `name` — variable name; `caster` — conversion function.
- Returns: the converted number, or `None` if the variable is not set.
- Steps: get raw → `None` short-circuit → `caster(raw)` in try/except.
- Side effects: none.
- On failure: a `TypeError`/`ValueError` from the caster becomes `ConfigurationError(f"{name} must be a number, got {raw!r}")` (with `from None` to hide the original traceback).

**`load_env_file(path: Path) -> None`**
- What it does: The project's dependency-free replacement for python-dotenv: reads a `KEY=VALUE` `.env` file and copies entries into `os.environ`, but only for keys not already set — real environment variables always win. Shared by every entry point so CLI, HTTP API, and gunicorn all see the same configuration.
- Called by (verified): `run_anonymizer.py:182` (with the script's own directory's `.env`), `gunicorn.conf.py:9` (same pattern), and `load_runtime_config` itself (line 157, with `Path.cwd() / ".env"`).
- Parameters: `path` — the `.env` file to read; silently ignored if it is not a file.
- Returns: `None` (its output is the mutated environment).
- Steps: (1) `path.is_file()` guard; (2) read UTF-8 text, iterate lines; (3) skip blanks and `#` comments; (4) strip an optional leading `export `; (5) skip lines without `=`; (6) partition on the first `=`, trim whitespace around key and value; (7) strip one pair of matching surrounding single or double quotes; (8) write to `os.environ` only if the key is non-empty and not already present.
- Side effects: mutates `os.environ` (process-wide); reads a file. Never logs variable values (secrets stay out of logs).
- On failure: no custom errors; a genuinely unreadable file would surface the underlying `OSError`/`UnicodeDecodeError` uncaught. A missing file is a silent no-op by design.

**`load_runtime_config(env: Mapping[str, str] | None = None) -> RuntimeConfig`**
- What it does: Builds the immutable `RuntimeConfig` from the environment: auto-loads the root `.env` first (only when no explicit `env` is injected), validates that the selected provider's required variables are present, and applies any optional tuning overrides while keeping dataclass defaults for absent knobs.
- Called by (verified): `run_anonymizer.py:212` (CLI startup) and `anonymizer/api.py:28` (FastAPI lifespan startup).
- Parameters: `env` — an optional explicit mapping; `None` (the normal case) means "load `.env` from the current working directory, then use `os.environ`". Passing a mapping skips the `.env` load entirely, keeping tests hermetic.
- Returns: a fully-populated `RuntimeConfig`.
- Steps: (1) if `env is None`: `load_env_file(Path.cwd() / ".env")` then `env = os.environ`; (2) read `ANON_PROVIDER` (default `"openai"`), reject anything other than `"openai"`/`"azure"`; (3) for openai: `_require` `OPENAI_API_KEY` and `ANON_MODEL`; for azure: `_require` `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `ANON_AZURE_DEPLOYMENT`, `ANON_AZURE_API_VERSION`; (4) collect optional overrides — `ANON_LLM_TIMEOUT_S` (float), `ANON_CHUNK_SIZE_CHARS`, `ANON_MAX_COMPLETION_TOKENS`, `ANON_LLM_CONCURRENCY`, `ANON_MAX_UPLOAD_MB` (ints via `_optional_number`), `ANON_LOG_LEVEL` (plain string) — adding a key to the `overrides` dict only when the variable exists; (5) construct `RuntimeConfig(...)` with `**overrides`.
- Side effects: in the default path only, indirectly mutates `os.environ` via `load_env_file` and reads a `.env` file from the current working directory (this is why both entry points must run from the project root).
- On failure: raises `ConfigurationError` for an invalid provider, a missing required variable, or a non-numeric knob. Downstream: CLI prints and exits (`run_anonymizer.py:215`); in the API this happens at startup inside the lifespan, so the app fails to boot (and a `ConfigurationError` reaching the handler would map to 503).

**`_load_yaml_mapping(path: Path, missing_message: str) -> dict`**
- What it does: Loads one YAML file safely and guarantees a dict comes back — an empty file yields `{}` rather than `None`.
- Called by (verified): `load_file_config` only (lines 252 and 280, for `policy.yaml` and `regex_patterns.yaml`).
- Parameters: `path` — the YAML file; `missing_message` — the exact `ConfigurationError` message to raise if it does not exist.
- Returns: the parsed mapping as a `dict` (`{}` for a blank file).
- Steps: existence check → open UTF-8 → `yaml.safe_load(f) or {}`.
- Side effects: file read only.
- On failure: raises `ConfigurationError(missing_message)` when the file is absent; malformed YAML would raise PyYAML's `yaml.YAMLError` uncaught. Note: it returns whatever `safe_load` produced, so a YAML file whose top level is a list would flow through untyped — the callers immediately treat it as a mapping.

**`_load_allowlist(path: Path) -> frozenset[str]`**
- What it does: Reads a plain-text allowlist (one entry per line) into a frozenset, skipping blank lines and `#` comments. Unlike the YAML loader it is lenient: a missing file is only a logged warning and an empty set, because a missing allowlist degrades detection quality but does not make the service unusable.
- Called by (verified): `load_file_config` only (lines 293-295, for `dou.txt`, `public_services.txt`, `legal_refs.txt`).
- Parameters: `path` — the text file to read.
- Returns: `frozenset[str]` of stripped, non-empty, non-comment lines (duplicates collapse).
- Steps: existence check (warn + empty set if missing) → read UTF-8 → per-line strip/filter → accumulate into a set → freeze.
- Side effects: file read; `logger.warning("Allowlist file not found: %s (using empty allowlist)", path)` on a missing file.
- On failure: never raises for a missing file; an unreadable existing file would surface the underlying `OSError` uncaught.

**`load_file_config(config_dir: Path) -> FileConfig`**
- What it does: Loads everything policy- and detector-related from a config directory and returns it as one immutable `FileConfig`. This is where the resolver's thresholds, the regex detector's patterns, and the Greek-domain allowlists all enter the process.
- Called by (verified): `run_anonymizer.py:213` (CLI, with its resolved config dir) and `anonymizer/api.py:29` (API startup, with `Path("config")`).
- Parameters: `config_dir` — directory expected to contain `policy.yaml`, `regex_patterns.yaml`, and an `allowlists/` subdirectory with `dou.txt`, `public_services.txt`, `legal_refs.txt`.
- Returns: `FileConfig(policy=PolicySettings(...), rules=DetectorRules(...))`.
- Steps: (1) coerce `config_dir` to `Path`; (2) `_load_yaml_mapping` on `policy.yaml` and take its `policy` key (tolerating `None` via `or {}`); (3) build `PolicySettings` — the three thresholds are **mandatory** (direct `policy_map[...]` indexing, cast to float) while the two hard-category lists default to empty frozensets; (4) extract `preserve_email_domains` from the same policy map, stripped and casefolded, dropping empties; (5) `_load_yaml_mapping` on `regex_patterns.yaml` and normalize it to `dict[str, dict[str, str]]`, silently skipping any top-level entry whose value is not a dict; (6) `_load_allowlist` the three files under `allowlists/`; (7) assemble `DetectorRules` then `FileConfig`.
- Side effects: file reads; possible `logger.warning` per missing allowlist file.
- On failure: raises `ConfigurationError` if either YAML file is missing; a policy file that exists but lacks one of the three threshold keys raises a plain `KeyError` (not wrapped), and a non-numeric threshold raises `ValueError` — both would escape as non-`AnonymizerError` exceptions (CLI traceback / API 500 rather than 503).

**`__all__`** (module constant) — declares the public surface: the four dataclasses and the three loaders. The underscore-prefixed helpers are internal, and grep confirms no module outside `config.py` calls them.

---

## anonymizer/docx_engine.py — DOCX package I/O: validation, parsing into TextUnits, redaction write-back, and metadata scrubbing

**Purpose:** This module is the only place in the codebase that touches raw DOCX bytes. A DOCX file is really a ZIP archive (technically an OPC package) full of XML files, and this module handles both directions of the pipeline's document boundary: on the way in it validates the ZIP and parses the Word XML parts into `TextUnit` objects, each carrying a *per-character map* (`char_map`) that records exactly which XML text node and character index every visible character came from; on the way out it applies a `RedactionPlan` by overwriting each redacted character with the redaction glyph (a dot, `REDACTION_GLYPH = "."`) directly inside the original XML nodes, scrubs identifying metadata/comments/tracked-changes/hidden-text, and rebuilds the ZIP byte-verbatim — every member that was not deliberately modified is copied through with its original bytes and ZIP metadata. This 1:1 character-substitution design (never insert/delete, only replace) is what lets detector offsets computed on extracted text map back onto the XML without any re-alignment.

**Imports:**
- *stdlib:* `io` (in-memory byte buffers for reading/writing ZIPs without touching disk), `unicodedata` (NFC Unicode normalization of extracted characters — NFC means composing accented characters into their single canonical code point), `zipfile` (reading and writing the DOCX ZIP container), plus `from __future__ import annotations` (lazy type-hint evaluation).
- *third-party:* `lxml` (`etree`) — the XML parser/serializer used for all Word XML parts; chosen because it exposes `getparent()`/`index()` needed for the child-index path addressing scheme.
- *project:* `anonymizer.errors` (`DocumentProcessingError`, `InvalidDocumentError` — the two typed failures this module is allowed to raise) and `anonymizer.models` (`DocumentData`, `REDACTION_GLYPH`, `RedactionPlan`, `TextUnit`, `XmlCharRef` — the data structures it produces and consumes).

**Imported by:** (verified by grep)
- `anonymizer/pipeline.py` — `from anonymizer.docx_engine import parse_docx, validate_docx_bytes, write_redacted_docx` (the main anonymization flow).
- `anonymizer/postcheck.py` — `from anonymizer.docx_engine import parse_docx, validate_docx_bytes` (the CLI-only `--qa` residual-leak audit re-parses the redacted output).

### Functions & classes

*Module-level constants (no classes are defined in this file):* `W_NS`, `CP_NS`, `DC_NS`, `DCTERMS_NS` are the XML namespace URIs for WordprocessingML, core-properties, Dublin Core, and Dublin Core terms; `NSMAP = {'w': W_NS}` is the prefix map used in XPath queries; `XML_PARSER` is a hardened shared `etree.XMLParser` (`resolve_entities=False` and `no_network=True` block XXE-style attacks, `recover=True` tolerates slightly malformed XML, `remove_blank_text=False` preserves whitespace exactly). `__all__` exports the five public functions.

**`validate_docx_bytes(data: bytes) -> None`**
- What it does: Cheap structural sanity check that `data` really is a DOCX. It opens the bytes as a ZIP, runs the ZIP's built-in CRC integrity test, and confirms the three parts every DOCX must have are present. It does not parse any XML.
- Called by: `anonymizer/pipeline.py:48` (on the uploaded bytes, before parsing) and `:103` (on the redacted output, as a post-write sanity check); `anonymizer/postcheck.py:92`; internally by `parse_docx` (line 178) and `write_redacted_docx` (line 536).
- Parameters: `data` — the candidate DOCX file content as raw bytes.
- Returns: `None` on success (success is signaled by *not* raising).
- Steps: (1) open `io.BytesIO(data)` as a `zipfile.ZipFile`; (2) collect member names and run `zf.testzip()` (CRC check of every member); (3) if `testzip` names a corrupt member, raise; (4) verify `[Content_Types].xml`, `_rels/.rels`, and `word/document.xml` all exist, raising with the missing names otherwise.
- Side effects: none.
- On failure: raises `InvalidDocumentError` — `'Not a valid DOCX package'` (wrapping `zipfile.BadZipFile`/`OSError`), `'...corrupt member <name>'`, or `'...missing <names>'`. Downstream, the API layer maps this to a client-error HTTP response and the CLI to an error exit; the pipeline never proceeds with bad input.

**`_parse_xml_parts(package_data: dict[str, bytes]) -> dict[str, etree._Element]`**
- What it does: Turns the raw bytes of every XML-ish member of the package into a parsed lxml tree. Non-XML members (images, fonts) and members that fail to parse even with the recovering parser are silently skipped — they will later be copied through verbatim instead of modified.
- Called by: `parse_docx` (line 183) and `write_redacted_docx` (line 545) in this file only.
- Parameters: `package_data` — mapping of ZIP member name (e.g. `'word/document.xml'`) to that member's raw bytes.
- Returns: dict mapping part name → lxml root `_Element`, containing only members ending in `.xml` or `.rels` that parsed successfully.
- Steps: (1) filter names by suffix; (2) `etree.fromstring(blob, parser=XML_PARSER)` per member; (3) skip on `XMLSyntaxError` or a `None` result; (4) collect the rest.
- Side effects: none.
- On failure: does not raise for bad XML (skips it); any other unexpected exception would propagate to the caller (and inside `write_redacted_docx` be wrapped as `DocumentProcessingError`).

**`_serialize_xml(root: etree._Element) -> bytes`**
- What it does: One-liner that serializes a parsed XML tree back to UTF-8 bytes with an `<?xml ...?>` declaration, for writing into the output ZIP.
- Called by: `write_redacted_docx` (line 563) only.
- Parameters: `root` — the lxml root element of a part.
- Returns: the serialized XML as `bytes`.
- Steps: single `etree.tostring(root, encoding='UTF-8', xml_declaration=True)` call.
- Side effects: none.
- On failure: lxml errors would propagate; in practice wrapped by `write_redacted_docx` into `DocumentProcessingError('failed during write')`.

**`_local_name(element: etree._Element) -> str`**
- What it does: Strips the namespace from an element's tag — e.g. `{...ns...}Company` → `Company` — so code can match tags regardless of namespace prefix.
- Called by: `_cleanup_app_properties` (line 378) only.
- Parameters: `element` — any lxml element.
- Returns: the local (namespace-free) tag name string.
- Steps: `etree.QName(element).localname`.
- Side effects: none.
- On failure: raises `ValueError` on non-element nodes (comments/PIs); the sole caller pre-filters with `isinstance(element.tag, str)` so this cannot occur in practice.

**`_is_word_text_part(part_name: str) -> bool`**
- What it does: Decides whether a package part carries visible body text that the pipeline must detect over: the main document, any header/footer part, and the footnotes/endnotes parts.
- Called by: `parse_docx` (line 188) and `_cleanup_word_parts` (line 496).
- Parameters: `part_name` — ZIP member name.
- Returns: `bool` — True for `word/document.xml`, `word/header*.xml`, `word/footer*.xml`, `word/footnotes.xml`, `word/endnotes.xml`.
- Steps: string prefix/suffix and set-membership checks.
- Side effects: none.
- On failure: cannot fail.

**`_element_path(root: etree._Element, element: etree._Element) -> str`**
- What it does: Produces a stable "address" for an element as a slash-separated list of child indices from the root, e.g. `/2/0/1` meaning root's 3rd child → its 1st child → its 2nd child. This is the pointer format stored in every `XmlCharRef.text_node_path`, and it is what lets a fresh re-parse of the same bytes (in `write_redacted_docx`) find exactly the same node again.
- Called by: `_extract_para_chars` (line 154) only.
- Parameters: `root` — the part's root element; `element` — a descendant to address.
- Returns: the path string; `'/'` if `element` *is* `root`.
- Steps: (1) short-circuit for the root; (2) walk `getparent()` upward, appending `parent.index(current)` at each hop; (3) reverse and join with `/`.
- Side effects: none.
- On failure: cannot raise; if `element` is detached from `root` the loop breaks at the orphan and returns a partial path — never happens in this module because inputs always come from iterating the same tree.

**`_find_by_element_path(root: etree._Element, path: str) -> etree._Element | None`**
- What it does: The inverse of `_element_path`: follows the child indices in `path` down from `root` and returns the element there. Strictly rejects malformed paths (empty tokens like in `/3//1`, non-integer tokens, out-of-range indices) by returning `None` rather than guessing.
- Called by: `_apply_node_edits` (line 285) only.
- Parameters: `root` — the tree to resolve within; `path` — a path string previously produced by `_element_path`.
- Returns: the resolved `etree._Element`, or `None` for any invalid path.
- Steps: (1) `'/'` → return root; (2) reject paths not starting with `'/'`; (3) split on `/`, reject empty tokens, `int()` each token, index into `list(current)` with bounds checking; (4) return the final node.
- Side effects: none.
- On failure: never raises — all invalid input maps to `None`, which `_apply_node_edits` treats as "skip this edit" (the redaction for that node silently does not happen; in practice paths are always valid because the same bytes are re-parsed).

**`_extract_para_chars(root: etree._Element, paragraph: etree._Element, part_name: str) -> tuple[list[str], list[XmlCharRef]]`**
- What it does: The heart of the text↔XML mapping. Walks one Word paragraph and emits two parallel lists: the visible characters, and one `XmlCharRef` per character saying exactly where it lives in the XML. Each character from a `w:t` (text) node is NFC-normalized *individually* — normalizing the whole string at once could change its length and desynchronize offsets from the node's stored text. Tabs (`w:tab`) become `'\t'` and line/carriage breaks (`w:br`, `w:cr`) become `'\n'`, with synthetic marker paths (`'<w:tab/>'`, `'<w:br/>'`, `'<w:cr/>'`) that the write-back stage recognizes and skips (you can't redact a tab).
- Called by: `parse_docx` (lines 221 and 248) only.
- Parameters: `root` — the part's root (needed to compute element paths); `paragraph` — the `w:p` element to extract; `part_name` — the part's ZIP name, stamped into each `XmlCharRef`.
- Returns: `(chars, char_map)` — a `list[str]` of single characters and an equal-length `list[XmlCharRef]`; index *i* in one corresponds to index *i* in the other.
- Steps: (1) `paragraph.iter()` over all descendants; (2) skip non-element nodes (comments/PIs, where `.tag` is not a `str`); (3) for `w:t`: compute the node's element path once, then append each character NFC-normalized plus `XmlCharRef(part_name, node_path, idx)`; (4) for `w:tab`/`w:br`/`w:cr`: append the whitespace character with a synthetic ref.
- Side effects: none.
- On failure: does not raise in practice; any lxml error would propagate to `parse_docx`.

**`parse_docx(data: bytes, document_id: str) -> DocumentData`**
- What it does: The public entry for the "parse DOCX" pipeline stage. Converts the uploaded bytes into a `DocumentData` — an ordered list of `TextUnit`s (one per table cell and one per non-table paragraph) across every Word text part, each unit carrying its text and per-character `char_map`. Table cells are extracted first (with row/column/header metadata in `location`, so detectors can use column headers as context), and their paragraphs are remembered so the paragraph pass doesn't emit them twice. Note `text` and `normalized_text` are set to the same joined string, and `unit_id`s (`u0`, `u1`, …) come from one global counter shared by cells and paragraphs.
- Called by: `anonymizer/pipeline.py:49` and `anonymizer/postcheck.py:93`.
- Parameters: `data` — DOCX bytes; `document_id` — caller-chosen identifier stamped onto the result (the pipeline passes its request ID; postcheck passes `"postcheck"`).
- Returns: a `DocumentData(document_id=..., text_units=[...], parts_inventory=sorted member names, warnings=[])`. Each `TextUnit` has `unit_id`, `part_name`, `unit_type` (`'table_cell'` or `'paragraph'`), `text`, `normalized_text`, `char_map`, and a `location` dict (`table_index`/`row_index`/`col_index`/`column_header`/`is_header_row` for cells; `paragraph_index` — actually the global unit counter, downstream relies only on document order — for paragraphs). Empty cells/paragraphs are skipped entirely.
- Steps: (1) `validate_docx_bytes(data)`; (2) read every ZIP member into memory; (3) `_parse_xml_parts`; (4) for each Word text part in sorted name order: find all tables (`.//w:tbl`), take direct-child rows only (a nested table's text is deliberately absorbed into its enclosing outer cell because the cell extraction uses `.//w:p`); compute header texts from row 0; emit one `TextUnit` per non-empty cell, guarding `header_texts[col_idx]` against ragged tables; (5) then emit one `TextUnit` per non-empty paragraph not already consumed by a cell; (6) assemble `DocumentData`.
- Side effects: none (pure in-memory transformation; no logging, files, or network).
- On failure: raises `InvalidDocumentError` for bad packages (via the upfront validation). Unparseable individual XML parts don't raise — they're skipped and simply contribute no text units. Downstream, the pipeline aborts before any detection runs.

**`_apply_node_edits(root: etree._Element, edits: list[tuple[str, int, str]]) -> None`**
- What it does: Executes a batch of single-character replacements against `w:t` nodes. Edits are grouped per target node, then applied to that node's text in descending character-index order — since every replacement is exactly one character for one character the order is defensive rather than load-bearing, but it means even a multi-character replacement couldn't shift the yet-unapplied lower indices. Synthetic paths beginning with `'<'` (tabs/breaks) and out-of-range indices are skipped.
- Called by: `apply_plan` (line 322) only.
- Parameters: `root` — the part tree to mutate; `edits` — list of `(text_node_path, char_index, replacement)` triples (in practice `replacement` is always `REDACTION_GLYPH`).
- Returns: `None`.
- Steps: (1) group edits by node path, dropping `'<...>'` paths; (2) resolve each path with `_find_by_element_path`, skipping `None`; (3) explode `node.text` into a char list; (4) apply each `(index, replacement)` high-to-low with a `0 <= index < len` bounds guard; (5) rejoin and assign `node.text`.
- Side effects: mutates the XML tree under `root` in place (that is its purpose). No logging or I/O.
- On failure: does not raise under any input it can receive — unresolvable paths and bad indices are silently skipped, meaning that character simply stays unredacted (the CLI `--qa` postcheck is the safety net that would catch such a residual leak).

**`apply_plan(parsed_parts: dict[str, etree._Element], document: DocumentData, plan: RedactionPlan) -> None`**
- What it does: Translates the abstract `RedactionPlan` (unit-relative character offsets decided by the detection/resolution stages) into concrete XML edits. For every span whose `action` is `REDACT`, it looks up each character position in the owning unit's `char_map` and replaces that exact character in the XML with the dot glyph. Only `REDACT` spans do anything — `PRESERVE` (and any other action) spans are ignored here. Offsets are defensively clamped into `[0, len(char_map)]` so a slightly out-of-range span degrades gracefully instead of crashing.
- Called by: `write_redacted_docx` (line 548) only within the project (it is also exported in `__all__`).
- Parameters: `parsed_parts` — part name → lxml root, freshly re-parsed from the original bytes; `document` — the `DocumentData` from `parse_docx` whose `char_map`s address those same trees; `plan` — the final `RedactionPlan` (list of `Span`s with `unit_id`, `start`, `end`, `action`, ...).
- Returns: `None`.
- Steps: (1) bucket spans by `unit_id`; (2) for each text unit, fetch its part root (skip if the part isn't parsed); (3) iterate that unit's spans sorted by `start` descending; (4) skip unless `str(span.action).upper() == 'REDACT'`; (5) clamp `start`/`end` to the char-map length; (6) build one edit per in-range character whose ref is a real node path (synthetic `'<...>'` refs skipped); (7) hand the batch to `_apply_node_edits`.
- Side effects: mutates the trees inside `parsed_parts` in place; does not modify `document` or `plan`. No logging or I/O.
- On failure: does not raise for the usual degenerate cases (unknown unit part, empty/reversed spans, non-REDACT actions — all skipped). A truly unexpected exception (e.g. non-numeric `span.start` failing `int()`) propagates and is wrapped by `write_redacted_docx` into `DocumentProcessingError('failed during apply_plan')`.

**`_first_child(root: etree._Element, qname: str) -> etree._Element | None`**
- What it does: Finds the first *direct* child of `root` whose fully-qualified tag (namespace + local name, e.g. `{http://purl.org/dc/elements/1.1/}creator`) equals `qname`.
- Called by: `_blank_children` (line 340) and `_set_child_text` (line 349).
- Parameters: `root` — parent element; `qname` — fully-qualified tag string to match.
- Returns: the matching child element or `None`.
- Steps: linear scan over direct children, skipping non-element nodes.
- Side effects: none.
- On failure: cannot fail.

**`_blank_children(root: etree._Element, qnames: list[str]) -> None`**
- What it does: For each listed tag, empties the first matching direct child: sets its text to `''` and deletes all its subelements. Used to wipe metadata values while keeping the elements themselves present (so the XML stays schema-shaped).
- Called by: `_cleanup_core_properties` (line 361) only.
- Parameters: `root` — parent element (the core-properties root); `qnames` — fully-qualified tags to blank.
- Returns: `None`.
- Steps: per qname, `_first_child`; if found, `child.text = ''` and remove every subelement.
- Side effects: mutates the tree in place.
- On failure: cannot fail; missing children are ignored.

**`_set_child_text(root: etree._Element, qname: str, text: str) -> None`**
- What it does: Like `_blank_children` but writes a specific value instead of an empty string — used to reset the created/modified timestamps to a fixed epoch so output files don't leak real edit dates.
- Called by: `_cleanup_core_properties` (lines 368–369) only.
- Parameters: `root` — parent element; `qname` — fully-qualified tag; `text` — replacement text value.
- Returns: `None`.
- Steps: `_first_child`; if found, assign `child.text = text` and strip subelements.
- Side effects: mutates the tree in place.
- On failure: cannot fail; a missing child is a no-op.

**`_cleanup_core_properties(parsed_parts: dict[str, etree._Element]) -> None`**
- What it does: Scrubs `docProps/core.xml` — the "core properties" part where Word records who wrote the file. Blanks creator, lastModifiedBy, title, keywords, and category, and rewrites the created/modified timestamps to `2000-01-01T00:00:00Z`.
- Called by: `clean_sensitive_parts` (line 510) only.
- Parameters: `parsed_parts` — the parsed-package dict; the function looks up `'docProps/core.xml'` itself.
- Returns: `None`.
- Steps: (1) fetch the part, return early if absent; (2) `_blank_children` on the five identifying fields; (3) `_set_child_text` on `dcterms:created` and `dcterms:modified`.
- Side effects: mutates the core-properties tree in place.
- On failure: cannot fail in practice; absent part is a no-op.

**`_cleanup_app_properties(parsed_parts: dict[str, etree._Element]) -> None`**
- What it does: Scrubs `docProps/app.xml` (the "extended/application properties" part): blanks any element locally named `Company`, `Manager`, or `Template` anywhere in the part, regardless of namespace.
- Called by: `clean_sensitive_parts` (line 511) only.
- Parameters: `parsed_parts` — the parsed-package dict.
- Returns: `None`.
- Steps: (1) fetch the part or return; (2) iterate all elements; (3) match by `_local_name`; (4) empty the text and remove subelements.
- Side effects: mutates the app-properties tree in place.
- On failure: cannot fail in practice.

**`_remove_custom_properties(parsed_parts: dict[str, etree._Element], removed_parts: set[str]) -> None`**
- What it does: Deletes `docProps/custom.xml` (arbitrary user-defined document properties, a metadata leak risk) from the package entirely, and — so Word doesn't see a dangling reference — also removes its relationship entry from `_rels/.rels` and its Override entry from `[Content_Types].xml`. The part name is unconditionally added to `removed_parts`, which the ZIP writer uses as a skip-list, so the part is dropped even if it was one of the (rare) unparseable blobs that never made it into `parsed_parts`.
- Called by: `clean_sensitive_parts` (line 512) only.
- Parameters: `parsed_parts` — the parsed-package dict; `removed_parts` — the accumulating set of part names to exclude from the output ZIP.
- Returns: `None`.
- Steps: (1) add `'docProps/custom.xml'` to `removed_parts` and pop it from `parsed_parts`; (2) in `_rels/.rels`, remove relationships whose `Target` is `docProps/custom.xml` (with or without leading `/`) or whose `Type` ends with `/custom-properties`; (3) in `[Content_Types].xml`, remove the Override with `PartName='/docProps/custom.xml'`.
- Side effects: mutates `parsed_parts` (key removal plus tree edits) and `removed_parts` (adds one name).
- On failure: cannot fail; missing parts are no-ops.

**`_remove_elements(root: etree._Element, qnames: list[str]) -> None`**
- What it does: Generic deep delete — removes every element anywhere under `root` whose fully-qualified tag is in `qnames`, contents and all.
- Called by: `_cleanup_comments` (line 421) only.
- Parameters: `root` — tree to prune; `qnames` — fully-qualified tags to delete.
- Returns: `None`.
- Steps: snapshot `list(root.iter())` (safe iteration while mutating), match by tag, `parent.remove(element)`.
- Side effects: mutates the tree in place. Note it does *not* preserve tail text (unlike `_drop_element`) — acceptable for the marker elements it's used on, which carry no meaningful tails.
- On failure: cannot fail.

**`_cleanup_comments(parsed_parts: dict[str, etree._Element]) -> None`**
- What it does: Neutralizes Word comments: if the package has a `word/comments.xml` part, replaces its whole tree with a brand-new empty `<w:comments/>` element (so all comment text vanishes but the part still exists and relationships stay valid), then strips the three comment marker elements (`commentRangeStart`, `commentRangeEnd`, `commentReference`) out of the document body.
- Called by: `clean_sensitive_parts` (line 513) only.
- Parameters: `parsed_parts` — the parsed-package dict.
- Returns: `None`.
- Steps: (1) overwrite `parsed_parts['word/comments.xml']` with `etree.Element('{W_NS}comments', nsmap={'w': W_NS})` if present; (2) `_remove_elements` on `word/document.xml` for the three marker tags.
- Side effects: mutates `parsed_parts` (rebinding one value, editing the document tree).
- On failure: cannot fail; missing parts are no-ops.

**`_append_tail(parent: etree._Element, index: int, tail: str | None) -> None`**
- What it does: Low-level helper for splicing elements out of mixed content. In lxml, text that follows an element is stored as that element's `.tail`; when you delete an element you must re-home its tail or the text vanishes. This attaches `tail` at child position `index`: onto the previous sibling's tail, or onto the parent's leading `.text` if there is no previous sibling.
- Called by: `_unwrap_element` (line 457) and `_drop_element` (line 468).
- Parameters: `parent` — the container element; `index` — the child slot where the removed content used to be; `tail` — the text to re-home (may be `None`/empty → no-op).
- Returns: `None`.
- Steps: (1) return if falsy tail; (2) if `index > 0`, concatenate onto `parent[index-1].tail`; (3) else concatenate onto `parent.text`.
- Side effects: mutates the tree in place.
- On failure: cannot fail for the indices its callers pass.

**`_unwrap_element(element: etree._Element) -> None`**
- What it does: Removes a wrapper element but keeps everything inside it — its children are promoted into the parent at the same position, and its leading text and trailing tail are merged into the surrounding text. Used to *accept* tracked insertions (`w:ins`/`w:moveTo`): the wrapper marking "this was inserted" goes away, the inserted content stays.
- Called by: `_cleanup_tracked_changes` (line 480) only.
- Parameters: `element` — the wrapper to dissolve.
- Returns: `None`.
- Steps: (1) return if no parent; (2) record index, children, `element.text`, `element.tail`; (3) remove the element; (4) re-home leading text (previous sibling's tail or parent's text); (5) insert the children back at the original index in order; (6) `_append_tail` the old tail after the last promoted child.
- Side effects: mutates the tree in place.
- On failure: cannot fail for attached elements; detached elements are a no-op.

**`_drop_element(element: etree._Element) -> None`**
- What it does: Removes an element *and* its contents, preserving only the tail text that followed it. Used to accept tracked deletions (`w:del`/`w:moveFrom`) — the deleted content is discarded for real — and to remove hidden runs.
- Called by: `_cleanup_tracked_changes` (line 482) and `_cleanup_hidden_text` (line 490).
- Parameters: `element` — the element to delete.
- Returns: `None`.
- Steps: (1) return if no parent; (2) record index and tail; (3) `parent.remove(element)`; (4) `_append_tail` the tail at the vacated index.
- Side effects: mutates the tree in place.
- On failure: cannot fail; detached elements are a no-op.

**`_cleanup_tracked_changes(root: etree._Element) -> None`**
- What it does: "Accepts all tracked changes" (Word's revision-marking feature) in one part, so no revision history — which can contain pre-redaction text — survives into the output: insertion wrappers (`w:ins`, `w:moveTo`) are unwrapped keeping their content, deletion wrappers (`w:del`, `w:moveFrom`) are dropped with their content.
- Called by: `_cleanup_word_parts` (line 497) only.
- Parameters: `root` — the root of one Word text part.
- Returns: `None`.
- Steps: (1) collect all four wrapper kinds in document order; (2) iterate them **in reverse** so splicing an inner wrapper never invalidates positions of an outer one still pending; (3) skip any already detached (its ancestor was dropped first); (4) `_unwrap_element` or `_drop_element` by tag.
- Side effects: mutates the tree in place.
- On failure: cannot fail in practice.

**`_cleanup_hidden_text(root: etree._Element) -> None`**
- What it does: Deletes every run (`w:r` — Word's smallest formatted-text container) marked with `w:vanish` in its run properties, i.e. text formatted as hidden. Hidden text is invisible on screen but present in the file, so it is a classic leak channel; it is also invisible to the detectors (extraction includes it, but the safest treatment is removal).
- Called by: `_cleanup_word_parts` (line 498) only.
- Parameters: `root` — the root of one Word text part.
- Returns: `None`.
- Steps: (1) collect runs where `./w:rPr/w:vanish` matches; (2) `_drop_element` each still-attached run.
- Side effects: mutates the tree in place.
- On failure: cannot fail in practice.

**`_cleanup_word_parts(parsed_parts: dict[str, etree._Element]) -> None`**
- What it does: Fans the tracked-changes and hidden-text cleanups out across every Word text part (document, headers, footers, footnotes, endnotes).
- Called by: `clean_sensitive_parts` (line 514) only.
- Parameters: `parsed_parts` — the parsed-package dict.
- Returns: `None`.
- Steps: iterate a snapshot of `parsed_parts.items()`; for parts passing `_is_word_text_part`, run `_cleanup_tracked_changes` then `_cleanup_hidden_text`.
- Side effects: mutates the trees in `parsed_parts` in place.
- On failure: cannot fail in practice.

**`clean_sensitive_parts(parsed_parts: dict[str, etree._Element], removed_parts: set[str] | None = None) -> set[str]`**
- What it does: The public one-call metadata scrubber — the pipeline's defense against everything sensitive that lives *outside* the visible body text. Runs, in order: core-properties blanking, app-properties blanking, custom-properties removal, comment neutralization, and tracked-changes/hidden-text cleanup. An important subtlety: only `None` triggers a fresh set — a caller-supplied set (even an empty one) is populated in place and returned, so callers can accumulate removals across calls.
- Called by: `write_redacted_docx` (line 551) only within the project (also exported in `__all__`).
- Parameters: `parsed_parts` — part name → lxml root for the whole package; `removed_parts` — optional pre-existing set of part names slated for removal.
- Returns: the `set[str]` of part names removed entirely from the package (currently always contains `'docProps/custom.xml'`); this is the same object the caller passed in, if it passed one.
- Steps: (1) default `removed_parts` to a new set only when `None`; (2) `_cleanup_core_properties`; (3) `_cleanup_app_properties`; (4) `_remove_custom_properties` (feeds `removed_parts`); (5) `_cleanup_comments`; (6) `_cleanup_word_parts`; (7) return `removed_parts`.
- Side effects: mutates `parsed_parts` (tree edits, one key removed, comments part rebound) and the `removed_parts` set.
- On failure: does not raise in practice; anything unexpected propagates to `write_redacted_docx` and becomes `DocumentProcessingError('failed during clean_sensitive_parts')`.

**`_copy_zipinfo(info: zipfile.ZipInfo) -> zipfile.ZipInfo`**
- What it does: Clones a ZIP member's metadata record — filename, timestamp, comment, extra field, internal/external attributes, creating system, and compression method — so re-written members keep identical ZIP-level metadata to the original. This is half of the "byte-verbatim" guarantee: even members whose *content* changed keep their original container metadata.
- Called by: `write_redacted_docx` (line 566) only.
- Parameters: `info` — the source `zipfile.ZipInfo` from the input archive.
- Returns: a new `zipfile.ZipInfo` with the copied fields.
- Steps: construct with filename/date_time, then copy the six remaining attributes field by field.
- Side effects: none.
- On failure: cannot fail.

**`write_redacted_docx(input_bytes: bytes, document: DocumentData, plan: RedactionPlan) -> bytes`**
- What it does: The public write-back stage — the final document-producing step of the pipeline. It re-reads the *original* upload bytes (not any intermediate state), re-parses the XML parts, applies the redaction plan (dot-glyph substitution), scrubs sensitive parts, and rebuilds the ZIP: parts that were parsed get re-serialized, parts on the removal list are omitted, and everything else (images, fonts, unparsed blobs) is copied through with its exact original bytes and cloned ZIP metadata. A `stage` string tracks progress so failures report which phase broke.
- Called by: `anonymizer/pipeline.py:102` only.
- Parameters: `input_bytes` — the original uploaded DOCX bytes; `document` — the `DocumentData` produced by `parse_docx` over those same bytes (its char maps must correspond to them); `plan` — the resolved `RedactionPlan`.
- Returns: the complete redacted DOCX as `bytes`.
- Steps: (1) `validate_docx_bytes(input_bytes)`; (2) *read*: load all members and their `ZipInfo`s into memory; (3) *parse*: `_parse_xml_parts`; (4) *apply_plan*: `apply_plan(parsed_parts, document, plan)`; (5) *clean_sensitive_parts*: get `removed_parts`; (6) *write*: open an in-memory output ZIP and, iterating the original member order, skip duplicates and removed parts, write `_serialize_xml(parsed_parts[name])` for parsed parts and the verbatim original `package_data[name]` otherwise, each under `_copy_zipinfo(info)`; (7) return `output.getvalue()`.
- Side effects: none externally observable (all I/O is in-memory `BytesIO`; no logging, files, network, or env writes). Internal `parsed_parts` mutation is local to the call; `document` and `plan` are not modified.
- On failure: `InvalidDocumentError` from the upfront validation passes through untouched; `InvalidDocumentError`/`DocumentProcessingError` raised inside the try also pass through; any other exception is wrapped as `DocumentProcessingError(f'failed during {stage}')` with the original exception chained. Downstream, `pipeline.py` lets this propagate to the API/CLI error handling, and additionally re-validates the returned bytes (`pipeline.py:103`) before building the counts-only summary.

---

## anonymizer/detector_patterns.py — constants-only home of every regex used by the deterministic detection pass

**Purpose:** This module is a pure data file: it defines all the regular expressions (regexes — text-matching rules) and small lookup tables that the deterministic (non-LLM) detection stage uses to find sensitive or preservable text in Greek tax-decision documents. It contains no functions, no classes, and no I/O — only module-level constants. Keeping the patterns in one file separates "what to look for" (this file) from "how to search" (`detector_support.py`) and "which detectors run" (`detectors.py`). In the pipeline it sits at the very start of the detection stage: `detectors.detect_all` produces the first, high-confidence set of spans from these patterns before the two-pass LLM detection adds more.

**Imports:**
- Stdlib: `re` — used only to pre-compile the pattern constants at import time (e.g. `re.compile(...)` with `re.IGNORECASE` where appropriate).
- Third-party: none.
- Project: none. This module is deliberately dependency-free so it can never create an import cycle.

**Imported by:** exactly one project module — `anonymizer/detector_support.py` (line 25), which imports 26 of the constants and re-exports them via its `__all__`. `anonymizer/detectors.py` consumes the constants only through that re-export, never directly. (`BUILDER_REPORT.md` and `ded_anonymizer.egg-info/SOURCES.txt` mention the file but are documentation/packaging metadata, not code.)

### Functions & classes

This file defines **no top-level functions or classes** — its entire public surface is module-level constants. Every constant is documented below in file order; "Used by" locations are grep-verified. Unless stated otherwise, string constants are raw regex fragments compiled later by the consumer, and `_..._RE` constants are already-compiled `re.Pattern` objects.

**`_ELISION_APOSTROPHES: str`**
- A five-character string of apostrophe look-alikes (U+2019 right single quote, U+0027 ASCII apostrophe, U+02BC modifier apostrophe, U+1FBD Greek koronis, U+0384 Greek tonos). Greek legal text writes "υπ' αριθ." ("under number") with whatever apostrophe the typist's keyboard produced, so any of the five must match.
- Used by: within this file only — interpolated into the `legal_ref_fek` body (line 54) and `_CHALLENGED_ACT_RE` (line 83). Re-exported by `detector_support` but not referenced in `detectors.py`.

**`_DEFAULT_PATTERNS: dict[str, dict[str, str]]`**
- The master table of named ID patterns. Each key is a pattern name (e.g. `"afm"`, `"iban"`, `"date_numeric"`); each value is a dict with a `"body"` regex string and, for some entries, a `"prefix"` regex string (the contextual trigger that must appear before the value, e.g. `Α.Φ.Μ.:` before the nine digits). These are the *defaults*: at runtime a `DetectorRules.patterns` dict loaded from configuration can override any entry, and `detector_support._body` / `_prefix` perform that lookup-with-fallback. Entries cover: `afm` (Greek tax ID, 9 digits), `amka` (Greek social-security number, 11 digits), `email`, `iban`, three phone forms (`phone_intl`, `phone_local`, `phone_00`), `protocol_number`, `act_number`, `audit_order`, `invoice_number`, `transaction_id`, `date_numeric`, `date_greek` (day + Greek month name + year), `dou` (local tax office), legal-reference preservers (`legal_ref_law`, `legal_ref_pd`, `legal_ref_short`, `article_ref`, `court_decision`, `legal_ref_fek`, `legal_ref_pol`, `legal_ref_ste`, `legal_ref_nsk`, `legal_ref_aade`), and non-identifying financial context (`money`, `tax_year`, `percentage`, `fiscal_period`).
- Used by: `detector_support._body` (line 68) and `detector_support._prefix` (line 74), which are the only readers; `detectors.py` never indexes this dict directly.

**`_GREEK_CAPITALIZED: str`**
- Regex fragment matching one capitalized Greek word: an uppercase Greek letter (including accented/diaeresis forms) followed by one or more Greek letters. It is the building block for "this looks like a proper name" heuristics — capitalization is the signal, so consumers must compile it case-sensitively.
- Used by: `detectors.py` module level to build `_DOU_FALLBACK_RE` (line 58), and inside `detect_review_candidates` for the two-capitalized-words person-name heuristic (line 760), the company-with-legal-suffix heuristic (line 778), and the street-address heuristic (line 790).

**`_MEDICAL_TERMS: set[str]`**
- An 8-entry Greek gazetteer (word list) of medical vocabulary: διάγνωση (diagnosis), ασθένεια (illness), νόσος (disease), θεραπεία (treatment), φαρμακευτική (pharmaceutical), χειρουργείο (surgery), καρκίνος (cancer), διαβήτης (diabetes). Health information is highly sensitive, so any hit flags the surrounding text for review.
- Used by: `detectors.detect_review_candidates` (line 799), iterating over the set. This is the canonical copy; `detectors.py` imports it via `detector_support` so there is a single source of truth.

**`_DATE_SUFFIX_RE: re.Pattern`**
- Compiled regex splitting a combined "serial/date" value like `1234/15-03-2023` into a serial part (group 1), the separator (group 2), and a trailing `DD-MM-YYYY`-shaped date (group 3). Lets the pipeline redact only the serial while keeping the date visible.
- Used by: `detector_support._split_serial_date` (line 224) — its only consumer.

**`_CHALLENGED_ACT_RE: re.Pattern`** and **`_CHALLENGED_ACT_CONTEXT_RE: re.Pattern`**
- The first (compiled `IGNORECASE`) finds "υπ' αριθ. <number>" / "με αριθ. <number>" phrasings — how a decision cites the administrative act being challenged — capturing the act number (which must start with a digit or uppercase letter). The second is the confirmation check: words like Οριστικ-, Πράξη, Διορθωτικ-, Φ.Π.Α, φόρου, προστίμου near the match confirm the number really refers to a tax act, cutting false positives.
- Used by: `detectors.detect_challenged_act_numbers` (lines 276 and 278 — the context regex is searched over a window around each match; non-confirming matches are dropped).

**`_AUTHORITY_HEADER_CUES: re.Pattern`**
- Compiled `IGNORECASE` alternation of phrases that appear in the letterhead of the issuing authority (ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ, ΔΙΕΥΘΥΝΣΗ ΕΠΙΛΥΣΗΣ ΔΙΑΦΟΡΩΝ, Α.Α.Δ.Ε., Ταχ. Δ/νση, Τηλέφωνο, Fax, E-mail, …). Contact details in the *authority's* header are public information and must be preserved, unlike a taxpayer's contact details.
- Used by: `detectors.detect_authority_header` (line 830, via `.findall`).

**`_DECISION_TITLE_RE: re.Pattern`**
- Matches the literal title word `ΑΠΟΦΑΣΗ` ("DECISION") at a word boundary, case-sensitively. Marks the end of the header region.
- Used by: `detectors.detect_authority_header` (line 828, via `.match` on the stripped unit text).

**`_DECISION_NUMBER_RE: re.Pattern`** and **`_DECISION_PLACE_DATE_RE: re.Pattern`**
- Decision metadata that must stay readable: the first matches "Αριθμός απόφασης: <digits>" (decision number); the second matches a known DED-seat city name (Αθήνα, Καλλιθέα, Θεσσαλονίκη, …) followed by a `DD-MM-YYYY` date — the place-and-date line. Both compiled `IGNORECASE`.
- Used by: `detectors.detect_decision_metadata` (lines 501 and 514).

**`_APPELLANT_NAME_RE: re.Pattern`**
- Finds the appellant's (the taxpayer filing the appeal) name: after the case-insensitive trigger "ενδικοφανή προσφυγή του/της" or "προσφυγή του/της", it captures a run of capitalized Greek words (the capture itself is case-sensitive so it stops at the next lowercase prose word).
- Used by: `detectors.detect_appellant_identity` (line 543, via `_capture_spans`).

**`_FATHER_NAME_RE: re.Pattern`**
- Finds a father's/patronymic name: "του/της <Capitalized Name...>" but only when immediately followed by an identity cue ("με ΑΦΜ", "κάτοικ-", "οδός", "ατομική"), which distinguishes a genitive personal name from the ubiquitous Greek article "του".
- Used by: `detectors.detect_appellant_identity` (line 555, via `_capture_spans`).

**`_PRIVATE_ADDRESS_RE: re.Pattern`**
- Captures a private address after "κάτοικος/κάτοικη" ("resident of") or "οδός" ("street"), stopping at two-plus spaces, a period, a ", ΤΚ" (postal code) marker, a newline, or end of text. Compiled `IGNORECASE`.
- Used by: `detectors.detect_appellant_identity` (line 567, via `_capture_spans`).

**`_BUSINESS_SEAT_RE: re.Pattern`**
- Captures a company's registered seat after "με έδρα (την/τον)" ("with seat at"), with similar lookahead stops. Compiled `IGNORECASE`.
- Used by: `detectors.detect_appellant_identity` (line 579, via `_capture_spans`).

**`_COMPANY_WORD: str`** and **`_COMPANY_NAME_AFTER_CTX: re.Pattern`**
- `_COMPANY_WORD` is a fragment for one company-name word: starts with an uppercase Greek or Latin letter, then letters/dots/ampersands/hyphens — the leading-uppercase requirement makes the capture stop at the next lowercase prose word. `_COMPANY_NAME_AFTER_CTX` uses it to capture a full company name after triggers like "με επωνυμία" ("under the name"), "εταιρεία", or "εκδότρια (νομική οντότητα)", optionally ending in a Greek legal-form suffix (Α.Ε., Ε.Π.Ε., Ι.Κ.Ε., Ο.Ε., Ε.Ε.). Trigger is case-insensitive via inline `(?i:...)`; the captured name stays case-sensitive.
- Used by: `_COMPANY_WORD` only inside this file (lines 137-138); `_COMPANY_NAME_AFTER_CTX` by `detectors.detect_private_companies` (line 598).

**`_BANK_ACCOUNT_RE: re.Pattern`**
- Finds bank account numbers after a case-insensitive "λογ." / "λογαριασμό(ν)" trigger. The captured body is case-sensitive and matches either an IBAN-like shape (two uppercase letters then 4-29 alphanumerics/spaces, ending on an alphanumeric) or a plain 6-26 digit account number.
- Used by: `detectors.detect_bank_payment_ids` (line 632, via `_capture_spans`).

**`_BENEFICIARY_RE: re.Pattern`**
- Captures a payment beneficiary's name after the case-insensitive "δικαιούχο/δικαιούχη τον/την" ("beneficiary being") trigger; the name capture is case-sensitive capitalized-Greek words.
- Used by: `detectors.detect_bank_payment_ids` (line 644, via `_capture_spans`).

**`_FISCAL_ID_RE: re.Pattern`** and **`_PARTIAL_STAR_RE: re.Pattern`**
- `_FISCAL_ID_RE` (IGNORECASE) captures cash-register / fiscal-device serials (ΦΗΜ = certified fiscal device) after triggers "αριθμό μητρώου" (registry number), "ταμειακή (μηχανή)", or "ΦΗΜ". `_PARTIAL_STAR_RE` matches already-partially-masked identifiers like `ABC***123` (uppercase letters, then asterisks, then alphanumerics) so the remaining visible fragment also gets redacted.
- Used by: `detectors.detect_fiscal_device_ids` (lines 664 and 673 respectively).

**`_INVOICE_CELL_RE: re.Pattern`** and **`_INVOICE_PARAGRAPH_RE: re.Pattern`**
- Both match invoice/receipt document references starting with an uppercase abbreviation (ΤΙΜ., ΤΠΥ, ΔΑ, ΑΠΥ, ΤΔΑ, ΔΕΛΤΙΟ) followed by an identifier and optionally "σειρά <letter>" (series). Deliberately compiled **case-sensitive with a leading `\b`** — the in-file comment records that v1 compiled them `IGNORECASE`/unanchored, which made "ΤΙΜ"/"ΔΑ" match inside ordinary lowercase words ("τιμολογίου", "Επαμεινώνδα") and mutilate running prose. The cell variant matches the whole reference (fine inside a table cell, where the whole cell is the value); the paragraph variant captures only the numeric identifier (group 1) and series letter (group 2) so the abbreviation and the word "σειρά" stay visible in flowing text.
- Used by: `detectors.detect_table_sensitive_values` — paragraph variant at line 698, cell variant at line 735.

**`_SIGNATURE_TITLE_RE: re.Pattern`**
- IGNORECASE alternation of signature-block phrases ("Ακριβές αντίγραφο" = certified copy, "ΜΕ ΕΝΤΟΛΗ" = by order, Ο ΠΡΟΪΣΤΑΜΕΝΟΣ/Η ΠΡΟΪΣΤΑΜΕΝΗ = head of department, director titles, department names). Locates the official signature block at the end of the decision, where the signatory's name is a public official's and must be preserved.
- Used by: `detectors.detect_final_signatory` (line 869).

**`_ISOLATED_ALLCAPS_NAME_RE: re.Pattern`**
- Anchored (`^...$`) regex matching a line that is *only* 2-4 all-caps Greek words — the shape of a signatory name printed alone on its own line.
- Used by: `detectors.detect_final_signatory` (line 874, via `.match`).

**`_PRIVATE_PARTY_CUE_RE: re.Pattern`**
- IGNORECASE alternation of substrings signalling a *private* person context (προσφεύγ- = appellant, υπόχρε- = liable party, ΑΦΜ, κάτοικ-, έδρα, δικαιούχ-, πατέρ-, αδελφ-, σύζυγ-, λογαριασμ-). A safety brake: if these appear near a would-be signatory name, the name is treated as a private party, not a public official, and is not preserved.
- Used by: `detectors.detect_final_signatory` (line 883).

---

## anonymizer/detector_support.py — pure helper layer (pattern lookup, span builders, checksum validators) for the deterministic detectors

**Purpose:** This module holds the small, file-free helper functions that all deterministic detectors share: resolving a pattern name to its regex (with config override), constructing `Span` objects, running a regex over a text unit, and validating candidate matches with real checksums (AFM, AMKA, IBAN) so that random 9-digit numbers are not falsely redacted as tax IDs. It also **re-exports** all 26 constants from `detector_patterns` so `anonymizer.detectors` can import constants and helpers from one place. By design it performs no file access — no YAML, no path loading, no module-level allowlists; anything data-driven arrives through the `rules: DetectorRules` parameter, which keeps every helper a pure function that is trivial to test.

**Imports:**
- Stdlib: `re` (compiling/searching regexes), `datetime.date` (AMKA birth-date validation), `from __future__ import annotations` (lazy type annotations).
- Third-party (optional): `stdnum.iban.is_valid` from `python-stdnum`, imported inside a `try/except Exception` guard and bound to `_stdnum_iban_is_valid` (set to `None` if the package is missing) — the primary IBAN validator, with a self-contained mod-97 fallback in `_iban_is_valid`.
- Project: `anonymizer.config.DetectorRules` (the frozen dataclass carrying `patterns`, `dou_allowlist`, `public_services`, `legal_refs`, `preserve_email_domains`), `anonymizer.models.Span` and `anonymizer.models.TextUnit` (the detection data model), and the 26-name import block from `anonymizer.detector_patterns` (the re-export). One quirk worth knowing: the import-block comment says `_TABLE_HEADER_ACTIONS` is "deliberately NOT imported (see module note below)" but no such note exists in this file — that constant actually lives in `detectors.py` (line 65).

**Imported by:** exactly one project module — `anonymizer/detectors.py` (line 8), which imports 11 helpers and 22 of the re-exported constants. Nothing else in the codebase imports it (grep-verified; `resolver.py`'s `_make_span_from_run` is a different, locally defined function).

### Functions & classes

**`_body(rules: DetectorRules, name: str) -> str`**
- What it does: Looks up the `"body"` regex string for a named pattern (e.g. `"afm"`). If the runtime configuration (`rules.patterns`) provides an override for that name, the override wins; otherwise the hardcoded default from `_DEFAULT_PATTERNS` is returned. This is how config can retune a detector without code changes.
- Called by: `anonymizer/detectors.py` only — `detect_structured_ids` (lines 100, 118, 136), `detect_contacts` (160, 197), `detect_protocols_and_acts` (222, 254), `_detect_dates` (309, 325), `_detect_legal_refs` (416), `detect_preserve_spans` (452, 463, 474, 485).
- Parameters: `rules` — the `DetectorRules` config object whose `patterns` dict may override defaults; `name` — the pattern key (must exist in `_DEFAULT_PATTERNS` if not overridden).
- Returns: the regex string (coerced through `str(...)`), never compiled.
- Steps: (1) `rules.patterns.get(name, {})` — fetch the override dict, empty if none; (2) `.get("body", _DEFAULT_PATTERNS[name]["body"])` — take override body or default; (3) wrap in `str()`.
- Side effects: none.
- On failure: raises `KeyError` if `name` is neither in `rules.patterns`-with-a-body nor in `_DEFAULT_PATTERNS` — an unhandled programming error that would abort the detection stage. Note the fallback indexes `_DEFAULT_PATTERNS[name]` eagerly, so an override-only pattern name absent from the defaults still raises even though its value would not be needed... unless the override supplies `"body"`, in which case `.get`'s default argument is still evaluated first in Python — meaning any `name` absent from `_DEFAULT_PATTERNS` raises `KeyError` regardless of the override.

**`_prefix(rules: DetectorRules, name: str) -> str`**
- What it does: Same lookup as `_body` but for the optional `"prefix"` regex (the contextual trigger before a value, e.g. `ΑΜΚΑ:`). Patterns without a prefix yield `""`, so callers can always concatenate `_prefix(...) + _body(...)`.
- Called by: `anonymizer/detectors.py` — `detect_structured_ids` (lines 100, 118), `detect_protocols_and_acts` (222, 254).
- Parameters: `rules` — the `DetectorRules` config; `name` — the pattern key.
- Returns: the prefix regex string, or `""` when the default entry has no `"prefix"` key.
- Steps: (1) fetch override dict via `rules.patterns.get(name, {})`; (2) `.get("prefix", _DEFAULT_PATTERNS[name].get("prefix", ""))`; (3) `str()`.
- Side effects: none.
- On failure: `KeyError` if `name` is not in `_DEFAULT_PATTERNS` (same eager-default-evaluation caveat as `_body`).

**`_iter_allowlist_matches(text: str, entries)`** (generator; no annotations — `entries` is any iterable of strings, `yields re.Match`)
- What it does: For each entry in a gazetteer (allowlist of known names, e.g. public services or legal references), yields every case-insensitive occurrence of that entry in `text`. Entries are escaped with `re.escape`, so they are matched literally, not as regexes. Entries are tried longest-first so a longer allowlist name wins over a shorter prefix of itself (e.g. "Υπουργείο Οικονομικών" is found before "Υπουργείο"). This is how the deterministic PRESERVE pass locates known public-service and legal-reference names.
- Called by: `anonymizer/detectors.py` — `_detect_public_services` (line 380, with `rules.public_services`) and `_detect_legal_refs` (line 424, with `rules.legal_refs`).
- Parameters: `text` — the unit's normalized text to scan; `entries` — iterable of literal strings (in practice a `frozenset[str]` from `DetectorRules`).
- Returns: a generator of `re.Match` objects (position + matched text), in entry order (longest entry first), then document order within each entry.
- Steps: (1) `sorted(entries, key=len, reverse=True)`; (2) skip empty entries; (3) `re.finditer(re.escape(entry), text, re.IGNORECASE)` and `yield from` its matches.
- Side effects: none.
- On failure: nothing raised in practice (inputs are strings); a non-string entry would raise `TypeError` from `len`/`re.escape` and abort the calling detector. Note it does not deduplicate: overlapping entries can yield overlapping matches — overlap is settled later by the pipeline's conflict-resolution stage.

**`_make_span(unit: TextUnit, start: int, end: int, category: str, detector: str, confidence: float, action: str, reason: str) -> Span`**
- What it does: The single constructor every deterministic detector uses to turn a character range into a `Span` record. It slices the span's text out of `unit.normalized_text[start:end]` itself, so the stored `text` is always exactly what the offsets point at — a consistency guarantee the downstream verbatim write-back relies on.
- Called by: `_regex_spans` and `_capture_spans` in this module, plus 15 detector functions in `anonymizer/detectors.py`: `detect_structured_ids` (115, 133, 139), `detect_contacts` (165, 178), `detect_protocols_and_acts` (237), `detect_challenged_act_numbers` (290), `_detect_dates` (311), `_detect_dou` (362), `_detect_public_services` (382), `_detect_legal_refs` (426), `detect_decision_metadata` (503, 516), `detect_private_companies` (610), `detect_fiscal_device_ids` (675), `detect_table_sensitive_values` (703, 723, 737), `detect_review_candidates` (802), `detect_authority_header` (838), `detect_final_signatory` (887).
- Parameters: `unit` — the `TextUnit` (one paragraph/cell of the DOCX with `unit_id`, `normalized_text`, char map); `start`/`end` — character offsets into `unit.normalized_text`; `category` — the span's category label (e.g. `"AFM"`, one of the `SpanCategory` literals); `detector` — machine name of the detector that produced it (e.g. `"afm_checksum"`); `confidence` — 0-1 score; `action` — `"REDACT"`, `"PRESERVE"`, or `"REVIEW"`; `reason` — human-readable justification.
- Returns: a `Span` dataclass instance with `unit_id`, `start`, `end`, `text` (the slice), and the five labels.
- Steps: single expression — construct `Span(unit_id=unit.unit_id, start=start, end=end, text=unit.normalized_text[start:end], ...)`.
- Side effects: none (does not mutate `unit`).
- On failure: does not raise for out-of-range offsets (Python slicing clamps silently — the `text` would just be shorter than `end - start`); invalid `category`/`action` values are not runtime-checked (`Literal` types are static-only).

**`_regex_spans(unit: TextUnit, regex: str | re.Pattern[str], category: str, detector: str, confidence: float, action: str, reason: str, flags: int = re.IGNORECASE) -> list[Span]`**
- What it does: The workhorse "find all matches, make one span per full match" helper. Runs the given regex over `unit.normalized_text` and builds a `Span` covering each complete match. Accepts either a regex string (compiled here with `flags`, defaulting to case-insensitive) or a precompiled `re.Pattern` (in which case `flags` is ignored — the pattern's own flags apply).
- Called by: `anonymizer/detectors.py` — `detect_contacts` (195), `detect_protocols_and_acts` (256), `_detect_dates` (323), `_detect_legal_refs` (414), `detect_preserve_spans` (450, 461, 472, 483), `detect_review_candidates` (758, 771, 788 — line 771's call passes `flags=0` explicitly because `_GREEK_CAPITALIZED` relies on capitalization as the signal).
- Parameters: `unit` — the text unit to scan; `regex` — pattern string or precompiled pattern; `category`/`detector`/`confidence`/`action`/`reason` — stamped verbatim onto every produced span; `flags` — `re` flags used only when `regex` is a string (default `re.IGNORECASE`).
- Returns: `list[Span]`, one per non-overlapping match in document order (empty list if no matches).
- Steps: (1) `compiled = regex if isinstance(regex, re.Pattern) else re.compile(regex, flags)`; (2) list comprehension over `compiled.finditer(unit.normalized_text)` calling `_make_span(unit, match.start(), match.end(), ...)`.
- Side effects: none.
- On failure: `re.error` if a string pattern is malformed (would propagate up and abort detection); otherwise nothing.

**`_capture_spans(unit: TextUnit, pattern: str | re.Pattern[str], group: int, category: str, detector: str, confidence: float, action: str, reason: str, flags: int = re.IGNORECASE) -> list[Span]`**
- What it does: Like `_regex_spans` but produces one span per **capture group** rather than per full match — used when only part of a match should be redacted (e.g. redact the appellant's name but keep the trigger phrase "προσφυγή του" visible). Matches where the group did not participate (`start/end == -1`) or captured an empty string are skipped, and a `group` index the pattern does not have is tolerated (skipped via `IndexError` catch) instead of crashing.
- Called by: `anonymizer/detectors.py` — `detect_protocols_and_acts` (223), `detect_appellant_identity` (541, 553, 565, 577), `detect_bank_payment_ids` (630, 642), `detect_fiscal_device_ids` (662).
- Parameters: `unit` — the text unit; `pattern` — string or precompiled pattern; `group` — 1-based index of the capture group to turn into a span; remaining five label parameters and `flags` — as in `_regex_spans` (`flags` ignored for precompiled patterns).
- Returns: `list[Span]`, one per match whose selected group captured non-empty text, in document order.
- Steps: (1) compile if needed; (2) for each `finditer` match, read `match.start(group)`/`match.end(group)` inside `try/except IndexError: continue`; (3) keep only `0 <= gs < ge`; (4) `_make_span(unit, gs, ge, ...)` and append.
- Side effects: none.
- On failure: swallows `IndexError` per-match (bad group index silently yields no spans); `re.error` on a malformed string pattern propagates.

**`_valid_afm(value: str) -> bool`**
- What it does: Checksum-validates a candidate Greek tax number (ΑΦΜ/AFM). An AFM is nine digits where the first eight, weighted by descending powers of two (2⁸ down to 2¹), summed, taken mod 11 then mod 10, must equal the ninth digit. This filters out arbitrary 9-digit numbers (amounts, references) so they are not falsely redacted as tax IDs; in `detectors.py`, an invalid checksum downgrades the span to lower confidence/REVIEW rather than discarding it.
- Called by: `anonymizer/detectors.py` — `detect_structured_ids` (line 103).
- Parameters: `value` — the candidate string (should be exactly nine ASCII digits).
- Returns: `bool` — `True` only if length 9, all digits, and the checksum holds.
- Steps: (1) reject wrong length or non-digits; (2) convert to digit list; (3) `total = Σ digits[i] · 2^(8−i)` for i = 0..7; (4) compare `total % 11 % 10` with `digits[8]`.
- Side effects: none.
- On failure: never raises (all invalid inputs return `False`).

**`_valid_amka_birth_date(value: str) -> bool`**
- What it does: Plausibility-checks a candidate Greek social-security number (ΑΜΚΑ/AMKA), whose first six digits encode the holder's birth date as DDMMYY. It reconstructs the full year with a pivot on the current two-digit year (suffix ≤ current year's suffix → 2000s, else 1900s), requires the year to fall between 1900 and today, and requires day/month to form a real calendar date. This weeds out random 11-digit numbers.
- Called by: `anonymizer/detectors.py` — `detect_structured_ids` (line 121).
- Parameters: `value` — the candidate string (should be exactly eleven ASCII digits).
- Returns: `bool` — `True` only if length 11, all digits, and the leading DDMMYY is a real date in [1900, current year].
- Steps: (1) reject wrong length/non-digits; (2) parse day = `value[:2]`, month = `value[2:4]`, year suffix = `value[4:6]`; (3) resolve century against `date.today().year`; (4) range-check the year; (5) attempt `date(year, month, day)` inside `try/except ValueError`; (6) return `True` if it constructs.
- Side effects: reads the system clock via `date.today()` (result varies by run date); otherwise none.
- On failure: never raises (impossible dates are caught and return `False`).

**`_iban_is_valid(value: str) -> bool`**
- What it does: Validates a candidate IBAN (International Bank Account Number). It strips spaces and hyphens, uppercases, then delegates to `python-stdnum`'s `iban.is_valid` when that library is installed (module-level guard); otherwise it runs a self-contained ISO 13616 mod-97 check: verify the `LLDD...` shape, move the first four characters to the end, convert letters to numbers (A=10 … Z=35), and confirm the resulting big number mod 97 equals 1.
- Called by: `anonymizer/detectors.py` — `detect_structured_ids` (line 137).
- Parameters: `value` — the candidate string, possibly containing spaces/hyphens as printed in documents.
- Returns: `bool` — `True` if the (normalized) string is a valid IBAN under whichever validator ran. Note the stdnum path is stricter (checks per-country length/format); the fallback checks only the generic shape and checksum.
- Steps: (1) `re.sub(r"[\s-]+", "", value).upper()`; (2) if `_stdnum_iban_is_valid` is not `None`, return `bool(stdnum result)`; (3) else reject if shorter than 5 chars or not matching `[A-Z]{2}\d{2}[A-Z0-9]+`; (4) rearrange `stripped[4:] + stripped[:4]`; (5) map letters to `ord(ch) − 55`; (6) fold mod 97 digit by digit; (7) return `remainder == 1`.
- Side effects: none.
- On failure: never raises in practice; malformed inputs return `False`. (If `stdnum` itself threw, that would propagate — its `is_valid` is documented not to raise.)

**`_split_serial_date(value: str)`** (no annotations; returns `tuple[str, str] | None`)
- What it does: Splits a combined value like `1234/15-03-2023` (protocol/act serial + issuing date) into its serial part and date part, so the detector can redact only the identifying serial while preserving the date. Returns `None` when the structure is ambiguous — specifically when what precedes the date is empty once separator characters (`/`, `\`, `-`) are stripped, meaning there is no real serial.
- Called by: `anonymizer/detectors.py` — `detect_protocols_and_acts` (line 233) and `detect_challenged_act_numbers` (line 281).
- Parameters: `value` — the raw matched value (stripped of surrounding whitespace internally).
- Returns: `(serial_part, date_part)` — regex groups 1 and 3 of `_DATE_SUFFIX_RE` (the separator, group 2, is dropped) — or `None`.
- Steps: (1) `_DATE_SUFFIX_RE.match(value.strip())`; (2) require the match and a non-empty `group(1).strip("/\\-")`; (3) return `(match.group(1), match.group(3))` else `None`.
- Side effects: none.
- On failure: never raises for string input; `None` is the "cannot split" signal, and callers then treat the whole value as one span.

**`_normalize_header(value: str) -> str`**
- What it does: Canonicalizes a table-column header for comparison: collapses all runs of whitespace to single spaces and lowercases aggressively with `casefold()` (a stronger, locale-robust lowercase suited to Greek final sigma etc.). This lets `"ΑΦΜ "` and `"αφμ"` hit the same key in the header-action map.
- Called by: `anonymizer/detectors.py` — at module import time to build every key of `_TABLE_HEADER_ACTIONS` (line 66), and inside `detect_table_sensitive_values` (line 718) to normalize the current cell's `column_header` before lookup.
- Parameters: `value` — the raw header string (callers pass `str(unit.location.get("column_header", ""))`).
- Returns: the normalized string (possibly `""` for empty/whitespace-only input).
- Steps: (1) `value.split()` — split on any whitespace, dropping empties; (2) `" ".join(...)`; (3) `.casefold()`.
- Side effects: none.
- On failure: never raises for string input (a non-string would raise `AttributeError`, but callers pre-coerce with `str()`).

**Module-level details (not functions but part of the file's behavior):**
- `_stdnum_iban_is_valid` — bound at import time inside `try/except Exception` to `stdnum.iban.is_valid`, or `None` when `python-stdnum` is unavailable; consumed only by `_iban_is_valid`. This is the module's only conditional dependency.
- The 26-name re-export block (lines 25-52) plus `__all__` (lines 235-275, listing all 26 constants and the 11 helpers) exists so `anonymizer.detectors` has a single import source. The comment on lines 21-24 warns that this block must mirror `detector_patterns`' actual names exactly — any name absent there is an `ImportError` at process start (i.e. the whole service fails to boot, loudly, rather than a detector silently missing).

---

## anonymizer/detectors.py — the deterministic (regex/rule-based) detection stage: every pattern detector plus the `detect_all` aggregator

**Purpose:** This module is the first detection stage of the ded-anonymizer pipeline: after `parse_docx` turns the DOCX into `TextUnit`s (one per paragraph, table cell, header, etc.), `detect_all` runs 14 rule-based detectors over the document and produces `Span` objects — a *span* is a labelled character range inside one text unit's `normalized_text`, carrying a category (e.g. `AFM`), a confidence score, and an *action*: `REDACT` (must be blotted out), `PRESERVE` (must stay visible, e.g. laws and dates), or `REVIEW` (uncertain — handed to the LLM stage to adjudicate). The module exists so that everything findable with regexes, checksums, and word lists (gazetteers) is caught deterministically and cheaply before the mandatory two-pass LLM stage; its output feeds both the LLM prompts (deterministic spans become the pass-2 KNOWN SPANS list, review hints are LLM input only) and the character-ownership conflict resolver. All detectors are pure functions: they read text, return span lists, and touch nothing else. It also holds three module-level constants: `_DOU_PREFIX_RE` (matches the "Δ.Ο.Υ."/"ΔΟΥ" tax-office label, case-insensitive), `_DOU_FALLBACK_RE` (a run of capitalized Greek words, built from `_GREEK_CAPITALIZED` at import time), and `_TABLE_HEADER_ACTIONS` (a dict mapping normalized table-column headers like "ΑΦΜ" or "ΦΠΑ" to a `(category, action, confidence, reason)` tuple used for whole-cell decisions).

**Imports:**
- *stdlib:* `re` (all pattern matching), `dataclasses.dataclass` (for `DetectionResult`), `__future__.annotations`.
- *third-party:* none directly (IBAN validation via `python-stdnum` lives in `detector_support`).
- *project:* `anonymizer.config.DetectorRules` (the frozen dataclass carrying regex pattern overrides and the four allowlists: `patterns`, `dou_allowlist`, `public_services`, `legal_refs`, `preserve_email_domains`); `anonymizer.models.DocumentData / Span / TextUnit` (the parsed-document and span data types); and a large block from `anonymizer.detector_support`: accessors and helpers (`_body`/`_prefix` resolve a named regex fragment from `rules.patterns` with fallback to `_DEFAULT_PATTERNS`; `_make_span` builds a `Span`; `_regex_spans` emits one span per full regex match, defaulting to IGNORECASE; `_capture_spans` emits one span per capture group, skipping empty/non-participating groups; `_split_serial_date` splits "serial/date" strings; `_iter_allowlist_matches` yields case-insensitive matches of gazetteer entries longest-first; `_valid_afm`, `_valid_amka_birth_date`, `_iban_is_valid` checksum/date validators; `_normalize_header` collapses whitespace and casefolds), the shared regex fragment `_GREEK_CAPITALIZED` and gazetteer `_MEDICAL_TERMS`, and 20 precompiled contextual regexes (`_CHALLENGED_ACT_RE`, `_APPELLANT_NAME_RE`, `_BANK_ACCOUNT_RE`, `_SIGNATURE_TITLE_RE`, etc. — canonical copies live in `anonymizer.detector_patterns` and are re-exported by `detector_support`).

**Imported by:** `anonymizer/pipeline.py` only (`from anonymizer.detectors import detect_all`, used at pipeline.py:60 inside `anonymize_document`). No other project module imports it; the individual `detect_*` functions have no external callers — they are exported via `__all__` but invoked only by `detect_all` in this same file.

### Functions & classes

**`detect_structured_ids(unit: TextUnit, rules: DetectorRules) -> list[Span]`**
- What it does: Finds the three Greek structured identifiers — AFM (9-digit tax ID), AMKA (11-digit social-security number), and IBAN (bank account number) — in one text unit. Each match is validated (AFM checksum, AMKA embedded birth date, IBAN mod-97 checksum) and the confidence is scaled by whether validation passed and whether a textual label (prefix like "ΑΦΜ:") preceded the digits.
- Called by: `detect_all` (detectors.py:927) only.
- Parameters: `unit` — the text unit to scan (matching runs over `unit.normalized_text`); `rules` — supplies the `afm`/`amka`/`iban` regex bodies and prefixes via `_body`/`_prefix`.
- Returns: `list[Span]`, all with action `REDACT`; categories `AFM`, `AMKA`, `IBAN`.
- Steps: (1) Build the AFM regex as optional prefix + body with digit-lookaround guards `(?<!\d)…(?!\d)`; for each match take capture group 1 as the digits, run `_valid_afm`, and detect prefix presence via `match.start() < match.start(1)`; confidence 1.0 (checksum passed) / 0.75 (label but bad checksum) / 0.4 (shape only). (2) Same for AMKA using `_valid_amka_birth_date`; confidence 0.95 / 0.75 / 0.5. (3) IBAN body between `\b` boundaries; confidence 1.0 if `_iban_is_valid` else 0.3. All spans cover the full match (label included when present).
- Side effects: none (pure).
- On failure: no error handling — a missing pattern name would raise `KeyError` from `_DEFAULT_PATTERNS`, a malformed `rules.patterns` override raises `re.error`, and an override body without a capture group raises `IndexError` at `match.group(1)`; any such exception propagates through `detect_all` and aborts the pipeline's detect stage.

**`detect_contacts(unit: TextUnit, rules: DetectorRules) -> list[Span]`**
- What it does: Finds email addresses and Greek phone numbers. Emails whose domain is on the `preserve_email_domains` allowlist (public-service inboxes) become PRESERVE spans; every other email is REDACT. Phone numbers are never decided here — they are emitted as REVIEW so the LLM can distinguish an official switchboard from a private number.
- Called by: `detect_all` (detectors.py:928) only.
- Parameters: `unit` — text unit to scan; `rules` — supplies the `email`, `phone_intl`, `phone_00`, `phone_local` regex bodies and the `preserve_email_domains` frozenset.
- Returns: `list[Span]`: `PUBLIC_SERVICE`/PRESERVE (0.95) for allowlisted emails, `EMAIL`/REDACT (0.95) otherwise, `PHONE`/REVIEW for phones (0.9 for international `+30`/`0030` forms, 0.7 for local 10-digit forms).
- Steps: (1) Iterate email regex matches; split the matched string on the last `@`, casefold the domain, check membership in `rules.preserve_email_domains`, emit PRESERVE or REDACT accordingly. (2) For each of the three phone pattern names, call `_regex_spans` with digit-lookaround guards and `flags=0` (case-sensitivity irrelevant for digits; explicit to avoid the IGNORECASE default).
- Side effects: none.
- On failure: same propagation as above (`KeyError`/`re.error` from bad rules); nothing is caught locally.

**`detect_protocols_and_acts(unit: TextUnit, rules: DetectorRules) -> list[Span]`**
- What it does: Finds contextual case identifiers — protocol numbers ("αρ. πρωτ. …"), audit orders, act numbers, invoice numbers, and transaction IDs. For the two label-prefixed kinds (protocol, audit order) it redacts only the value (capture group 1), trims off a trailing date so the date stays visible, and when the value is a joined list like "123/456 & 789" emits a separate span per component so separators survive.
- Called by: `detect_all` (detectors.py:931) only.
- Parameters: `unit` — text unit to scan; `rules` — supplies prefix+body fragments for `protocol_number`, `audit_order`, `act_number`, `invoice_number`, `transaction_id`.
- Returns: `list[Span]`, all REDACT at confidence 0.85; categories `PROTOCOL_NUMBER`, `AUDIT_ORDER`, `ACT_NUMBER`, `INVOICE_NUMBER`, `TRANSACTION_ID`.
- Steps: (1) For `protocol_number` and `audit_order`: concatenate `_prefix + _body`, get group-1 spans via `_capture_spans`, run `_split_serial_date` on each value (if it returns `(serial, date)` keep only the serial; if `None` treat the whole value as the serial), then `re.finditer(r"[^/&\s]+", serial)` to emit one span per component, offset back into unit coordinates via `value_span.start + component.start()`. (2) For the other three names: `_regex_spans` over prefix+body, one span per full match.
- Side effects: none.
- On failure: no local handling; bad rule patterns propagate as above.

**`detect_challenged_act_numbers(unit: TextUnit) -> list[Span]`**
- What it does: Finds the number of the *challenged* tax act (the act the taxpayer is appealing) — a standalone serial that must be confirmed by a tax-act context cue (e.g. "πράξη διορθωτικού προσδιορισμού") appearing within the next 100 characters. Only the serial part is redacted; a trailing date inside the same token stays visible.
- Called by: `detect_all` (detectors.py:930) only.
- Parameters: `unit` — text unit to scan. (No `rules`: it uses the precompiled `_CHALLENGED_ACT_RE` / `_CHALLENGED_ACT_CONTEXT_RE`.)
- Returns: `list[Span]` with category `CHALLENGED_ACT_NUMBER`, action REDACT, confidence 0.9.
- Steps: (1) Iterate `_CHALLENGED_ACT_RE` matches. (2) Take the 100-character window after `match.end()`; skip the match unless `_CHALLENGED_ACT_CONTEXT_RE` finds a cue in it. (3) `_split_serial_date` on group 1: if it splits, span covers `match.start(1)` through `start + len(serial)`; otherwise the full group-1 range. (4) Guard `gs < ge` before emitting.
- Side effects: none.
- On failure: raises nothing itself; regexes are precompiled at import, so runtime failure is effectively impossible.

**`_detect_dates(unit: TextUnit, rules: DetectorRules) -> list[Span]`** *(module-private)*
- What it does: Finds numeric dates (e.g. 12/03/2019) and Greek textual dates (e.g. "12 Μαρτίου 2019") and marks them PRESERVE — dates must remain readable in the published decision.
- Called by: `detect_preserve_spans` (detectors.py:445) only.
- Parameters: `unit` — text unit; `rules` — supplies `date_numeric` and `date_greek` bodies.
- Returns: `list[Span]`, category `DATE`, action PRESERVE (0.95 numeric, 0.9 Greek textual).
- Steps: explicit `re.finditer` (IGNORECASE) over `date_numeric` building spans with `_make_span`, then `_regex_spans` for `date_greek` (IGNORECASE default).
- Side effects: none.
- On failure: bad rule patterns propagate; no local handling.

**`_detect_dou(unit: TextUnit, rules: DetectorRules) -> list[Span]`** *(module-private)*
- What it does: Finds tax-office references — "Δ.Ο.Υ." (ΔΟΥ, the local Greek tax office) followed by its name — and marks them PRESERVE, because the handling tax office is public information. It first tries the `dou_allowlist` gazetteer (known office names, longest entry first), and if none matches falls back to grabbing the run of capitalized Greek words after the label at lower confidence.
- Called by: `detect_preserve_spans` (detectors.py:446) only.
- Parameters: `unit` — text unit; `rules` — supplies `dou_allowlist` (frozenset of office names).
- Returns: `list[Span]`, category `DOU`, action PRESERVE, detector name `dou_gazetteer`; confidence 0.95 (gazetteer hit) or 0.7 (capitalized-word fallback). The span covers the label *and* the name (starts at `prefix_match.start()`).
- Steps: (1) Find each `_DOU_PREFIX_RE` occurrence (case-insensitive, so lowercase "δου" also triggers). (2) Against the text after the label, try each allowlist entry longest-first with `re.match(re.escape(entry) + r"\b", …, IGNORECASE)`. (3) If none matched, apply `_DOU_FALLBACK_RE.match` to the suffix; skip the occurrence entirely when that also fails. (4) Emit the span.
- Side effects: none.
- On failure: raises nothing in practice; no local handling.

**`_detect_public_services(unit: TextUnit, rules: DetectorRules) -> list[Span]`** *(module-private)*
- What it does: Marks every occurrence of a known public-service name (ΑΑΔΕ, ΔΕΔ, ministries, etc., from the `public_services` gazetteer) as PRESERVE, since government bodies are not private data.
- Called by: `detect_preserve_spans` (detectors.py:447) only.
- Parameters: `unit` — text unit; `rules` — supplies `public_services`.
- Returns: `list[Span]`, category `PUBLIC_SERVICE`, PRESERVE, confidence 0.9, detector `public_service_gazetteer`.
- Steps: iterate `_iter_allowlist_matches(unit.normalized_text, rules.public_services)` (escaped, IGNORECASE, longest-first) and wrap each match with `_make_span`.
- Side effects: none.
- On failure: raises nothing in practice.

**`_detect_legal_refs(unit: TextUnit, rules: DetectorRules) -> list[Span]`** *(module-private)*
- What it does: Marks legal citations as PRESERVE: laws ("ν. 4174/2013"), presidential decrees, FEK (government gazette) references, POL circulars, StE (Council of State) and NSK (Legal Council) decisions, ΑΑΔΕ decisions, article references, and court-decision numbers — plus any entry from the `legal_refs` abbreviation gazetteer.
- Called by: `detect_preserve_spans` (detectors.py:448) only.
- Parameters: `unit` — text unit; `rules` — supplies the ten pattern bodies (`legal_ref_law`, `legal_ref_pd`, `legal_ref_short`, `legal_ref_fek`, `legal_ref_pol`, `legal_ref_ste`, `legal_ref_nsk`, `legal_ref_aade`, `article_ref`, `court_decision`) and the `legal_refs` gazetteer.
- Returns: `list[Span]`, PRESERVE; categories `LEGAL_REF` (0.9–0.95), `ARTICLE_REF` (0.9), `COURT_DECISION` (0.85); gazetteer hits are `LEGAL_REF` at 0.9 with detector `legal_ref_gazetteer`.
- Steps: loop the ten `(pattern_name, category, confidence)` triples through `_regex_spans`, then add gazetteer matches via `_iter_allowlist_matches`.
- Side effects: none.
- On failure: bad rule patterns propagate; no local handling.

**`detect_preserve_spans(unit: TextUnit, rules: DetectorRules) -> list[Span]`**
- What it does: The umbrella detector for everything that must *stay visible* in one text unit. It delegates to the four private helpers above and then adds four direct patterns: money amounts, tax years, percentages, and fiscal periods. These PRESERVE spans later shield their characters from overlapping REDACT claims in the conflict resolver.
- Called by: `detect_all` (detectors.py:925) only.
- Parameters: `unit` — text unit; `rules` — passed through to helpers and used for the `money`, `tax_year`, `percentage`, `fiscal_period` bodies.
- Returns: `list[Span]`, all PRESERVE: `DATE`, `DOU`, `PUBLIC_SERVICE`, `LEGAL_REF`/`ARTICLE_REF`/`COURT_DECISION`, `MONEY` (0.95), `TAX_YEAR` (0.9), `PERCENTAGE` (0.95), `FISCAL_PERIOD` (0.9).
- Steps: extend with `_detect_dates`, `_detect_dou`, `_detect_public_services`, `_detect_legal_refs` in that order, then four `_regex_spans` calls for the direct patterns.
- Side effects: none.
- On failure: any helper exception propagates unchanged.

**`detect_decision_metadata(unit: TextUnit) -> list[Span]`**
- What it does: Preserves the decision's own bookkeeping — its decision number (e.g. "ΑΠΟΦΑΣΗ … 1234") and the place/date line (e.g. "Καλλιθέα, 12.05.2020") — at near-certain confidence, because these identify the published decision itself, not any private party.
- Called by: `detect_all` (detectors.py:924) only.
- Parameters: `unit` — text unit (uses precompiled `_DECISION_NUMBER_RE` and `_DECISION_PLACE_DATE_RE`; no rules needed).
- Returns: `list[Span]`, category `DECISION_METADATA`, PRESERVE, confidence 0.98, detector `decision_number` or `decision_place_date`.
- Steps: two `finditer` loops over `unit.normalized_text`, one per regex, each match wrapped by `_make_span`.
- Side effects: none.
- On failure: raises nothing in practice.

**`detect_appellant_identity(unit: TextUnit) -> list[Span]`**
- What it does: Finds the appellant's (the taxpayer filing the appeal) identity details using Greek legal phrasing cues: the name after "ενδικοφανή προσφυγή" (the administrative-appeal phrase), the father's name in genitive before "ΑΦΜ"/"κάτοικ", a private address after "κάτοικος"/"οδός", and a business seat after "με έδρα". Only the captured value (group 1) is redacted, never the cue phrase.
- Called by: `detect_all` (detectors.py:933) only.
- Parameters: `unit` — text unit (uses precompiled `_APPELLANT_NAME_RE`, `_FATHER_NAME_RE`, `_PRIVATE_ADDRESS_RE`, `_BUSINESS_SEAT_RE`).
- Returns: `list[Span]`, all REDACT: `APPELLANT_NAME` (0.9), `FATHER_NAME` (0.85), `PRIVATE_ADDRESS` (0.85), `BUSINESS_SEAT` (0.85).
- Steps: four `_capture_spans(unit, <regex>, 1, …)` calls, results concatenated.
- Side effects: none.
- On failure: raises nothing in practice.

**`detect_private_companies(unit: TextUnit, rules: DetectorRules) -> list[Span]`**
- What it does: Finds private company names that follow an explicit context cue (via the precompiled `_COMPANY_NAME_AFTER_CTX` regex) and redacts them — unless the name is, or contains, a known public service, so ΑΑΔΕ-like bodies are never redacted as "companies".
- Called by: `detect_all` (detectors.py:934) only.
- Parameters: `unit` — text unit; `rules` — supplies `public_services` for the skip check.
- Returns: `list[Span]`, category `PRIVATE_COMPANY_NAME`, REDACT, confidence 0.85, detector `company_ctx`.
- Steps: (1) Casefold the public-services gazetteer once into a set. (2) For each regex match, strip group 1; skip if empty, if the casefolded name is exactly in the set, or if any gazetteer entry appears as a substring of the name. (3) Emit a span covering `match.start(1)` through `start + len(stripped_name)` (so leading text isn't included; note the end is computed from the *stripped* length, trimming trailing whitespace off the span).
- Side effects: none.
- On failure: raises nothing in practice.

**`detect_bank_payment_ids(unit: TextUnit) -> list[Span]`**
- What it does: Finds bank account numbers introduced by "λογ."/"λογαριασμό" cues and beneficiary names after "δικαιούχο", redacting only the captured value.
- Called by: `detect_all` (detectors.py:935) only.
- Parameters: `unit` — text unit (uses precompiled `_BANK_ACCOUNT_RE`, `_BENEFICIARY_RE`).
- Returns: `list[Span]`, REDACT: `BANK_ACCOUNT` (0.85, detector `bank_account_ctx`) and `PRIVATE_BENEFICIARY` (0.9, detector `beneficiary_ctx`).
- Steps: two `_capture_spans(…, group=1, …)` calls, concatenated.
- Side effects: none.
- On failure: raises nothing in practice.

**`detect_fiscal_device_ids(unit: TextUnit) -> list[Span]`**
- What it does: Finds fiscal-device identifiers (cash-register / ΦΗΜ serial numbers) two ways: values after an explicit context cue (`_FISCAL_ID_RE`, group 1), and "partial-star" tokens — identifiers already half-masked with asterisks (e.g. "ΑΒ12****34", matched by `_PARTIAL_STAR_RE`) which are redacted in full because the remaining characters still leak information.
- Called by: `detect_all` (detectors.py:936) only.
- Parameters: `unit` — text unit.
- Returns: `list[Span]`, category `FISCAL_DEVICE_ID`, REDACT; detector `fiscal_device_ctx` (0.85) or `partial_star` (0.9).
- Steps: `_capture_spans` for the contextual regex, then a `finditer` loop over `_PARTIAL_STAR_RE` emitting full-match spans.
- Side effects: none.
- On failure: raises nothing in practice.

**`detect_table_sensitive_values(unit: TextUnit) -> list[Span]`**
- What it does: The table-aware detector. For a table cell it looks up the cell's column header in `_TABLE_HEADER_ACTIONS` and, on a hit, emits ONE span covering the whole cell with the mapped category/action/confidence (e.g. an "ΑΦΜ" column cell is wholly REDACTed; a "ΦΠΑ" (VAT) column cell is wholly PRESERVEd; an "Όνομα" (name) column cell becomes REVIEW). Cells with unmapped headers get a shape-based fallback that redacts invoice-like values. For non-cell units (regular paragraphs) it instead finds inline invoice identifiers in running text and redacts just the identifier and its series letter.
- Called by: `detect_all` (detectors.py:938) only.
- Parameters: `unit` — text unit; behavior branches on `unit.unit_type` (`"table_cell"` vs anything else) and reads `unit.location["column_header"]`.
- Returns: `list[Span]`. Paragraph branch: `INVOICE_TABLE_ID`/REDACT (0.85, detector `invoice_inline`). Header-mapped branch: one whole-cell span `(0, len(normalized_text))` with the mapped tuple, detector `table_cell_header` (categories include `AFM`, `PHONE`, `EMAIL`, `POSSIBLE_PERSON`, `POSSIBLE_PRIVATE_LOCATION`, `INVOICE_TABLE_ID`, `MONEY`, `DATE`; actions REDACT/REVIEW/PRESERVE per the map). Fallback branch: `INVOICE_TABLE_ID`/REDACT (0.85, detector `invoice_cell_shape`).
- Steps: (1) If not a table cell: for each `_INVOICE_PARAGRAPH_RE` match, emit one span per non-empty capture group 1 and 2; return. (2) If the cell text is blank, return `[]`. (3) Normalize the `column_header` from `unit.location` with `_normalize_header` and look it up in `_TABLE_HEADER_ACTIONS`; on a hit return the single whole-cell span immediately. (4) Otherwise run `_INVOICE_CELL_RE` over the cell and emit a span per match.
- Side effects: none.
- On failure: raises nothing in practice (`unit.location.get` tolerates a missing header key).

**`detect_review_candidates(unit: TextUnit) -> list[Span]`**
- What it does: Emits deliberately low-confidence REVIEW candidates for the LLM to adjudicate — things that *look like* sensitive data but need judgment: two adjacent capitalized Greek words (possible person name), a capitalized name followed by a legal-form suffix (ΑΕ, Ε.Π.Ε., ΟΕ, ΙΚΕ — possible company), street-like addresses after "οδός"/"Λεωφόρος", and any of the eight medical terms from `_MEDICAL_TERMS`. None of these become redactions on their own; per `detect_all`, REVIEW spans are LLM input only.
- Called by: `detect_all` (detectors.py:940) only.
- Parameters: `unit` — text unit.
- Returns: `list[Span]`, all REVIEW: `POSSIBLE_PERSON` (0.45, `greek_name_shape`), `POSSIBLE_COMPANY` (0.65, `company_suffix`), `POSSIBLE_PRIVATE_LOCATION` (0.6, `street_shape`), `MEDICAL_TERM` (0.5, `medical_term_list`).
- Steps: three `_regex_spans` calls, each explicitly passing `flags=0` so matching is case-*sensitive* (capitalization is the whole signal; the `_regex_spans` IGNORECASE default would match any two Greek words) — the company-suffix pattern ends in `(?!\w)` instead of `\b` so dot-terminated suffixes like "Α.Ε." match before a space or end-of-text; then a nested loop matching each `_MEDICAL_TERMS` entry with `re.escape` + IGNORECASE.
- Side effects: none.
- On failure: raises nothing in practice.

**`detect_authority_header(document: DocumentData) -> list[Span]`**
- What it does: A document-level detector (it sees the whole document, not one unit). It scans the first 30 body paragraphs — the letterhead region naming the issuing authority (Ministry of Finance / ΑΑΔΕ / ΔΕΔ) — and preserves each paragraph containing authority cues, stopping as soon as it hits the decision title. This stops the LLM/redactor from blanking the official header.
- Called by: `detect_all` (detectors.py:920) only.
- Parameters: `document` — the full parsed `DocumentData`; it filters `document.text_units` down to paragraphs whose `part_name == "word/document.xml"` (main body only, excluding headers/footers parts).
- Returns: `list[Span]` covering entire paragraphs `(0, len(normalized_text))`, category `PUBLIC_AUTHORITY_HEADER`, PRESERVE, detector `authority_header`; confidence 1.0 with ≥2 cues, 0.7 with exactly 1 (a "soft preserve" that still outranks a soft REDACT in the resolver).
- Steps: (1) Build the body-paragraph list. (2) For each of the first 30: `break` if `_DECISION_TITLE_RE` matches the stripped text; count `_AUTHORITY_HEADER_CUES.findall` hits; skip on 0 cues; otherwise emit the whole-paragraph span with cue-based confidence.
- Side effects: none.
- On failure: raises nothing in practice.

**`detect_final_signatory(document: DocumentData) -> list[Span]`**
- What it does: A document-level detector that preserves the *official's* name in the signature block: within the last 20% of body paragraphs, it looks for a signature-title line (e.g. "Ο Προϊστάμενος της Διεύθυνσης") and then preserves the first isolated ALL-CAPS name paragraph among the next five — unless a private-party cue (e.g. appellant wording) appears in the surrounding context, in which case that candidate is skipped so a taxpayer's name is never accidentally preserved.
- Called by: `detect_all` (detectors.py:919) only.
- Parameters: `document` — the full `DocumentData`; same body-paragraph filter as `detect_authority_header`.
- Returns: `list[Span]` covering whole candidate paragraphs, category `OFFICIAL_SIGNATORY`, PRESERVE, confidence 0.95, detector `final_signatory`.
- Steps: (1) Filter to body paragraphs; return `[]` if none. (2) `threshold_index = int(len * 0.80)`; slice the tail. (3) For each tail paragraph matching `_SIGNATURE_TITLE_RE`, examine the next five paragraphs as candidates. (4) A candidate must match `_ISOLATED_ALLCAPS_NAME_RE` (whole stripped text); an already-preserved `unit_id` is skipped via `continue`. (5) Build a context string from paragraphs `i-1` through `i+5` (excluding the candidate itself); if `_PRIVATE_PARTY_CUE_RE` matches it, skip that candidate. (6) Otherwise record the `unit_id` in the `preserved` set, emit the span, and `break` out of the candidate loop for this title (one signatory per title line; note the asymmetry — the private-cue skip is a `continue` to the next candidate, the successful preserve is a `break`).
- Side effects: none.
- On failure: raises nothing in practice.

**`class DetectionResult`** *(dataclass)*
- Why it exists: the typed return value of `detect_all`, making the split between the two downstream consumers explicit instead of returning a bare tuple: REDACT/PRESERVE spans go to the conflict resolver (and the LLM pass-2 KNOWN SPANS list), while REVIEW spans are *hints for the LLM only* and never reach the resolver directly (pipeline.py:87 comment confirms this).
- Attributes: `resolver_spans: list[Span]` — every deterministic span whose action is `REDACT` or `PRESERVE`; `review_hints: list[Span]` — every span whose action is `REVIEW`.
- How instances are created: exactly one place — the last line of `detect_all` via keyword arguments. Plain mutable dataclass, no methods, no defaults.
- State changes during execution: none after construction; `anonymize_document` only reads `.resolver_spans` and `.review_hints` (pipeline.py:65-75, 89).

**`detect_all(document: DocumentData, rules: DetectorRules) -> DetectionResult`**
- What it does: The single public entry point of the deterministic stage. Runs the two document-level detectors first, then loops every text unit through the twelve unit-level detectors in a fixed priority-flavored order (hard preserves → structured redacts → case references → identity redacts → table-aware → review candidates last), then splits the combined span list strictly by action — no detector gets special-cased.
- Called by: `anonymize_document` in `anonymizer/pipeline.py` (line 60) — the only caller in the project.
- Parameters: `document` — the parsed `DocumentData` from `parse_docx`; `rules` — the `DetectorRules` loaded from the rules file (`files.rules` in the pipeline), threaded into every rules-aware detector.
- Returns: a `DetectionResult` with `resolver_spans` (REDACT + PRESERVE) and `review_hints` (REVIEW). Original detector ordering is retained within each list.
- Steps: (1) `detect_final_signatory(document)` and `detect_authority_header(document)`. (2) Per unit, in order: `detect_decision_metadata`, `detect_preserve_spans`, `detect_structured_ids`, `detect_contacts`, `detect_challenged_act_numbers`, `detect_protocols_and_acts`, `detect_appellant_identity`, `detect_private_companies`, `detect_bank_payment_ids`, `detect_fiscal_device_ids`, `detect_table_sensitive_values`, `detect_review_candidates`. (3) Two list comprehensions filter `all_spans` by `s.action == "REVIEW"` vs `s.action in ("REDACT", "PRESERVE")`. (4) Construct and return `DetectionResult`.
- Side effects: none — no logging, no I/O, no mutation of `document` or `rules` (the pipeline logs the counts, not this module).
- On failure: it catches nothing; any exception from any detector (typically `KeyError`/`re.error`/`IndexError` caused by a malformed `rules.patterns` override) propagates to `anonymize_document`, aborting the detect stage — the CLI run or API request fails before the LLM stage ever starts.

---

## anonymizer/resolver.py — character-ownership conflict resolver that turns overlapping candidate spans into a final redaction plan

**Purpose:** This module is the pipeline's "resolve" stage — the single final authority on what gets redacted. Upstream stages (the deterministic regex detectors and the two-pass LLM detector) each independently produce candidate spans (a *span* is a labelled slice of a text unit: start/end offsets, category such as AFM, an action of REDACT or PRESERVE, and a confidence score), and those candidates routinely overlap or contradict each other. The resolver settles every conflict at the individual-character level: each character of each text unit is "owned" by at most one span, and a fixed priority ladder plus policy-driven hard-preserve/hard-redact overrides decide which span wins each character. The winning ownership map is converted back into non-overlapping spans and packaged as a `RedactionPlan`, along with warnings for any string that ended up both redacted and preserved in different places. The module also carries a module-level constant `_STRUCTURED_REDACT_CATEGORIES = frozenset({"AFM", "AMKA", "IBAN", "EMAIL"})` — the structured-identifier categories that qualify for the dedicated high-confidence redact tier (tier 5); it is deliberately hard-coded rather than policy-driven.

**Imports:**
- Stdlib: `collections.defaultdict` (grouping candidate spans by text-unit id), `from __future__ import annotations` (postponed annotation evaluation, allowing `Span | None` syntax).
- Project: `anonymizer.config.PolicySettings` (the thresholds and hard-category sets loaded from the policy file), `anonymizer.models.DocumentData`, `RedactionPlan`, `Span` (the pipeline's core dataclasses).
- Third-party: none.

**Imported by:** `anonymizer/pipeline.py` (`from anonymizer.resolver import resolve_redactions`, line 17). No other project module imports it.

### Functions & classes

**`_confidence(span: Span) -> float`**
- What it does: Safely converts a span's `confidence` field to a `float`. If the value is missing (`None`) or not parseable as a number, it returns `0.0` instead of crashing, so malformed confidences simply lose all priority comparisons.
- Called by: `_priority` (line 29), `_is_hard_redact` (line 56), and the sort key inside `resolve_redactions` (line 171). All in this module.
- Parameters: `span` — the candidate span whose confidence is being read.
- Returns: the confidence as a `float`, or `0.0` on failure.
- Steps: (1) attempt `float(span.confidence)`; (2) on `TypeError`/`ValueError`, return `0.0`.
- Side effects: none.
- On failure: cannot fail — the only plausible exceptions are caught and mapped to `0.0`.

**`_length(span: Span) -> int`**
- What it does: Computes the span's character length as `end - start`, clamped so it never goes below 0 (an inverted span reports length 0 rather than a negative number).
- Called by: the sort key inside `resolve_redactions` (line 171). Only caller.
- Parameters: `span` — the span to measure.
- Returns: `int` length, `>= 0`.
- Steps: `max(0, int(span.end) - int(span.start))`.
- Side effects: none.
- On failure: raises `TypeError`/`ValueError` if `start`/`end` are not coercible to `int` (e.g. `None`); that would propagate out of the sort in `resolve_redactions` and abort the pipeline run.

**`_priority(span: Span, policy: PolicySettings) -> int`**
- What it does: Assigns a span to one of the resolver's priority tiers — the ladder that decides which span wins a contested character. Higher number wins. The tiers are: **6** = high-confidence PRESERVE (confidence ≥ `policy.preserve_high_confidence_threshold`); **5** = high-confidence REDACT of a structured identifier (category in `_STRUCTURED_REDACT_CATEGORIES` and confidence ≥ `policy.redact_high_confidence_threshold`); **4** = ordinary REDACT at or above `policy.redact_threshold`; **3** = low-confidence PRESERVE; **0** = everything else (notably a REDACT below `redact_threshold`), which can never claim a character. There is intentionally no tier 2 — the v1 REVIEW tier was deleted in v2.
- Called by: `_incoming_replaces_existing` (lines 66 and 86). Only caller.
- Parameters: `span` — the span being ranked; `policy` — the `PolicySettings` supplying the three confidence thresholds.
- Returns: `int` in `{6, 5, 4, 3, 0}`.
- Steps: (1) coerce confidence via `_confidence`; (2) check the four tier conditions top-down (6, 5, 4, 3); (3) fall through to 0.
- Side effects: none.
- On failure: cannot realistically fail (confidence coercion is safe; the rest is attribute reads and comparisons).

**`_is_hard_preserve(span: Span, policy: PolicySettings) -> bool`**
- What it does: Tests whether a span is a PRESERVE whose category appears in `policy.hard_preserve_categories` — the policy's list of categories that must survive redaction (e.g. institutional boilerplate). Note there is no confidence requirement on this side.
- Called by: `_incoming_replaces_existing` (lines 74–75). Only caller.
- Parameters: `span` — the span to test; `policy` — supplies `hard_preserve_categories` (a `frozenset[str]`).
- Returns: `bool`.
- Steps: single boolean expression: `action == "PRESERVE" and category in policy.hard_preserve_categories`.
- Side effects: none.
- On failure: cannot fail.

**`_is_hard_redact(span: Span, policy: PolicySettings) -> bool`**
- What it does: Tests whether a span is a REDACT whose category appears in `policy.hard_redact_categories` **and** whose confidence is at or above `policy.redact_high_confidence_threshold`. Unlike hard-preserve, hard-redact status must be earned with high confidence.
- Called by: `_incoming_replaces_existing` (lines 72–73). Only caller.
- Parameters: `span` — the span to test; `policy` — supplies `hard_redact_categories` and `redact_high_confidence_threshold`.
- Returns: `bool`.
- Steps: single boolean expression combining action, category membership, and `_confidence(span) >= threshold`.
- Side effects: none.
- On failure: cannot fail.

**`_incoming_replaces_existing(incoming: Span, existing: Span | None, policy: PolicySettings) -> bool`**
- What it does: The per-character arbitration rule — decides whether the `incoming` candidate span should take ownership of a character position away from the current owner (`existing`, possibly `None` if unowned). It first requires the incoming span to have a positive priority at all, then applies four hard-override rules before falling back to a plain "higher tier wins" comparison. On an exact priority tie the existing owner keeps the character (strict `>`).
- Called by: `resolve_redactions` (line 181), inside the per-character loop. Only caller.
- Parameters: `incoming` — the candidate span currently being painted onto the ownership array; `existing` — the span that currently owns this character, or `None`; `policy` — thresholds and hard-category sets.
- Returns: `True` if the incoming span wins the character, `False` if the existing owner keeps it.
- Steps in order: (1) if `_priority(incoming) <= 0`, return `False` (tier-0 spans never claim anything); (2) if the character is unowned, return `True`; (3) compute the four hard flags for both spans; (4) hard-redact incoming beats hard-preserve existing → `True`; (5) hard-redact existing beats hard-preserve incoming → `False`; (6) hard-preserve incoming beats a non-hard REDACT existing → `True`; (7) hard-preserve existing blocks a non-hard REDACT incoming → `False`; (8) otherwise `incoming_priority > _priority(existing)`.
- Side effects: none.
- On failure: cannot realistically fail.

**`_make_span_from_run(source: Span, start: int, end: int, text: str) -> Span`**
- What it does: Constructs a brand-new `Span` covering `[start, end)` with the given text, copying every other field (`unit_id`, `category`, `detector`, `confidence`, `action`, `reason`) from the `source` span. Needed because character-level arbitration can slice a winning span into shorter runs whose offsets and text no longer match the original.
- Called by: `_recover_spans_from_owners` (line 121). Only caller.
- Parameters: `source` — the owning span whose metadata is copied; `start`/`end` — the run's offsets in the unit's normalized text; `text` — the exact substring of normalized text for that run.
- Returns: a new `Span` dataclass instance.
- Steps: one `Span(...)` constructor call.
- Side effects: none (the source span is not mutated).
- On failure: cannot fail.

**`_recover_spans_from_owners(normalized_text: str, owners: list[Span | None]) -> list[Span]`**
- What it does: Walks the per-character `owners` array (one entry per character of the unit's normalized text) and collapses each maximal run of characters owned by *the same span object* (identity comparison, `is`) back into a single contiguous span. Unowned characters (`None`) are skipped. This is the inverse of the "painting" step: it converts the ownership map back into a clean, non-overlapping span list in left-to-right text order.
- Called by: `resolve_redactions` (line 184). Only caller.
- Parameters: `normalized_text` — the unit's normalized text, used to slice out each run's exact substring; `owners` — the ownership array, same length as `normalized_text`.
- Returns: `list[Span]` — one new span per run, ordered by start offset. A span that was split by a competitor produces multiple output spans.
- Steps: (1) scan index `i` across the array; (2) skip `None` entries; (3) on a non-`None` owner, advance while `owners[i] is owner` to find the run's end; (4) build a span via `_make_span_from_run` with `normalized_text[start:end]`; (5) append and continue.
- Side effects: none.
- On failure: cannot realistically fail given the array is built the same length as the text (which `resolve_redactions` guarantees).

**`_consistency_sweep(resolved_spans_by_unit: dict[str, list[Span]]) -> list[str]`**
- What it does: A document-wide sanity check run after resolution. It collects the casefolded text of every resolved REDACT span and every resolved PRESERVE span, intersects the two sets, and emits one human-readable warning per string that was treated both ways somewhere in the document (e.g. a name redacted in one paragraph but preserved in another). It does not change the plan — it only warns.
- Called by: `resolve_redactions` (line 186). Only caller.
- Parameters: `resolved_spans_by_unit` — mapping from unit id to that unit's resolved spans.
- Returns: `list[str]` of warning messages (sorted by the offending string), empty when consistent. Note the warnings embed the conflicting string itself (`{s!r}`) — these become `RedactionPlan.warnings` and flow into the summary/API response.
- Steps: (1) bucket span texts (casefolded) into `redacted_strings` / `preserved_strings` sets; (2) intersect; (3) format one message per string in sorted order.
- Side effects: none.
- On failure: cannot fail.

**`resolve_redactions(document: DocumentData, candidate_spans: list[Span], policy: PolicySettings) -> RedactionPlan`**
- What it does: The module's only public function and the pipeline's resolve stage. Given the parsed document and the combined candidate spans from both detectors, it performs character-ownership arbitration independently for each text unit and returns the final, non-overlapping `RedactionPlan`. It begins with an invariant guard: any span whose action is not REDACT or PRESERVE (i.e. a leaked REVIEW span) triggers an immediate `RuntimeError`, because review hints are LLM input only and must never reach the resolver.
- Called by: `anonymizer/pipeline.py:89` — `plan = resolve_redactions(document, llm_spans + detection.resolver_spans, files.policy)`. Only caller in the project.
- Parameters: `document` — the parsed `DocumentData` whose `text_units` define the coordinate space (offsets are into each unit's `normalized_text`); `candidate_spans` — all candidate spans from the LLM and deterministic detectors, possibly overlapping/contradictory; `policy` — the `PolicySettings` (three thresholds plus hard-preserve/hard-redact category sets) loaded from the policy file.
- Returns: a `RedactionPlan` with `document_id=document.document_id`, `spans` = all resolved spans across all units sorted by `(unit_id, start)` (each guaranteed REDACT or PRESERVE, non-overlapping within a unit), and `warnings` = the consistency-sweep messages.
- Steps in order: (1) invariant guard — raise on any non-REDACT/PRESERVE action; (2) group candidates by `unit_id` into a `defaultdict(list)`; (3) for each text unit: allocate an `owners` array of `None` with one slot per character of `normalized_text`; (4) sort that unit's candidates by `(start asc, length desc, confidence desc)` — a deterministic processing order so longer, more confident spans are painted first at equal starts; (5) for each candidate, clamp `start`/`end` into `[0, len(text)]` and skip empty/inverted spans; (6) for each character index in the clamped range, ask `_incoming_replaces_existing` and overwrite the owner if it wins; (7) rebuild the unit's span list via `_recover_spans_from_owners`; (8) after all units, run `_consistency_sweep` for warnings; (9) flatten, sort by `(unit_id, start)`, and return the `RedactionPlan`.
- Side effects: none — pure computation; no logging, no I/O, and neither `document` nor the input spans are mutated (winning spans that get sliced are re-created, not edited).
- On failure: raises `RuntimeError("REVIEW span reached the resolver — programming bug")` if the invariant is violated; a `TypeError`/`ValueError` could propagate from the sort key if a span carries non-numeric `start`/`end`. Any exception propagates uncaught to `anonymize_document`, which also catches nothing, so the whole request/CLI run for that document fails.

## anonymizer/summary.py — counts-only summary builder for a resolved redaction plan

**Purpose:** A deliberately tiny privacy boundary. After resolution, the pipeline must report *what happened* without leaking *what was found*: this module condenses a `RedactionPlan` into a `PlanSummary` containing only aggregate counts (total spans, and per-action / per-category / per-detector tallies) plus the plan's own warning strings. No span text, character offsets, or unit ids ever appear in the summary — this is what makes the service's output "counts-only" as promised by both the CLI's `--summary-json` output and the API's `?summary=1` JSON response.

**Imports:**
- Stdlib: `collections` (for `collections.Counter`, which does the tallying).
- Project: `anonymizer.models.PlanSummary`, `RedactionPlan` (input and output dataclasses).
- Third-party: none.

**Imported by:** `anonymizer/pipeline.py` (`from anonymizer.summary import build_summary`, line 18). No other project module imports it.

### Functions & classes

**`build_summary(plan: RedactionPlan) -> PlanSummary`**
- What it does: Turns a resolved redaction plan into an aggregate-counts summary. It counts how many spans exist in total, then tallies them three ways — by `action` (REDACT/PRESERVE), by `category` (AFM, EMAIL, DATE, ...), and by `detector` (which detection stage produced the span) — and copies across the plan's warnings. It carries no span text, offsets, or unit ids, only counts and the warnings list.
- Called by: `anonymizer/pipeline.py:117` (`summary=build_summary(plan)` inside `anonymize_document`). Only caller in the project.
- Parameters: `plan` — the final `RedactionPlan` produced by `resolve_redactions`.
- Returns: a `PlanSummary` dataclass with `spans_total: int`, `by_action: dict[str, int]`, `by_category: dict[str, int]`, `by_detector: dict[str, int]`, and `warnings: list[str]` (a fresh list copy of `plan.warnings`). Downstream, this dataclass is serialized with `dataclasses.asdict` by both the CLI (`run_anonymizer.py:248`) and the API (`anonymizer/api.py:98`).
- Steps: one `PlanSummary(...)` construction — `len(plan.spans)` for the total; three `collections.Counter` generator passes converted to plain `dict`s; `list(plan.warnings)` for a defensive copy.
- Side effects: none (the plan is not mutated; warnings are copied, not aliased).
- On failure: cannot realistically fail on a well-formed `RedactionPlan`; there is no error handling, so any exception (e.g. from a malformed plan object) would propagate to `anonymize_document` and abort the run. One caveat worth knowing: the warnings copied here originate from the resolver's consistency sweep, which quotes the conflicting string — so warnings, unlike counts, can contain document text.

## anonymizer/pipeline.py — transport-neutral orchestrator running parse → detect → llm → resolve → apply

**Purpose:** This is the heart of the service: a single function that takes raw DOCX bytes in and returns redacted DOCX bytes plus a counts-only summary. It is *transport-neutral* — it knows nothing about HTTP or the command line — so both entry points (the removable CLI `run_anonymizer.py` and the FastAPI app `anonymizer/api.py`) call the exact same code. It wires the five pipeline stages together in order, times each one with `time.perf_counter`, logs a one-line structured progress message per stage, enforces the "no non-final action in the plan" invariant, and deliberately catches nothing so every failure surfaces to the caller with full context. The out-of-band postcheck audit is *not* part of this function — it lives in `anonymizer/postcheck.py` and is only invoked by the CLI's `--qa` flag.

**Imports:**
- Stdlib: `logging` (module logger for stage progress lines), `time` (`perf_counter` stage timing), `uuid` (auto-generating a document id when the caller supplies none), `typing.Any` (type of the duck-typed LLM client), `from __future__ import annotations` (allows `str | None` syntax on older interpreters).
- Project: `anonymizer.config` — `FileConfig`, `RuntimeConfig` (typed configuration objects); `anonymizer.detectors.detect_all` (deterministic regex detection stage); `anonymizer.docx_engine` — `parse_docx`, `validate_docx_bytes`, `write_redacted_docx` (DOCX parsing, validation, and byte-verbatim redaction write-back); `anonymizer.llm.detector.run_llm_detection` (the mandatory two-pass LLM stage); `anonymizer.models.AnonymizeResult` (the return dataclass); `anonymizer.resolver.resolve_redactions` (conflict resolution); `anonymizer.summary.build_summary` (counts-only summary).
- Third-party: none.

**Imported by:** `run_anonymizer.py` (`from anonymizer.pipeline import anonymize_document`, line 48) and `anonymizer/api.py` (same import, line 22). No other project module imports it. The module also defines the constant `_FINAL_ACTIONS = {"REDACT", "PRESERVE"}` used by the invariant check, and a module-level `logger = logging.getLogger(__name__)` whose name (`anonymizer.pipeline`) the CLI explicitly attaches a console handler to (`run_anonymizer.py:177`).

### Functions & classes

**`anonymize_document(docx_bytes: bytes, *, config: RuntimeConfig, files: FileConfig, client: Any, document_id: str | None = None) -> AnonymizeResult`**
- What it does: Runs the entire anonymization pipeline over one document's raw bytes: validate and parse the DOCX into text units, run deterministic regex detection, run the mandatory two-pass LLM detection (pass 1 blind, pass 2 informed validation over the known-spans list), merge both span sources through the character-ownership resolver, then write the redactions back into the original bytes verbatim (dot glyph) and validate the output. Each stage is individually timed and logged with the document id and a size metric. All keyword arguments after `docx_bytes` are keyword-only (the `*` in the signature).
- Called by: `run_anonymizer.py:225` (inside the CLI's per-file loop in `main`) and `anonymizer/api.py:81` (inside the FastAPI `POST /anonymize` handler). Verified by grep; no other callers.
- Parameters: `docx_bytes` — the original DOCX file as raw bytes; `config` — `RuntimeConfig` (provider/model settings, `llm_timeout_s`, `chunk_size_chars`, `llm_concurrency`, etc.), consumed by the LLM stage and by the result's `model` field; `files` — `FileConfig` bundling `rules` (a `DetectorRules` object feeding `detect_all`) and `policy` (a `PolicySettings` object feeding `resolve_redactions`); `client` — the already-built LLM client (typed `Any` because it is duck-typed; the pipeline never constructs it, callers build it via `anonymizer.llm.client.build_client` or supply a mock); `document_id` — optional stable identifier for logs and the result; when `None`, a fresh 12-hex-character id is generated from `uuid.uuid4().hex[:12]`.
- Returns: an `AnonymizeResult` dataclass with `document_id: str`, `redacted_docx: bytes` (the redacted file), `summary: PlanSummary` (counts only), `warnings: list[str]` (a copy of the plan's consistency warnings — duplicated here at top level in addition to living inside `summary.warnings`), `model: str` (`config.model_handle` — the OpenAI model name or Azure deployment name actually used), and `timings: dict[str, float]` with keys `"parse"`, `"detect"`, `"llm"`, `"resolve"`, `"apply"`, `"total"` (seconds).
- Steps in order: (1) default `document_id` via `uuid` if absent; (2) start the total timer; (3) **parse** — `validate_docx_bytes(docx_bytes)` then `document = parse_docx(docx_bytes, document_id)`; log unit count; (4) **detect** — `detection = detect_all(document, files.rules)`; log counts of `detection.resolver_spans` (final-action REDACT/PRESERVE candidates) and `detection.review_hints` (REVIEW-action hints); (5) **llm** — `llm_spans = run_llm_detection(document, deterministic_spans=detection.resolver_spans, review_hints=detection.review_hints, client=client, cfg=config)`; the deterministic spans and review hints are LLM *input* (the known-spans context for pass 2); log the LLM span count; (6) **resolve** — `plan = resolve_redactions(document, llm_spans + detection.resolver_spans, files.policy)`; note the deterministic `resolver_spans` travel both paths (into the LLM as context *and* directly into the resolver), so the LLM can never suppress a deterministic detection, while `review_hints` never reach the resolver; (7) **invariant 1** — if any plan span's action is outside `_FINAL_ACTIONS`, raise `RuntimeError("plan contains a non-final action — programming bug")`; (8) **apply** — `redacted = write_redacted_docx(docx_bytes, document, plan)` followed by `validate_docx_bytes(redacted)` to prove the output is still a valid DOCX; (9) record `timings["total"]` and assemble the `AnonymizeResult` (calling `build_summary(plan)` for the summary).
- Side effects: logging only — one `logger.info` line per stage (`stage=... document_id=... elapsed=...`) on the `anonymizer.pipeline` logger, containing counts and sizes but never document text. No file, network, or `os.environ` access of its own (network I/O happens inside `run_llm_detection` via the passed-in client, on a thread pool of `cfg.llm_concurrency` workers). `docx_bytes` is never mutated; `write_redacted_docx` produces new bytes.
- On failure: by design it catches nothing — the docstring states every callee exception propagates, and the only exception the function itself raises is the invariant-1 `RuntimeError` (line 92). So a corrupt upload fails in `validate_docx_bytes`/`parse_docx`, LLM/provider errors bubble up from `run_llm_detection`, and so on. Downstream, the CLI catches exceptions per-file at `run_anonymizer.py::main` (one failed document does not stop the batch), and the API layer maps typed exceptions to HTTP status codes (400/422/502/503/504, with a fixed 500 fallback). On any failure, no redacted output is produced for that document — there is no partial-result path.

---

# LLM module group documentation

## anonymizer/llm/client.py — LLM client factory (OpenAI vs Azure OpenAI)

**Purpose:** The smallest file in the LLM package: a single factory function that turns the runtime configuration into a ready-to-use LLM client object. It exists so that the choice of provider (plain OpenAI vs Azure OpenAI, which use different constructors and credentials) is decided in exactly one place, and so both entry points (the CLI and the FastAPI service) build the client identically. The client it returns is what the detection engine later uses to make chat-completion calls; the rest of the pipeline never looks at provider details again — it just receives an object with a `.chat.completions.create(...)` method.

**Imports:**
- *Third-party:* `openai` — provides the `openai.OpenAI` and `openai.AzureOpenAI` client classes.
- *Project:* `anonymizer.config.RuntimeConfig` — the frozen configuration dataclass whose fields (`provider`, `openai_api_key`, `azure_api_key`, `azure_endpoint`, `azure_api_version`, `llm_timeout_s`) drive which client is built and how.

**Imported by:**
- `run_anonymizer.py` (line 47) — the CLI entry point.
- `anonymizer/api.py` (line 21) — the FastAPI entry point.
No other project module imports it.

### Functions & classes

**`build_client(cfg: RuntimeConfig) -> "openai.OpenAI | openai.AzureOpenAI"`**
- What it does: Builds and returns the LLM client for whichever provider the configuration selected. If `cfg.provider == "openai"` it returns a standard `openai.OpenAI` client keyed by `cfg.openai_api_key`; for anything else (in practice `"azure"`, the only other value `load_config` allows) it returns an `openai.AzureOpenAI` client built from the Azure key, endpoint, and API version. Both clients get the same per-call timeout, `cfg.llm_timeout_s` (default 60.0 seconds).
- Called by: `run_anonymizer.py:214` (inside the CLI `main`, once per run before processing documents) and `anonymizer/api.py:31` (once at app startup). Not called anywhere inside the `anonymizer` package itself — the built client is passed *into* the pipeline as an argument.
- Parameters: `cfg` — the `RuntimeConfig` produced by `anonymizer.config.load_config`, carrying provider selection, credentials, and the timeout.
- Returns: an SDK client instance — `openai.OpenAI` or `openai.AzureOpenAI`. Note the return annotation is a string ("forward reference"), which is just a typing convenience; at runtime it is a real client object.
- Steps: (1) check `cfg.provider`; (2) if `"openai"`, construct `openai.OpenAI(api_key=..., timeout=...)`; (3) otherwise construct `openai.AzureOpenAI(api_key=..., azure_endpoint=..., api_version=..., timeout=...)`.
- Side effects: none of its own. Constructing the client does not make a network call; the SDK may read `os.environ` for unset options, but this code writes nothing.
- On failure: it has no error handling of its own. If a required credential were `None` the SDK constructor would raise (e.g. `openai.OpenAIError` for a missing API key); in practice `load_config` has already validated that the selected provider's variables exist, so this is not reached. Any such exception would propagate to the caller (the CLI's error handler or the API startup).

---

## anonymizer/llm/prompts.py — system prompts and user-message builders for the two LLM passes

**Purpose:** This file is the "prompt layer": it owns all the text that gets sent to the LLM, and nothing else. It defines the shared instruction core (what to redact, what to preserve, the JSON output schema, the table-handling rules), the two pass-specific system prompts (a *system prompt* is the standing instruction message that frames every LLM call), and the two functions that build the per-chunk *user messages* (the message carrying the actual document excerpt). Keeping prompts here, separate from the calling logic in `detector.py`, means the wording can be tuned without touching the engine, and building both prompts from one `_PROMPT_CORE` guarantees pass 1 and pass 2 can never drift apart on categories or output format.

**Imports:**
- *Stdlib:* `json` — used only to serialize the known-spans list into the pass-2 user message (`ensure_ascii=False` keeps Greek text readable rather than escaped).
- No third-party or project imports.

**Imported by:**
- `anonymizer/llm/detector.py` (lines 34–39) — imports `SYSTEM_PROMPT_PASS1`, `SYSTEM_PROMPT_PASS2`, `build_pass1_message`, `build_pass2_message`. This is the only importer in the project.

### Functions & classes

*Module-level constants (no top-level classes exist in this file):*
- **`_PROMPT_CORE`** (private `str`) — the shared instruction block used by both passes. It declares the assistant's role (GDPR anonymization for Greek administrative/legal documents), lists every REDACT category (names, ΑΦΜ/AFM tax IDs, AMKA, IBANs, emails, private phone numbers, private addresses, case/act reference numbers, invoice-table identifiers, etc.), every PRESERVE category (public institutions, law citations, official dates/amounts, authority contact headers, official signatories, percentages, fiscal periods), the "err toward REDACT when uncertain" rule with the phone/name context exception, the exact JSON-array output schema (`{"text", "action", "category"}` with the full closed list of category names), the rule that `REVIEW` is not a legal output action, and special per-column rules for excerpts rendered as tables.
- **`SYSTEM_PROMPT_PASS1`** (`str`) — `_PROMPT_CORE` plus a tail declaring "THIS IS PASS 1 — A BLIND READING": the model gets only the raw excerpt, no suggestions or prior spans, and must propose everything from scratch.
- **`SYSTEM_PROMPT_PASS2`** (`str`) — `_PROMPT_CORE` plus a tail declaring "THIS IS PASS 2 — INFORMED VALIDATION": the user message will include a KNOWN SPANS block (deterministic detections plus the model's own pass-1 proposals), and the model must CONFIRM, CORRECT, DECIDE every `REVIEW` entry, ADD missing spans, or DROP entries via `SKIP`, emitting a final decision for every entry.

**`build_pass1_message(chunk_text: str) -> str`**
- What it does: Builds the user message for the blind first pass. It is deliberately minimal — the excerpt and nothing else — so pass 1 stays truly blind (no hints from the deterministic regex detectors can leak in).
- Called by: `anonymizer/llm/detector.py:484`, inside `_process_chunk` within `run_llm_detection`. Only caller.
- Parameters: `chunk_text` — the chunk's rendered text (the `Chunk.text` property output: newline-joined paragraphs, or a `TABLE:` header plus pipe-joined rows).
- Returns: a single string: `"DOCUMENT EXCERPT:\n"` followed by the chunk text.
- Steps: one string concatenation.
- Side effects: none.
- On failure: cannot realistically fail (pure string operation); a non-string argument would raise `TypeError` at the concatenation.

**`build_pass2_message(chunk_text: str, known_spans: list[dict]) -> str`**
- What it does: Builds the user message for the informed second pass: the same excerpt, followed by a `KNOWN SPANS` block containing one JSON array of everything already known about this chunk. The inline label reminds the model these are context, not binding, and that it must emit a final decision for every entry.
- Called by: `anonymizer/llm/detector.py:504`, inside `_process_chunk` within `run_llm_detection`. Only caller.
- Parameters: `chunk_text` — the same rendered chunk text as pass 1; `known_spans` — a uniform list of dicts, each shaped `{"text", "category", "action", "context"}`, mixing deterministic detections, deterministic review hints, and located pass-1 proposals.
- Returns: a single string: `DOCUMENT EXCERPT:` + chunk text + blank line + the `KNOWN SPANS (...)` header + `json.dumps(known_spans, ensure_ascii=False)`.
- Steps: (1) format the excerpt section; (2) serialize `known_spans` to JSON with Greek characters unescaped; (3) join into one f-string.
- Side effects: none.
- On failure: `json.dumps` would raise `TypeError` if a non-serializable object were in `known_spans`; in practice the detector only ever passes plain str-valued dicts.

---

## anonymizer/llm/detector.py — the two-pass LLM detection engine (chunking, provider calls, parsing, span location)

**Purpose:** This is the heart of the LLM stage — the third stage of the pipeline, after DOCX parsing and deterministic regex detection. It splits the parsed document into *chunks* (LLM-sized work items: each table whole, then runs of paragraphs up to `cfg.chunk_size_chars`), and for each chunk runs two LLM calls: pass 1 reads the text blind and proposes candidates; pass 2 re-reads the text alongside a KNOWN SPANS list (deterministic detections + review hints + the pass-1 proposals) and must confirm, correct, or add. Only pass-2 output is turned into `Span` objects (a *span* is a located piece of text: unit id + start/end character offsets + category + action); pass-1 findings are advisory context only. Chunks run concurrently on a thread pool of `cfg.llm_concurrency` workers, and the LLM stage is mandatory — any provider failure aborts the whole run rather than degrading.

**Imports:**
- *Stdlib:* `json` (parsing model output), `logging` (progress and warning logs), `re` (the bracketed-array fallback when output isn't clean JSON), `time` (per-chunk timing logs), `concurrent.futures.ThreadPoolExecutor` (concurrent chunk processing), `dataclasses.dataclass` (the `Chunk` class), `typing.Any` (the duck-typed `client` parameter), plus `from __future__ import annotations` (lazy type annotations).
- *Third-party:* `openai` — imported **only for its exception types** (`APITimeoutError`, `APIConnectionError`, `APIStatusError`, `OpenAIError`) used to translate SDK errors; the client object itself is duck-typed.
- *Project:* `anonymizer.config.RuntimeConfig` (chunk size, model handle, token limit, concurrency, timeout); `anonymizer.errors` (`AIProviderError`, `AITimeoutError`, `AIUnavailableError` — the typed errors the rest of the app maps to exit codes / HTTP statuses); `anonymizer.llm.prompts` (the two system prompts and two message builders); `anonymizer.models` (`ALL_CATEGORIES` — the closed category set, `DocumentData`, `Span`, `TextUnit`).

**Imported by:**
- `anonymizer/pipeline.py` (line 15) — imports `run_llm_detection`; this is the only project module that imports from this file.
- `run_anonymizer.py` references the string `"anonymizer.llm.detector"` at line 177 only to set that logger's level to INFO for CLI progress output — it is not an import.

*Module-level constants:*
- **`_CATEGORY_ALIASES`** (`dict[str, str]`) — maps common model category improvisations back onto the official schema (e.g. `"PERSON"` → `"POSSIBLE_PERSON"`, `"TAXPAYER"`/`"APPELLANT"` → `"APPELLANT_NAME"`, `"BANK"` → `"BANK_ACCOUNT"`). Copied verbatim from the task spec; a code comment forbids editing it without a matching schema change. Used by both parsers.
- **`_CONTEXT_WINDOW`** (`int`, 40) — how many characters of surrounding text to include on each side of a known span when building pass-2 context snippets.

### Functions & classes

**`class Chunk`** (dataclass)
- Why it exists: one LLM work item. The model can't be sent the whole document at once, so the document is cut into pieces; `Chunk` bundles the `TextUnit`s of one piece together with how to render them as prompt text, and remembers whether the piece is a table (tables get special rendering and prompt rules).
- Attributes: `units: list[TextUnit]` — the parsed text units (paragraphs or table cells) in this chunk; `is_table: bool` — True when the chunk is one whole table; `table_index: int | None` (default `None`) — the table's index within its document part, set only for table chunks.
- How instances are created: only by `split_into_chunks` (three construction sites: one per table, one when a paragraph chunk fills up, one for the trailing paragraph chunk).
- How state changes: it doesn't — after construction a `Chunk` is read-only in practice; the two properties are computed on access.
- **`unit_ids` (property) -> set[str]`** — returns `{u.unit_id for u in self.units}`; used by `run_llm_detection._process_chunk` to filter the document-wide deterministic spans and review hints down to this chunk. No side effects.
- **`text` (property) -> str`** — renders the chunk as the text actually sent to the model. For a table: groups units by `int(unit.location["row_index"])`, sorts each row's cells by `int(unit.location["col_index"])`, and emits a `"TABLE:"` header line followed by one `" | "`-joined line per row (rows in ascending row-index order). For paragraphs: newline-joins each unit's `normalized_text`. Called via `chunk.text` in `_process_chunk` (both message builders). Raises `KeyError`/`ValueError` if a table cell's `location` dict lacked numeric `row_index`/`col_index` (the parser always sets them). No side effects.

**`split_into_chunks(document: DocumentData, chunk_size_chars: int) -> list[Chunk]`**
- What it does: Cuts the parsed document into the list of chunks the LLM will see. Tables come first — each table is one chunk no matter how big, so the model always sees a table whole with its header row. Then all non-table units with non-empty `normalized_text` are accumulated in document order into paragraph chunks whose joined length (units plus one newline between each) stays within `chunk_size_chars`; a single unit longer than the limit becomes its own oversized chunk, and a unit is never split across chunks.
- Called by: `run_llm_detection` (detector.py:468). Only caller in the project.
- Parameters: `document` — the `DocumentData` from the parse stage (its `text_units` list drives everything); `chunk_size_chars` — the character budget per paragraph chunk (`cfg.chunk_size_chars`, default 3000).
- Returns: `list[Chunk]` — all table chunks (first-seen order, keyed by `(part_name, table_index)`), then all paragraph chunks in document order.
- Steps: (1) walk `document.text_units`, grouping `unit_type == "table_cell"` units by `(part_name, int(location["table_index"]))` while recording first-seen key order; (2) emit one `Chunk(is_table=True, table_index=...)` per group in that order; (3) walk the units again, skipping table cells and units with empty `normalized_text`, accumulating a `current` list and running length `current_len`; when adding the next unit (plus a joining newline) would exceed `chunk_size_chars` and `current` is non-empty, flush `current` as a paragraph chunk and start fresh; (4) flush any trailing `current`.
- Side effects: none (builds new lists; does not mutate `document`).
- On failure: no error handling of its own; a malformed `location` dict would raise `KeyError`/`ValueError`, propagating out of `run_llm_detection` and aborting the pipeline run.

**`_extract_json_array(raw: str) -> list | None`**
- What it does: The shared two-step JSON extractor for model output. First tries `json.loads` on the raw completion; if that fails, falls back to regex-grabbing the outermost `[...]` block (`r"\[.*\]"` with `re.DOTALL`, greedy, so it spans from the first `[` to the last `]`) and parsing that — this rescues completions where the model wrapped the array in prose or a markdown fence. Anything that still fails, or parses to a non-list, yields `None`; the caller decides whether `None` is lenient (pass 1: empty findings) or fatal (pass 2: error).
- Called by: `parse_pass1_findings` (detector.py:208) and `parse_pass2_spans` (detector.py:250). No other callers.
- Parameters: `raw` — the raw text content of one LLM completion.
- Returns: the parsed `list`, or `None` on unparseable/non-list output.
- Steps: (1) `json.loads(raw)`; (2) on `JSONDecodeError`, `re.search` for a bracketed block over `raw or ""` (guarding a `None`-ish input); (3) `json.loads` the match; (4) reject non-list results.
- Side effects: none.
- On failure: never raises — all `json.JSONDecodeError`s are caught and converted to `None`.

**`parse_pass1_findings(raw: str) -> list[dict]`**
- What it does: Parses pass-1 output *leniently* into advisory findings — plain dicts, never `Span` objects. The design intent: a broken pass 1 should degrade to a blind pass 2 rather than kill the run, because pass-1 findings are only context for pass 2. Entries are cleaned and filtered: blank text dropped, `SKIP` dropped silently, unknown actions dropped, categories alias-normalized via `_CATEGORY_ALIASES` and rejected if not in `ALL_CATEGORIES`.
- Called by: `run_llm_detection._process_chunk` (detector.py:487). Only caller.
- Parameters: `raw` — the pass-1 completion text.
- Returns: `list[dict]`, each dict having exactly the keys `text` (stripped), `action` (one of `REDACT`/`PRESERVE`/`REVIEW`, uppercased), `category` (a valid schema category). Possibly empty.
- Steps: (1) `_extract_json_array(raw)`; if `None`, log one warning ("pass-1 output unparseable; continuing with empty findings") and return `[]`; (2) for each entry: skip non-dicts; strip `text`, skip if empty; uppercase `action`, skip `SKIP`, drop (debug log) anything not in `{REDACT, PRESERVE, REVIEW}`; uppercase and alias-resolve `category`, drop (debug log) if not in `ALL_CATEGORIES`; (3) collect surviving `{"text", "action", "category"}` dicts.
- Side effects: logging only (`logger.warning` on unparseable output, `logger.debug` on dropped entries).
- On failure: never raises. Downstream, an empty return simply means pass 2 sees only the deterministic spans as known-span context.

**`parse_pass2_spans(raw: str, chunk: Chunk) -> list[Span]`**
- What it does: Parses pass-2 output *strictly* and turns it into located `Span` objects — the only place LLM output becomes spans. Strict because pass 2 is the authoritative pass: unparseable output is a hard error. Each valid entry's `text` is searched for in every unit of the chunk (all occurrences, via repeated `str.find`), and each hit becomes one `Span` with `detector="llm_pass2"` and `confidence=0.9`. Two safety behaviors: category is validated *before* the action switch (so garbage-category entries can never trigger the coercion warning), and a leftover `REVIEW` action is coerced to `REDACT` (with a warning, only if it actually located spans) because `REVIEW` is not a legal final action.
- Called by: `run_llm_detection._process_chunk` (detector.py:507). Only caller.
- Parameters: `raw` — the pass-2 completion text; `chunk` — the `Chunk` the completion answers for (its `units` are searched to locate each decision's text).
- Returns: `list[Span]` — every located occurrence of every kept decision, with `unit_id`, `start`/`end` offsets into the unit's `normalized_text`, `text`, alias-normalized `category`, `detector="llm_pass2"`, `confidence=0.9`, `action` (`REDACT` or `PRESERVE`), and `reason=f"LLM pass-2 decision: {action}"`.
- Steps: (1) `_extract_json_array(raw)`; `None` → raise `AIProviderError("pass-2 output could not be parsed as a JSON array")`; (2) per entry: skip non-dicts and empty text; **category first** — uppercase, alias-resolve, drop (debug) if not in `ALL_CATEGORIES`; then action — skip `SKIP`, coerce `REVIEW`→`REDACT` setting `was_coerced`, drop (debug) anything else not `REDACT`/`PRESERVE`; (3) set `guard_short` when the action is `REDACT` and the text is under 4 characters; (4) scan every `unit.normalized_text` with a `find` loop for all occurrences; under `guard_short`, reject a hit whose neighboring character on either side is alphanumeric (i.e. short REDACT texts must be standalone tokens, so redacting "12" can't chew a hole out of "2012") and resume searching at `idx + 1`; otherwise append the `Span` and resume at `end`; (5) after scanning, if the entry was coerced *and* located at least one span, log the warning "pass-2 coerced REVIEW to REDACT for category %s".
- Side effects: logging only (debug drops, coercion warning). Does not mutate `chunk`.
- On failure: raises `AIProviderError` on unparseable/non-list output. That propagates out of `_process_chunk`, cancels queued chunks, and aborts the run (see `run_llm_detection`). Note the lenient side of strictness: a decision whose text simply isn't found in the chunk produces zero spans silently.

**`_span_context(span: Span, units_by_id: dict[str, TextUnit]) -> str`**
- What it does: Produces the human-readable `context` snippet for a deterministic span in the pass-2 payload: up to `_CONTEXT_WINDOW` (40) characters on each side of the span within its unit's `normalized_text`, with `"..."` prepended/appended wherever the snippet was cut.
- Called by: `_suggestion` (detector.py:350). Only caller.
- Parameters: `span` — the deterministic `Span` to contextualize; `units_by_id` — the document-wide `unit_id → TextUnit` lookup built in `run_llm_detection`.
- Returns: the context string; falls back to `span.text` itself when the span's `unit_id` is not in the lookup.
- Steps: (1) look up the unit, fall back on miss; (2) clamp `[span.start - 40, span.end + 40]` to the unit text bounds; (3) slice; (4) add ellipses on cut edges.
- Side effects: none.
- On failure: cannot raise under normal data (the lookup miss is handled).

**`_suggestion(span: Span, units_by_id: dict[str, TextUnit]) -> dict`**
- What it does: Renders one deterministic span (a regular detection or a REVIEW hint) as one entry of the uniform KNOWN SPANS payload — the same `{"text", "category", "action", "context"}` shape used for located pass-1 findings, so the model sees one homogeneous list with no hint of which source each entry came from.
- Called by: `run_llm_detection._process_chunk` (detector.py:492 for deterministic spans, :493 for review hints). Only callers.
- Parameters: `span` — the deterministic `Span`; `units_by_id` — the unit lookup for context extraction.
- Returns: `{"text": span.text, "category": span.category, "action": span.action, "context": _span_context(...)}`. Note `action` may be `"REVIEW"` here — pass 2 is explicitly required to resolve those.
- Steps: one dict literal wrapping a `_span_context` call.
- Side effects: none.
- On failure: cannot realistically fail.

**`_finding_known_span(finding: dict, chunk: Chunk) -> dict`**
- What it does: Renders one pass-1 finding as a KNOWN SPANS entry, attaching real surrounding context by locating the finding's text at its *first* occurrence in the chunk's units and slicing ±40 characters around it (ellipsized where cut). If the text can't be found anywhere, the text itself doubles as the context. This location is payload-only — the docstring stresses that pass-1 findings still never become `Span` objects.
- Called by: `run_llm_detection._process_chunk` (detector.py:494). Only caller.
- Parameters: `finding` — a dict from `parse_pass1_findings` (`text`/`action`/`category` keys); `chunk` — the chunk whose units are searched.
- Returns: `{"text", "category", "action", "context"}` — same uniform shape as `_suggestion`.
- Steps: (1) default `context = text`; (2) scan `chunk.units` in order with `normalized_text.find(text)`; (3) on the first hit, slice the ±40-char window, add ellipses on cut edges, and stop; (4) build the dict.
- Side effects: none.
- On failure: `KeyError` if the finding dict were missing keys — impossible in practice since `parse_pass1_findings` always emits all three.

**`_call(client: Any, cfg: RuntimeConfig, system_prompt: str, user_message: str, chunk_index: int, pass_number: int) -> str`**
- What it does: Makes exactly one chat-completion call to the provider and returns the completion text, translating every SDK exception into the project's typed error hierarchy so upstream code (CLI exit codes, API HTTP statuses) never touches `openai` exceptions. There is no local retry loop — the SDK's built-in retries are already active — so the first hard error aborts the whole run, by design.
- Called by: `run_llm_detection._process_chunk` (detector.py:483 for pass 1, :502 for pass 2). Only callers.
- Parameters: `client` — the duck-typed LLM client (anything with `.chat.completions.create`; in practice the object from `build_client`); `cfg` — supplies `model_handle` (OpenAI model name or Azure deployment name) and `max_completion_tokens`; `system_prompt` — `SYSTEM_PROMPT_PASS1` or `SYSTEM_PROMPT_PASS2`, selecting the pass; `user_message` — the built pass-1 or pass-2 message; `chunk_index`, `pass_number` — labels used only in error messages so failures pinpoint which chunk/pass died.
- Returns: `response.choices[0].message.content` — the non-empty completion string.
- Steps: (1) `client.chat.completions.create(model=cfg.model_handle, messages=[system, user], max_completion_tokens=cfg.max_completion_tokens)`; (2) translate exceptions in a **load-bearing order** — `openai.APITimeoutError` → `AITimeoutError` must be caught *before* `openai.APIConnectionError` → `AIUnavailableError` because the former subclasses the latter; then `openai.APIStatusError` (HTTP-level errors, status code included in the message) → `AIProviderError`; then any other `openai.OpenAIError` → `AIProviderError`; (3) reject an empty/None `content` (a symptom of content filtering) with `AIProviderError`.
- Side effects: network access (the HTTPS call to OpenAI/Azure). No logging, no environment writes, no argument mutation.
- On failure: raises `AITimeoutError`, `AIUnavailableError`, or `AIProviderError` (always chained `from` the SDK exception). The raise propagates through `_process_chunk` and aborts the run.

**`run_llm_detection(document: DocumentData, deterministic_spans: list[Span], review_hints: list[Span], client: Any, cfg: RuntimeConfig) -> list[Span]`**
- What it does: The stage orchestrator — the single public entry point of this module, called once per document by the pipeline. It chunks the document, then processes all chunks concurrently on a thread pool (a pool of worker threads; safe here because the OpenAI client is thread-safe, and the core deliberately stays synchronous — no asyncio outside `api.py`). Within each chunk the order is strict — blind pass 1, then informed pass 2 over the combined known-spans list — and only pass-2 spans are collected. Results are gathered in submission (chunk) order, so output is deterministic regardless of which thread finished first.
- Called by: `anonymizer/pipeline.py:72`, inside `anonymize_document` ("Stage: llm"), with `deterministic_spans=detection.resolver_spans` and `review_hints=detection.review_hints`. Only caller.
- Parameters: `document` — the parsed `DocumentData`; `deterministic_spans` — the regex stage's REDACT/PRESERVE spans (they also go to the resolver independently); `review_hints` — the regex stage's REVIEW-action spans, which exist *only* as LLM input and never reach the resolver; `client` — the duck-typed LLM client; `cfg` — supplies `chunk_size_chars`, `llm_concurrency`, and everything `_call` needs.
- Returns: `list[Span]` — all pass-2 spans from all chunks, concatenated in chunk order. The pipeline then feeds `llm_spans + detection.resolver_spans` into the conflict resolver.
- Steps: (1) build `units_by_id` from `document.text_units`; (2) `split_into_chunks(document, cfg.chunk_size_chars)`; return `[]` immediately if there are zero chunks; (3) define the nested worker **`_process_chunk(chunk_index: int, chunk: Chunk) -> list[Span]`**, which per chunk: records a start time; filters `deterministic_spans` and `review_hints` to the chunk's `unit_ids`; logs "pass 1 (blind reading)" and calls `_call` with `SYSTEM_PROMPT_PASS1` + `build_pass1_message(chunk.text)`; parses findings leniently with `parse_pass1_findings`; assembles the uniform `known_spans` list in a fixed order — deterministic spans (via `_suggestion`), then review hints (via `_suggestion`), then located pass-1 findings (via `_finding_known_span`); logs "pass 2 (validation of N known spans)" and calls `_call` with `SYSTEM_PROMPT_PASS2` + `build_pass2_message(...)`; parses strictly with `parse_pass2_spans`; logs the done line with span count and elapsed seconds; returns the chunk's spans; (4) compute `workers = min(max(1, int(cfg.llm_concurrency)), total)` and log "LLM detection: %d chunks, %d workers"; (5) submit every chunk to a `ThreadPoolExecutor(max_workers=workers)` and iterate `future.result()` over the futures *in submission order*, extending `all_spans`; (6) on any `BaseException` from a result, call `.cancel()` on all futures — queued-but-unstarted chunks are dropped, already-running ones finish and are discarded — then re-raise, aborting the run (the mandatory-LLM design: no partial output is ever returned); (7) return `all_spans`.
- Side effects: logging (per-chunk progress at INFO — the lines the CLI surfaces by raising this logger to INFO — plus warnings from the parsers) and network access via `_call` on worker threads. Does not mutate `document`, the span lists, or `cfg`.
- On failure: whatever the failing chunk raised — typically `AITimeoutError` / `AIUnavailableError` / `AIProviderError` from `_call` or `AIProviderError` from `parse_pass2_spans` — propagates to `anonymize_document`, which lets it bubble to the entry point (CLI exit code or API error response). There is no fallback path: a failed LLM stage means a failed anonymization run.

*Module tail:* **`__all__`** = `["Chunk", "split_into_chunks", "run_llm_detection", "parse_pass1_findings", "parse_pass2_spans"]` — the declared public surface; the underscore-prefixed helpers and constants are internal.

---

## anonymizer/api.py — FastAPI HTTP entry point that exposes the anonymization pipeline as a web service

**Purpose:** This module is the HTTP face of ded-anonymizer v2. It builds a FastAPI application (`app`) with two endpoints — `POST /anonymize` (upload a DOCX, get back the redacted DOCX or a JSON summary) and `GET /healthz` (liveness/config probe) — plus exception handlers that translate the project's typed error hierarchy into meaningful HTTP status codes. Configuration, file-based policy, and the shared LLM client are loaded exactly once per worker process at startup (via the `lifespan` context manager) and stashed on `app.state`, so every request reuses them instead of re-reading `.env` / YAML or re-creating an OpenAI client. The heavy lifting is delegated entirely to `anonymizer.pipeline.anonymize_document`; this file only handles transport concerns (upload parsing, size limits, response shaping, error mapping).

**Imports:**
- *stdlib:* `base64` (encode the redacted DOCX into the JSON summary response), `dataclasses` (`asdict` to serialize the counts-only `PlanSummary`), `logging` + `sys` (configure root logging to stdout at startup), `contextlib.asynccontextmanager` (define the FastAPI lifespan), `pathlib.Path` (locate the `config/` directory).
- *third-party:* `fastapi` (`FastAPI`, `Request`, `Depends`, `HTTPException`) and `fastapi.responses` (`Response`, `JSONResponse`) — the web framework and response types.
- *project:* `anonymizer.config.load_runtime_config` / `load_file_config` (env-driven runtime settings and YAML/allowlist file config; `load_runtime_config` auto-loads the `.env` in the current working directory when called with no argument, real env vars winning), the typed exceptions from `anonymizer.errors` (for the status-code map and the exception handler), `anonymizer.llm.client.build_client` (constructs the `openai.OpenAI` / `openai.AzureOpenAI` client), and `anonymizer.pipeline.anonymize_document` (the entire pipeline behind one call).

**Imported by:** No project module imports `anonymizer.api` (verified by grep — the only references are docstrings/README). It is loaded by ASGI servers via the import string `anonymizer.api:app`: `uvicorn anonymizer.api:app --reload` in development, or `gunicorn anonymizer.api:app -c gunicorn.conf.py` in production (README lines 109/283–289).

### Functions & classes

**`lifespan(app: FastAPI)` — async context manager (decorated with `@asynccontextmanager`)**
- What it does: FastAPI's startup/shutdown hook. Before the server accepts requests it loads runtime config from the environment, loads the file-based config from the relative `config` directory, sets up stdout logging at the configured level, builds the LLM client, and attaches all three to `app.state`. On shutdown (after the `yield`) it closes the LLM client's HTTP connections.
- Called by: FastAPI itself — passed as `lifespan=lifespan` when constructing `app` on line 39. Never called directly by project code.
- Parameters: `app` — the `FastAPI` instance whose lifetime this manages.
- Returns: an async context manager (yields nothing usable; the yield point marks "server is running").
- Steps: (1) `cfg = load_runtime_config()` — reads env vars, auto-loading `./​.env` first (missing/invalid required vars raise `ConfigurationError`); (2) `files = load_file_config(Path("config"))` — note the *relative* path, so the process must be started from the project root; (3) `logging.basicConfig(level=cfg.log_level, stream=sys.stdout)`; (4) `client = build_client(cfg)`; (5) stores `cfg`, `files`, `client` on `app.state`; (6) yields; (7) `client.close()` on shutdown.
- Side effects: configures process-wide root logging; mutates `app.state`; `load_runtime_config` writes `.env` values into `os.environ`; `load_file_config` reads YAML/allowlist files from disk; `build_client` creates (but doesn't yet connect) a network client.
- On failure: a `ConfigurationError` (or file-read error) during startup aborts worker boot — the ASGI server fails to start rather than serving a half-configured app.

**`app` (module-level `FastAPI` instance)** — the ASGI application object that servers import; created with `FastAPI(lifespan=lifespan)`.

**`_ERROR_STATUS_CODES: dict[type[AnonymizerError], int]` (module-level constant)** — maps each typed pipeline exception to an HTTP status: `InvalidDocumentError` → 400 (bad upload), `DocumentProcessingError` → 422 (valid upload the pipeline couldn't process), `AIProviderError` → 502 (upstream LLM returned an error), `ConfigurationError` / `AIUnavailableError` → 503 (service not usable right now), `AITimeoutError` → 504 (LLM call timed out). Used only by `handle_anonymizer_error`; anything unmapped falls back to 500.

**`_read_payload(request: Request) -> bytes` (async)**
- What it does: pulls the uploaded DOCX bytes out of the incoming request, accepting either a multipart form upload (field name `file`) or a raw body with a DOCX/octet-stream content type, then enforces non-emptiness and the configured size cap.
- Called by: FastAPI's dependency-injection system only — wired into the `anonymize` endpoint via `payload: bytes = Depends(_read_payload)`. No direct calls anywhere (grep-verified).
- Parameters: `request` — the incoming `fastapi.Request`.
- Returns: the raw upload bytes (the unmodified DOCX file content).
- Steps: (1) read the `content-type` header; (2) if it starts with `multipart/form-data`, parse the form and read the `file` field (missing field → `InvalidDocumentError`); (3) else if it starts with the DOCX MIME type (`application/vnd.openxmlformats-officedocument.wordprocessingml.document`) or `application/octet-stream`, read the raw body; (4) any other content type → `HTTPException(415)`; (5) empty payload → `InvalidDocumentError`; (6) payload larger than `cfg.max_upload_mb` MB → `HTTPException(413)`.
- Side effects: none beyond consuming the request body.
- On failure: raises `InvalidDocumentError` (handled by `handle_anonymizer_error` → 400 JSON) or `HTTPException` with 415/413 (handled by FastAPI's built-in handler). The endpoint body never runs when this dependency raises.

**`anonymize(request: Request, summary: int = 0, payload: bytes = Depends(_read_payload)) -> Response`**
- What it does: the `POST /anonymize` endpoint. Runs the full pipeline (parse → deterministic regex detection → two-pass LLM detection → conflict resolution → byte-verbatim dot-glyph redaction) on the uploaded document, then returns either the redacted DOCX file itself or, when `?summary=1`, a JSON envelope containing the counts-only summary plus the base64-encoded DOCX. Note it is a `def` (not `async def`), so FastAPI runs it on a thread-pool worker — the blocking, LLM-calling pipeline doesn't stall the event loop.
- Called by: FastAPI routing for `POST /anonymize`; no in-project callers.
- Parameters: `request` — used to reach `app.state` (config, file config, LLM client); `summary` — query parameter, `0` (default) returns the binary DOCX, any non-zero value returns the JSON envelope; `payload` — the upload bytes injected by `_read_payload`.
- Returns: when `summary` is falsy, a binary `Response` with the DOCX media type and a `Content-Disposition: attachment; filename="<document_id>_redacted.docx"` header; otherwise a `JSONResponse` with keys `document_id`, `summary` (the `PlanSummary` dataclass as a dict — counts only, never the detected text), `warnings` (list of strings), `model` (LLM model handle used), and `docx_base64` (the redacted DOCX, base64-encoded ASCII).
- Steps: (1) call `anonymize_document(payload, config=…, files=…, client=…)` with the process-wide state (no `document_id` passed, so the pipeline generates one); (2) branch on `summary` and build the corresponding response.
- Side effects: network calls to the LLM provider and pipeline logging (both inside `anonymize_document`); the endpoint itself mutates nothing.
- On failure: any `AnonymizerError` from the pipeline propagates to `handle_anonymizer_error` (mapped status + JSON); anything else hits `handle_unexpected_error` (opaque 500).

**`healthz(request: Request) -> dict`**
- What it does: the `GET /healthz` endpoint — a cheap liveness probe that also confirms which AI provider/model the worker was configured with. It does not touch the network or the LLM.
- Called by: FastAPI routing for `GET /healthz`; no in-project callers.
- Parameters: `request` — used only to read `app.state.cfg`.
- Returns: `{"status": "ok", "provider": <cfg.provider>, "model": <cfg.model_handle>}` (FastAPI serializes the dict to JSON).
- Steps: read two config attributes, return the dict.
- Side effects: none.
- On failure: cannot realistically fail once startup succeeded (state is always populated by `lifespan`).

**`handle_anonymizer_error(request: Request, exc: AnonymizerError) -> JSONResponse`**
- What it does: exception handler (registered via `@app.exception_handler(AnonymizerError)`) that converts any typed pipeline error into a structured JSON error response, looking up the HTTP status in `_ERROR_STATUS_CODES` by the exception's exact type.
- Called by: FastAPI's exception-handling machinery whenever an endpoint or dependency raises an `AnonymizerError` subclass; no direct calls.
- Parameters: `request` — unused (required by the handler signature); `exc` — the raised error.
- Returns: `JSONResponse` with the mapped status (default 500 for unmapped subclasses) and body `{"error": "<ExceptionClassName>", "detail": "<str(exc)>"}`.
- Steps: `type(exc)` lookup in the map with 500 fallback; build the response. Note the lookup is by exact type, not `isinstance`, so a new subclass of a mapped error would fall back to 500 until added to the map.
- Side effects: none.
- On failure: n/a (pure mapping).

**`handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse`**
- What it does: catch-all exception handler (registered via `@app.exception_handler(Exception)`) that returns a deliberately opaque 500 so internal details — which, in this service, could include fragments of a confidential tax decision — never leak into an HTTP response.
- Called by: FastAPI's exception machinery for any exception not covered by a more specific handler; no direct calls.
- Parameters: `request`, `exc` — both effectively unused in the body.
- Returns: `JSONResponse(status_code=500, content={"error": "InternalServerError", "detail": "internal error"})`.
- Steps: build and return the constant response.
- Side effects: none in the function itself (the ASGI server still logs the traceback).
- On failure: n/a.

---

## gunicorn.conf.py — production server configuration for running the API under Gunicorn

**Purpose:** Declarative configuration file that Gunicorn (the production process manager) executes when started as `gunicorn anonymizer.api:app -c gunicorn.conf.py`. Gunicorn config files are plain Python modules whose top-level variable names are the settings, so this file contains no functions or classes — just assignments. Its one non-trivial behavior: before reading any setting it loads the project's `.env` file through the same dependency-free loader the CLI and API use, so the server's bind address, worker count, and timeouts come from the exact same file as the application config (a real environment variable always beats the `.env` value). It exists so the LLM-heavy, long-running pipeline gets appropriately generous timeouts and multiple worker processes without anyone memorizing command-line flags.

**Imports:**
- *stdlib:* `os` (read the env vars via `os.getenv`), `pathlib.Path` (locate the `.env` next to this file).
- *third-party:* none imported here, but the `worker_class` string names `uvicorn_worker.UvicornWorker` from the `uvicorn-worker` package — the adapter that lets Gunicorn (a WSGI-era process manager) host the ASGI FastAPI app.
- *project:* `anonymizer.config.load_env_file` — the shared KEY=VALUE `.env` loader (not python-dotenv).

**Imported by:** No project module imports it (grep-verified; only README mentions). Gunicorn itself exec-loads the file at startup when passed via `-c`.

### Functions & classes

*None — this module has no `def` or `class` statements.* Its top-level execution does the following, in order:

1. **`load_env_file(Path(__file__).resolve().parent / ".env")`** — populates `os.environ` from the project-root `.env` (skipping keys already set in the real environment) *before* any `os.getenv` below. Side effect: writes to `os.environ`. If `.env` is missing the loader is a no-op; a malformed line is skipped, not fatal.
2. **`bind`** — `"<ANON_HOST>:<ANON_PORT>"`, defaulting to `0.0.0.0:8000`. The listen address.
3. **`workers`** — `int(WEB_CONCURRENCY)`, default `2`. Number of OS processes; each runs `lifespan` independently, so each has its own config, file config, and LLM client. A non-integer value raises `ValueError` at load time and Gunicorn refuses to start.
4. **`worker_class = "uvicorn_worker.UvicornWorker"`** — the ASGI worker class required for FastAPI.
5. **`timeout`** — `int(ANON_GUNICORN_TIMEOUT)`, default `900` seconds. How long a worker may go silent before Gunicorn kills it; set to 15 minutes because a large document's two-pass LLM run is slow.
6. **`graceful_timeout`** — `int(ANON_GRACEFUL_TIMEOUT)`, default `900` seconds. How long a worker gets to finish in-flight requests on shutdown/reload.
7. **`keepalive = 5`** — seconds to hold idle client connections open.
8. **`accesslog = "-"` / `errorlog = "-"`** — both log streams to stdout, container-friendly.

---

## run_anonymizer.py — self-contained, removable CLI for anonymizing one DOCX or a folder of them

**Purpose:** The entire command-line surface of the project in a single file at the repo root. It wraps the same public pipeline API the HTTP service uses (`load_runtime_config`, `load_file_config`, `build_client`, `anonymize_document`) and adds batch processing over a folder, file naming (`<stem>_redacted.docx`), per-document console reporting, an optional `--summary-json` machine-readable line, and — uniquely, since nothing else in the project invokes it — the `--qa` flag that runs the out-of-band postcheck residual-leak audit on each redacted output. By design it imports no private names, so deleting this one file removes the CLI with zero edits elsewhere. It communicates outcomes to shell scripts via documented exit codes (0/1/2/3/4/130).

**Imports:**
- *stdlib:* `argparse` (CLI parsing), `dataclasses` (`asdict` for `--summary-json`), `json` (serialize that summary), `logging` (quiet, message-only console with pipeline/LLM progress at INFO), `sys` (stderr printing, `sys.exit`), `pathlib.Path` (all path handling); `from __future__ import annotations` for deferred type-hint evaluation.
- *project:* `anonymizer.config.load_env_file` / `load_file_config` / `load_runtime_config` (env + file configuration), `anonymizer.errors.AnonymizerError` / `ConfigurationError` (per-document failure handling vs. fatal config errors), `anonymizer.llm.client.build_client` (LLM client), `anonymizer.pipeline.anonymize_document` (the pipeline), `anonymizer.postcheck.scan_redacted_docx_bytes` (the `--qa` audit).

**Imported by:** No project module imports it (grep-verified — only README/BUILDER_REPORT prose mention it). It is executed directly: `python .\run_anonymizer.py <path>`.

### Functions & classes

**Module-level constants:** `logger` (a `run_anonymizer` logger, currently unused by the code paths below); exit codes `EXIT_OK = 0`, `EXIT_PROCESSING_FAILED = 1`, `EXIT_USAGE = 2`, `EXIT_CONFIG = 3`, `EXIT_QA_HIGH = 4`; and `_REDACTED_SUFFIX = "_redacted.docx"` (both the output-name suffix and the skip filter that keeps prior outputs from being re-processed as inputs).

**`_build_arg_parser() -> argparse.ArgumentParser`**
- What it does: constructs the CLI's argument parser with one optional positional (`input`) and four flags. Positional and `--file` are alternatives for the same thing — a `.docx` file or a folder of them.
- Called by: `main` only (line 172).
- Parameters: none.
- Returns: a configured `argparse.ArgumentParser` (prog name `run_anonymizer`).
- Steps: create the parser; add `input` (positional, `nargs="?"`, default `None`), `--file` (same meaning, default `None`), `--out-dir` (output directory; default is next to each input), `--config-dir` (location of `policy.yaml` / `regex_patterns.yaml` / `allowlists/`; default `config/` next to the script), `--qa` (store_true — run the postcheck audit on each output), `--summary-json` (store_true — print each counts-only summary as one JSON line).
- Side effects: none.
- On failure: n/a (argparse itself exits with code 2 on malformed flags when `parse_args` runs later).

**`_collect_inputs(input_path: Path) -> list[Path]`**
- What it does: turns the user's single path argument into the concrete list of documents to process. A file yields just itself; a directory yields its immediate `*.docx` children (non-recursive), excluding files that already end in `_redacted.docx` so re-running on the same folder never anonymizes its own outputs.
- Called by: `main` only (line 196).
- Parameters: `input_path` — the path the user supplied.
- Returns: a sorted `list[Path]`; empty when the path doesn't exist or the folder has no eligible `.docx` files (the caller treats empty as a usage error).
- Steps: `is_file()` → `[input_path]`; `is_dir()` → sorted glob of `*.docx` filtered to real files not ending in `_REDACTED_SUFFIX`; otherwise `[]`.
- Side effects: filesystem reads (stat/glob) only.
- On failure: doesn't raise under normal conditions; nonexistent paths simply return `[]`.

**`_output_path(source: Path, out_dir: Path | None) -> Path`**
- What it does: computes where a document's redacted copy will be written: `<stem>_redacted.docx`, placed in `out_dir` when one was given, otherwise beside the source file.
- Called by: `main` only (line 222).
- Parameters: `source` — the input document path; `out_dir` — the `--out-dir` directory or `None`.
- Returns: the target `Path` (not created; `main` writes to it later).
- Steps: pick `out_dir` or `source.parent`; join with `f"{source.stem}{_REDACTED_SUFFIX}"`.
- Side effects: none.
- On failure: cannot fail.

**`_report_qa(redacted_bytes: bytes, files_config, source_name: str) -> int`**
- What it does: runs the postcheck — the out-of-band residual-leak audit that re-scans an already-redacted DOCX for PII that survived redaction (AFM/AMKA/IBAN numbers, emails, phones, names, placeholder/metadata residue) — and prints a status line plus one indented line per finding. "Out-of-band" means it is a separate verification pass, not part of the redaction pipeline itself.
- Called by: `main` only (line 250), and only when `--qa` was passed.
- Parameters: `redacted_bytes` — the redacted DOCX produced by the pipeline; `files_config` — the `FileConfig` (untyped in the signature) whose allowlists/preservation rules the scanner honors; `source_name` — the original filename, used only to label the printed report.
- Returns: `int` — the count of HIGH-severity findings (`qa.by_severity.get("HIGH", 0)`); `main` accumulates this to decide exit code 4.
- Steps: (1) `qa = scan_redacted_docx_bytes(redacted_bytes, files_config)` returning a `PostcheckSummary` (`clean`, `findings_total`, `by_severity`, `by_kind`, `findings`); (2) print `qa[<name>]: CLEAN|FINDINGS total=… by_severity=… by_kind=…`; (3) print each finding's severity, kind, location, and detail; (4) return the HIGH count.
- Side effects: prints to stdout. No file or network access (the scan runs on in-memory bytes).
- On failure: exceptions from `scan_redacted_docx_bytes` are *not* caught here; since `main` only wraps `anonymize_document` in its try/except, a postcheck crash would escape `main` and hit the `__main__` guard (traceback, unless it's a `KeyboardInterrupt`).

**`main(argv: list[str] | None = None) -> int`**
- What it does: the CLI orchestrator. Parses arguments, sets up quiet logging, loads `.env` + config + the LLM client once, then loops over every input document: anonymize, write the output, print progress/summary/warnings, optionally run QA. Converts every outcome into a documented exit code instead of raising to the shell.
- Called by: the `if __name__ == "__main__"` block (line 261, inside `sys.exit(main())`). `argv=None` makes argparse read `sys.argv`; the parameter exists so the function is testable with an explicit list.
- Parameters: `argv` — optional argument list overriding `sys.argv[1:]`.
- Returns: `int` exit code — `0` all documents OK (and no HIGH QA findings when `--qa`), `1` at least one document failed, `2` usage error (both/neither inputs given, or no `.docx` found), `3` `ConfigurationError` during setup, `4` all processed but `--qa` found HIGH-severity residuals.
- Steps: (1) parse args; (2) `logging.basicConfig(level=WARNING, format="%(message)s")` then raise `anonymizer.pipeline` and `anonymizer.llm.detector` to INFO — so only pipeline/LLM progress prints, bare of timestamps, while other libraries stay at WARNING; (3) `load_env_file(<script dir>/.env)` so the CLI works from any working directory (real env vars win); (4) reject giving both `--file` and the positional (→ 2); reject neither (→ 2); (5) `_collect_inputs`; empty → 2; (6) create `--out-dir` (`mkdir(parents=True, exist_ok=True)`) if given; (7) resolve `--config-dir` (default `config/` next to the script); (8) `load_runtime_config()` + `load_file_config(config_dir)` + `build_client(runtime)` inside one `try` — `ConfigurationError` → print to stderr, return 3; (9) per document: compute target via `_output_path`, print `started:`, call `anonymize_document(source.read_bytes(), config=…, files=…, client=…, document_id=source.stem)`; on `AnonymizerError` count a failure, print `FAILED …` to stderr, `continue`; otherwise `target.write_bytes(result.redacted_docx)`, print `done:` plus a stats line (`spans`, `by_action`, `model`, `elapsed` from `result.timings["total"]`), print any `result.warnings`, print the JSON summary line if `--summary-json`, and accumulate `_report_qa(...)` if `--qa`; (10) return 1 if any failures, else 4 if `--qa` and HIGH findings exist, else 0.
- Side effects: writes `.env` values into `os.environ`; configures process-wide logging; creates the output directory; reads input files and writes `*_redacted.docx` files; extensive stdout/stderr printing; LLM network traffic via `anonymize_document`.
- On failure: `ConfigurationError` at setup and `AnonymizerError` per document are caught and turned into exit codes 3 and 1; anything unexpected (including a crash inside `_report_qa` or the output `write_bytes`) propagates out of `main`.

**`if __name__ == "__main__"` guard (lines 259–266)**
- Runs `sys.exit(main())` so the process exit code is `main`'s return value. Wraps the call in `try/except KeyboardInterrupt`: Ctrl+C (most likely while blocked on an LLM call) prints `interrupted by user` to stderr and exits with the conventional SIGINT code `130` instead of dumping a traceback.

---

## anonymizer/postcheck_support.py — regex patterns and validators for the residual-leak audit

**Purpose:** Holds all the constants (compiled regular expressions and a header allowlist) and small pure helper functions that the optional post-redaction audit uses to spot Greek PII that survived redaction. It exists so `postcheck.py` can stay focused on orchestration while the "what does a leak look like" knowledge lives in one dependency-free place. It is deliberately out-of-band: nothing in the serving path (API or pipeline) imports it, it uses only the stdlib `re` module, imports nothing from `anonymizer.*`, and never logs. In the pipeline diagram it sits behind `postcheck.py`, which is itself only reached via the CLI `--qa` flag.

**Imports:**
- *Stdlib:* `re` — to compile every detection pattern at module import time.
- *Third-party:* none.
- *Project:* none (by design; keeps the audit independent of the code it audits).

**Imported by:** `anonymizer/postcheck.py` only (verified by grep; it imports `qa_patterns`, all `_`-prefixed regex constants, `_INVOICE_COLUMN_HEADERS`, and all four helper functions).

### Functions & classes

**Module-level constants** (not functions, but they are the module's main payload):
- `qa_patterns: dict[str, re.Pattern]` — six named patterns: `AFM` (any 9-digit run; AFM = Greek tax ID number), `AMKA` (11 digits whose positions 3–6 must form a valid DDMM-style birth date — AMKA = Greek social-security number, which embeds a birth date), `IBAN_GR` (`GR` + 25 digits, case-insensitive), `EMAIL` (standard user@domain shape), `PHONE` (optional `+30`/`0030` country prefix then a mobile `69…` or landline `2…` shape, 8–14 more digit/space/dash chars, guarded by "no digit before/after" lookarounds), `DIGIT_RUN` (any bare 9–11 digit run).
- `_WRONG_PLACEHOLDER_RE` — residue from *old/incorrect* redaction styles: `[NAME]`, `[AFM]`, `[ADDRESS]`, `[COMPANY]`, `[ACT_NUMBER]`, `[REDACTED]`, `<REDACTED>`, `PERSON_1`/`COMPANY_2`-style tags, `***123`, or 5+ stars. Finding one means a stale code path or raw AI output leaked into the document. HIGH severity.
- `_ELLIPSIS_RUN_RE` — one or more U+2026 `…` characters; a run of 2+ is the fingerprint of the previous redaction glyph applied character-by-character.
- `_CASE_REF_LEAK_RE` — a case-specific reference value (digits/letters, 3+ chars, captured as group 1) surviving right after a trigger label such as "υπ' αρ.", "αρ. πρωτ.", "εντολής ελέγχου", "ΑΒΜ", "ΕΞ" etc.
- `_BENEFICIARY_LEAK_RE` — a capitalized Greek word right after "δικαιούχο τον/την" ("beneficiary the …"), i.e. a beneficiary name that should have been redacted.
- `_PARTIAL_STAR_RESIDUE_RE` — partially star-masked identifiers like `DCX *****423` (2+ uppercase letters, stars, then alphanumerics).
- `_PERSON_LEAK_RE` — 2+ consecutive capitalized Greek words (a person name, group 1) after identity contexts "ενδικοφανή προσφυγή της/του" or "με ΑΦΜ …".
- `_OVER_REDACT_RE` — the opposite failure, *over*-anonymization: dot runs after labels that the policy says must be preserved ("Αριθμός Απόφασης:", "ν.", "ΦΕΚ", "ΠΟΛ", "ΣτΕ", "ΝΣΚ") or 2+ dots immediately before `%` (a redacted percentage).
- `_OFFICIAL_CONTACT_LABEL_RE` / `_OFFICIAL_HEADER_CONTEXT_RE` / `_DECISION_BODY_START_RE` — cues used to decide whether a surviving phone number is a legitimately preserved *authority* contact (label like "Τηλ."/"Fax"/"Ταχ.", or authority-header text like "ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ"/"ΑΑΔΕ"/"ΔΕΔ"), and where the decision body begins (`ΑΠΟΦΑΣΗ`).
- `_INVOICE_COLUMN_HEADERS: set[str]` — casefolded, whitespace-normalized table-column headers ("ΠΑΡΑΣΤΑΤΙΚΟ", "ΤΙΜΟΛΟΓΙΟ", "ΑΡΙΘΜΟΣ", …) whose cells must contain no digits after redaction.

**`_afm_checksum_ok(s: str) -> bool`**
- What it does: Verifies a candidate AFM (Greek 9-digit tax ID) using the official checksum: the first 8 digits are weighted by powers of two (`2**8` down to `2**1`), summed, taken mod 11 then mod 10, and compared to the 9th digit. This separates *real* AFMs (HIGH severity) from random 9-digit runs (MEDIUM).
- Called by: `anonymizer/postcheck.py` → `scan_redacted_docx_bytes` (AFM check block).
- Parameters: `s` — the candidate string, expected to be exactly 9 digits.
- Returns: `True` if the checksum matches; `False` for wrong length, non-digits, or checksum mismatch.
- Steps: (1) reject if `len != 9` or not all digits; (2) compute the weighted sum of digits 0–7; (3) compare `(total % 11) % 10` with digit 8.
- Side effects: none.
- On failure: cannot raise on string input; malformed input simply returns `False`, so downstream the run is reported as `afm_shape` (MEDIUM) instead of `residual_afm` (HIGH).

**`_iban_checksum_ok(s: str) -> bool`**
- What it does: Verifies a candidate IBAN (International Bank Account Number) with the standard mod-97 algorithm: move the first 4 chars to the end, convert letters to numbers (A=10 … Z=35), and check the whole number mod 97 equals 1. Used to confirm a surviving `GR…` string really is a bank account.
- Called by: `anonymizer/postcheck.py` → `scan_redacted_docx_bytes` (IBAN check block).
- Parameters: `s` — the candidate IBAN string; spaces are tolerated and stripped, case is normalized to upper.
- Returns: `True` if the mod-97 check passes; `False` otherwise (including strings shorter than 4 chars or containing characters that don't convert to digits).
- Steps: (1) strip spaces, uppercase; (2) reject if `len < 4`; (3) rearrange `s[4:] + s[:4]`; (4) map alphabetic chars via `ord(c) - 55`; (5) `int(numeric) % 97 == 1`, with `ValueError` caught and returning `False`.
- Side effects: none.
- On failure: swallows `ValueError` internally and returns `False`; a non-verifying IBAN produces no finding at all downstream.

**`_normalized_greek_phone(value: str) -> str | None`**
- What it does: Decides whether a raw matched string is genuinely a Greek phone number and, if so, returns it as a bare 10-digit string. It strips all non-digits and an optional `+30`/`0030` country prefix, then requires exactly 10 digits starting with `69` (mobile) or `2` (landline). It rejects anything containing a newline or tab, so a "phone" that regex-matched across separate lines/cells is dismissed.
- Called by: `anonymizer/postcheck.py` → `scan_redacted_docx_bytes` (twice: the PHONE block and the DIGIT_RUN block).
- Parameters: `value` — the raw regex match text, possibly containing spaces, dashes, and a country prefix.
- Returns: the normalized 10-digit string, or `None` if the value does not qualify as a Greek phone number.
- Steps: (1) return `None` on `\n` or `\t`; (2) remove all non-digits; (3) strip a leading `0030`, or a leading `30` when 12 digits long; (4) require exactly 10 digits; (5) require a `69` or `2` prefix.
- Side effects: none.
- On failure: cannot raise on string input; `None` means "not a phone", which downstream suppresses a `phone_shape` finding (PHONE block) or allows/suppresses a `digit_run` finding (DIGIT_RUN block).

**`_looks_like_official_contact_phone(text: str, start: int) -> bool`**
- What it does: Decides whether a phone number found at position `start` in the joined document text is an *official authority contact* (e.g., the ΔΕΔ office phone printed in the letterhead), which the anonymization policy intentionally preserves and therefore should not be flagged. It accepts a phone on any line carrying a contact label ("Τηλ.", "Fax", "Ταχ." …), or an unlabeled phone only if it appears *before* the decision body starts (before the word "ΑΠΟΦΑΣΗ") and official-header cues (ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ, ΑΑΔΕ, ΔΕΔ, …) appear within the preceding 800 characters or on the same line.
- Called by: `anonymizer/postcheck.py` → `scan_redacted_docx_bytes` (PHONE block).
- Parameters: `text` — the full joined document text; `start` — the character offset where the phone match begins.
- Returns: `True` if the phone looks like a legitimate preserved authority contact; `False` if it should be flagged.
- Steps: (1) slice out the full line containing `start` using `rfind("\n")`/`find("\n")`; (2) if `_OFFICIAL_CONTACT_LABEL_RE` matches the line → `True`; (3) if `_DECISION_BODY_START_RE` matches anywhere in `text[:start]` (we're already inside the decision body) → `False`; (4) otherwise search `_OFFICIAL_HEADER_CONTEXT_RE` over the last 800 chars of the prefix plus the line.
- Side effects: none.
- On failure: cannot raise for in-range inputs; a `False` result downstream yields a MEDIUM `phone_shape` finding.

## anonymizer/postcheck.py — the out-of-band residual-leak audit over redacted DOCX bytes

**Purpose:** Implements the "QA" audit that re-opens an *already redacted* DOCX and hunts for anything that should not have survived: real AFMs/AMKAs/IBANs, emails, phones, names after identity phrases, wrong-placeholder residue, over-redacted metadata, plus package-level dangers (comments, tracked changes, hidden text, document-properties author fields, embedded objects, long tokens in headers/footers). It is a safety net *after* the main pipeline (parse → regex + two-pass LLM detection → conflict resolution → dot-glyph write-back), not part of it: the only production caller is the CLI's `--qa` flag; the FastAPI service never runs it. By its own docstring contract it does not log, and finding `detail` strings never echo matched document text except for `wrong_placeholder` and `over_redaction`, where the matched text cannot be PII by construction.

**Imports:**
- *Stdlib:* `__future__.annotations` (postponed annotation evaluation); `bisect` (map a character offset in the joined text back to the text unit it came from); `io` + `zipfile` (open the DOCX — which is a ZIP archive — for package-level checks); `re` (the local `_LONG_TOKEN_RE`); `collections.Counter` (severity/kind tallies); `dataclasses.dataclass` and `typing.Literal` (the two result types).
- *Third-party:* `lxml.etree` — parse individual XML parts inside the ZIP (comments, tracked changes, hidden runs, core properties, header/footer text) with `resolve_entities=False` (blocks XML external-entity attacks) and `recover=True` (tolerates slightly broken XML).
- *Project:* `anonymizer.config.FileConfig` (carries `rules.preserve_email_domains`, the audit's only policy input); `anonymizer.docx_engine.parse_docx` and `validate_docx_bytes` (reuse the pipeline's own parser so the audit sees the same text units); `anonymizer.postcheck_support` (all patterns and helpers described above).

**Imported by:** `run_anonymizer.py` only (line 49: `from anonymizer.postcheck import scan_redacted_docx_bytes`). Nothing under `anonymizer/` imports it — confirming the out-of-band claim.

### Functions & classes

**`class PostcheckFinding` (frozen dataclass)**
- Why it exists: one immutable record per detected problem, small enough to print as a CLI table row. Frozen (immutable) so findings can't be altered after creation.
- Attributes: `severity: Literal["HIGH", "MEDIUM"]` — HIGH means near-certain PII leak or dangerous package content, MEDIUM means suspicious shape or policy deviation; `kind: str` — machine-readable category slug (e.g. `residual_afm`, `wrong_placeholder`, `tracked_change`); `location: str` — where it was found, either `"{part_name}:{unit_id}"` for text findings (e.g. `word/document.xml:p42`), a `"table {t} row {r} col {c}"` string for table findings, or a package part name (e.g. `docProps/core.xml`) for ZIP-level findings; `detail: str` — human-readable explanation that avoids echoing document text except for the two safe kinds noted above.
- How instances are created: constructed inline inside `scan_redacted_docx_bytes` and appended to its `findings` list. State never changes after construction (frozen).

**`class PostcheckSummary` (dataclass)**
- Why it exists: the single return value of the audit — a counts-first summary plus the full finding list, mirroring the pipeline's "counts-only" reporting philosophy while still letting the CLI print details.
- Attributes: `clean: bool` — `True` iff zero findings; `findings_total: int` — count of findings; `by_severity: dict[str, int]` — e.g. `{"HIGH": 2, "MEDIUM": 5}` (keys absent when count is zero); `by_kind: dict[str, int]` — per-`kind` counts; `findings: list[PostcheckFinding]` — every finding in detection order.
- How instances are created: built once at the end of `scan_redacted_docx_bytes` from the accumulated list. Not frozen, but never mutated after return in current code; `run_anonymizer.py::_report_qa` only reads it.

**`_is_text_part(name: str) -> bool`**
- What it does: Classifies a ZIP member name as a DOCX part that carries body text worth scanning for tracked changes and hidden runs: the main document, any header/footer XML, footnotes, or endnotes. (It duplicates the logic of `docx_engine._is_word_text_part` locally so the audit stays self-contained at the ZIP layer.)
- Called by: `scan_redacted_docx_bytes` (the tracked-change/hidden-text loop) — no other callers (grep-verified).
- Parameters: `name` — a ZIP member path such as `word/document.xml` or `word/header1.xml`.
- Returns: `bool`.
- Steps: string equality/prefix/suffix tests, in one boolean expression.
- Side effects: none.
- On failure: cannot raise on a string.

**`_is_header_footer_part(name: str) -> bool`**
- What it does: Narrower classifier — `True` only for header or footer XML parts. Used for the long-token check, which applies only to headers/footers (where a 13+ character alphanumeric token, like a case ID or reference code, is suspicious).
- Called by: `scan_redacted_docx_bytes` (long-token loop) — no other callers.
- Parameters: `name` — a ZIP member path.
- Returns: `bool`.
- Steps: `(startswith "word/header" or "word/footer") and endswith ".xml"`.
- Side effects: none.
- On failure: cannot raise on a string.

**`_overlaps(span: tuple[int, int], ranges: list[tuple[int, int]]) -> bool`**
- What it does: Tests whether a half-open `(start, end)` character span intersects any span in a list. Used to stop the generic DIGIT_RUN check from double-reporting digits already claimed by the AMKA or phone checks.
- Called by: `scan_redacted_docx_bytes` (DIGIT_RUN block, called with `amka_ranges` and `phone_ranges`) — no other callers.
- Parameters: `span` — the candidate `(start, end)` offsets; `ranges` — previously recorded `(start, end)` pairs.
- Returns: `True` on any overlap (strict inequality test `s < re_ and rs < e`, so mere touching endpoints do not count), else `False`.
- Steps: linear scan over `ranges` with early return.
- Side effects: none.
- On failure: cannot raise for well-formed tuples.

**`scan_redacted_docx_bytes(redacted_bytes: bytes, files: FileConfig) -> PostcheckSummary`**
- What it does: The module's single public entry point and the whole audit. It re-parses the redacted DOCX with the pipeline's own parser, runs ~12 text-level leak checks over the joined document text, one table-level check, and six ZIP/package-level checks, then returns everything bucketed by severity and kind. "Bytes in, summary out" — it never touches the filesystem or network.
- Called by: `run_anonymizer.py::_report_qa` (line 153), which the CLI's `main` invokes per document when `--qa` is passed; `_report_qa` prints the summary and returns the HIGH-severity count.
- Parameters: `redacted_bytes` — the full redacted `.docx` file as bytes (a ZIP archive); `files` — the loaded `FileConfig`, of which only `files.rules.preserve_email_domains` (a frozenset of casefolded domains the policy allows to survive, e.g. the tax authority's own domain) is consulted.
- Returns: a `PostcheckSummary` (see class above): `clean` flag, total, `by_severity`/`by_kind` dicts built with `Counter`, and the ordered `findings` list.
- Steps:
  1. **Validate & parse:** `validate_docx_bytes(redacted_bytes)` (ZIP well-formedness + required parts), then `parse_docx(redacted_bytes, "postcheck")` producing `DocumentData` whose `text_units` each carry `normalized_text`, `part_name`, `unit_id`, `unit_type`, and `location`.
  2. **Build joined text + offset map:** concatenate every unit's `normalized_text` with `"\n"` separators, recording each unit's starting offset in a parallel `offsets` list. A nested closure `locate(pos)` uses `bisect.bisect_right` on `offsets` to translate any character position in the joined text back to `"{part_name}:{unit_id}"` (or `"unknown"` if there are no units).
  3. **Text checks, in order:** AFM — every 9-digit run: `residual_afm` HIGH if `_afm_checksum_ok`, else `afm_shape` MEDIUM. AMKA — every date-valid 11-digit run: `residual_amka` HIGH, span recorded in `amka_ranges`. IBAN — `residual_iban` HIGH only if `_iban_checksum_ok` passes. EMAIL — `residual_email` HIGH unless the domain is in `files.rules.preserve_email_domains`. PHONE — skip if `_normalized_greek_phone` returns `None`; record span in `phone_ranges`; skip if `_looks_like_official_contact_phone`; else `phone_shape` MEDIUM. DIGIT_RUN — 9–11 digit runs: skip 9-digit (AFM owns that length), skip spans overlapping `amka_ranges`/`phone_ranges`, skip runs that normalize to a phone; else `digit_run` MEDIUM with the run *length* (not value) in `detail`. Then pattern sweeps: `wrong_placeholder` HIGH (detail echoes the placeholder — safe by construction), `ellipsis_residue` (HIGH for runs of 2+ `…`, MEDIUM for a single one), `case_ref_leak` MEDIUM (skipped when the captured value contains a `.`, i.e. already partially dotted-out by redaction), `beneficiary_leak` MEDIUM, `partial_star_residue` MEDIUM, `person_name_leak` MEDIUM, `over_redaction` MEDIUM (detail echoes the match — safe). Note the location anchor: AFM/AMKA use `m.start(1)` (group-1 start); the others use `m.start()`.
  4. **Table check:** for every unit with `unit_type == "table_cell"`, if its `location["column_header"]` (whitespace-normalized, casefolded) is in `_INVOICE_COLUMN_HEADERS` and the cell still contains any digit → `table_invoice_leak` MEDIUM, located as `"table {table_index} row {row_index} col {col_index}"`.
  5. **ZIP-level checks:** reopen `redacted_bytes` with `zipfile.ZipFile` and a hardened `etree.XMLParser(resolve_entities=False, recover=True)`. (a) `word/comments.xml` containing any `w:comment` element → `nonempty_comments` HIGH. (b) Every text part (via `_is_text_part`): any `w:ins`/`w:del` element (tracked changes — Word's revision history, which can hide original PII) → `tracked_change` HIGH; any `w:rPr/w:vanish` (hidden text formatting) → `hidden_text` MEDIUM. (c) `docProps/core.xml`: non-blank `dc:creator` → `metadata_creator` HIGH; non-blank `cp:lastModifiedBy` → `metadata_last_modified_by` HIGH. (d) Any `word/embeddings/oleObject*.bin` or anything under `word/media/` → `embedded_object` MEDIUM (embedded files/images can carry unredacted content). (e) Every header/footer part (via `_is_header_footer_part`): join all XML text with `root.itertext()` and flag each 13+ character alphanumeric token (`_LONG_TOKEN_RE`) as `long_token_header_footer` MEDIUM, reporting only its length.
  6. **Summarize:** `clean = len(findings) == 0`; build `by_severity`/`by_kind` via `Counter`; return the `PostcheckSummary`.
- Side effects: none beyond CPU/memory — no logging (module contract), no file or network I/O (operates purely on the in-memory bytes), no mutation of its arguments.
- On failure: `validate_docx_bytes` raises `anonymizer.errors.InvalidDocumentError` for a broken/non-DOCX input, which propagates to the caller (`_report_qa` in the CLI does not catch it, so the CLI's `main` error handling deals with it); `parse_docx` may likewise raise its parsing errors. Individual XML parts inside the ZIP that fail to parse are tolerated (`recover=True` plus explicit `root is None` guards), so a single corrupt part skips its check rather than aborting the audit.

---

## 7. Code quality, bugs, and risks (current state — after all fixes to date)

Every item below is grounded in the code as it exists now. Historical defects that have already
been fixed in this repo (the `_body/_prefix` argument reversal, the missing
`_iter_allowlist_matches`, the duplicate detectors module, the IGNORECASE review-candidate and
invoice regexes, the signatory `break`, the latent `docx_engine` contract issues) are documented
in `BUILDER_REPORT.md` and are NOT repeated here.

**High priority**

1. **No automated tests at all.** (whole repo) v1 (`apodeltiosi/tests/`) had a full pytest
   suite; v2 has zero test files. Every regression so far was caught by manual runs and ad-hoc
   scripts. Why it matters: any future edit to a regex or the resolver can silently change
   redaction behavior on real documents. Fix: port v1's tests (models/detectors/resolver/
   docx_engine round-trip/QA) and add tests for the v2-only behaviors (two-pass payload shape,
   category-first validation, concurrency ordering, `.env` precedence).
2. **The API has no authentication.** (`anonymizer/api.py`) Anyone who can reach the port can
   submit documents and burn your OpenAI credit. It must never be exposed publicly as-is —
   network-restrict it (VPN/private subnet) or put an authenticating reverse proxy in front.
3. **Hard availability coupling to OpenAI.** (`llm/detector.py` — by explicit design decision)
   No key, quota exhausted, provider outage, or one failed chunk ⇒ the whole document fails
   (502/503/504). There is no deterministic-only fallback. Acceptable for a batch tool;
   worth remembering for SLAs.

**Medium priority**

4. **Rate-limit sensitivity × concurrency.** (`llm/detector.py`) 8 parallel chunks ⇒ bursts of
   ~8 simultaneous calls; on a low OpenAI tier that means 429s, and after the SDK's retries the
   run aborts. Mitigation is configuration: lower `ANON_LLM_CONCURRENCY`.
5. **Startup working-directory dependency.** (`api.py:lifespan` → `load_file_config(Path("config"))`,
   `config.load_runtime_config` → `Path.cwd()/".env"`) Start the server from anywhere but the
   project root and you get a 503 `ConfigurationError` (or silently missing `.env`). Docker
   solves this with `WORKDIR /app`; on bare metal, always `cd` first.
6. **Real secret in a cloud-synced folder.** (`.env`) The OpenAI key lives in `.env` under
   OneDrive. It is git-ignored but still synced to the cloud and to every machine sharing that
   OneDrive. For production, inject the key as a real environment variable (which always wins
   over `.env`) or move the deployment copy out of OneDrive.
7. **Config is read once at startup.** (`api.py:lifespan`) Edits to `policy.yaml` or the
   allowlists require a server restart to take effect. Fine operationally, but easy to forget.
8. **Residual invoice false positive for ALL-CAPS words.** (`detector_patterns._INVOICE_*_RE`)
   The regexes are now case-sensitive with a word boundary, but an all-caps word beginning with
   a trigger — e.g. a heading containing `ΔΑΠΑΝΕΣ` (`ΔΑ` + captured `ΠΑΝΕΣ`) — can still
   match. The declined third hardening (require a digit in the captured identifier) is the
   remaining lever if this shows up in practice.

**Low priority / by-design trade-offs worth knowing**

9. **`greek_name_shape` flags every pair of capitalized Greek words** as a POSSIBLE_PERSON
   review hint (confidence 0.45). That is intentional recall bias — the LLM adjudicates — but
   it means prompt size grows with the number of proper nouns (71 hints on the test decision).
10. **LLM span location is by text search.** (`parse_pass2_spans`) If the model returns a text
    that occurs 12 times in a chunk, all 12 occurrences get the span. Short REDACTs (<4 chars)
    are restricted to standalone tokens, but repeated longer strings are applied everywhere —
    usually desirable for PII, occasionally surprising.
11. **Defensive confidence coercion in the resolver.** (`resolver._confidence`) A malformed
    span (e.g. `confidence=None`) silently ranks as 0.0 instead of crashing. Masks upstream
    bugs; flagged in the audit ledger, kept as-is.
12. **Duplicated checksum logic — intentionally.** `_valid_afm`/`_iban_is_valid`
    (`detector_support.py`) vs `_afm_checksum_ok`/`_iban_checksum_ok`
    (`postcheck_support.py`). The auditor must stay independent of the code it audits, so the
    duplication is a feature — but a bug fix in one must be mirrored in the other by hand.
13. **413/415 responses have a different body shape.** (`api.py:_read_payload`) They are
    FastAPI `HTTPException`s (`{"detail": ...}`) while every other error is
    `{"error", "detail"}`. Documented in the README; clients must accept both.
14. **`document_id` is the file name (CLI).** (`run_anonymizer.py` passes `source.stem`)
    Filenames appear in logs and in the output `Content-Disposition`. If your input filenames
    contain personal names, the logs will too.
15. **No overall per-document time cap in the core.** Each LLM call has `ANON_LLM_TIMEOUT_S`,
    and gunicorn kills API workers at 900 s, but the CLI will happily let a 500-chunk document
    run for as long as it takes.
16. **`UnitType` is broader than reality.** (`models.py`) The taxonomy allows
    `header/footer/footnote/endnote/comment/textbox`, but `parse_docx` only ever assigns
    `paragraph` and `table_cell` (header/footnote text is parsed but typed as `paragraph`;
    textbox paragraphs likewise). Harmless, mildly misleading.
17. **Windows cannot run the production server.** gunicorn is Unix-only. On Windows use
    `uvicorn anonymizer.api:app`; the gunicorn command is for Linux/Docker.

---

## 8. Docker — everything you need

The three files are already in the repo: **`Dockerfile`**, **`docker-compose.yml`**,
**`.dockerignore`**.

**What goes into the image (the complete list):**

| Item | Why |
|---|---|
| `anonymizer/` (whole package, incl. `llm/`) | the application code |
| `config/policy.yaml`, `config/regex_patterns.yaml`, `config/allowlists/{dou,public_services,legal_refs}.txt` | runtime rule data — the app reads `config/` relative to `WORKDIR` |
| `gunicorn.conf.py` | production server settings (bind, workers, 900 s timeouts) |
| `requirements.txt` | dependency list (fastapi, uvicorn, gunicorn, uvicorn-worker, openai, lxml, pyyaml, python-stdnum) |
| `run_anonymizer.py` | optional — lets you `docker exec` in and run the CLI for debugging |
| **NOT** `.env` | excluded by `.dockerignore`; secrets are injected as environment variables at run time (the `.env` loader is a harmless no-op when the file is absent) |

**Commands:**

```bash
# build + run with compose (uses your local .env to inject env vars — the file itself never enters the image)
docker compose up --build -d
docker compose logs -f
curl http://localhost:8000/healthz

# or plain docker
docker build -t ded-anonymizer .
docker run -d -p 8000:8000 \
  -e ANON_PROVIDER=openai \
  -e OPENAI_API_KEY=sk-... \
  -e ANON_MODEL=gpt-5.4-2026-03-05 \
  -e ANON_MAX_COMPLETION_TOKENS=8000 \
  ded-anonymizer
```

**What to tell your DevOps (hand them this paragraph):**

> It's a stateless synchronous HTTP service in one container. Build from the `Dockerfile` in
> `anonimizer_ded/`. It needs outbound HTTPS to `api.openai.com` (or your Azure OpenAI endpoint)
> and nothing else — no database, no volumes, no persistent state. Configuration is entirely
> environment variables: required are `OPENAI_API_KEY` + `ANON_MODEL` (or, with
> `ANON_PROVIDER=azure`, the four `AZURE_*`/`ANON_AZURE_*` variables); useful optional ones are
> `ANON_MAX_COMPLETION_TOKENS=8000`, `ANON_LLM_CONCURRENCY` (lower it if OpenAI 429s appear in
> logs) and `WEB_CONCURRENCY` (gunicorn workers, default 2). The service listens on port 8000;
> liveness/readiness probe is `GET /healthz` (does not call OpenAI). Requests can legitimately
> take minutes — a large document makes dozens of LLM calls — so set the load-balancer/ingress
> idle timeout to at least 900 s to match gunicorn's worker timeout, and don't add aggressive
> retry policies in front (a retry re-bills the LLM calls). Logs go to stdout. There is NO
> authentication in the app — keep it on a private network or behind an authenticating proxy.
> Scale horizontally by adding replicas; each request is independent. Upload limit is 20 MB
> (`ANON_MAX_UPLOAD_MB`).

---

## 9. API for dummies

The API has exactly two endpoints.

**1. Is it alive?**

```bash
curl http://localhost:8000/healthz
# → {"status":"ok","provider":"openai","model":"gpt-5.4-2026-03-05"}
```
Fast, free, never contacts OpenAI. This is your monitoring probe.

**2. Anonymize a document.** Send the `.docx`, get the redacted `.docx` back:

```bash
# simplest form: multipart upload, save the redacted file
curl -X POST http://localhost:8000/anonymize \
     -F "file=@decision.docx" \
     -o decision_redacted.docx
```

Or ask for JSON instead of a file (`?summary=1`) — the document comes back base64-encoded plus
the counts:

```bash
curl -X POST "http://localhost:8000/anonymize?summary=1" -F "file=@decision.docx"
# → {
#     "document_id": "3f2a9c...",
#     "summary": {"spans_total": 427, "by_action": {"PRESERVE": 323, "REDACT": 104}, ...},
#     "warnings": [],
#     "model": "gpt-5.4-2026-03-05",
#     "docx_base64": "UEsDBBQABgAIA..."   ← base64-decode this to get the .docx bytes
#   }
```

You can also POST the raw bytes without multipart (set
`Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document` or
`application/octet-stream` and put the file in the body).

**Reading the errors** (body is `{"error": "<Type>", "detail": "<message>"}` except 413/415):

| Status | Meaning | What to do |
|---|---|---|
| 400 | not a valid DOCX (or empty body / missing `file` field) | check the file you sent |
| 413 | file bigger than `ANON_MAX_UPLOAD_MB` (20 MB) | split or raise the limit |
| 415 | wrong `Content-Type` | use multipart or one of the two accepted types |
| 422 | valid DOCX but processing failed | report it — likely a document edge case |
| 502 | OpenAI returned an error (incl. quota/429 after retries) | check billing/limits, retry later |
| 503 | config invalid or OpenAI unreachable | check env vars / network |
| 504 | one LLM call exceeded `ANON_LLM_TIMEOUT_S` | raise the timeout or check OpenAI status |
| 500 | unexpected bug (body never leaks details) | check container logs |

**Golden rules:** one document per request; expect minutes, not milliseconds, for big documents
(set your client timeout ≥ 900 s); every request costs real OpenAI money (~38 LLM calls for a
19-chunk decision); nothing is stored server-side — if you lose the response, you re-pay to
re-run it.
