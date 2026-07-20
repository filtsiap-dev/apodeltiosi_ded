# Reusable Engineering Analysis — from ded-anonymizer v2 toward a Skill

*2026-07-22. Every claim below was adversarially verified against the current code by independent
review agents; where my original claim was too generous, the corrected (honest) form is stated.
Sources: `anonimizer_ded/` (code), `build_prompts/anonimizer_ded/recommended_task_prompts/`
(specs), `BUILDER_REPORT.md` (audit), `CODEBASE_GUIDE.md` (reference).*

---

## 1. Summary of the reusable engineering approach

What this project actually demonstrates, stripped of its Greek-tax specifics, is one repeatable
way to build **document-in / document-out pipelines that mix deterministic rules with LLM
judgment**:

1. Treat the document as a **container to be surgically edited, never reconstructed** — parse to
   flat text *with a per-character reverse map*, edit characters 1:1, copy everything else
   through untouched.
2. Keep the **core transport-neutral** (bytes in, result out); CLI and HTTP are thin removable
   shells; configuration is validated once, up front, from the environment.
3. Treat the **LLM as an untrusted junior colleague**: it sees everything, proposes anything,
   but its output is schema-validated, its text is located by search (never trusted offsets),
   and a **deterministic resolver with explicit priorities** makes every final call.
4. **Verify your own output**: re-validate the artifact you produced, and audit it with an
   independent scanner that shares no detection code with the pipeline.
5. At the process level: build from **dependency-ordered, interface-frozen spec files** with
   owned names and negative constraints; audit code against specs into a **deviation ledger**;
   keep specs updated with every approved code change so regeneration stays safe.

Two distinct Skills fall out: **(A) hybrid document-redaction pipeline** (the product pattern)
and **(B) spec-driven build & audit** (the process pattern). Section 9 proposes both.

---

## 2. Reusable patterns found (verdicts after adversarial verification)

### A. Container & pipeline patterns

**A1. Byte-preserving container editing via a per-character reverse map.**
- *Where:* `docx_engine.py` — `_extract_para_chars` builds parallel `chars`/`char_map` lists of
  `XmlCharRef(part_name, text_node_path, char_index)`; `apply_plan` swaps single characters via
  the map; `write_redacted_docx` rewrites the ZIP entry-by-entry copying `ZipInfo` metadata.
- *Why:* re-rendering (python-docx style) destroys layout; offset drift redacts the WRONG
  characters — fatal in a PII tool.
- *Honest form (corrected):* non-XML members are byte-verbatim; **all parsed XML parts are
  re-serialized through lxml**, not only touched ones. The 1:1 substitution constraint means
  this architecture **cannot do placeholder/pseudonym replacement** (`[NAME_1]`) — it is a
  length-preserving-glyph design, and redacted lengths leak (9 dots ≡ ΑΦΜ). Per-character NFC
  can theoretically expand 1→N characters (unguarded invariant) and does not compose decomposed
  input.
- *Use when:* editing text inside OOXML containers (docx/xlsx/pptx) where formatting must
  survive. *Not when:* generating documents, doing length-changing replacement, or non-OOXML
  formats (PDF needs a different engine).
- *Becomes:* **Skill core + reusable module** (engine is liftable; the text-part list and
  cleanup policy become configuration).

**A2. Transport-neutral core with removable shells.** (Verified strongest pattern.)
- *Where:* `pipeline.anonymize_document(bytes, *, config, files, client) -> AnonymizeResult`;
  `run_anonymizer.py` imports only public names — deleting it removes the CLI with zero core
  edits; `api.py` is the only module that knows HTTP; errors map to statuses in ONE dict
  (`_ERROR_STATUS_CODES`). No asyncio outside `api.py`; core concurrency is threads.
- *Prevents:* untestable cores, HTTP leaking into business logic, circular imports.
- *Nit to fix when templating:* 413/415 are raised as raw `HTTPException` inside
  `_read_payload`, bypassing the one-dict rule.
- *Becomes:* **project template + coding standard.**

**A3. Typed error hierarchy, translated only at the edge.**
- *Where:* `errors.py` (7 exceptions); core raises them; `api.py` maps them; CLI prints them;
  `RuntimeError` reserved for "programming bug" invariants (REVIEW reaching the resolver).
- *Becomes:* **template.**

**A4. Two-loader config discipline.**
- *Where:* `config.py` — env → frozen `RuntimeConfig` (fail-fast, per-provider validation where
  the unselected provider's variables are never read); files → `FileConfig` (policy thresholds,
  regex overrides, gazetteers); nothing read at import time; dependency-free `.env` loader
  shared by all entry points, real env always wins, no-op when absent (container-friendly).
- *Corrected overclaim:* only regex patterns have in-code default fallbacks; `policy.yaml` is
  required and missing keys raise a raw `KeyError` (should be `ConfigurationError`) — fix
  before templating.
- *Becomes:* **reusable module + standard.**

**A5. Metadata/side-channel hygiene as a distinct stage.** (Critic-found addition.)
- *Where:* `clean_sensitive_parts` — blanks creator/lastModifiedBy, resets dates to epoch,
  drops `docProps/custom.xml` *including its relationship and content-type registrations*,
  empties comments, flattens tracked changes, strips hidden text.
- *Insight:* PII lives outside the visible text; removing a part means removing all three of
  its registrations.
- *Becomes:* **Skill section + checklist** ("enumerate non-body channels").

### B. LLM-integration patterns

**B1. Dual-path detection — deterministic spans always compete at the resolver.**
- *Where:* `pipeline.py:89` (`llm_spans + detection.resolver_spans`); REVIEW hints go only into
  the prompt.
- *Honest form (corrected):* the model **can** effectively suppress soft deterministic REDACTs:
  every LLM span carries hardcoded confidence 0.9, and PRESERVE ≥ 0.8 lands in tier 6, which
  outvotes tier-4/5 REDACTs for every category outside `hard_redact_categories` (only
  AFM/AMKA/IBAN/EMAIL today). The true guarantee: *deterministic detections always reach the
  arbiter; hard-redact categories are unsuppressable.* Whether names/addresses should also be
  hard-redact is a policy decision each project must make explicitly.
- *Becomes:* **Skill core pattern**, with the honest wording and "choose your hard categories"
  as a mandatory step.

**B2. Two-pass LLM (blind → informed validation) with one uniform JSON contract.**
- *Where:* `llm/prompts.py` (`SYSTEM_PROMPT_PASS1/2`, KNOWN SPANS `{text, category, action,
  context}`), `llm/detector.py` (lenient pass-1 parse that degrades; strict pass-2 parse that
  aborts; category-validated-before-action; alias map for model improvisations).
- *The transferable core:* **never trust model offsets — locate returned text by string
  search**; lenient/strict asymmetry; uniform payload shape; alias normalization.
- *Caveat (critic):* the blind first pass doubles cost/latency and its benefit is unmeasured
  in-repo — standardize the contract, but make pass 1 optional pending evaluation. Fix before
  enshrining: unlocatable pass-2 decisions vanish silently; the 0.9 confidence literal couples
  the LLM stage to `policy.yaml` thresholds and must become configuration.
- *Becomes:* **Skill pattern + prompt/schema templates.**

**B3. Duck-typed provider seam.** (Critic-found addition.)
- *Where:* `client: Any` throughout; `openai` imported only for exception types; one
  `build_client` factory behind an `ANON_PROVIDER` switch. This is what made the offline mock
  full-pipeline test (20 assertions, zero network) possible with no interface classes.
- *Becomes:* **Skill guidance:** "inject the vendor client; own only its exception translation."

**B4. Chunking that respects semantic units + deterministic parallelism.**
- *Where:* `split_into_chunks` (tables atomic, paragraphs by char budget, units never split);
  `run_llm_detection` (thread pool, results collected in submission order → deterministic
  output despite concurrency; first failure cancels queued work).
- *Fix before enshrining:* atomic tables are unbounded — a 500-row table → one giant prompt →
  truncated JSON → whole-document abort. A standard needs row-windowing with repeated headers,
  and token-based (not char-based) budgeting.
- *Becomes:* **template snippet** (the executor pattern is copy-paste ready).

### C. Safety & verification patterns

**C1. Output self-validation.** `pipeline.py` re-runs `validate_docx_bytes` on its **own
output** before returning. → **checklist**: every producer of a structured artifact re-validates
it at the point of production.

**C2. Independent out-of-band verifier.**
- *Honest form (corrected):* `postcheck` has independent *detection* logic (own regexes, own
  checksums, no imports of detectors/resolver/llm) but **shares the parser** (`parse_docx`) with
  the engine it audits — a shared blind spot. True independence requires an independent text
  extraction path. The severity-graded exit semantics (only HIGH blocks, CLI exit 4) are worth
  keeping.
- *Becomes:* **Skill pattern + checklist**, with the shared-parser caveat stated.

**C3. Privacy-safe observability.**
- *Where:* counts/stages/timings-only logs; counts-only summary; fixed 500 body.
- **Hole found by this review (fix in code before enshrining):** `resolver._consistency_sweep`
  embeds the actual inconsistent document string in its warning (`f"Inconsistent treatment of
  {s!r}..."`), which flows to `plan.warnings` → API JSON and CLI stdout. That string is by
  definition text that was redacted somewhere — suspected PII. Report a count/hash instead.
- *Becomes:* **non-negotiable rule** once the hole is closed.

**C4. Mechanical non-destructiveness proofs.** (Process-side, critic-confirmed.)
- *Where:* the AST scan harness — py_compile + real import + cross-module call-signature check
  (chosen specifically because it would have caught the historical `_body(rules, name)`
  reversal) + def-signature snapshot diff (proved the docstring sweep changed nothing).
- *Becomes:* **Skill script** (`ast_scan.py` is liftable nearly as-is).

**C5. Honest verification boundaries.** Reports explicitly name what was NOT verified
("statically unverifiable: model quality, recall vs gold data") and attribute failures to code
vs external causes (the 429 probed to `insufficient_quota`). → **report template sections.**

### D. Process patterns (the build system itself)

**D1. Meta-prompt that compiles a plan into dependency-ordered specs**
(`meta_prompt_plan_to_specs.md`): models first, entrypoint last, per-spec smoke test, critical
path, MVP cut. → this **is already a Skill**, near-verbatim.

**D2. Interface freezing in specs:** every task opens with "Nothing else of the codebase is
visible to you" + an `ASSUMED EXISTING INTERFACES` block quoting exact signatures, and closes
with "the following names are owned by this module." → **Skill + spec template block.**

**D3. VERBATIM pinning:** data the model must not "improve" is marked (constants "copied
VERBATIM", allowlists "must never be LLM-generated"). → **Skill rule** distinguishing generated
code from human-sourced data.

**D4. Load-bearing rationale at the point of temptation:** "the order is load-bearing
(APITimeoutError subclasses APIConnectionError)" written exactly where a builder would reorder.
Exact error strings dictated → messages become testable contracts. → **Skill rule.**

**D5. Negative deliverables:** "Do NOT define QAStatus... their absence is required"; per-module
import allowlists ("only api.py may import fastapi"). → **spec template section.**

**D6. Deviation ledger with 4-way classification** (pre-accepted / unexpected / PR-flag /
conformance-confirmed), record-don't-fix during audit, and **spec-sync**: every approved code
fix mirrored into the spec so regeneration cannot reintroduce the bug. The one failure we lived:
splitting one module's contract across 4 sub-specs caused the original integration bugs
(signature drift, missing helper, duplicate file) — helper layers and their callers must share
one interface-pinned contract. → **Skill (audit protocol) + ledger template.**

Minor patterns worth a line each: self-output exclusion on batch scans (`*_redacted.docx`
skipped on input collection); targeted quiet logging (root WARNING + named loggers at INFO);
table-to-text linearization convention (`"TABLE:"` + `" | "`-joined rows); Docker discipline
(requirements-first layer, `.env` excluded, healthcheck on the free endpoint, API-only image);
semantic CLI exit codes (0/1/2/3/4/130).

---

## 3. Recommended architecture for similar projects

```
project/
├── <core>/                      # the importable package — transport-neutral
│   ├── models.py                # shared dataclasses + taxonomies; ZERO behavior; imports nothing
│   ├── errors.py                # typed exception hierarchy; imports nothing
│   ├── config.py                # env→RuntimeConfig, files→FileConfig, load_env_file; no import-time I/O
│   ├── <container>_engine.py    # THE ONLY file that knows the file format (parse + write-back)
│   ├── detector_patterns.py     # pure constants (regexes, gazetteers-in-code)
│   ├── detector_support.py      # pure helpers (span builders, validators, accessors)
│   ├── detectors.py             # pure functions (unit, rules) -> spans; detect_all aggregator
│   ├── llm/
│   │   ├── client.py            # provider factory — the only place vendor clients are built
│   │   ├── prompts.py           # prompt constants + message builders; stdlib json only
│   │   └── detector.py          # chunking, calls, parsing, error translation, concurrency
│   ├── resolver.py              # pure arbitration: candidates + policy -> final plan
│   ├── pipeline.py              # the one orchestrator: bytes -> result; catches nothing
│   ├── summary.py               # counts-only reporting
│   ├── api.py                   # ONLY file importing fastapi; error→status map; async boundary
│   └── postcheck(.py/_support)  # independent output auditor; never imported by the pipeline
├── config/                      # runtime DATA (yaml policies, txt gazetteers) — not code
├── tests/                       # (missing in this project — required in the standard)
├── run_<tool>.py                # removable CLI; public imports only
├── gunicorn.conf.py             # prod server knobs (reads env)
├── pyproject.toml / requirements.txt (pinned) / .env (gitignored) / Dockerfile
```

**Purity map.** Pure (no side effects): `models`, `errors`, `detector_patterns`,
`detector_support`, `detectors`, `resolver`, `summary`, `prompts`. Side effects allowed and
localized: `config` (env/file reads), `<container>_engine` (bytes↔XML only — **no file paths in
the core**), `llm/detector` (network, logging), entry points (filesystem, HTTP, logging setup).

**Validation sites:** container validity on entry AND exit (engine); config at load (fail-fast
typed errors); LLM output at parse (schema/whitelists/location); plan invariants at resolve and
again in pipeline. **Logging sites:** pipeline (stage lines), llm/detector (chunk progress),
entry points (start/done/errors) — counts only, never payload text. **Error propagation:** core
raises typed errors and never catches; shells translate (HTTP dict / CLI exit codes).

---

## 4. Standard processing logic (stage contract)

| Stage | Purpose | Input | Output | Failure | Required validations |
|---|---|---|---|---|---|
| validate-in | reject junk early | raw bytes | same bytes | `InvalidDocumentError` | container integrity, required members |
| parse+normalize | flat text + reverse map | bytes | units w/ char maps | `DocumentProcessingError` | offset↔map alignment invariant |
| deterministic detect | high-precision rules | units + rules | spans (final + review) | none (pure) | checksums where they exist (AFM/IBAN) |
| LLM detect | judgment calls | chunks + known spans | located spans | `AIProviderError/Timeout/Unavailable` | schema parse, category/action whitelists, text located by search, budgets (tokens/timeout/concurrency) |
| resolve | one authority decides | all candidates + policy | final plan | `RuntimeError` on illegal state | no non-final actions; consistency sweep |
| apply | surgical write-back | original bytes + plan | new bytes | `DocumentProcessingError` | 1:1 edits only; untouched entries copied verbatim |
| validate-out | self-check | new bytes | same | `InvalidDocumentError` | same as validate-in |
| summarize | safe reporting | plan | counts | none | zero payload text |
| audit (out-of-band) | independent leak scan | output bytes | graded findings | none (advisory) | independent detection logic; severity gates |

Fallback/retry standard: SDK-level retries only; first hard failure aborts the artifact (a
half-redacted PII document must never ship); *no* silent degradation unless a project explicitly
opts into a deterministic-only mode.

---

## 5. Reusable modules and scripts (with independence ratings)

| Component | Responsibility | Must NOT do | Independence |
|---|---|---|---|
| `docx_engine.py` | parse/write OOXML byte-preservingly | accept paths; import detection/LLM/config | **High** — parameterize text-part list + cleanup policy |
| `config.py` (+`load_env_file`) | validated config from env+files | read at import time; know about providers' semantics | **High** after KeyError fix |
| `resolver.py` | overlapping-span arbitration | load files; default policies | **High** — ladder numbers become parameters |
| `llm/detector.py` scaffolding (`_extract_json_array`, `_call` error translation, locate-by-search, thread-pool loop) | robust LLM I/O | trust offsets; retry loops | **High** |
| `postcheck` skeleton | independent output audit | import the detection stack | **Medium** — regexes are domain; structure reusable |
| `api.py` / CLI skeletons | transport shells | contain business logic | **High** |
| `ast_scan.py`, mock-client E2E harness, concurrency test | mechanical verification | — | **High** — belongs in the Skill's `scripts/` |
| `models.py`, `prompts.py`, `detectors.py`, gazetteers, `policy.yaml` | domain vocabulary & rules | — | **Low** — templates only |

---

## 6. Non-negotiable rules

1. **Never reconstruct the container; edit it.** Prevents silent layout/content corruption.
   *Verify:* byte-compare untouched ZIP entries in a round-trip test with an empty plan.
2. **The core takes bytes and returns bytes/results — no paths, no transport imports.**
   *Verify:* `grep -r "fastapi\|argparse\|open(" core/` (path-opening only in shells);
   delete the CLI file — nothing breaks.
3. **All model output is untrusted input.** Strict schema parse, category/action whitelists,
   alias normalization, text located by search, never model-provided offsets.
   *Verify:* grep that no integer from LLM JSON is consumed as an offset.
4. **Deterministic detections always reach the arbiter on a path the model cannot block**, and
   the categories that must never be suppressible are explicitly listed as hard-redact.
   *Verify:* the merge line exists; hard-category list reviewed per project.
5. **One decision authority with explicit, written priorities — plus invariant tripwires** that
   raise on "impossible" states instead of coping. *Verify:* REVIEW-into-resolver raises.
6. **Typed errors in the core; one translation table at each edge.** *Verify:* the dict exists;
   no status codes outside the API module.
7. **No payload text in logs, summaries, warnings, or error bodies.** *Verify:* grep every
   f-string in log/warning/exception constructors for span/document variables (this rule is
   currently violated by `_consistency_sweep` — fix it first).
8. **Fail-fast frozen config; nothing read at import time; real env beats file config.**
   *Verify:* import every module with an empty environment — nothing crashes until a loader runs.
9. **The output auditor shares no detection code with the pipeline** (and ideally not the
   parser); duplicated logic (checksums) is fed by one shared golden test-vector set.
10. **Every produced artifact is re-validated before it is returned.**
11. **Specs/docs are updated in the same change as the code they describe** — a stale spec is a
    regeneration hazard, not a cosmetic issue. *Verify:* the deviation ledger has no open
    PR-flags at release.
12. **Pin dependency versions for anything deployed.** *Verify:* `requirements.txt` has `==`.

---

## 7. General vs domain-specific vs current-choice

**General (belongs in the Skill/standard):** everything in section 6; patterns A1–A4, B1–B4
(with corrections), C1–C5, D1–D6; the folder architecture; the stage contract.

**Domain-specific (template placeholders, not standard):** the 38-category Greek taxonomy; every
regex in `detector_patterns.py` and `regex_patterns.yaml`; the gazetteers (ΔΟΥ/public
services/legal refs); policy thresholds and hard-category lists; the table-header action map;
the prompt text; the dot glyph; the DOCX text-part list; postcheck's regex battery.

**Current implementation choices (work here, not required elsewhere):** mandatory LLM with no
deterministic-only fallback; two-pass (vs one informed pass) — unmeasured benefit; thread
count 8; sync core (threads over asyncio); REVIEW-tier removal from the resolver; postcheck
out-of-band only; `.env` auto-loading convenience; length-preserving dot redaction (vs
placeholders); no auth at the app layer (delegated to network); OpenAI/Azure as the only
providers.

---

## 8. Gaps in the current implementation (what the standard must add)

**Fix-now code holes surfaced by this review:**
- `resolver._consistency_sweep` puts redacted document text into warnings → API/CLI output
  (violates rule 7). Report counts/hashes instead.
- `config.load_file_config` raises raw `KeyError` on missing policy keys (should be
  `ConfigurationError`).
- Unbounded atomic table chunks + finite completion tokens can abort whole documents; needs
  row-windowing.
- Unlocatable pass-2 decisions are dropped silently; count and log them.
- LLM confidence 0.9 is a hardcoded literal entangled with `policy.yaml` thresholds; make it
  config and document the tier interaction (see B1).
- NFC 1→N expansion is an unguarded invariant; add an assertion `len(chars) == len(char_map)`.

**Standard-level gaps (each with its destination):**
- **No tests at all** → template ships `tests/` seeded from the mock-client E2E + concurrency
  harness; every spec owns a test deliverable. (Skill: mandatory.)
- **No CI** → template ships a workflow running the AST scan + tests; the dev-extras tools
  (pytest/ruff/mypy) are declared but never wired.
- **No JSON schema artifact** for the LLM contract — shape lives as prose in prompts + hand
  parsing; one schema file should feed prompt, validator, and tests. (Skill.)
- **No provenance stamp** — result carries `model` only; add config/prompt/package hashes to
  the summary so "which rules redacted this published document?" is answerable. (Template.)
- **No determinism controls** — no temperature/seed pinned, no response caching, re-runs re-pay
  and may differ. (Checklist.)
- **No golden corpus / eval harness** — regex edits change behavior invisibly; recall/precision
  never measured. (Skill: build the eval set alongside the detectors.)
- **Secrets hygiene** — real key in OneDrive-synced `.env`; `.env.example` was deleted so no
  safe committed reference remains; no secret-scan hook. (Checklist.)
- **Resource anchoring inconsistency** — CLI anchors to `__file__`, API to CWD; one rule needed.
- **No total budget** — per-call timeouts exist, but nothing caps a document's total calls/cost.
- **Dual unpinned dependency lists** (pyproject + requirements) with a manual sync note.
- **Duplicated checksum logic without shared test vectors.**
- **`UnitType` taxonomy wider than what the parser emits** (8 declared, 2 produced).

---

## 9. Proposed Skill structure (analysis only — not built yet)

### Skill A: `hybrid-doc-redaction-pipeline` (primary)

- **Purpose:** build or extend services that surgically edit text inside structured documents
  using deterministic rules + LLM judgment under a deterministic arbiter.
- **Invoke when:** the user asks for a document anonymizer/redactor/extractor over OOXML, or any
  "regex + LLM over document text, write results back" pipeline.
- **Required inputs:** target format(s); the category taxonomy with REDACT/PRESERVE/REVIEW
  assignment and the hard-redact list; provider(s); deployment target (CLI/API/both).
- **Expected outputs:** the layered package of section 3, with tests, pinned deps, Docker files,
  and a provenance-stamped summary.
- **Standard workflow:** taxonomy & policy first → models/errors → config → container engine
  (+ round-trip byte test) → deterministic detectors (+ eval fixtures) → LLM layer (schema,
  prompts, locate-by-search) → resolver (+ tier calibration table) → pipeline → shells → postcheck
  → Docker.
- **Mandatory checks (acceptance criteria):** AST scan clean (compile/import/signature); empty-plan
  round-trip byte-compare passes; mock-client E2E green; no-PII grep of all log/warning/exception
  f-strings; isolation greps (rule 2, 6); hard-category list explicitly signed off; eval-set
  recall/precision reported.
- **`scripts/`:** `ast_scan.py`, mock-client harness, round-trip validator, concurrency test.
- **`templates/`:** models/config/engine/pipeline/api/CLI skeletons, prompt pair + JSON schema,
  Dockerfile/.dockerignore/compose, deviation-ledger table, ops-handoff paragraph.
- **Anti-patterns (documented with the real incidents):** python-docx reconstruction;
  whole-string normalization without an offset map; trusting model offsets; IGNORECASE on
  capitalization-as-signal regexes (the 2,054-hint incident); `\b` after dot-terminated
  alternations (the `τιμ....ίου` incident); unbounded atomic chunks; PII in warnings.

### Skill B: `spec-driven-build-audit` (sibling, process)

`meta_prompt_plan_to_specs.md` upgraded with the lessons: one contract per interface (never
split helper/caller specs — the cause of the original integration bugs), owned names, ASSUMED
EXISTING INTERFACES blocks, VERBATIM pinning, negative deliverables, load-bearing rationale
inline; plus the audit protocol: 4-way deviation ledger, record-don't-fix, mandatory spec-sync
commits, honest "statically unverifiable" reporting.

---

## 10. Final checklist for future projects

1. Write the taxonomy + policy (incl. hard-redact list) before any code.
2. `models.py`/`errors.py` first, zero behavior, bottom of import graph.
3. Config: two loaders, frozen, fail-fast typed errors, no import-time I/O, env > file.
4. Container engine: reverse char map, 1:1 edits, verbatim copy, metadata hygiene stage,
   round-trip byte test on day one.
5. Deterministic detectors pure `(unit, rules) → spans`; checksums where possible; case
   sensitivity is a signal — never IGNORECASE a capitalization-based pattern.
6. LLM layer: schema file, blind/informed prompt pair (measure whether pass 1 earns its cost),
   lenient/strict parse asymmetry, locate-by-search, alias map, configurable confidence,
   budgets (tokens/timeout/concurrency/total).
7. Resolver: explicit ladder, hard overrides, tripwires; calibration documented next to the
   thresholds it depends on.
8. Pipeline catches nothing; shells translate; one error→status dict; semantic exit codes.
9. Re-validate output; independent postcheck with severity gates.
10. No payload text in any log/warning/error path (grep it).
11. Tests + CI from the first module; golden corpus for detection quality.
12. Provenance stamp in every result; pinned dependencies; `.env.example` committed, `.env`
    ignored, secrets scanned.
13. Specs updated with every approved code change; deviation ledger empty of PR-flags at
    release.
