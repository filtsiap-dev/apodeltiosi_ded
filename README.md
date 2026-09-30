# `ded-anonymizer`

Anonymizes Greek ΑΑΔΕ/ΔΕΔ tax-decision Word documents before public release.

Every document goes through the same pipeline, whether it arrives over HTTP or
through the CLI:

```
normalize -> parse -> screen -> detect -> llm -> resolve -> apply -> scan
                                                                      |
                                        residual text? -> pass 2 -> resolve -> apply
```

Deterministic detectors and a mandatory two-pass LLM reading both look at the
text; a resolver settles what they disagree about; the plan is applied back to
the package byte-verbatim; and an independent scan checks the *output* for
residual personal information before anything is returned.

**The scan runs exactly once, and it is not only a gate.** What it finds in the
document's *text* goes back to LLM pass 2 as an ordinary question — the exact
slice, in the redacted document, with the whole chunk in view — and pass 2's
answer goes through the same resolver and a second apply. What it finds in the
document's *package* (a surviving macro, a tracked change, a comment part) is
nothing a model can decide, and a HIGH one of those still refuses the document.
Nothing re-scans the correction, so there is no loop: one audit, one re-ask, and
the file is returned.

**One document per request, and one per CLI invocation.** The HTTP body is the
document in both directions — DOCX bytes in, redacted DOCX bytes out, no
envelope, no base64, nothing to decode.

**Human review is part of the workflow.** A document can come back
`needs-review`: a success, with a complete file, and one or more places a person
must settle before publication. See [Needs-review](#needs-review-is-a-success).

---

## What is and is not guaranteed

**In scope.** Text in the document body, tables, headers, footers, footnotes and
endnotes. That text is read by both detection paths and redacted in place.

**Out of scope, explicitly.** This service does **not** anonymize the package
*surface*: document properties (`docProps/core.xml` title, author, subject,
description), hyperlink targets, custom XML parts, or field codes. Personal
information there survives into the output. If your documents carry PII in those
places, strip it before or after this service — the post-redaction scan reports
some of it as a non-blocking finding, but nothing here removes it.

**Document author metadata is preserved, deliberately.** `dc:creator` and
`cp:lastModifiedBy` in `docProps/core.xml` are carried through to the output
unchanged, and the post-redaction scan does not fail a document for them. This
is a **ΔΕΔ-compatibility decision, not a privacy guarantee**: the published gold
decisions keep both fields — `dc:creator` reads `user` and `cp:lastModifiedBy`
carries the name of the clerk who prepared the file — and matching that output
is the requirement this service is held to.

A future `cp:lastModifiedBy` can hold a real person's name. It is not text the
detectors ever see, and nothing downstream removes it. A deployment that needs
the stronger behaviour must add both names back to the blank list in
`docx_engine._cleanup_core_properties` **and** restore the matching HIGH
findings in `anonymizer/postcheck.py`; the docstrings in both places say so.
`dc:title`, `cp:keywords` and `cp:category` are still blanked, and the
created/modified timestamps are still pinned to a fixed epoch.

**No global concurrency limit.** Each document is bounded (see
[Resource limits](#resource-limits)), but nothing caps how many documents the
process handles at once. Size your deployment with `WEB_CONCURRENCY` and the
per-document ceilings in mind.

---

## Accepted input

Four OOXML Word formats:

| Extension | Media type |
|---|---|
| `.docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `.docm` | `application/vnd.ms-word.document.macroEnabled.12` |
| `.dotx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.template` |
| `.dotm` | `application/vnd.ms-word.template.macroEnabled.12` |

The output is always a `.docx`.

**Legacy binary `.doc` and `.dot` are not supported.** They are a different file
format (OLE2, not a ZIP), and they are rejected with `415`. Open them in Word
and save as `.docx` first. There is no converter in this service and no
LibreOffice dependency.

**Macro-enabled input is accepted and de-macroed.** A `.docm` or `.dotm` is
normalised to a plain `.docx`: the VBA parts (`word/vbaProject.bin`,
`word/vbaData.xml` and their relationships) are removed rather than carried
through, and settings that would update content from external sources on open
are disabled. The output never executes macros. If a macro part somehow survived
normalisation, the post-redaction scan raises a HIGH finding and the document is
refused rather than returned — see [The post-redaction scan](#the-post-redaction-scan).

### The package is validated before any work starts

* the upload must be a readable ZIP whose central directory is consistent;
* `[Content_Types].xml` and `_rels/.rels` must be present and parse;
* the officeDocument relationship must resolve to a main part whose declared
  content type matches the format;
* `word/document.xml` is parsed **strictly**, with XML recovery off: it must be
  valid XML, its root must be `w:document`, and it must contain a `w:body`.

The strict parse is the one that matters most. A damaged file can contain every
expected filename; without it, the main document would be *recovered* into
nothing, the redaction plan would be empty, and the file would come back looking
anonymized although it was never read. A valid document with no text is fine —
this rejects unreadable input, not empty input.

Other parts keep a recovering parser, so a damaged header does not fail an
otherwise readable document.

---

## Quick start

### 1. Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

For development (tests, linting, type checking):

```powershell
pip install -e ".[dev]"
```

### 2. Fill in `.env`

The `.env` file next to `run_anonymizer.py` is loaded automatically by both
entry points. Real environment variables always win; the file only fills in what
is missing.

**OpenAI:**

```ini
ANON_PROVIDER=openai
OPENAI_API_KEY=sk-...
ANON_MODEL=gpt-4o
ANON_API_KEY=a-long-random-string    # required by the HTTP API only
```

**Azure OpenAI:**

```ini
ANON_PROVIDER=azure
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
ANON_AZURE_DEPLOYMENT=your-deployment-name
ANON_AZURE_API_VERSION=2024-02-01
ANON_API_KEY=a-long-random-string
```

The service **refuses to start** if any of this is missing, blank, or
nonsensical. See [Startup validation](#startup-validation).

### 3. Run

```powershell
# one document
python .\run_anonymizer.py .\decision.docx

# the HTTP API
python -m uvicorn anonymizer.api:app --host 0.0.0.0 --port 8000
```

---

## Running as a CLI

**One document per invocation.** There is no folder mode: the shell already has
a loop, and it composes better than anything this script could offer.

```powershell
# output next to the input, as <stem>_redacted.docx
python .\run_anonymizer.py .\decision.docx

# name the output file
python .\run_anonymizer.py .\decision.docx --out .\redacted\clean.docx

# --file is equivalent to the positional argument
python .\run_anonymizer.py --file .\decision.docx

# several documents: loop in the shell
Get-ChildItem *.docx | ForEach-Object { python .\run_anonymizer.py $_.FullName }
```

### Flags

| Flag | Meaning |
|---|---|
| `<path>` or `--file <path>` | the one document to process; give exactly one of the two |
| `--out <path>` | output **file** path (default: `<stem>_redacted.docx` beside the input). Parent directories are created. |
| `--config-dir <path>` | directory holding `policy.yaml`, `regex_patterns.yaml`, `prompt_injection.yaml`, `allowlists/` (default: `config/` next to the script) |
| `--qa` | print every finding of the post-redaction scan. The scan always runs; this only makes it verbose. |
| `--summary-json` | print the counts-only summary as one JSON line |

### The output is written atomically

The bytes go to a temporary file **in the destination directory**, are flushed
and `fsync`ed, and only then replace the destination in one operation. A crash,
a full disk or a Ctrl+C therefore leaves either the previous file or no file —
never a half-written DOCX that looks like a result. A failed write cannot
truncate an output that was already there.

`--out` overwrites an existing file without asking.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | processed — **including `needs-review`**, where the file *was* written |
| 1 | processing failed, or the input could not be read / the output written |
| 2 | usage error (see below) |
| 3 | configuration error |
| 4 | blocked by the post-redaction scan; **nothing was written** |
| 5 | the document exceeded its end-to-end budget |
| 130 | interrupted (Ctrl+C) |

Five distinct usage errors, because the fix differs in each case: both argument
forms given, neither given, the path does not exist, the path is not a regular
file, or the extension is outside the four accepted formats. **A directory** is
named specifically — that used to be folder mode.

---

## Running as an HTTP API

### Production

```powershell
gunicorn -c gunicorn.conf.py anonymizer.api:app
```

`gunicorn.conf.py` reads `ANON_HOST`, `ANON_PORT` and `WEB_CONCURRENCY`, logs
access lines to stdout, and sets a worker `timeout` of **900 seconds**. That is
three times the 300-second document budget, so gunicorn is a backstop rather
than the thing that ends a slow document. Lowering it to something nearer the
budget is a reasonable deployment change.

### Development

```powershell
python -m uvicorn anonymizer.api:app --reload
```

See [RUN_SERVICE.md](RUN_SERVICE.md) for Python installation and service startup.

### `POST /anonymize`

**The body is the document, in both directions.**

```
POST /anonymize
Authorization: Bearer <ANON_API_KEY>
Content-Type: <one of the four media types above>

<the raw document bytes>
```

Success is `200` with the redacted DOCX as the body. There is no form, no field
name, no envelope, no base64. `multipart/form-data` and
`application/octet-stream` are **refused with 415** — three ways in meant three
code paths and three sets of failure modes for the same bytes.

**Authentication happens before the body is touched.** The route declares no
body parameter, because FastAPI parses the body *before* it solves dependencies;
an unauthenticated request never has its upload read, spooled or processed.

#### Response headers

| Header | Value |
|---|---|
| `X-Document-ID` | opaque per-document id; every log line for this request carries it |
| `X-Anonymization-Status` | `processed` or `needs-review` |
| `X-Unresolved-Count` | integer |
| `X-Postcheck-Findings` | total non-blocking findings from the output scan |
| `X-Postcheck-Kinds` | per-kind breakdown, e.g. `embedded_object=1` |
| `Content-Disposition` | `attachment; filename="<document id>_redacted.docx"` |

Every value is an id, an enum or an integer. Nothing here is derived from the
document's text — headers reach proxy access logs that the body's protections do
not cover.

The `X-Document-ID` is **not** the filename and not a hash of the content. It is
a fresh opaque id per request. Quote it when reporting a problem: it is how an
operator finds everything that happened to your document.

### `GET /healthz`

Unauthenticated liveness probe. Returns `{"status", "provider", "model"}` — no
secret.

---

## Needs-review is a success

`X-Anonymization-Status: needs-review` is an **HTTP 200 with a complete file in
the body**, and CLI **exit 0** with the file written.

It means the LLM's second pass could not settle one or more findings even after
its corrective retry. Nothing was invented for those: the places were left
exactly as they were, and the deterministic rules still applied wherever they
had evidence. The document is built only from evidence that was validated.

**A person must look at those places before the document is published.**
`X-Unresolved-Count` says how many; the CLI prints each one's chunk, kind and
`(unit_id, start, end)` location. The text is never reported — only where to
look.

> An integrator who treats `200` as "done" will publish documents nobody
> checked. Read the header.

This is distinct from **exit 4 / HTTP 422** (`ResidualPIIError`), which is the
harder failure: the output scan found a HIGH-severity problem that no further
redaction can settle — a surviving macro, a tracked change, a comment part,
residue of the write path — so **nothing is written or returned at all**.
HIGH-severity *text* that survived does not end up here: it is put back to pass 2
first (see [The post-redaction scan](#the-post-redaction-scan)).

---

## The five-minute deadline

Every document gets an end-to-end budget, default **300 seconds**
(`ANON_DOCUMENT_DEADLINE_S`), started the moment the request authenticates and
covering the upload, every stage, every provider call and every retry sleep.

Exceeding it is **HTTP 504** / CLI **exit 5**, and no document is returned.

The budget is enforced in four places rather than one:

* between stages, at each of the eight boundaries — including once more before
  the response is built, so a document finished at 300.2 s is a 504 rather than
  a return;
* in the LLM collector, which waits only as long as the budget allows;
* per provider call, as `timeout = min(ANON_LLM_TIMEOUT_S, remaining)`, so a
  call already in flight ends *at* the deadline;
* before each retry sleep, which only starts if there is room for the call
  after it.

**What cancellation cannot do**, stated plainly: a Python thread cannot be
killed, so after a 504 a worker already inside a provider call runs until that
call's own (already-bounded) timeout and may write one or two attributable log
lines afterwards. CPU-bound stages are not preemptible; they are bounded by the
resource limits instead. And a client that connects but sends nothing leaves the
body read waiting on the transport, where gunicorn's 900-second worker timeout
is the only backstop.

---

## Resource limits

Every one is finite, validated at startup, and overridable. The defaults were
calibrated against a real decision (166 KB upload, 23 members, 1.1 MB expanded,
7:1 overall, 211 text units, 38,000 characters, 19 chunks).

| Limit | Default | Variable | Headroom |
|---|---|---|---|
| Upload | 20,000,000 bytes | `ANON_MAX_UPLOAD_BYTES` | 120× |
| ZIP members | 500 | `ANON_MAX_ZIP_MEMBERS` | 22× |
| Member expanded | 25,000,000 bytes | `ANON_MAX_ZIP_MEMBER_BYTES` | 61× |
| Total expanded | 60,000,000 bytes | `ANON_MAX_ZIP_TOTAL_BYTES` | 53× |
| Compression ratio | 50:1 | `ANON_MAX_COMPRESSION_RATIO` | — |
| Ratio floor | 1,000,000 bytes | `ANON_COMPRESSION_RATIO_FLOOR_BYTES` | members below this are not ratio-checked |
| Extracted text | 400,000 chars | `ANON_MAX_TEXT_CHARS` | 10× |
| Chunks | 150 | `ANON_MAX_CHUNKS` | 8× |

Exceeding any of them is **HTTP 413**.

The ZIP is checked from its **central directory first** — member count, declared
sizes and compression ratios are read as metadata, before a single byte is
decompressed — and members are then read with a bounded reader that also
validates CRCs. A zip bomb is refused on its own declarations.

Two limits can bind at different points: every table becomes its own chunk
regardless of size, so a table-heavy document can exceed 150 chunks while under
400,000 characters. Both are 413 with distinguishable codes.

> `ANON_MAX_UPLOAD_MB` **no longer exists** and is not aliased. Setting it has
> no effect — the default 20,000,000-byte limit stays in force. Use
> `ANON_MAX_UPLOAD_BYTES`.

---

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `ANON_PROVIDER` | `openai` | `openai` or `azure` |
| `OPENAI_API_KEY` | — | required when `ANON_PROVIDER=openai` |
| `ANON_MODEL` | — | required when `ANON_PROVIDER=openai` |
| `AZURE_OPENAI_API_KEY` | — | required when `ANON_PROVIDER=azure` |
| `AZURE_OPENAI_ENDPOINT` | — | required when `ANON_PROVIDER=azure`; must be an absolute http(s) URL |
| `ANON_AZURE_DEPLOYMENT` | — | required when `ANON_PROVIDER=azure` |
| `ANON_AZURE_API_VERSION` | — | required when `ANON_PROVIDER=azure` |
| `ANON_API_KEY` | — | bearer credential for the HTTP API; the API refuses to start without it. The CLI does not need it. |
| `ANON_DOCUMENT_DEADLINE_S` | `300.0` | end-to-end budget per document |
| `ANON_LLM_TIMEOUT_S` | `60.0` | per provider call |
| `ANON_CHUNK_SIZE_CHARS` | `3000` | target chunk size |
| `ANON_MAX_COMPLETION_TOKENS` | `3000` | output ceiling per call |
| `ANON_LLM_CONCURRENCY` | `8` | chunk worker threads |
| `ANON_LOG_LEVEL` | `INFO` | application log level |
| the eight limits above | see table | resource ceilings |

Gunicorn-only: `ANON_HOST`, `ANON_PORT`, `WEB_CONCURRENCY`,
`ANON_GUNICORN_TIMEOUT`, `ANON_GRACEFUL_TIMEOUT`.

### Startup validation

A configuration mistake found at startup costs one restart. The same mistake
found at request time costs a user their document and produces a 500 or 502 that
looks like a provider problem. So the loaders check, before the service accepts
anything:

* the selected provider's credentials are present and **not whitespace** — three
  spaces passes a truthiness test, reaches the provider and fails there;
* `AZURE_OPENAI_ENDPOINT` is an absolute http(s) URL (a plaintext `http`
  endpoint warns that document text will cross the network in the clear);
* every numeric knob is finite, positive, and within a sane ceiling. Zero is
  refused as firmly as negative — a timeout of zero is a call that cannot be
  made. `nan` gets its own mention: every comparison against it is False, so a
  NaN limit silently *disables* the check it names;
* the resource limits are mutually coherent (a member ceiling above the total
  ceiling is a limit that can never fire, while the operator believes otherwise);
* `policy.yaml` parses, its thresholds are numbers between 0 and 1 in the right
  order, and its hard categories exist and are not in both lists;
* every regex override in `regex_patterns.yaml` compiles **in every context the
  detectors interpolate it into** — a fragment that compiles alone can change
  meaning once wrapped;
* every rule in `prompt_injection.yaml` compiles, is uniquely named, and does
  not match the empty string;
* `ANON_LOG_LEVEL` is a real level, so it never reaches `basicConfig` and dies
  there;
* any malformed YAML is a `ConfigurationError` naming the file and the line, not
  a parser traceback.

**No error message ever contains a secret's value.** They name the variable.

---

## The two LLM passes

Both passes read the *same rendering* of a chunk, so they cannot disagree about
what the chunk is.

### Pass 1 — blind discovery

The **only** input is the chunk's own text. No rule spans, no REVIEW hints, no
hard-preserve knowledge, no prior candidates, no resolver output. The two
detection paths have to stay independent for their agreement to mean anything.

Pass 1 is **evidence, not a gate**. Every unusable response degrades to "no
findings, carry on": truncated output, an empty body, prose instead of JSON, or
an array whose every entry was dropped. Failing a document over a formatting
problem in one model response would be the wrong trade — the alternative to
degrading is not a better answer, it is no answer.

A genuinely empty array (`[]`) is different: "I found nothing" is an answer, and
the commonest one on boilerplate.

### Pass 2 — adjudication and discovery

Pass 2 receives the complete chunk, plus a queue of candidates built from the
deterministic spans, the REVIEW hints and pass 1's findings, each with a
transient id (`C1`, `C2`, …). It decides each by id and may also report findings
it made **for itself** (id `NEW`).

**When pass 2 may be skipped:** exactly one case — pass 1 **succeeded** and
produced no candidates, and the rules produced none either. Nobody needs to read
that chunk again.

A **degraded** pass 1 never qualifies, however empty the queue is. Pass 2 runs
over the whole chunk with an empty queue, because a chunk whose pass 1 came back
unusable and whose rules matched nothing would otherwise be released **unread**.

### An incomplete response is not a reading

A pass-2 response is classified **before its body is parsed**. Truncated at the
token ceiling, content-filtered, refused, stopped for an unknown reason, empty,
or unparseable — each is an unusable attempt, and its body is never read. JSON
that happens to parse is not evidence that the model finished speaking.

### The corrective retry

Each chunk gets **one** corrective retry, so at most **three** provider requests
per chunk:

* an **unusable** first attempt → the whole queue is asked again;
* a **distrusted** first attempt (it answered ids the queue never issued, or
  returned junk entries) → the whole queue is asked again, keeping no decisions
  but **promoting every discovery it made**, so nothing vanishes;
* a **trusted** first attempt → accepted decisions are kept and only what is
  outstanding is re-asked, **by id**.

After the retry, anything still outstanding becomes an unresolved finding and
the document is returned `needs-review`. Two unusable or twice-distrusted
responses are a controlled `AIProviderError` → **502**: a total absence of a
usable reading is a failure, not a document.

### Duplicate ids

Ids are counted across the whole response **before** any entry is processed. An
id that appears twice is voided entirely and every copy skipped, so
`[C1=SKIP, C1=PRESERVE]` and its reverse both yield one rejection and no
decision — the first answer never silently wins.

### Findings pass 2 makes for itself

A `NEW` finding is located in the rendered chunk (so it can cross a paragraph
break or a table cell join) and mapped back to source units. A finding shorter
than the standalone threshold is accepted only as a whole token, so a two-letter
finding can never claim the middle of a longer word — in either direction, since
a stray PRESERVE inside a name would shield it as wrongly as a stray REDACT
would blot it.

A conflicting or off-schema `NEW` is **promoted** to a real candidate with its
own id and re-asked, rather than being dropped. One that cannot be located has no
identity to re-ask by, and is recorded as unresolved.

---

## Hard preserve, hard redact, and who decides

The resolver is the final authority for ordinary spans. Two categories of policy
outrank it and outrank the LLM:

* **hard preserve** — categories in `policy.yaml`'s `hard_preserve_categories`
  are never redacted, whatever the model says;
* **hard redact** — categories in `hard_redact_categories` are always redacted,
  whatever the model says.

Both are **deterministic-only**: they come from the rules, not from the LLM, so a
confident model PRESERVE cannot shield a checksum-valid AFM, and a model REDACT
cannot blot a legal reference.

Everything else is resolved by an eight-rung priority ladder over
character-level ownership, with `Span.origin` (`deterministic` / `llm_pass2`)
and confidence deciding overlaps.

---

## Prompt-injection screening

Before any text reaches the model, the extracted text is scanned against a small
deterministic rule set (`config/prompt_injection.yaml`) for content shaped like
an instruction to the model. A match is **HTTP 422** and the document is
refused; **no provider call is made**.

The scan runs against a normalised copy — the stored text, its offsets and
everything the redaction stage uses are untouched.

There is **no off switch and no report-only mode**. Recovering from a false
positive means editing the rule file and restarting, which is why the rule set is
deliberately narrow and every rule requires an imperative or second-person verb
sitting against a specific object. Four common Greek verbs are deliberately
absent because ordinary decisions use them constantly.

**Which rule fired is logged for the operator, not returned to the caller.**
Whoever tunes the rules needs to know; telling the sender is precise guidance on
what to change to get past the screen next time. **Neither gets the matched
text** — the match is the attempt itself.

---

## The post-redaction scan

Mandatory, independent of the detectors, run on the **output** bytes, and run
**exactly once per document**. What a finding does depends on whether it points
at document *text*.

### A finding that names text is a question

A surviving AFM, AMKA, IBAN, email, phone-shaped number, digit run, case
reference, beneficiary name, person name or property identifier is reported with
its exact `(unit_id, start, end)` slice in the **redacted** document. An invoice
*cell* is not on that list: the check fires on "this cell under an invoice header
still holds digits", which is right to warn about and wrong to blank, since a
decision carries no offsets with which pass 2 could narrow the cell to the
identifier inside it. Those slices are put back to **LLM pass 2** — the same prompt, the same
validation, the same single corrective retry, the same token ledger and the same
five-minute budget — as candidates whose recommendation names the source
`postcheck`. Pass 2 sees the complete chunk of the already-redacted text, so it
can also report anything sensitive still visible that the scan did not mention.

Its answers are ordinary `llm_pass2` spans: they go through the **normal
resolver**, where they rank exactly where any pass-2 decision ranks and can
claim no hard-policy tier, and the accepted ones are applied to the document
that already exists. Existing redactions are never undone — the glyphs replaced
the characters — and nothing restarts from the source file.

**A `PRESERVE` from that re-ask stands.** There is no second scan to overrule it,
because a second scan is either a loop with no proof it terminates or a gate
that fails a document immediately after correcting it. `result.postcheck` and
the `X-Postcheck-*` headers therefore describe the document as it was *before*
the correction, and `result.warnings` says so.

### A finding that names no text still blocks

A surviving macro part, tracked change, comment part, hidden run or embedded
object names a *part*, not a slice, and the over-redaction reports name text
that is already gone. Nothing there is a decision a language model can make, so
these keep the handling they always had:

* a **HIGH** one raises `ResidualPIIError`: nothing is written and nothing is
  returned (HTTP 422, CLI exit 4). It is checked *before* the re-ask, so a
  document that cannot be saved costs no extra provider call;
* lower-severity ones are reported and do not block — as
  `X-Postcheck-Findings` / `X-Postcheck-Kinds` headers, or printed by `--qa`.

The scan carries its own copy of the macro-part list rather than importing the
normaliser's, so a botched de-macroing is caught by a check that does not share
code with the thing that failed.

**No matched text is logged, ever.** The slice a finding carries exists so pass 2
can be shown what it is being asked about; it is kept out of `repr`, out of every
log line, out of the warnings and out of the error bodies. The remediation stage
logs counts and transient candidate ids only:

```
stage=remediate ... postcheck_remediation=true candidate_count=2 \
  candidate_ids=['C1', 'C2'] pass2_calls=1 remediation_redactions=2
```

---

## Provider retries

**Two separate mechanisms. Do not confuse them.**

### Transport retries

A failed provider call is retried on this ladder: initial attempt, retry
immediately, retry after 1 second, retry after 2 seconds — four attempts total.
The OpenAI SDK's own retrying is disabled (`max_retries=0`) so there is one
retry policy, not two multiplying together.

A sleep only starts if the remaining document budget covers it *plus* the call
after it.

Each retry line carries the provider, the HTTP status and whether another
attempt follows. HTTP 429 is labelled `rate_limited` specifically, so a rate
limit is never reported as a timeout.

### The pass-2 corrective retry

A *logically separate* mechanism: one targeted re-ask of a chunk whose pass 2
was unusable, distrusted or incomplete. It is about the *content* of a
successful response, not about the call failing. See
[The corrective retry](#the-corrective-retry).

---

## Logs

One line per event, `key=value`, on **stdout**.

Every line for one document carries `request_id=` and `document_id=`, minted
after authentication and before the body is read. There is no request-logging
middleware: the server already logs request lines and the application logs the
work it does.

Each document produces **exactly one** final event:

```
document_finished request_id=... document_id=... outcome=... status=200 \
  elapsed_s=12.34 unresolved_count=0 error_code=-
```

INFO for 2xx, WARNING for 4xx, ERROR for 5xx, so counting by level gives the
same answer as counting by `outcome=`.

### What is never logged

* extracted document text, prompts containing it, or model responses containing
  it;
* detected spans, or the text of any finding;
* the text a prompt-injection rule matched;
* user-controlled filenames — the correlation ids are opaque and generated;
* secrets, `Authorization` headers or API keys;
* arbitrary exception messages from the document path, and **no source lines**
  in tracebacks: a traceback is rendered as file, line and function only,
  because `format_tb` would include the source of each frame and a literal in a
  raise statement would reach the log verbatim.

`openai`, `httpx` and `httpcore` are pinned to WARNING regardless of
`ANON_LOG_LEVEL`, and that also overrides `OPENAI_LOG=debug`. The leak is
concrete: the OpenAI SDK logs its request options at DEBUG, and those options
contain `messages` — the document.

---

## Error responses

```json
{"error": "InvalidDocumentError", "code": "INVALID_DOCUMENT",
 "detail": "the request body is not a readable Word (OOXML) document"}
```

`code` is the stable identifier to branch on. `detail` is a **fixed public
sentence per error class** — never the raised message, which is written from
deep in the document path and quotes what it found there (a parser error carries
a fragment of the XML; a corrupt-member failure carries the member name). Those
specifics go to the operator's log. If you need them, quote your
`X-Document-ID`.

| Status | Meaning |
|---|---|
| 400 | the file is malformed |
| 401 | missing or invalid API key |
| 413 | exceeds a configured size or resource limit |
| 415 | a real document in a format this service does not accept |
| 422 | refused on content: prompt injection, or residual PII in the output |
| 500 | this service could not turn valid input into valid output |
| 502 | the provider failed, was unavailable, or timed out |
| 503 | this service is misconfigured |
| 504 | **your document exceeded the deadline** — and nothing else |

504 means exactly one thing, so a caller seeing it knows which limit they hit.
A provider call that timed out is a provider failure like any other: **502**.

---

## Calling the API from another application

`examples/anonymize_client.py` is a complete, dependency-free reference client —
standard library only, nothing imported from this service, so it can be copied
as-is.

```powershell
python examples/anonymize_client.py `
    --url http://localhost:8000 `
    --file decision.docx `
    --out decision_redacted.docx
```

It demonstrates the parts that are easy to get wrong: the extension → media type
map, a **finite timeout** (default 330 s — the server's budget plus a margin, so
a client timeout means the network and a 504 means the document), handling
`URLError` / timeouts / `OSError` separately, **checking the body is a package
before writing it** (a proxy answering 200 with an HTML error page is a real
thing), an atomic write, and printing the review headers on every run.

### curl

```bash
curl -X POST http://localhost:8000/anonymize \
  -H "Authorization: Bearer $ANON_API_KEY" \
  -H "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document" \
  --data-binary @decision.docx \
  -D headers.txt \
  -o decision_redacted.docx

grep -i x-anonymization-status headers.txt
```

---

## Development

```powershell
python -m pytest -q          # the local suite
python -m ruff check .       # linting
python -m mypy               # type checking
```

The type checker is clean with **no `# type: ignore` comments anywhere in the
application**, and `warn_unused_ignores` is on — that is the bar for a change.

Strings that arrive from outside (a model's category label, `ANON_PROVIDER`) are
narrowed by `TypeGuard` validators at the boundary rather than cast, so the
check is real at runtime *and* the type narrows.

### Dependencies

`pyproject.toml` holds the abstract list; `requirements.txt` is the pin. Both
declare `starlette` and `anyio` explicitly: `anonymizer/api.py` imports
`anyio.from_thread` and `anonymizer/upload.py` types its parameter as
`starlette.requests.Request`, and a dependency a module *names* is a dependency
the project has, whether or not something else happens to install it.

Python service startup instructions are in [RUN_SERVICE.md](RUN_SERVICE.md).
