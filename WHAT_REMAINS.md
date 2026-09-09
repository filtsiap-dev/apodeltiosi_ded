# What Remains for the Anonymizer

## Goal

The application must receive the same kind of Greek tax-decision DOCX files that the CLI accepts today, anonymize them with the existing pipeline, and return the anonymized DOCX.

Do not redesign the anonymization logic. Keep one shared pipeline for both the CLI and API.

## What Already Exists

The anonymization pipeline is already implemented. It:

1. Opens a DOCX and extracts its text.
2. Finds personal information using rules and two LLM passes.
3. Decides which text must be redacted or preserved.
4. Writes the redactions back into the DOCX.
5. Removes comments, tracked changes, hidden text, and identifying document properties.

The CLI already accepts one DOCX or a folder of DOCX files and creates files named `*_redacted.docx`.

An HTTP API also already exists. `POST /anonymize` accepts a DOCX as a multipart upload in a field named `file`, or as the raw request body, and returns the anonymized DOCX. `GET /healthz` reports whether the application started correctly.

## Work 1: Confirm the Current CLI Release

Before adding more features, use the CLI with several real DOCX files of the kind the application is expected to receive. Open every produced file in Microsoft Word and confirm:

- the file opens normally;
- the document layout remains usable;
- private names and identifiers have been removed;
- public authority information, legal references, dates, and amounts that should remain are still present.

Do not expand support to unusual Word content yet. For now, define the accepted input as ordinary `.docx` decisions containing paragraphs, tables, headers, footers, footnotes, and endnotes.

## Work 2: Make the Existing API Usable by Another Application

The API does not need to be created again. It needs a clear, stable request contract.

Keep this request:

```http
POST /anonymize
Content-Type: multipart/form-data
file=<DOCX file>
```

Keep the normal response as the anonymized DOCX file. The API must use exactly the same `anonymize_document` pipeline as the CLI so that CLI and API results do not drift apart.

Document one example request using `curl` and one example using Python. The calling application should only need the API address, an API key, and the DOCX file.

### Done

- The request contract is unchanged and is now locked by tests:
  `tests/test_api_contract.py` (10 tests) asserts the multipart `file` field,
  the DOCX media type and `Content-Disposition` of the normal response, the
  `?summary=1` JSON shape, the raw-body alternative, and the `400 / 413 / 415`
  guards.
- One of those tests (`test_api_and_cli_produce_the_same_redactions`) feeds the
  same bytes through the HTTP endpoint and through `anonymize_document`
  directly and compares the resulting text, so CLI/API drift now fails the
  suite. The API remains transport only — it calls the same pipeline function
  the CLI calls.
- `anonymizer/api.py`: a multipart body whose `file` part is a plain text field
  used to raise `AttributeError` and return `500`; it now returns `400`
  (`InvalidDocumentError`). Added a module docstring stating the endpoint
  contract and the shared-pipeline rule.
- `tests/conftest.py`: added `ApiClient`, a small synchronous ASGI client.
  Starlette 0.27's `TestClient` passes `app=` to `httpx.Client`, which httpx
  0.28 removed, so the installed versions cannot use it; `ApiClient` drives the
  app through `httpx.ASGITransport` instead. No package versions were changed.
- `README.md`: new section "Calling the API from Another Application" with a
  `curl` example and a Python example, the timeout advice, and the reason the
  returned filename is the server-side `document_id` rather than the uploaded
  name (an uploaded filename is often itself personal information).
- `examples/anonymize_client.py`: a complete, standard-library-only reference
  client a calling application can copy as one file.

## Work 3: Add API Authentication

Add one environment setting named `ANON_API_KEY`.

Every request to `POST /anonymize` must include:

```http
Authorization: Bearer <ANON_API_KEY>
```

The API must compare the supplied value with `ANON_API_KEY` using a constant-time comparison. If the header is missing, malformed, or incorrect, return HTTP `401` without processing the document. Do not include the expected key in the response or logs.

Leave `GET /healthz` unauthenticated so another service can check that the application is running. Add `ANON_API_KEY` to `.env.example`, but never place a real key in the repository.

### Done

- `anonymizer/config.py`: `RuntimeConfig` gained `anon_api_key`, read from
  `ANON_API_KEY`. An all-whitespace value counts as unset, so a blank line in
  `.env` can never become a usable credential.
- `anonymizer/api.py`: added `require_api_key`, wired as a **route-level**
  dependency on `POST /anonymize`. FastAPI resolves route-level dependencies
  before parameter dependencies, so it runs before `_read_payload` — a rejected
  request never has its body parsed and the document is never processed.
  Comparison is `secrets.compare_digest` over UTF-8 bytes (constant time, and a
  non-ASCII header cannot raise). The scheme is matched case-insensitively.
- All failures — missing header, wrong scheme, empty token, wrong key — return
  the same `401` with `WWW-Authenticate: Bearer` and
  `{"detail": "missing or invalid API key"}`. The expected key is never put in a
  response, a header, or a log line; the rejection log records only that a
  request was refused.
- The service fails closed: `lifespan` raises `ConfigurationError` when
  `ANON_API_KEY` is unset, so there is no unauthenticated mode. A hand-built
  state with no key answers `503`, never 200.
- `GET /healthz` is left unauthenticated.
- `.env.example`: added `ANON_API_KEY` with a placeholder and the generator
  command — no real key. `.env` (git-ignored, untracked) received a locally
  generated key so the service still starts here; rotate it at will.
- `tests/test_api_auth.py` (16 tests): the 401 matrix, that a rejected request
  makes no LLM call at all, that neither the response nor the logs contain the
  key, that `/healthz` needs no credential, and that the lifespan refuses to
  start without `ANON_API_KEY`.
- Verified against a real `uvicorn` process, not only the test harness:
  `/healthz` → 200 unauthenticated; `/anonymize` → 401 with no header, a wrong
  key, and a `Basic` scheme; → 400 (document validation) with the correct key.
- Docs updated: README config table, a new "Authentication" section, the `401`
  and `503` rows in the status-code table, and the `curl`/Python/example-client
  snippets now send `Authorization: Bearer`. `examples/anonymize_client.py`
  takes `--api-key` or reads `ANON_API_KEY` from the environment.

## Work 4: Check the Anonymized File Before Returning It

The project already contains a post-redaction audit. Here, "audit" only means a final scan of the produced DOCX for personal information that may still be visible, such as an AFM, AMKA, IBAN, private email, or other suspicious identifier. It is not a legal audit and it does not send information anywhere.

Run this scan automatically after `write_redacted_docx` and before either the CLI saves the file or the API returns it.

If the scan finds a HIGH-severity item, do not return or save the document as a successful result. Report that the document needs manual review. Lower-severity warnings may be returned in the summary without blocking the file.

This changes the flow to:

```text
receive DOCX -> anonymize DOCX -> scan anonymized DOCX -> return it only when no HIGH finding remains
```

### Done

- The scan is now a pipeline stage, not an optional extra. `anonymize_document`
  runs `scan_redacted_docx_bytes` immediately after `write_redacted_docx`, on the
  exact bytes about to be handed back, and there is no flag to skip it — CLI and
  API get the same guarantee because it lives in the shared pipeline.
- A HIGH-severity finding raises the new `ResidualPIIError` instead of returning
  a result. A successful `AnonymizeResult` can therefore only exist for a
  document that passed; no caller has to remember to check. The message names
  the finding kinds and locations and never the matched text.
- The API maps `ResidualPIIError` to `422` with
  `{"error": "ResidualPIIError", ...}` and no document body.
- The CLI catches it separately from other failures: it prints
  `NEEDS MANUAL REVIEW`, writes no `*_redacted.docx` for that input, continues
  with the remaining files, and exits `4`. Exit `1` still means an ordinary
  processing failure.
- Lower-severity findings never block. They travel on `result.postcheck`
  (`PostcheckSummary`), are summarized into `result.warnings`, appear on the
  default HTTP response as `X-Postcheck-Findings` / `X-Postcheck-Kinds`
  (kind names only), and appear in full in the `?summary=1` JSON.
- `--qa` no longer runs a second scan; it prints the findings of the scan the
  pipeline already performed.
- `anonymizer/postcheck.py`'s docstring said it was out-of-band and imported by
  nothing in the serving path; it now states its actual role.
- `tests/test_postcheck_gate.py` (8 tests). The leaking document is produced
  honestly — the mock LLM returns `PRESERVE` for a checksum-valid AFM that the
  rules had marked `REDACT`, so a real leak reaches the scanner rather than the
  scanner being monkeypatched. Covered: the result carries the scan; MEDIUM
  findings do not block; a HIGH raises and leaks no value into the message; the
  API returns 422 with no DOCX; the headers and the `?summary=1` payload; and
  both CLI paths end to end (blocked → exit 4 and no file on disk; clean → file
  written, `--qa` output printed).
- README: a new "The Post-Redaction Scan" section with the flow diagram and the
  table of where findings surface, plus updated CLI flag/exit-code tables, the
  `422` row, and the `postcheck` key in the summary-response example.

## Work 5: Reject Files the Parser Did Not Really Read

The current initial check mainly confirms that the upload is a ZIP package containing the usual DOCX filenames. A broken file can contain those filenames while its main document XML is unreadable. In that case, the pipeline could see no text even though the package contains data.

For the API release, parse the required DOCX XML strictly. Reject the input when `word/document.xml` is invalid or when the parser cannot extract a valid Word document. Do not continue with an empty redaction plan for a file that could not actually be read.

This work is only about rejecting broken or misleading uploads. It does not require adding support for every possible Microsoft Word feature.

### Done

- `anonymizer/docx_engine.py`: added `STRICT_XML_PARSER` (`recover=False`) and
  `_validate_main_document_xml`. `validate_docx_bytes` now reads
  `word/document.xml` and requires that it parse as valid XML, that its root be
  `w:document`, and that it contain a `w:body`. Anything else raises
  `InvalidDocumentError` naming the part that failed, so the caller learns which
  half of the package is wrong.
- Every other part keeps the recovering parser: a damaged header must not fail
  an otherwise readable decision. Only the part the whole pipeline depends on is
  strict.
- `parse_docx` additionally refuses when `word/document.xml` is missing from the
  parsed parts, so the strict validator and the recovering parser can never
  disagree and quietly produce a document with no text.
- The rejection is about unreadable input, not empty input: a valid
  `w:document` with an empty `w:body` is still accepted and yields zero text
  units.
- Because the check lives in `validate_docx_bytes`, it applies to the CLI, the
  API, and the post-redaction scan, and it runs before any detection or LLM
  work: a broken upload never reaches an empty redaction plan.
- `tests/test_docx_strict_parse.py` (30 tests): nine broken packages — truncated
  XML, an unclosed tag, an undeclared namespace, plain text, empty bytes, binary
  garbage, HTML instead of WordprocessingML, a `w:styles` root, and a document
  with no `w:body` — each asserted rejected by `validate_docx_bytes`, by
  `parse_docx`, and by `anonymize_document` (with the mock client asserted to
  have received no call at all), plus the API's `400`, the empty-but-valid
  document, and the damaged-header case.
- Checked against reality, not only fixtures: 25 real Word-generated `.docx`
  files from the Desktop were validated and parsed read-only — 25 accepted, 0
  rejected — so the stricter check does not turn away genuine documents.
- README: new "Accepted Input" section stating the accepted content and the
  three strict-parse rules with the reason they exist, and an expanded `400` row
  in the status-code table.

## Work 6: Make LLM Responses Complete

The LLM is asked to return a JSON list of decisions. Sometimes an LLM can return incomplete JSON or omit a candidate that it was asked to review.

Require the second LLM pass to return valid structured JSON. Validate every returned item before using it, and confirm that every rule-based item marked `REVIEW` received a final `REDACT` or `PRESERVE` decision. If the response is incomplete, retry the LLM call once. If it is still incomplete, stop processing that document instead of silently treating the missing decision as safe.

Keep the existing rule-based redactions in the final plan even when the LLM does not repeat them.

### Done

- `anonymizer/llm/detector.py` now separates three jobs that used to be one
  function: `validate_pass2_entries` (JSON array -> validated `Pass2Decision`
  items), `unresolved_review_hints` (the completeness check), and
  `locate_pass2_decisions` (decisions -> spans). `parse_pass2_spans` is kept as
  the composition of the first and third, so nothing outside changed shape.
- Validation is per item: a non-object, an empty `text`, an unsupported
  `action`, or an off-schema category (after alias resolution) is dropped and
  counted in a warning, never guessed at. A payload that is not a JSON array is
  a rejected response, not a set of decisions.
- Completeness: every rule-flagged `REVIEW` hint in the chunk must come back
  with a final `REDACT` or `PRESERVE`. `SKIP` does not resolve one — that is
  precisely the "missing decision treated as safe" case. Matching is
  whitespace-normalized, case-insensitive, and satisfied by containment in
  either direction, because a model that answers about the whole authority
  header line has genuinely decided the name inside it. An illegal `REVIEW`
  action is still coerced to `REDACT` (existing fail-safe behavior) and counts
  as decided, since the text ends up redacted rather than dropped.
- Retry: `_pass2_attempt` makes one call and judges it. On rejection the call is
  retried exactly once via the new `build_pass2_retry_message`, which repeats
  the original message and appends the rejection reason plus the verbatim texts
  still awaiting a decision — a correction, not a blind second roll. A second
  failure raises `AIProviderError` (`502` over HTTP) and the document is
  abandoned. Provider/transport errors are unchanged: they still abort the run
  immediately.
- Rule-based redactions are untouched by any of this: the pipeline still passes
  `llm_spans + detection.resolver_spans` to the resolver, so a deterministic
  `REDACT` survives a pass 2 that never mentions it. There is a test for exactly
  that (the AFM is redacted although pass 2 only talks about other spans).
- Deliberate choice: "valid structured JSON" is enforced by strict client-side
  validation plus the retry, not by the provider's `response_format` /
  `json_schema` mode. Provider-side enforcement would mean reshaping the shared
  prompt core from a JSON array to a wrapper object — a change to the detection
  logic this document says not to redesign — and it is not uniformly available
  across the Azure API versions the service supports. Say the word if you want
  it added on top.
- `tests/conftest.py`: `DEFAULT_PASS2` was an incomplete response (it answered
  two of the sample's seven REVIEW hints), which is now a failure by design. It
  was rewritten as a complete, realistic response and keeps its three edge cases
  — a coerced `REVIEW`, an off-schema category, and an unlocatable text.
- `tests/test_llm_pass2_completeness.py` (17 tests): the resolution rule
  (exact, containment, unrelated, `SKIP`, coerced `REVIEW`), item validation and
  alias resolution, and the retry behavior end to end — incomplete then
  accepted, unparseable then accepted, truncated JSON then accepted, incomplete
  twice, unparseable twice, `SKIP` twice, a complete answer never retried, and a
  chunk with no hints never retried. The retry message is asserted to name the
  missing text, and pass 1 is asserted not to be repeated.
- README: new "Pass-2 Completeness" section, an updated `502` row, and a note in
  "Completion Token Limit" that a too-low token budget now surfaces as `502`
  rather than as quietly thinner redaction.

## Verified End to End (2026-09-08)

One synthetic Greek decision — invented name, patronymic, AFM, address, phone,
e-mail, protocol and act numbers; nothing from a real document — was run through
the CLI against the configured live model (`gpt-5.4-2026-03-05`):

```text
stage=parse  units=16
stage=detect candidate_spans=33 review_hints=17
chunk 1/1: pass 2 rejected (5 rule-flagged REVIEW entry/entries received no
           REDACT or PRESERVE decision); retrying once
chunk 1/1: done — 83 spans located (50.4s)
stage=scan   findings=1 high=0 by_kind={'case_ref_leak': 1}
exit 0, file written
```

The output redacts the name, patronymic, AFM, private address, private phone,
e-mail, protocol number and challenged-act number, and preserves the authority
header, the official phone and `@aade.gr` address, the decision number and
dates, the legal references, the amounts, and the ΔΟΥ.

Two things worth keeping in mind from that run:

- **The retry is load-bearing, not a formality.** The real model left 5 of 17
  REVIEW hints undecided on its first answer and resolved all of them when the
  retry named them. Documents with many REVIEW hints in one chunk therefore lean
  on the retry; if you start seeing `502` with "still incomplete after one
  retry" in production, the first knobs to reach for are a smaller
  `ANON_CHUNK_SIZE_CHARS` (fewer hints per request) and a larger
  `ANON_MAX_COMPLETION_TOKENS`.
- The single MEDIUM finding (`case_ref_leak`) is the date fragment left after
  the act number was redacted. It is reported and does not block, which is the
  intended behavior for a non-HIGH finding.

Work 1 is still yours: these checks confirm the pipeline mechanically, but no
output has been opened in Microsoft Word.

## Completion Order

Implement the remaining work in this order:

1. Confirm the current CLI on accepted real documents.
2. Confirm the existing API accepts and returns the same documents.
3. Add bearer API-key authentication.
4. Make the post-redaction scan mandatory.
5. Reject DOCX files that were not parsed correctly.
6. Enforce complete structured output from the second LLM pass.

After these steps, the application will have one consistent path: it can anonymize accepted DOCX files locally through the CLI or remotely through an authenticated API, and it will check the output before releasing it.
