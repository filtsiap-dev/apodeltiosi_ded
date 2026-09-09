# `ded-anonymizer`

A service that anonymizes Greek ΑΑΔΕ/ΔΕΔ tax-decision DOCX files before public release.

It runs a mandatory two-pass LLM detection pipeline over the extracted document text:

1. A blind first pass.
2. A revision pass that receives:

   * the first-pass findings
   * deterministic spans

The service applies the resulting redaction plan back to the DOCX byte-verbatim and returns the redacted document.

There are two ways to use it:

* A one-shot **CLI** for local or batch files.
* A long-running **HTTP API** for integration with other systems.

Two LLM providers are supported:

* **OpenAI**
* **Azure OpenAI**

Choose one usage mode and one LLM provider below.

---

## Accepted Input

An ordinary `.docx` decision: paragraphs, tables, headers, footers, footnotes,
and endnotes. Text in all of those parts is read and redacted.

The upload is checked before any work starts, and `word/document.xml` — the one
part everything depends on — is parsed **strictly**, with XML recovery turned
off:

* it must parse as valid XML;
* its root element must be `w:document`;
* it must contain a `w:body`.

A package that fails any of these is rejected with `400`
(`InvalidDocumentError`) naming `word/document.xml`. This matters because a
damaged file can still contain every expected filename: without the strict
parse, its main document would be recovered into nothing, the redaction plan
would be empty, and the file would come back looking anonymized although it was
never read. Rejecting is about unreadable input, not empty input — a valid
document with no text is accepted.

The other parts keep a recovering parser, so a damaged header does not fail an
otherwise readable document.

---

## Quick Start

### 1. Install

```powershell
pip install -e .
```

Alternatively, install without editable mode:

```powershell
pip install -r requirements.txt
```

The `requirements.txt` file is kept in sync with the dependency list in `pyproject.toml`.

---

### 2. Fill in `.env` — Choose an LLM Provider

Open [`.env`](.env) at the project root and fill in exactly one provider block.

#### Option A: OpenAI

OpenAI is the default provider.

```ini
ANON_PROVIDER=openai
OPENAI_API_KEY=sk-...
ANON_MODEL=your-openai-model-name
```

#### Option B: Azure OpenAI

```ini
ANON_PROVIDER=azure
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
ANON_AZURE_DEPLOYMENT=your-deployment-name
ANON_AZURE_API_VERSION=2024-02-15-preview
```

`ANON_PROVIDER` is the only provider-selection switch.

It is safe to have both the OpenAI and Azure OpenAI variables filled in at the same time. The variables belonging to the provider that is not selected by `ANON_PROVIDER` are not read.

To change providers, change only `ANON_PROVIDER`.

Any configuration value not shown above uses its default value. See the full [configuration reference](#configuration-reference) below.

> [!IMPORTANT]
> The `.env` file at the project root is loaded **automatically by every entry point** — the CLI (`run_anonymizer.py`), the HTTP API (`anonymizer.api`), and Gunicorn (`gunicorn.conf.py`).
>
> Loading uses the project's own dependency-free loader (`anonymizer.config.load_env_file`); the `python-dotenv` package is not used.

Filling in `.env` is all that is required — no shell variables need to be set by hand.

Precedence rule: a variable that is already set in the real process environment (shell session, system environment variables, a process manager, or a container's injected secrets) always **wins**; the `.env` line for it is ignored. The file only fills in what is missing.

`.env` is excluded from Git via `.gitignore`, so real secrets are never committed.

---

### 3. Run the Service

Choose either the CLI or HTTP API.

#### Option A: CLI

The CLI processes a file or folder and then exits. It is suitable for local and batch processing.

```powershell
python .\run_anonymizer.py --file "C:\absolute\path\to\decision.docx"
```

#### Option B: HTTP API

The HTTP API runs as a persistent service that other systems can call.

```powershell
uvicorn anonymizer.api:app --reload
```

Both modes read the following configuration resources:

* `config/policy.yaml`
* `config/regex_patterns.yaml`
* `config/allowlists/`

These paths are resolved relative to the current working directory.

Run the commands from the project root, next to this README, so that the `config/` directory resolves correctly.

---

## Configuration Reference

All application configuration is provided through environment variables.

| Variable                     |   Default | Required                    | Purpose                                                                       |
| ---------------------------- | --------: | --------------------------- | ----------------------------------------------------------------------------- |
| `ANON_PROVIDER`              |  `openai` | No                          | Selects the LLM provider. Supported values: `openai` or `azure`.              |
| `OPENAI_API_KEY`             |         — | When `ANON_PROVIDER=openai` | OpenAI API key.                                                               |
| `ANON_MODEL`                 |         — | When `ANON_PROVIDER=openai` | OpenAI model handle.                                                          |
| `AZURE_OPENAI_API_KEY`       |         — | When `ANON_PROVIDER=azure`  | Azure OpenAI API key.                                                         |
| `AZURE_OPENAI_ENDPOINT`      |         — | When `ANON_PROVIDER=azure`  | Azure OpenAI endpoint URL.                                                    |
| `ANON_AZURE_DEPLOYMENT`      |         — | When `ANON_PROVIDER=azure`  | Azure OpenAI deployment name.                                                 |
| `ANON_AZURE_API_VERSION`     |         — | When `ANON_PROVIDER=azure`  | Azure OpenAI API version.                                                     |
| `ANON_API_KEY`               |         — | To serve the HTTP API       | Bearer credential for `POST /anonymize`. The API refuses to start without it; the CLI does not use it. |
| `ANON_LLM_TIMEOUT_S`         |      `60` | No                          | Per-call LLM timeout in seconds.                                              |
| `ANON_CHUNK_SIZE_CHARS`      |    `3000` | No                          | Paragraph chunk size in characters. Tables are always processed as one chunk. |
| `ANON_MAX_COMPLETION_TOKENS` |    `2000` | No                          | Maximum number of tokens the model may generate per LLM call.                 |
| `ANON_LLM_CONCURRENCY`       |       `8` | No                          | How many document chunks are processed by the LLM in parallel (each chunk still runs pass 1 → pass 2 in order). Lower it if you hit 429 rate limits. |
| `ANON_LOG_LEVEL`             |    `INFO` | No                          | Root logging level.                                                           |
| `ANON_MAX_UPLOAD_MB`         |      `20` | No                          | Maximum accepted upload size in megabytes. API only.                          |
| `ANON_HOST`                  | `0.0.0.0` | No                          | API bind host, consumed by `gunicorn.conf.py`.                                |
| `ANON_PORT`                  |    `8000` | No                          | API bind port, consumed by `gunicorn.conf.py`.                                |
| `WEB_CONCURRENCY`            |       `2` | No                          | Gunicorn worker count, consumed by `gunicorn.conf.py`.                        |
| `ANON_GUNICORN_TIMEOUT`      |     `900` | No                          | Gunicorn worker timeout in seconds.                                           |
| `ANON_GRACEFUL_TIMEOUT`      |     `900` | No                          | Gunicorn graceful-shutdown timeout in seconds.                                |

### Completion Token Limit

Each LLM call must return a JSON array of detected spans.

Large or densely redacted chunks may contain many candidate spans. If `ANON_MAX_COMPLETION_TOKENS` is too low, the response may be truncated in the middle of the JSON array. A truncated second pass is retried once and then fails the document (see [Pass-2 Completeness](#pass-2-completeness)), so a value that is too low shows up as `502` responses rather than as quietly thinner redaction.

Increase `ANON_MAX_COMPLETION_TOKENS` for:

* Long documents.
* Documents containing many personal identifiers.
* Documents requiring extensive redaction.

### Gunicorn-Only Variables

The following variables are read directly by `gunicorn.conf.py`, rather than by the application:

* `ANON_HOST`
* `ANON_PORT`
* `WEB_CONCURRENCY`
* `ANON_GUNICORN_TIMEOUT`
* `ANON_GRACEFUL_TIMEOUT`

They only affect the API when it is run in production through Gunicorn. `gunicorn.conf.py` loads the project `.env` before reading them, so setting them in `.env` works the same as for the application variables.

---

## Running as a CLI

`run_anonymizer.py`, located in the project root, contains the entire command-line interface.

Deleting this file removes the CLI without requiring changes to any other file.

### Process One File

The redacted output is written next to the input file as `decision_redacted.docx`.

```powershell
python .\run_anonymizer.py --file "C:\absolute\path\to\decision.docx"
```

### Process a Folder

Processes all `.docx` files in the specified folder.

Folder processing is non-recursive.

```powershell
python .\run_anonymizer.py `
    --file "C:\absolute\path\to\folder_of_docx" `
    --out-dir .\redacted
```

### Print Every Residual-Leak Finding

The residual-leak scan always runs — see
[The Post-Redaction Scan](#the-post-redaction-scan). `--qa` only prints every
finding it produced instead of the one-line summary.

```powershell
python .\run_anonymizer.py `
    --file "C:\absolute\path\to\decision.docx" `
    --qa
```

### Print the Counts-Only Summary

Prints each document's counts-only summary as a JSON line.

```powershell
python .\run_anonymizer.py `
    --file "C:\absolute\path\to\decision.docx" `
    --summary-json
```

### Use a Positional Path

A relative or absolute positional path can be used instead of `--file`.

```powershell
python .\run_anonymizer.py .\decision.docx
```

### CLI Flags

| Flag                 | Meaning                                                                                                                               |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `--file <path>`      | A `.docx` file or a folder containing `.docx` files. The path may be absolute or relative.                                            |
| `input`              | Positional alternative to `--file`. Provide exactly one of `input` or `--file`.                                                       |
| `--out-dir <dir>`    | Directory where redacted files are written. By default, each output is written next to its input file.                                |
| `--config-dir <dir>` | Directory containing `policy.yaml`, `regex_patterns.yaml`, and `allowlists/`. Defaults to the `config/` directory next to the script. |
| `--qa`               | Prints every finding of the post-redaction residual-leak scan. The scan always runs; this flag only makes it verbose.                 |
| `--summary-json`     | Prints each document's counts-only summary as one JSON line.                                                                          |

### CLI Output

For each input file named:

```text
name.docx
```

The CLI creates:

```text
name_redacted.docx
```

The output is written either:

* Next to the input file.
* Inside the directory specified by `--out-dir`.

Nothing is printed to standard output except:

* Progress and status lines.
* Optional `--qa` findings.
* Optional `--summary-json` output.

### Exit Codes

| Code | Meaning                                                                                                                            |
| ---: | ---------------------------------------------------------------------------------------------------------------------------------- |
|  `0` | Every document was processed successfully and passed its post-redaction scan.                                                      |
|  `1` | At least one document failed to process.                                                                                           |
|  `2` | Usage error: no input was provided, both input forms were provided, the input path does not exist, or no `.docx` files were found. |
|  `3` | Configuration error caused by missing or invalid environment variables or configuration files.                                     |
|  `4` | Every other document succeeded, but at least one was blocked by the mandatory post-redaction scan and needs manual review. No file is written for a blocked document. |
| `130` | The run was interrupted by the user (Ctrl+C).                                                                                      |

---

## Running as an HTTP API

### Production

```bash
gunicorn anonymizer.api:app -c gunicorn.conf.py
```

### Development

```bash
uvicorn anonymizer.api:app --reload
```

---

## Pass-2 Completeness

The second LLM pass is the only producer of LLM spans, so its answer has to be
both readable and complete. Every response is validated before it is used:

* it must parse as a JSON array;
* each item is checked on its own — a non-object, an empty `text`, an unknown
  `action`, or a category outside the schema (after alias resolution) is dropped
  rather than guessed at;
* every span the deterministic rules flagged `REVIEW` for that chunk must come
  back with a final `REDACT` or `PRESERVE`. `SKIP`, or simply not mentioning it,
  does not count: a `REVIEW` span is text the rules could not decide, so an
  omission is a missing decision, not a safe one.

A response that fails any of these is **retried once**, with the rejection
reason and the still-undecided texts named in the retry message. If the retry
also fails, processing of that document stops with `AIProviderError` (`502` over
HTTP) instead of releasing a document with a decision missing.

Deterministic redactions are independent of all this: rule-based `REDACT` spans
stay in the final plan whether or not the model repeats them.

---

## The Post-Redaction Scan

Every document is scanned after it is redacted and before anything is returned
or saved. The scan is part of `anonymize_document`, so it runs identically for
the CLI and the API and there is no flag that turns it off:

```text
receive DOCX -> anonymize DOCX -> scan the anonymized DOCX -> release it only
                                  when no HIGH finding remains
```

It is a final check of the produced file for personal information that may still
be visible — an AFM with a valid checksum, an AMKA, an IBAN, a private email,
surviving tracked changes or document properties, and similar. It contacts
nothing and sends nothing anywhere.

**A HIGH-severity finding blocks the document.** The pipeline raises
`ResidualPIIError`; the file is not returned by the API and not written by the
CLI, and the document is reported as needing manual review. The message names
the finding kinds and their locations but never the matched text.

**Lower-severity findings do not block.** They are reported alongside the file:

| Where | How the findings appear |
| ----- | ----------------------- |
| API, default response | `X-Postcheck-Findings` (total) and `X-Postcheck-Kinds` (`kind=count,…`) headers |
| API, `?summary=1` | the full `postcheck` object in the JSON body |
| CLI | a one-line summary in `warnings`; `--qa` prints every finding |
| Library | `result.postcheck`, a `PostcheckSummary` |

---

## API Endpoints

### Authentication

Every `POST /anonymize` request must carry the API key as a bearer token:

```http
Authorization: Bearer <ANON_API_KEY>
```

The value is compared with `ANON_API_KEY` in constant time. A missing,
malformed, or incorrect credential returns `401` with
`WWW-Authenticate: Bearer` and the body `{"detail": "missing or invalid API key"}`
— the document is never read or processed, and the expected key never appears in
a response or a log line.

The service **refuses to start** when `ANON_API_KEY` is unset, so `/anonymize` is
never exposed without authentication. Generate a key with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`GET /healthz` is deliberately unauthenticated so another service can probe
liveness.

### `POST /anonymize`

Anonymizes an uploaded DOCX document.

The endpoint accepts the document in either of the following formats.

#### Multipart Upload

Send the document as `multipart/form-data` using a field named `file`.

#### Raw Request Body

Send the DOCX bytes directly in the request body using one of these content types:

```http
Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document
```

or:

```http
Content-Type: application/octet-stream
```

### Default Response

By default, the endpoint returns the redacted DOCX as a file attachment.

```http
Content-Disposition: attachment; filename="<document_id>_redacted.docx"
```

### JSON Summary Response

Add the following query parameter:

```text
?summary=1
```

The endpoint then returns JSON:

```json
{
  "document_id": "...",
  "summary": {
    "...": "..."
  },
  "warnings": [
    "..."
  ],
  "model": "...",
  "postcheck": {
    "clean": true,
    "findings_total": 0,
    "by_severity": {},
    "by_kind": {},
    "findings": []
  },
  "provenance": {
    "...": "..."
  },
  "docx_base64": "..."
}
```

`postcheck` is the mandatory post-redaction scan of the returned file. It can
only ever contain non-HIGH findings — see
[The Post-Redaction Scan](#the-post-redaction-scan).

---

### `GET /healthz`

Returns the configured provider and model without contacting the provider. No
credential is required and none is exposed.

```json
{
  "status": "ok",
  "provider": "openai",
  "model": "..."
}
```

---

## Calling the API from Another Application

A calling application needs three things: the API address, an API key, and the
DOCX file. The stable contract is one request:

```http
POST /anonymize
Authorization: Bearer <ANON_API_KEY>
Content-Type: multipart/form-data
file=<DOCX file>
```

The response body is the anonymized DOCX. Nothing else about the request is
required — no query parameters, no other headers.

Both the API and the CLI call the same `anonymize_document` pipeline on the same
bytes, so a document anonymized over HTTP is byte-for-byte the document the CLI
would have produced from the same input (`tests/test_api_contract.py` asserts
this).

### curl

```bash
curl -f -X POST http://localhost:8000/anonymize   -H "Authorization: Bearer $ANON_API_KEY"   -F "file=@decision.docx"   -o decision_redacted.docx
```

`-f` makes curl exit non-zero on an error status instead of writing the JSON
error body into the output file.

### Python

```python
import os

import requests

with open("decision.docx", "rb") as fh:
    response = requests.post(
        "http://localhost:8000/anonymize",
        headers={"Authorization": f"Bearer {os.environ['ANON_API_KEY']}"},
        files={"file": ("decision.docx", fh, DOCX_MIME)},
        timeout=900,
    )
response.raise_for_status()

with open("decision_redacted.docx", "wb") as out:
    out.write(response.content)
```

`DOCX_MIME` is
`application/vnd.openxmlformats-officedocument.wordprocessingml.document`.
Use a generous timeout: a long decision runs several LLM calls, so a request can
take minutes.

A complete, dependency-free version of the same client (standard library only)
is in [`examples/anonymize_client.py`](examples/anonymize_client.py):

```bash
python examples/anonymize_client.py   --url http://localhost:8000   --api-key "$ANON_API_KEY"   --file decision.docx   --out decision_redacted.docx
```

It also reads the key from the `ANON_API_KEY` environment variable when
`--api-key` is omitted, so the credential need not appear in a shell history or
a process list.

### Returned Filename

The `Content-Disposition` filename is built from the server-generated
`document_id`, never from the uploaded filename — an uploaded name such as
`ΠΑΠΑΔΟΠΟΥΛΟΣ_ΓΕΩΡΓΙΟΣ.docx` is itself personal information and is never echoed
back. Callers that need their own name should use the path they uploaded from.

---

## Error Responses

Typed application errors and the internal-error catch-all use this response format:

```json
{
  "error": "<ExceptionClassName>",
  "detail": "<message>"
}
```

The `401`, `413`, and `415` guards are raised as FastAPI `HTTPException` instances and use FastAPI's default response format:

```json
{
  "detail": "..."
}
```

### HTTP Status Codes

| Status | Condition                                                                                               |
| -----: | ------------------------------------------------------------------------------------------------------- |
|  `400` | `InvalidDocumentError`: empty body, missing `file` field, an invalid, corrupt, or non-DOCX upload, or a package whose `word/document.xml` does not strictly parse as a Word document. |
|  `401` | Missing, malformed, or incorrect `Authorization: Bearer <ANON_API_KEY>` header. The document is not processed. |
|  `413` | The upload exceeds `ANON_MAX_UPLOAD_MB`.                                                                |
|  `415` | Unsupported `Content-Type`.                                                                             |
|  `503` | The server has no `ANON_API_KEY` configured (unreachable through normal startup, which fails instead).  |
|  `422` | `DocumentProcessingError`: the DOCX is valid, but a redaction plan could not be produced or applied.    |
|  `422` | `ResidualPIIError`: the document was redacted, but the mandatory scan still found HIGH-severity personal information. No document is returned; it needs manual review. |
|  `500` | Unexpected internal error. No exception text or traceback is exposed.                                   |
|  `502` | `AIProviderError`: provider API failure, or model output that was unusable or still incomplete after one retry. |
|  `503` | `ConfigurationError` or `AIUnavailableError`: invalid runtime configuration or an unreachable provider. |
|  `504` | `AITimeoutError`: the per-call LLM timeout was exceeded.                                                |

For unexpected internal errors, the response body is always:

```json
{
  "error": "InternalServerError",
  "detail": "internal error"
}
```
