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

Large or densely redacted chunks may contain many candidate spans. If `ANON_MAX_COMPLETION_TOKENS` is too low, the response may be truncated in the middle of the JSON array and fail to parse.

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

### Run the Residual-Leak Audit

Runs the out-of-band post-processing audit and prints its findings.

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
| `--qa`               | Runs the out-of-band residual-leak audit and prints its findings.                                                                     |
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
|  `0` | Every document was processed successfully. When `--qa` is enabled, no HIGH-severity findings were detected.                        |
|  `1` | At least one document failed to process.                                                                                           |
|  `2` | Usage error: no input was provided, both input forms were provided, the input path does not exist, or no `.docx` files were found. |
|  `3` | Configuration error caused by missing or invalid environment variables or configuration files.                                     |
|  `4` | All documents were processed, but `--qa` detected HIGH-severity residual findings.                                                 |
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

## API Endpoints

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
  "docx_base64": "..."
}
```

---

### `GET /healthz`

Returns the configured provider and model without contacting the provider.

```json
{
  "status": "ok",
  "provider": "openai",
  "model": "..."
}
```

---

## Error Responses

Typed application errors and the internal-error catch-all use this response format:

```json
{
  "error": "<ExceptionClassName>",
  "detail": "<message>"
}
```

The `413` and `415` guards are raised as FastAPI `HTTPException` instances and use FastAPI's default response format:

```json
{
  "detail": "..."
}
```

### HTTP Status Codes

| Status | Condition                                                                                               |
| -----: | ------------------------------------------------------------------------------------------------------- |
|  `400` | `InvalidDocumentError`: empty body, missing `file` field, or an invalid, corrupt, or non-DOCX upload.   |
|  `413` | The upload exceeds `ANON_MAX_UPLOAD_MB`.                                                                |
|  `415` | Unsupported `Content-Type`.                                                                             |
|  `422` | `DocumentProcessingError`: the DOCX is valid, but a redaction plan could not be produced or applied.    |
|  `500` | Unexpected internal error. No exception text or traceback is exposed.                                   |
|  `502` | `AIProviderError`: provider API failure or unusable model output.                                       |
|  `503` | `ConfigurationError` or `AIUnavailableError`: invalid runtime configuration or an unreachable provider. |
|  `504` | `AITimeoutError`: the per-call LLM timeout was exceeded.                                                |

For unexpected internal errors, the response body is always:

```json
{
  "error": "InternalServerError",
  "detail": "internal error"
}
```
