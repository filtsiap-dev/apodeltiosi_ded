# ded-anonymizer (Java)

Anonymizes Greek ΑΑΔΕ / ΔΕΔ tax-decision documents (`.docx`). Personal data (names, ΑΦΜ,
ΑΜΚΑ, IBAN, e-mails, private addresses, case identifiers …) is replaced character for
character with `.`, so layout and length are unchanged. Every output passes a mandatory
residual-PII scan first: a document that still contains high-severity personal data is
**never** written or returned.

Pipeline: validate → parse DOCX → deterministic detectors → two-pass LLM review →
resolve → length-preserving write-back → metadata cleanup (author, comments, tracked
changes, hidden text, custom properties) → residual-PII scan.

## Requirements

- JDK 21, Maven 3.9+
- An OpenAI or Azure OpenAI deployment (the LLM stage is mandatory)

## Build

```
mvn verify          # compile + 67 unit tests
mvn package         # target/ded-anonymizer-2.0.0.jar, dependencies in target/lib
```

Ship `target/ded-anonymizer-2.0.0.jar` together with `target/lib/` and the `config/` folder.

## Command line

```
java -jar target/ded-anonymizer-2.0.0.jar decision.docx
java -jar target/ded-anonymizer-2.0.0.jar --file C:\decisions --out-dir redacted --qa --summary-json
```

A folder is processed non-recursively; outputs are named `<name>_redacted.docx`.
`--qa` prints the scan's non-blocking findings; `--summary-json` prints counts only.

Exit codes: `0` all done · `1` a document failed · `2` usage error · `3` configuration error ·
`4` a document was blocked by the residual-PII scan and needs manual review · `130` interrupted.

## HTTP service

```
java -cp target/ded-anonymizer-2.0.0.jar dev.filtsiap.ded.api.ApiServer
```

| Endpoint | |
|---|---|
| `POST /anonymize` | `Authorization: Bearer <ANON_API_KEY>`; multipart field `file`, or a raw DOCX / `application/octet-stream` body. Returns the redacted DOCX (`X-Postcheck-Findings`, `X-Postcheck-Kinds` headers), or JSON with the file in base64 when `?summary=1`. |
| `GET /healthz` | unauthenticated liveness probe |

Errors are JSON `{"error": "<Type>", "detail": "..."}`: 400 invalid document, 422 blocked by the
scan or unprocessable, 502 provider error, 503 provider unreachable / configuration, 504 LLM timeout.
The service refuses to start without `ANON_API_KEY`.

## Configuration

Environment variables, or a `.env` file (next to the application and/or in the working
directory; real environment variables win). Never commit `.env`.

| Variable | Default | |
|---|---|---|
| `ANON_PROVIDER` | `openai` | `openai` or `azure` |
| `OPENAI_API_KEY`, `ANON_MODEL` | — | required for `openai` |
| `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `ANON_AZURE_DEPLOYMENT`, `ANON_AZURE_API_VERSION` | — | required for `azure` |
| `OPENAI_BASE_URL`, `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID` | — | optional, as in the OpenAI SDKs |
| `ANON_API_KEY` | — | bearer token for the HTTP service |
| `ANON_LLM_TIMEOUT_S` | `60` | per LLM call (connect / read / write) |
| `ANON_CHUNK_SIZE_CHARS` | `3000` | text per LLM request |
| `ANON_MAX_COMPLETION_TOKENS` | `2000` | |
| `ANON_LLM_CONCURRENCY` | `8` | parallel LLM requests per document |
| `ANON_MAX_UPLOAD_MB` | `20` | HTTP upload limit |
| `ANON_LOG_LEVEL` | `INFO` | HTTP service: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `ANON_HOST`, `ANON_PORT` | `0.0.0.0`, `8000` | HTTP service bind address |
| `ANON_GRACEFUL_TIMEOUT` | `900` | seconds in-flight requests get on shutdown |

Detection rules live in `config/`: `policy.yaml` (confidence thresholds, categories that are
always kept or always redacted, public e-mail domains), `regex_patterns.yaml` (pattern
overrides) and `allowlists/` (tax offices, public services, legal abbreviations). Their
sha256 is stamped into every result's provenance.

## Where this code comes from

This branch is the Java application on its own. It is a port of the Python implementation
on the `java` branch, where it is verified against that implementation output for output
(`parity/`). Four files are generated from the Python sources there and must not be edited
by hand: `DetectorPatterns`, `PostcheckPatterns`, `llm/PromptText`, `IbanRegistry`. Change
detection rules or prompts on the `java` branch and regenerate. The design decisions and the
few deliberate differences from Python are recorded in `CLAUDE.md` on that branch.
