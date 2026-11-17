# ded-anonymizer (Java)

Anonymizes Greek ΑΑΔΕ / ΔΕΔ tax-decision documents (`.docx`). Personal data (names, ΑΦΜ,
ΑΜΚΑ, IBAN, e-mails, private addresses, case identifiers …) is replaced character for
character with `.`, so layout and length are unchanged. Every output goes through a mandatory
residual-PII scan. Located initial-scan findings in document text (a surviving ΑΦΜ, phone, name,
property identifier …) are put back to the LLM's adjudicating pass against the redacted document,
and its answers are applied. A HIGH-severity text finding (ΑΦΜ, ΑΜΚΑ, IBAN, e-mail, property
identifier) is settled only by being redacted: if the model answers PRESERVE, the file keeps the
value as it decided but comes back `needs-review`. A HIGH finding without a text span (a macro,
tracked change, comment, or placeholder left by the write path) stops the document, and nothing
is written or returned. MEDIUM package warnings remain visible in the audit.

Pipeline: validate → parse DOCX → prompt-injection screen → deterministic detectors → two-pass
LLM review (a REDACT the model draws is narrowed to its value) → resolve → length-preserving
write-back → metadata cleanup (author, comments, tracked changes, hidden text, custom
properties) → residual-PII scan → remediation (LLM pass 2 only, over the redacted text; resolve;
write-back) → deterministic final scan when remediation writes. There is one remediation round;
the final scan never calls a model.

## What is and is not guaranteed

**In scope:** the text of the body, tables, headers, footers, footnotes and endnotes. Both
detection paths read it and it is redacted in place.

**Out of scope, as in v2:** the package *surface*. Document properties other than those cleaned
below (`docProps/core.xml` subject and description), hyperlink targets (a `mailto:` behind a
redacted link text keeps the address), custom XML parts and field codes are not anonymized, and
personal data there survives into the output. Strip it before or after this service if your
documents carry it there.

Unlike v2, which keeps `dc:creator` and `cp:lastModifiedBy` because the published golds do, this
application blanks both, together with title, keywords and category.

## Requirements

- JDK 24 (what CI tests and the Docker image runs; the code compiles for 21), Maven 3.9+
- An OpenAI or Azure OpenAI deployment (the LLM stage is mandatory)

## Build

```
mvn verify          # compile + unit tests
mvn clean verify    # target/ded-anonymizer-2.0.0.jar, dependencies included in the shaded JAR
```

Ship `target/ded-anonymizer-2.0.0.jar` together with the `config/` folder. The manifest entrypoint is the HTTP server.

## Command line

```
java -cp target/ded-anonymizer-2.0.0.jar dev.filtsiap.ded.RunAnonymizer decision.docx
java -cp target/ded-anonymizer-2.0.0.jar dev.filtsiap.ded.RunAnonymizer --file C:\decisions --out-dir redacted --qa --summary-json
```

A folder is processed non-recursively; outputs are named `<name>_redacted.docx`.
`--qa` prints findings for the returned bytes. Audit references `P<n>` identify the initial scan; `F<n>` identify the final scan. They carry their scan phase, kind and location and are not interchangeable QA row numbers. `--summary-json` prints one JSON
line per document with counts, ids and kinds only, never document text: the plan summary, status,
the unresolved findings (kind, category, location, and the scan finding behind each), provenance,
stage timings, the LLM ledger (`llm_usage`) and the cost accounting (`accounting`, see below).

Exit codes: `0` all done · `1` a document failed · `2` usage error · `3` configuration error ·
`4` a document was blocked by a non-text scan finding and needs manual review · `5` a document ran
out of its processing budget (`ANON_DOCUMENT_DEADLINE_S`; nothing is written for it) ·
`130` interrupted. With several documents the lowest of `1`, `5`, `4` that occurred wins.

## HTTP service

```
java -cp target/ded-anonymizer-2.0.0.jar dev.filtsiap.ded.api.ApiServer
```

| Endpoint | |
|---|---|
| `POST /anonymize` | `Authorization: Bearer <ANON_API_KEY>`, `Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document`, the raw `.docx` bytes as the body. Returns `200` with the redacted DOCX bytes as the body: no form, no field name, no JSON, no base64. Any other content type (`multipart/form-data` and `application/octet-stream` included) is refused with `415`. |
| `GET /healthz` | unauthenticated liveness probe: `{"status", "provider", "model"}` |

```
curl.exe -X POST http://localhost:8000/anonymize -H "Authorization: Bearer $key" -H "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document" --data-binary "@decision.docx" -D headers.txt -o decision_redacted.docx
```

Response headers on success (ids, an enum and counts only, never document text):

| Header | Value |
|---|---|
| `X-Document-ID` | opaque per-document id (not the filename), also returned on errors after authentication; pipeline/final logs use it |
| `X-Anonymization-Status` | `processed`, or `needs-review`: the file is complete but a person must check the unresolved locations (from the LLM review or its post-scan remediation) before publishing |
| `X-Unresolved-Count` | integer |
| `X-LLM-Fallback-Used` | `true`, only when LLM pass 2 was unavailable for some candidates after its retries and the documented fallback decided them (or left them undecided); always with `needs-review`. Absent otherwise |
| `X-Postcheck-Findings`, `X-Postcheck-Kinds` | the deterministic scan of the returned bytes, e.g. `phone_shape=1` |
| `X-Processing-Time-Ms`, `X-LLM-Time-Ms` | elapsed since authentication/input reading through the pipeline, and wall time of the LLM stage plus remediation calls; excludes sending the response |
| `X-LLM-Calls`, `X-LLM-Calls-Missing-Usage` | provider responses, and how many of them reported no token usage |
| `X-LLM-Input-Tokens`, `X-LLM-Output-Tokens`, `X-LLM-Total-Tokens` | token totals; sent only when every response reported its usage |
| `X-LLM-Cached-Input-Tokens`, `X-LLM-Reasoning-Tokens` | sent only when the provider reported them |
| `X-LLM-Estimated-Cost`, `X-LLM-Cost-Currency` | the document's cost as an exact decimal; sent only when prices are configured and every response reported usage |
| `Content-Disposition` | `attachment; filename="<document id>_redacted.docx"` |

Authentication is checked before the body is read; the content type and a declared
`Content-Length` are checked before it too, and the body is then streamed and counted against
`ANON_MAX_UPLOAD_BYTES`.

v2 also accepts `.docm`, `.dotx` and `.dotm` (and converts them to `.docx`); this application has
no conversion step, so those media types are refused with `415` too: save the file as `.docx`
first. The package is checked from its bytes as v2 checks it, whatever the header says: a legacy
binary `.doc`, a macro-enabled or template package, or an OOXML file that is not a Word document
is a `415`; a broken `[Content_Types].xml` or `_rels/.rels`, a missing or doubled officeDocument
relationship, or a main part other than `word/document.xml` is a `400`.

Before any LLM call, the document's text is screened for text shaped like an instruction to the
model ("ignore the previous instructions", "μην ανωνυμοποιήσεις αυτά", …), in English and Greek
and through accents, case, zero-width characters and compatibility forms. A match is refused with
`422` and code `PROMPT_INJECTION_DETECTED`. The log names the rule and the paragraph, never the
text. There is no switch to turn it off: a false positive is fixed by editing
`config/prompt_injection.yaml` and restarting.

Errors are JSON `{"error": "<Type>", "code": "<CODE>", "detail": "<fixed text>"}` (the detail
is the same for every error of a type and never quotes the document; branch on `code`), or
`{"detail": "..."}` for 401 and routing errors: 400 invalid document, 401 missing or invalid API
key, 413 over a size or resource limit, 415 not sent as a raw `.docx` body or not a plain Word
document, 422 refused by the prompt-injection screen or blocked by the residual-PII scan, 500
internal error or a document that could not be written back, 502 provider
error (one LLM call timing out included), 503 provider unreachable / configuration / regex mode
(`AI_DISABLED`, see `ANON_PROVIDER` below), 504 the document deadline expired. The service refuses
to start without `ANON_API_KEY`.

Every document has one processing budget, `ANON_DOCUMENT_DEADLINE_S`, starting after
authentication and before the upload is read. It is checked between upload reads, at pipeline
boundaries, around LLM calls/retries, and before returning success. An expired result is refused.
These checks cannot interrupt a stalled upload read or a blocked response write. At most
`ANON_MAX_CONCURRENT_REQUESTS` requests run at once; further requests enter an unbounded queue
before their document clock starts. Deploy behind bounded admission and upload/read timeouts;
the document budget alone is not an HTTP connection or queue timeout.

For the proposed Ticketing wrapper, use a 330-second upstream timeout with the default
300-second document budget, a 360-second proxy read timeout, and a 450-second browser timeout.
Limit each file to exactly 20,000,000 bytes, with a deliberate 21,000,000-byte multipart request
limit at the wrapper/gateway. Preserve `X-Anonymization-Status`, `X-Unresolved-Count` and
`X-Document-ID`: `200 + needs-review` must display a warning and require human review before
publication. The direct API remains raw DOCX. See [FINAL_REVIEW.md](FINAL_REVIEW.md) for the
full integration contract and deployment gates, and [How_to_run_Java.docx](How_to_run_Java.docx)
for the operational guide.

### POST /anonymize-text

Masks personal data in plain text (chatbot conversation logs). No LLM is called.

```bash
curl -s -X POST http://localhost:8000/anonymize-text \
  -H "Authorization: Bearer $ANON_API_KEY" \
  -H "Content-Type: text/plain; charset=utf-8" \
  --data-binary "Καλησπέρα, με λένε Γιώργο Παπαδόπουλο, ΑΦΜ 090000045"
```

The response is the same text with every masked character replaced by `.`. It has the same
length, in Unicode code points, as the input after NFC normalisation (a leading BOM is dropped),
and whitespace is kept.

Location information is not masked (owner decision 2026-10-14): an area ("μένω στο Μαρούσι"), a
tax office ("ΔΟΥ Κηφισιάς"), a street address ("Αμοργού 4") and a postal code stay visible. The name
rule may still mask a place that looks like a name or is not an ordinary word ("Ζωγράφου", "Αθήνα").

After an ID's name (ΑΦΜ, ΑΜΚΑ, ΑΔΤ/ταυτότητα, διαβατήριο, τηλ/τηλέφωνο/κινητό, IBAN, and their Latin
forms) the next number is masked whatever its length or checksum ("ΑΜΚΑ 123456", "ΑΔΤ ΑΚ 12345"), if at
most 25 characters with no digit and no line break lie between them; the cue word stays visible. So a
number that is not an ID is masked too when it follows such a word ("τηλ. στις 10:30" masks "10").

`anonymized` does not promise that nothing personal is left. A date of birth is masked only after a
birth cue ("γεννήθηκα", "ημ. γέννησης", "date of birth", "DOB"); other dates stay. Phone numbers
spelled in words and Greeklish are out of scope for v1 and are not detected, and the detectors are
measured, not proven (`eval/chat-anonymization/`).

| Header | Meaning |
|---|---|
| `x-anonymization-status` | `anonymized`, or `needs-review` when a safety net fired; check `x-review-reasons` |
| `x-redaction-counts` | `PERSON=2,AFM=1`, or `none`: masked regions per type, so a first name and a surname count as two `PERSON`; not a count of people |
| `x-review-reasons` | Only on `needs-review`: `residual:<pattern>`, `ner_unavailable` |
| `x-document-id`, `x-processing-time-ms` | As on `/anonymize` |

Errors:
- 401: auth.
- 415: not `text/plain`, or a charset other than UTF-8.
- 400: invalid UTF-8.
- 413: more than `ANON_MAX_TEXT_CHARS` characters.
- 503: the chat pipeline is not configured on this server, or the server is shutting down.
- 504: the document deadline (`ANON_DOCUMENT_DEADLINE_S`) expired.

Errors raised by the anonymizer carry `code` (e.g. `INVALID_UTF8`, `TEXT_TOO_LARGE`,
`UPLOAD_TOO_LARGE`); the human-readable `detail` text is shared with `/anonymize`. HTTP-level
errors (401, 404/405, and the 503 of a server that is shutting down) carry only `detail`, and a 500
that escapes the endpoint's own handling carries only `error` and `detail`. The 503 for a missing
chat pipeline is an anonymizer error and carries `code` `CONFIGURATION_ERROR`.

### POST /anonymize-log

Masks the `user_query` of one chatbot log entry. The body is ONE JSON object
(`Content-Type: application/json`, charset absent or UTF-8); the answer is the same body with only
the string value of the top-level key `"user_query"` masked by the same rules as `/anonymize-text`.
Every other byte comes back unchanged: field order, whitespace, number formatting, escapes in other
strings and unknown fields. A `user_query` nested inside another object is not touched.

```bash
curl -s -X POST http://localhost:8000/anonymize-log \
  -H "Authorization: Bearer $ANON_API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @entry.json
```

- A missing or `null` `user_query` returns the body unchanged, `anonymized`, counts `none`.
- A `user_query` that is not a string (number, object, array, boolean) returns the body unchanged
  with `needs-review` and `x-review-reasons: user_query_not_a_string`.
- If `user_query` appears twice at the top level, both values are masked.
- A body that starts with a UTF-8 BOM is accepted, and the BOM is kept in the answer.
- A query with nothing masked keeps its original bytes: its JSON spelling (even `\uXXXX` escapes
  and `\/`) and its Unicode normalisation (a decomposed, non-NFC query is not rewritten).
- A query with something masked is replaced as a whole by the pipeline's output, which is the query
  in NFC with the masked characters turned into `.`. So in the rest of that value:
  - characters are NFC-normalised (`ε` followed by a combining acute accent becomes the single code point `έ`);
  - it is written as raw UTF-8: `\uXXXX` escapes and `\/` become the characters themselves;
  - only these are escaped: `"` as `\"`, `\` as `\\`, newline, carriage return and tab as `\n`,
    `\r`, `\t`, every other control character (U+0000-U+001F) as a lowercase `\u00xx`, and an
    unpaired surrogate as its lowercase `\uxxxx` (so `\ud83d` comes back as `\ud83d`).

The headers are those of `/anonymize-text` and describe the `user_query` result only. The body is
limited by `ANON_MAX_UPLOAD_BYTES` (a log entry carries pages of retrieved text); the decoded
`user_query` is limited by `ANON_MAX_TEXT_CHARS`.

Errors:
- 401: auth.
- 415: not `application/json`, or a charset other than UTF-8.
- 400: invalid UTF-8 (`INVALID_UTF8`), not valid JSON or more than one JSON value (`INVALID_JSON`),
  or valid JSON that is not an object (`NOT_A_JSON_OBJECT`). The JSON parser's default limits also
  answer `INVALID_JSON`: nesting deeper than 1000 levels, or a number longer than about 1000 digits.
- 413: body over `ANON_MAX_UPLOAD_BYTES` (`UPLOAD_TOO_LARGE`), or `user_query` over
  `ANON_MAX_TEXT_CHARS` characters (`TEXT_TOO_LARGE`).
- 503 / 504: as on `/anonymize-text`.

One `log_finished` line per request carries ids, outcome, status, time, body bytes and
`user_query` characters, never any body content.

Word lists live in `config/chat/`; their sources, licences and how to rebuild them are in
`config/chat/README.md`. Detection quality is measured on `eval/chat-anonymization/`. Design:
`docs/superpowers/specs/2026-10-09-chat-text-anonymizer-design.md`.

### Run in a container

```bash
docker compose up --build      # http://localhost:8000; stop with: docker compose down
```

`docker-compose.yml` builds the `Dockerfile` (which copies `config/`, so the chat word lists and their
licence notices ship in the image) and reads the `ANON_*` values from the `.env` next to it; `ANON_API_KEY`
is required. `POST /anonymize-text` and `POST /anonymize-log` never call an LLM, so the provider values
default to placeholders; only `POST /anonymize` (.docx) needs real ones. The service refuses to start (exit 3)
if `config/chat` is missing or corrupt.

### Bruno collection

`bruno/ded-anonymizer/` is a [Bruno](https://www.usebruno.com) collection for the two chat endpoints:
`/anonymize-text` (a masking request, a request with nothing to mask, 401, 415) and `/anonymize-log`
(masking only `user_query`, nothing to mask, a non-string `user_query`, invalid JSON, 401), plus `/healthz`.
Open the folder in Bruno, choose the **Local** environment and set the secret variable `apiKey` to your
`ANON_API_KEY` (`baseUrl` is `http://localhost:8000`). Every request has tests on the status, the headers
and the masked body. The samples are synthetic; do not paste real chat logs into the collection.

## Configuration

Environment variables, or a `.env` file (next to the application and/or in the working
directory; real environment variables win). Never commit `.env`.

| Variable | Default | |
|---|---|---|
| `ANON_PROVIDER` | `openai` | `openai`, `azure` or `regex`. `regex` needs no model keys: `/anonymize-text` and `/anonymize-log` work as usual, `/anonymize` answers 503 `AI_DISABLED` and logs `Error: AI model endpoint called while running in regex mode`, and the CLI prints that line and exits 3 |
| `OPENAI_API_KEY`, `ANON_MODEL` | — | required for `openai` |
| `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `ANON_AZURE_DEPLOYMENT`, `ANON_AZURE_API_VERSION` | — | required for `azure` |
| `OPENAI_BASE_URL`, `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID` | — | optional, as in the OpenAI SDKs |
| `ANON_API_KEY` | — | bearer token for the HTTP service |
| `ANON_LLM_TIMEOUT_S` | `60` | per LLM attempt: connect / read / write and total request cap, reduced to remaining document time |
| `ANON_CHUNK_SIZE_CHARS` | `7000` | paragraph text per LLM chunk (each table is its own chunk; a paragraph is never split) |
| `ANON_MAX_COMPLETION_TOKENS` | `3000` | a pass-2 answer cut off at this limit is not accepted |
| `ANON_LLM_CONTEXT_TOKENS` | — | optional: the deployed model's whole context window (input + completion), as you know it from the provider; never inferred from a model or deployment name. Unset, no whole-request check is made (startup logs that it is disabled). Set, startup refuses a value that cannot hold one ordinary request, and a pass-2 candidate that cannot fit even alone is not sent: it takes the pass-2-unavailable fallback (`cause=context_limit`) and is set aside for review. At most `100000000` |
| `ANON_LLM_CONCURRENCY` | `8` | parallel LLM requests per document |
| `ANON_DOCUMENT_DEADLINE_S` | `300` | cooperative document budget after admission/authentication (at most `86400`) |
| `ANON_MAX_UPLOAD_BYTES` | `20000000` | HTTP upload limit, in bytes (replaces `ANON_MAX_UPLOAD_MB`, which is no longer read) |
| `ANON_MAX_ZIP_MEMBERS` | `500` | parts in one DOCX package |
| `ANON_MAX_ZIP_MEMBER_BYTES` | `25000000` | expanded size of one part |
| `ANON_MAX_ZIP_TOTAL_BYTES` | `60000000` | expanded size of the whole package |
| `ANON_MAX_COMPRESSION_RATIO` | `50` | expansion ratio allowed for a part above the floor |
| `ANON_COMPRESSION_RATIO_FLOOR_BYTES` | `1000000` | parts up to this size are not ratio-checked |
| `ANON_MAX_TEXT_CHARS` | `400000` | characters of text in one document, enforced while the text is extracted |
| `ANON_MAX_CHUNKS` | `150` | LLM chunks per document |
| `ANON_MAX_XML_BYTES` | `10000000` | expanded size of the package's `.xml`/`.rels` parts together; the memory bound (Java-only), see [Memory](#memory) |
| `ANON_MEMORY_BUDGET_BYTES` | `0` | heap the documents in progress may reserve together; `0` = 60% of the maximum heap, see [Memory](#memory) |
| `ANON_LOG_LEVEL` | `INFO` | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG` or `NOTSET`, any case |
| `ANON_HOST`, `ANON_PORT` | `0.0.0.0`, `8000` | HTTP service bind address |
| `ANON_GRACEFUL_TIMEOUT` | `120` | whole-second shutdown budget, `0`–`120`; see [Shutdown](#shutdown) (a larger value, such as v2's `900`, is capped at `120` with a startup warning) |
| `ANON_MAX_CONCURRENT_REQUESTS` | `40` | HTTP requests processed at once (Java-only; the Python service's bound is its 40 worker threads per process) |
| `ANON_INPUT_COST_PER_1M_TOKENS`, `ANON_OUTPUT_COST_PER_1M_TOKENS` | — | your prices per million prompt / completion tokens, as decimals; set both or neither |
| `ANON_CACHED_INPUT_COST_PER_1M_TOKENS` | — | optional price for prompt tokens served from the provider's cache |
| `ANON_COST_CURRENCY` | `USD` | ISO 4217 code the prices above are in |

Numbers must be finite and greater than zero (`ANON_LLM_TIMEOUT_S` at most `3600`,
`ANON_CHUNK_SIZE_CHARS` `200000`, `ANON_MAX_COMPLETION_TOKENS` `1000000`, `ANON_LLM_CONCURRENCY`
`64`), and the limits must be coherent (a part no larger than the package, the upload no larger
than the package, the XML parts no larger than the package, the ratio floor no larger than a part). Prices must be non-negative decimals of
at most `1000000`. Anything else stops startup with a `configuration error`, as does a regex
override that does not compile where it is used.

### Shutdown

On SIGTERM or Ctrl+C the HTTP service finishes within `ANON_GRACEFUL_TIMEOUT` seconds (1 s for
`0`), however busy it is:

1. It stops admitting: the listening socket closes, and a request that reaches it afterwards (a
   keep-alive connection's next request, or one still queued for a worker) gets
   `503 {"detail":"the server is shutting down"}` and is never processed.
2. With no request in progress it exits at once. Idle keep-alive connections are not work.
3. Otherwise requests in progress may finish for the budget minus a cleanup reserve (half the
   budget, at least 1 s and at most 5 s: 115 s of the default 120 s). The service exits as soon as
   the last one finishes.
4. Whatever is still running then is cancelled: body reads, provider calls and response writes
   are interrupted. The caller gets the same 503 if its connection is still open, and the
   `document_finished` line says `outcome=cancelled status=503` (`status=200` when the document
   was already being sent: the caller got a cut-off 200). A document's own failure in that
   moment (an invalid file, a prompt injection) keeps its own status. The reserve covers closing the
   connections and the provider client.

`0` means no waiting: everything in progress is cancelled at once. The log names each step
(`There are pending requests: active=…, queued=…. Waiting up to … seconds before shutdown.`, then
`All pending requests finished…` or `The … s grace period expired…`, and finally
`Shutdown complete: elapsed_s=… cancelled=… refused=… still_running=…`).

Give the platform more time than the budget before it kills the process. The default does NOT
fit Kubernetes' default `terminationGracePeriodSeconds` of 30 s or `docker stop`'s default of
10 s: set `terminationGracePeriodSeconds: 130`, use `docker stop -t 130` or
`stop_grace_period: 130s` in Compose, or lower `ANON_GRACEFUL_TIMEOUT`.

### Memory

Heap is reserved per document before parsing, from one budget, so a few hostile uploads cannot
run the JVM out of memory. Measured on element-dense XML, a document needs about 100 bytes of
heap per byte of XML: 5 MB of XML parts, in a 70 KB upload, needed 508 MB.

- Each stage that parses or writes the whole package (parse, write, scan, remediation) reserves
  `16 MiB + 100 × XML bytes + 4 × package bytes`, from sizes the ZIP declares, before anything
  is decompressed. The LLM stage holds no reservation.
- A document whose estimate is larger than the whole `ANON_MEMORY_BUDGET_BYTES` gets
  `413 MEMORY_BUDGET_EXCEEDED`. Otherwise it waits for room; the wait counts against
  `ANON_DOCUMENT_DEADLINE_S` (`504` if no room comes in time) and logs `memory_admission_wait`.
- XML parts above `ANON_MAX_XML_BYTES` get `413 XML_TOTAL_TOO_LARGE`, text above
  `ANON_MAX_TEXT_CHARS` `413 TEXT_TOO_LARGE` as soon as it is reached, and XML nested deeper than
  256 levels `413 XML_TOO_DEEP` (lxml's limit, so v2's; it also stops a StackOverflowError).

Size the heap to the documents you must accept. A typical decision (about 1 MB of XML) is
estimated at about 120 MB. The largest document the defaults accept (10 MB of XML in a 60 MB
package) is estimated at about 1.26 GB, so with the default 60% budget it needs a heap of at
least 2.1 GB for admission. These are admission estimates, not peak-heap or concurrency guarantees.
The Dockerfile currently runs `java -jar app.jar` and sets no heap or out-of-memory flags.
Choose explicit heap settings in the deployment and inspect the effective JVM/container limits;
`JAVA_TOOL_OPTIONS` can supply deployment-specific options. Revalidate memory use after changes
to parsing and writeback. The local original-file acceptance test uses `-Xmx768m`, the default
60% admission budget, and unchanged document limits; this is a tested local setting, not production sizing.

### Slow clients (R-4): put a gateway in front

The JDK's built-in HTTP server has only one connection timeout: an idle keep-alive connection is
closed after 5 s. Nothing limits how long a client takes to send its request headers, to send
its body, or to read the response; the document deadline starts only after authentication. A
client that sends slowly, or never reads, holds one of the `ANON_MAX_CONCURRENT_REQUESTS` worker
slots for as long as it likes, and the header phase needs no API key. With every slot held,
`/anonymize` and `/healthz` stop answering, and a liveness probe on `/healthz` restarts the pod,
losing every document in progress.

**Do not expose the service directly.** Put it behind a reverse proxy or gateway that:

- buffers the whole request before forwarding it, and the whole response before sending it on
  (nginx: `proxy_request_buffering on;` `proxy_buffering on;`), so slow clients cost the proxy,
  not a worker;
- times out the client: headers (nginx `client_header_timeout 10s`), body (`client_body_timeout
  60s`, matching the upload cap), response (`send_timeout 60s`);
- caps the body at 21,000,000 bytes (`client_max_body_size 21m`) and waits for the service up to
  360 s (`proxy_read_timeout 360s`);
- limits connections per client (nginx `limit_conn`).

Give the liveness probe enough slack (`timeoutSeconds`, `failureThreshold`) that a busy
service is not restarted. The JDK's `sun.net.httpserver.maxReqTime` / `maxRspTime` properties
are not set and have not been tested here.

### Request queue (R-5): bound it at the gateway

At most `ANON_MAX_CONCURRENT_REQUESTS` (40) requests are processed at once. Every other request
waits in an unbounded first-in-first-out queue: none is refused when the service is saturated,
and a burst of 10,000 requests is accepted and kept. Time in the queue is not counted in the
document deadline, which starts once a worker has authenticated the request. A caller whose own
timeout (330 s for Ticketing) expires while it waits has gone, but its document is still
processed later, LLM calls and cost included, and nobody receives the result.

Until the service bounds its own queue, bound it in front of the service:

- allow at most `ANON_MAX_CONCURRENT_REQUESTS` connections per instance upstream (nginx
  `upstream … server … max_conns=40;`, HAProxy `maxconn 40`), plus at most a short queue
  (HAProxy `timeout queue 30s`);
- answer the overflow with `503` and `Retry-After` at the gateway;
- make callers (Ticketing) retry `503` with backoff, never immediately;
- scale with more instances, not a larger `ANON_MAX_CONCURRENT_REQUESTS`: the memory budget
  above, not the slot count, is what each instance can actually hold.

### Per-document accounting

Every provider response a document causes (pass 1 and its corrective call, pass 2, pass 2's corrective retry, the
post-redaction remediation) is booked on that document's own ledger, with the token counts the
provider reported for it. A count the provider did not report is absent, never estimated, and a
failed transport attempt costs time but no tokens. No price is built in: with no prices
configured the tokens are still counted and the cost is reported as unavailable. With prices
configured the cost is exact decimal arithmetic:

```
cost = ( (input_tokens - cached_input_tokens) x input_price
       +  cached_input_tokens                 x cached_input_price
       +  output_tokens                       x output_price ) / 1 000 000
```

Cached tokens are part of the input tokens, and reasoning tokens part of the output tokens, so
neither is counted twice. With no cached price configured, cached tokens are charged at the input
price (an upper bound). The cost is unavailable, not zero, when any response reported no usage.
The accounting is in the response headers above, in the `document_finished` log line (for failed
documents too), and in `--summary-json`, with the prices used.

`pass2_calls` includes its corrective retries; `remediation_calls` includes remediation retries.
`corrective_retry_calls` is their combined subset, not additional calls. Failed transport attempts
are reported separately. `provider_time_ms` sums attempt durations and can exceed wall time with
parallel chunks; `llm_time_ms` measures the LLM stage and remediation wall time. Missing optional
cache detail falls back to the normal input rate; this is a configured estimate, not a provider
invoice. A failed document's ledger is a snapshot at failure; a canceled provider request can
still finish or be billed afterwards.

Detection rules live in `config/`: `policy.yaml` (confidence thresholds, categories that are
always kept or always redacted, public e-mail domains), `regex_patterns.yaml` (pattern
overrides, and `preserve_families`: the hard-preserve phrase families described below),
`prompt_injection.yaml` (the screening rules; required, and every rule is validated at startup) and
`allowlists/` (tax offices, public services, legal abbreviations, and the administrative regions
that end a kept "municipality + region" residence such as "κατοίκου Νέας Σμύρνης Αττικής"). The
DOCX detectors also read `chat/given_names.txt` and `chat/surnames.txt`, as positive evidence of a
person's name only (optional here; warn and continue). Their sha256 is stamped into every result's
provenance.

`preserve_families` is the one definition of the structural phrases that are always kept: headings,
public bodies and their units, legal and procedural terms, field labels, party and administrative
roles, and the fixed parts of composite references ("ΕΞ 2026", "ΕΛ.ΚΕ.1 ΑΤ", a sender's "ΔΑ" and its
date; never the serial, and never a number for its value). Each family names a hard-preserve
category of `policy.yaml` (a family naming any other category, or an unknown one, is disabled with a
startup warning and never used; it is not promoted and not kept as an ordinary PRESERVE) and a
scope: `any`, or `label` for a
word kept only where it stands as a label ("Τράπεζα" as a header, never inside a bank's name). The
patterns are written folded (lowercase, unaccented, σ) and match every case, accent, final-sigma and
decomposed-accent variant at the document's own offsets. A malformed family stops the service
starting. The name lists propose an ordinary REDACT for a given name and a surname side by side, or
for a listed given name next to another capitalised word in a private-party context. They never
keep anything, and they never drop a hint for a word they don't list.

The final official signatory's NAME is a hard preserve (`OFFICIAL_SIGNATORY`): positively identified
after a signing title, in a paragraph or a table cell at the end of the document, with no
private-party cue in the block. The span covers the name alone. It is never redacted, never a pass-2
question (in the first adjudication or the post-redaction re-ask), and no other occurrence of the
same words is protected by it.

The OpenAI SDK's own HTTP logging is switched off in code, so `OPENAI_LOG=debug` cannot print
request or response bodies (document text) to standard output.
Access logs contain only normalized method/route labels, timestamp, status and byte count;
caller-controlled paths, query strings, Referer and User-Agent are omitted.

Kept by policy, whatever the LLM answers: the institution and its place after "Δήμου" /
"Πρωτοδικείου" / "Εφετείου" / "Δικαστηρίου" (genitive or nominative), a court chamber ("Τμήμα 1ο
Τριμελές"), a municipality with its region after "κάτοικος"/"κατοίκου" (category `PUBLIC_LOCALITY`),
and the all-zero ΚΑΕΚ suffix ("ΚΑΕΚ …………/0/0"; any other suffix is redacted with its root). A place
of two words is kept whole when its first word is a toponym modifier ("Νέας Σμύρνης", "Αγίας
Παρασκευής"); otherwise only its first word is a policy decision and the rest is left to the LLM,
so a name that follows a place is never shielded. These new-gold rules have no document-specific
city exceptions: they use grammatical cues and generic place modifiers. Existing tax-office and
administrative-region allowlists remain, as does the older decision-city/date rule. These follow the current gold and differ from v2, which
blanks the first three; both LLM prompts teach the same distinctions, including that public
geography is not a private address.

## Where this code comes from

This branch is the Java application on its own: a port of the Python implementation on branch
`v2` of `Soliddop/ticketing-kef-anonymizer`, which is the reference for its behaviour. The regex
and prompt constants (`DetectorPatterns`, `PostcheckPatterns`, `llm/PromptText`, `IbanRegistry`)
were generated from v2's own compiled values, but neither the generator nor a parity harness is
on this branch: a change to them is made by hand and checked against v2. The prompt text is v2's
except where the new gold differs, and its SHA-256 is pinned by `LlmDetectorTest`.

Deliberate differences from v2: a HIGH residual that the remediation preserves is
`needs-review` rather than `processed` (above); the gold-mandated places kept by policy, and the
prompts that teach them (above); only plain
`.docx` accepted (above); author metadata blanked (above); a street number is proposed only
directly after a street name (v2 also proposes "αρ. 9" in a citation of an article); the original
address rule is kept beside v2's, so a street written with its number and no "αρ." is still
proposed; and a region is given back from a model's span only as a whole word (v2 would publish
the end of a surname such as "Παπακρήτης").

Address and reference spans (also Java-only): an address proposal is the capitalised place or street
name and its house number, never the clause after it ("κάτοικος Λαμίας, προσέφυγε …" proposes
"Λαμίας"), never the "αρ." of the number and never the "Τ" of a following "Τ.Κ."; it ends at a line
break, a tab or a run of spaces. Street cues are read in any case and accenting ("ΟΔΟΣ", "οδού",
"οδό"), a number after "αριθ." is a street number too, and a street written after the residence with
no cue ("κάτοικος Αθηνών, Πατησίων 12") is its own proposal, so keeping the locality never meets one
redaction of both. A business seat is proposed whole: street, number and town. The authority header
ends at the first paragraph about a private party (and at a letter-spaced "Α Π Ο Φ Α Σ Η"), so in a
document with no title line the appellant's paragraph is never authority information. "αριθ.
ειδοποίησης" is a label like "αριθμό ειδοποίησης", its serial a notice number; an act number must
hold a digit (v2 read the letters of "ειδοποίησης" as one); and a reference a model redacted short
of its multi-part serial ("11010705" of "11010705/1/9871/15.09.2022") takes the serial's remaining
parts, the trailing date or year still visible.

### Review regressions and local original-file acceptance

`mvn -o clean verify` runs the synthetic regression suite (omit `-o` if dependencies are not cached).
`mvn -o -Dtest=OriginalDocumentLocalIT -DargLine=-Xmx768m test` additionally requires the unchanged
local `Test_big_doc.docx`; it pins its SHA-256 and checks remediation, hard-policy preservation/redaction,
and HTTP headers/output. The private fixture is not distributed or copied into test resources.
Both use fake models. Semantic accuracy, images, Word rendering, provider latency/quota and gateway
configuration still require validation in the intended environment.

Missing, malformed, refused, truncated or partially malformed discovery after correction now produces
`discovery_incomplete` review work. Usable evidence is retained; a valid empty array or deliberate
`SKIP` is complete discovery. Provider-failed discovery is counted as `pass1_provider_failure`.
Pass 2 retains its strict candidate contract. A reported length truncation divides a multi-candidate
batch into smaller requests with the original IDs. Every request uses the same document deadline and
accounting. Discovery still keeps whole tables/paragraphs, so unusually large discovery inputs remain a
separate measured risk.

### LLM routing, document-wide pass 2, retries and fallback

Every actionable candidate gets an LLM decision (pass 1's or pass 2's) before the resolver; hard
policy is the one exception. After pass 1, each chunk is routed (`Pass2Queue.route`):

| Situation | Decided by |
|---|---|
| rules and pass 1 agree (REDACT or PRESERVE), or pass 1 alone speaks | pass 1, no pass-2 call (pass 1's decision as an `llm_pass1` span) |
| a rule REDACT that no pass-1 decision covers over its whole place | pass 2, at the rule span's place |
| a rule PRESERVE alone (it changes nothing) | the resolver's existing ladder, no pass-2 call |
| a rule hint or pass 1 says REVIEW | pass 2 |
| the rules' decision and pass 1's disagree | pass 2, asked about the REDACT side's whole value |
| a pass-1 REDACT of a text that occurs more than once in the chunk, not confirmed by the rules | pass 2, per place |
| hard policy (including the official signatory's name) | hard policy, never asked |

The rules' spans always reach the resolver too, as evidence and as the documented fallback.

Pass-1 quotes are compared with the rule spans by exact unit coordinates, cut into atomic intervals
where they partly overlap; text is never compared. The rules' spans reach the resolver unchanged, so
its geometric guard still holds: a pass-2 PRESERVE never carves a hole in a REDACT it was not
answering at exactly that slice. A question no answer could change (covered by an applied pass-1
REDACT of another slice) is not sent. A pass-1 REDACT that narrows to no redactable value is not
applied and becomes `pass1_redact_unrepresentable` review work.

All chunks' questions form ONE document-wide queue. A question the document's decision registry
already answers is not asked (below). The rest get ids `C1..Cn`, issued once; exact duplicates (same
text, recommendations, context windows and fallback) are folded, and the queue is sent in batches of
at most 30 candidates and 7,000 estimated candidate-payload TOKENS (not the 7,000-character chunk
size). Fewer go in a batch when the completion budget (`ANON_MAX_COMPLETION_TOKENS`, which any
reasoning also uses) cannot answer 30: at most 60% of it for the answers, at an estimated 40 tokens
each. The system prompt is not counted against the payload budget. A whole-request check (system
prompt, message overhead, payload and the whole completion budget, by the same conservative token
estimate) applies only when `ANON_LLM_CONTEXT_TOKENS` is set; a candidate that cannot fit that window
even alone is never sent and takes the pass-2-unavailable fallback with `cause=context_limit`. The
post-redaction re-ask is not batched and is not covered by this check. An oversized single candidate
is otherwise sent alone, whole. An empty queue makes no pass-2 call.

The decision registry (`DecisionRegistry`) lives only for one document request. It reuses a
confirmed decision for the same complete value elsewhere in the document. Reuse applies to a private
person's name of two or more words, a company name, or a verified identifier (a hard redact). It
works through the ordinary resolver and keeps the original decision's origin and category. The
registry is built after every chunk has finished, so worker timing cannot affect it. Matching is
exact: whole words, case- and accent-insensitive, any run of spaces, tabs or no-break spaces between
two words counting as one (never a line break), every other character literal, never across
grammatical forms. A value that LLM
decisions both redacted and preserved is decided place by place, and so is a value a hard-preserve
rule keeps. An LLM PRESERVE is never reused document-wide. A hard preserve, the official signatory
and a place's own PRESERVE decision still win where they stand.

Tables are work items of their own. Several small tables share one work item, each in its own
`TABLE:` block. A table larger than a work item is cut into row groups (`TABLE (continued):`). Each
later group carries a copy of the header rows, and every group carries the paragraph just before
the table. When no header row is marked, the copy is the table's first row, labelled neutrally
(`[context] first row:`, not `header row`): pass 1 decides for itself whether a table has a header and
where (usually the first row, often the first column of a label | value table, rarely elsewhere, or
none). That reading guides only the model: the deterministic column rules use the document's own
header marking (below), so the model can never create a hard decision through a header. The copy and
the title are read-only `[context]` lines: they map to no source text, so nothing can be
written to them, and a quote of them alone is neither written nor held as unlocatable. An empty cell
keeps its column's place, and so does a row cut between its cells: a later part of it starts with
the empty places of the columns before it. Columns are the cells' positions in their row
(`w:tc`): a merged cell (`w:gridSpan`) can shift the cells after it against the header row, a known
limitation. Header rows are the rows Word repeats as headers (`w:tblHeader`). Without that marker the
first row is a header only when it is positively a row of known column labels (no digits, at most 40
characters a cell, a strict majority of its cells labels the column rules already know, at least two
of them or the row's only cell); otherwise the table has no header, so an ambiguous first row never
steers the column rules.

Provider retries: six attempts per request. A valid `retry-after-ms` is waited exactly (zero
included); otherwise an exponential backoff with jitter (2, 4, 8, 16, 32 s nominal, each drawn from
half to all of it). All the waits of one request together stay within 65 s, and a wait that cannot fit
in the document's deadline ends the retries.

When pass 2 stays unavailable for a batch (provider failures after the retries, or no usable reading),
the document is still returned: decisions already accepted are kept, other batches are unaffected, and
each affected candidate gets the documented fallback and a `pass2_unavailable` finding of its own
(its id, locations, recommendations and the action it ended with). The fallback: a pass-1 REDACT is
applied; a pass-1 PRESERVE against a rule REDACT leaves the REDACT (flagged); with no pass-1 decision
the rules decide by their ladder; a pass-1 PRESERVE with no rule REDACT is applied; a REVIEW alone
stays undecided. A question pass 2 answered but left undecided after its corrective retry gets the
same fallback. Nothing is recorded as a pass-2 answer. The same holds for the post-redaction re-ask.
A misconfigured service (HTTP 401, 403 or 404: a wrong key, no access, no such deployment) is not
treated as an outage and still fails the document. Such a response is `needs-review` and carries `X-LLM-Fallback-Used: true` (the header is absent
otherwise); `--summary-json` has `fallback_used`. Pass 1 failures stay `discovery_incomplete`, never
read as agreement.
