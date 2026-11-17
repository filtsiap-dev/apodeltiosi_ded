# Running ded-anonymizer (Java) — step by step

For Windows, PowerShell or the VS Code terminal. Use **test documents** until you are sure
everything works.

> **Pasting commands:** paste one command at a time and press Enter. Commands that are
> meant to be pasted together are written on a single line.

---

## 1. One-time setup

### 1.1 Install the tools

| Tool | Install | Check |
|---|---|---|
| Java 24 | `winget install EclipseAdoptium.Temurin.24.JDK`, or the `.msi` from https://adoptium.net (tick *Set JAVA_HOME*) | `java -version` shows **24** (the version CI and the Docker image use) |
| Maven 3.9 | see the one-liner below | `mvn -version` shows **Apache Maven 3.9.x** |
| Git | https://git-scm.com/download/win | `git --version` |
| VS Code extension | **Extension Pack for Java** (Microsoft) | — |

Maven, installed into your user folder (no admin rights needed), as **one line**:

```
$ProgressPreference='SilentlyContinue'; $v="3.9.9"; $bin="$HOME\tools\apache-maven-$v\bin"; if (-not (Test-Path "$bin\mvn.cmd")) { Invoke-WebRequest "https://archive.apache.org/dist/maven/maven-3/$v/binaries/apache-maven-$v-bin.zip" -OutFile "$env:TEMP\maven.zip"; Expand-Archive "$env:TEMP\maven.zip" -DestinationPath "$HOME\tools" -Force }; $p=[Environment]::GetEnvironmentVariable("Path","User"); if ($p -notlike "*$bin*") { [Environment]::SetEnvironmentVariable("Path","$p;$bin","User") }; $env:Path += ";$bin"; mvn -version
```

After installing anything: **File → Exit** VS Code and open it again, so that new terminals
see the new programs.

### 1.1b Show Greek text correctly in the terminal

Windows terminals start in an old character set, so Greek file names and some symbols in the
program's messages print as `?` or garbage (the documents themselves are not affected).
Switch the terminal to UTF-8 — for the current terminal:

```
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
```

To make it permanent for every PowerShell window (one line; creates your profile if needed):

```
if (-not (Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force | Out-Null }; Add-Content $PROFILE '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8'; "added to $PROFILE"
```

If PowerShell then says running scripts is disabled, use the per-terminal line above instead.

### 1.2 Get the code

In an **empty** folder, opened in VS Code (*File → Open Folder…*), terminal:

```
git clone --branch java-app --single-branch https://github.com/Soliddop/ticketing-kef-anonymizer.git .
```

You should see `src`, `config`, `pom.xml`, `README.md`.

### 1.3 Create `.env`

Create a file named exactly `.env` next to `pom.xml`. It is git-ignored: it is never committed.

```
ANON_PROVIDER=openai
OPENAI_API_KEY=sk-REPLACE-ME
ANON_MODEL=gpt-4.1-mini
ANON_API_KEY=REPLACE-WITH-A-LONG-RANDOM-STRING
ANON_HOST=127.0.0.1
ANON_PORT=8000
```

- Use the same key and model as your Python `.env` (the variable names are identical).
- **Comments go on their own line** (starting with `#`). `KEY=value # note` would make
  `# note` part of the value.
- A random value for `ANON_API_KEY`:
  ```
  -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | ForEach-Object { [char]$_ })
  ```
- `ANON_HOST=127.0.0.1` keeps the local service reachable from this PC only.
- Azure instead of OpenAI: `ANON_PROVIDER=azure` plus `AZURE_OPENAI_API_KEY`,
  `AZURE_OPENAI_ENDPOINT`, `ANON_AZURE_DEPLOYMENT`, `ANON_AZURE_API_VERSION`.
- No AI model at all: `ANON_PROVIDER=regex`, with no `OPENAI_*`/`AZURE_*` lines and no
  `ANON_MODEL`. Only `/anonymize-text` and `/anonymize-log` work; `/anonymize` answers 503.
- All settings: see `README.md`, section *Configuration*.

### 1.4 Build

```
mvn package
```

- The first run downloads libraries from the internet (a few minutes), then compiles and runs
  the complete test suite. It ends with **BUILD SUCCESS**.
- Result: `target\ded-anonymizer-2.0.0.jar` (a shaded JAR containing its dependencies). Its manifest starts the HTTP server.
- Faster rebuild without tests: `mvn package -DskipTests`.
- Rebuild after every code change or `git pull`.

---

## 2. Command line (CLI)

Always run from the project folder (where `pom.xml` and `.env` are).

### 2.1 One document

```
java -cp target\ded-anonymizer-2.0.0.jar dev.filtsiap.ded.RunAnonymizer "C:\path\to\decision.docx"
```

The redacted file is written **next to the original**: `decision_redacted.docx`.

### 2.2 A whole folder

```
java -cp target\ded-anonymizer-2.0.0.jar dev.filtsiap.ded.RunAnonymizer --file "C:\path\to\folder" --out-dir "C:\path\to\redacted"
```

Every `.docx` in the folder (not subfolders) is processed; files already ending in
`_redacted.docx` are skipped.

### 2.3 Options

| Option | Meaning |
|---|---|
| `"path"` or `--file "path"` | a `.docx` file or a folder (give one of the two) |
| `--out-dir "path"` | where to write outputs (default: next to each input) |
| `--qa` | also print every finding of the final safety scan (of the returned bytes) |
| `--summary-json` | print a JSON line per document with counts, ids, timings and the LLM cost accounting (no document text) |
| `--config-dir "path"` | use another rules folder instead of `config\` (with the same files, `prompt_injection.yaml` included) |
| `-h` | help |

### 2.4 Reading the output

```
started: decision.docx
done: C:\path\to\decision_redacted.docx
  status=processed
  spans=57 by_action={'REDACT': 31, 'PRESERVE': 26} model=gpt-4.1-mini elapsed=18.4s
  llm_calls=9 tokens_in=41210 tokens_out=1873 tokens_total=43083 cost=unavailable (pricing_not_configured)
  warning: post-redaction scan: 2 finding(s) {'phone_shape': 2}
  warning: post-redaction remediation: 2 residual finding(s) were re-adjudicated by LLM pass 2 and 1 further redaction(s) applied; the returned document was scanned again, deterministically, and the result's scan describes it
```

- `REDACT` = replaced by dots, `PRESERVE` = deliberately kept (dates, laws, amounts, public bodies…).
- Warnings never block the file; `--qa` shows the details.
- Located findings from the initial scan are asked about once (AI pass 2 only, on the redacted
  document). If remediation writes changes, a deterministic final scan audits those bytes.
  It starts no further model call. QA and HTTP scan headers describe the returned bytes.
- `status=needs-review` means a person must check some places before publishing: the AI left
  discovery coverage incomplete, findings undecided after correction, or a high-risk value the final scan found
  (ΑΦΜ, ΑΜΚΑ, IBAN, e-mail, property identifier) is still visible because the AI decided to keep
  it. The file **is** written (exit code 0), nothing was guessed, and each place is listed
  (`unresolved: chunk 2 high_residual_preserved AFM (u14[5:14]) from post-redaction HIGH
  residual_afm initial_scan:P3@word/document.xml:u14`; P3 is an initial-scan ID, not a final QA row. `F` IDs refer to the final scan. Candidate IDs are scoped by phase and chunk.)
- `llm_calls=… cost=…` is what the document cost. To see money, set your prices in `.env`
  (`ANON_INPUT_COST_PER_1M_TOKENS`, `ANON_OUTPUT_COST_PER_1M_TOKENS`, optionally
  `ANON_CACHED_INPUT_COST_PER_1M_TOKENS` and `ANON_COST_CURRENCY`); no price is built in.

If the final safety scan finds a high-risk problem that is not document text (a macro, a tracked
change, a comment, placeholder residue), **no file is written**:

```
NEEDS MANUAL REVIEW  decision.docx: post-redaction scan found 1 HIGH-severity finding(s) that no further redaction can settle; the document needs manual review (macro_part_survived@word/vbaProject.bin)
  no file written to C:\path\to\decision_redacted.docx
```

Anonymize that document by hand (or fix whatever left it there).

### 2.5 Exit codes

| Code | Meaning |
|---|---|
| 0 | all documents done |
| 1 | at least one document failed (e.g. not a valid DOCX, AI provider error) |
| 2 | wrong arguments / no input found |
| 3 | configuration error (e.g. missing `OPENAI_API_KEY`) |
| 4 | done, but at least one document was blocked for manual review (a non-text scan finding) |
| 5 | at least one document ran out of time (`TIMED OUT` line; no file written for it) — raise `ANON_DOCUMENT_DEADLINE_S` |
| 130 | stopped with Ctrl+C |

In PowerShell, `$LASTEXITCODE` shows the code of the last run.

---

## 3. HTTP service on localhost

### 3.1 Start

From the project folder:

```
java -cp target\ded-anonymizer-2.0.0.jar dev.filtsiap.ded.api.ApiServer
```

- It prints `listening on 127.0.0.1:8000` and keeps running: **leave this terminal open**.
- It refuses to start without `ANON_API_KEY` in `.env`.
- It also refuses to start (exit code 3) when `config\chat` is missing or corrupt, or when
  `config\chat\chat.yaml` sets `ner.enabled: true` (v1 has no NER model): the chat word lists for
  `POST /anonymize-text` are loaded at startup.
- If Windows Firewall asks, *Cancel* is fine for localhost-only use.
- Stop: **Ctrl+C** in that terminal. With no request in progress it exits at once. Otherwise it
  lets requests in progress finish for up to 115 s, cancels the rest, and exits within
  `ANON_GRACEFUL_TIMEOUT` (default 120 s; see README, *Shutdown*).

### 3.2 Check it is alive

Browser: http://localhost:8000/healthz → `{"status":"ok","provider":"openai","model":"..."}`

### 3.3 Anonymize a document

Open a **second** terminal in the project folder. Load your key from `.env` once (one line):

```
$key = (Select-String -Path .env -Pattern '^ANON_API_KEY=(.*)$').Matches[0].Groups[1].Value
```

Send the file as the request body, get the redacted file back as the response body (write
`curl.exe`, not `curl`; the `Content-Type` must be exactly the Word one):

```
curl.exe --max-time 330 -H "Authorization: Bearer $key" -H "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document" --data-binary "@C:\path\to\decision.docx" http://localhost:8000/anonymize -D headers.txt -o redacted.docx -w "HTTP %{http_code}\n"
Get-Content headers.txt
```

- `HTTP 200` → `redacted.docx` is the anonymized document.
- Any other code → `redacted.docx` contains the error message instead (open it with Notepad),
  see 3.4.
- The response headers `X-Postcheck-Findings` / `X-Postcheck-Kinds` summarise the scan findings
  for the returned bytes; `X-Document-ID` is the id the server log uses for this
  document. Add `-D -` to the command to print them.
- `X-Anonymization-Status: needs-review` (with `X-Unresolved-Count`) means the file is complete
  but a person must check the unresolved findings before publishing (an undecided finding, or a
  high-risk value the AI chose to keep); `processed` means none. `X-LLM-Fallback-Used: true` is
  added when the AI's second pass stayed unavailable after its retries and the document was finished
  with the documented fallback instead of failing.
- `X-Processing-Time-Ms`, `X-LLM-Calls`, `X-LLM-Input-Tokens`, `X-LLM-Output-Tokens`,
  `X-LLM-Total-Tokens` and, when prices are set, `X-LLM-Estimated-Cost` / `X-LLM-Cost-Currency`
  say what the document cost. A header is sent only when its value is known.
- Only a raw `.docx` body is accepted: a form upload (`-F "file=@..."`), `application/octet-stream`
  or a `.docm`/`.dotx`/`.dotm` file gets `415`. Save other Word formats as `.docx` first.
- A successful response body is the file itself; errors are JSON. For counts and
  scan details run the CLI with `--summary-json --qa`.

### 3.4 Error responses

Errors are JSON, e.g.
`{"error":"InvalidDocumentError","code":"INVALID_DOCUMENT","detail":"the request body is not a readable Word (OOXML) document"}`
or `{"detail":"..."}`. The `detail` is fixed per error type; `code` says which check failed
(e.g. `UPLOAD_TOO_LARGE`, `ZIP_MEMBER_TOO_LARGE`, `TEXT_TOO_LARGE`, `DOCUMENT_TIMEOUT`).

| HTTP | Meaning | What to do |
|---|---|---|
| 400 | not a valid DOCX, empty upload, unsafe or encrypted package, broken package structure (`MALFORMED_PACKAGE_XML`, `INVALID_ROOT_RELATIONSHIP`) | check the file opens in Word; save it again as `.docx` |
| 401 | missing/wrong `Authorization: Bearer ...` | check `$key` matches `ANON_API_KEY` |
| 413 | over a size limit: upload (`ANON_MAX_UPLOAD_BYTES`), package parts, text or chunks | see `code`; raise that limit in `.env`, restart |
| 415 | not sent as a raw `.docx` body, or the file is not a plain Word document (a legacy `.doc`, a macro-enabled or template package, a spreadsheet …) | send the bytes with `--data-binary` and `Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document`; save the file as `.docx` |
| 422 | `PROMPT_INJECTION_DETECTED`: the text contains an instruction aimed at the AI ("ignore the previous instructions" …); nothing was sent to the AI | check the document; if it is a false positive, the server log names the rule: edit `config/prompt_injection.yaml`, restart |
| 422 | **blocked by the final safety scan** (a non-text finding; manual review) | anonymize by hand |
| 500 | internal error, or the redacted file could not be written | report it with `X-Document-ID` / the `request_id` from the server log |
| 502 | AI provider error the documented fallback does not absorb: a misconfigured service (HTTP 401/403/404 from the provider: key, access, deployment name). An outage or rate limit during pass 1 or pass 2 now yields a `needs-review` 200 instead (`discovery_incomplete`, or `X-LLM-Fallback-Used`) | check `AZURE_OPENAI_*` / deployment; for repeated rate limits lower `ANON_LLM_CONCURRENCY` |
| 503 | AI provider unreachable / configuration problem, or the server is shutting down | check network, keys |
| 504 | the document ran out of time (`ANON_DOCUMENT_DEADLINE_S`) | retry; raise `ANON_DOCUMENT_DEADLINE_S` |

The server terminal logs each request and each pipeline stage (never document text), and one
`document_finished request_id=... document_id=... outcome=... status=... llm_calls=... tokens_in=...
cost=...` line per document, failed documents included.
At most `ANON_MAX_CONCURRENT_REQUESTS` (default 40) documents are processed at once; more wait.
The waiting queue is unbounded and precedes the 300-second document clock. The deadline checks
cannot interrupt a stalled body read. Production ingress must enforce bounded admission plus
upload/idle timeouts (README, *Slow clients* and *Request queue*). Use the canonical `/anonymize` URL
without a trailing slash.

Ticketing must retain the review headers and show a human-review warning for `needs-review`.
Use a 20,000,000-byte file limit and a 21,000,000-byte multipart request limit, a 330-second
upstream timeout, 360-second proxy read timeout and 450-second browser timeout. These assume
bounded admission and an upload capped at 60 seconds; 120 seconds is insufficient for the default
300-second processing budget. See [FINAL_REVIEW.md](FINAL_REVIEW.md) and
[How_to_run_Java.docx](How_to_run_Java.docx).

### 3.5 From another program

Any HTTP client works: the request body is the file and the response body is the file. Python
example:

```python
import requests
with open(r"C:\path\to\decision.docx", "rb") as f:
    r = requests.post("http://localhost:8000/anonymize",
                      headers={"Authorization": "Bearer YOUR_ANON_API_KEY",
                               "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                      data=f, timeout=330)  # the server's 300 s budget plus a margin
r.raise_for_status()
print(r.headers["X-Document-ID"], r.headers["X-Anonymization-Status"], r.headers["X-Unresolved-Count"])
open("redacted.docx", "wb").write(r.content)
```

---

## 4. Running from VS Code (buttons instead of commands)

**Tests:** beaker icon (*Testing*) in the left sidebar → ▶ *Run All Tests*.

**CLI and server:** create `.vscode\launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "java",
      "name": "CLI: anonymize a file",
      "request": "launch",
      "mainClass": "dev.filtsiap.ded.RunAnonymizer",
      "args": "\"C:\\path\\to\\decision.docx\" --qa",
      "cwd": "${workspaceFolder}"
    },
    {
      "type": "java",
      "name": "HTTP server (localhost:8000)",
      "request": "launch",
      "mainClass": "dev.filtsiap.ded.api.ApiServer",
      "cwd": "${workspaceFolder}"
    }
  ]
}
```

Then *Run and Debug* sidebar → choose a configuration → ▶. Breakpoints work.

---

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| `java` / `mvn` *is not recognized* | install (1.1), then **File → Exit** VS Code and reopen |
| `Program 'mvn.cmd' failed to run: The system cannot find the file specified` | the Windows `ComSpec` setting is broken: `[Environment]::SetEnvironmentVariable("ComSpec","C:\Windows\System32\cmd.exe","User")`, then restart VS Code |
| Greek names or `—` show as `?` in messages | switch the terminal to UTF-8 (1.1b) |
| red `Unexpected token` errors after pasting | the lines were glued together: paste one command at a time |
| `mvn package` cannot download libraries | company proxy: ask IT for the Maven proxy settings (`%USERPROFILE%\.m2\settings.xml`) |
| `configuration error: OPENAI_API_KEY is required...` | `.env` missing, misspelled, or not next to `pom.xml` |
| `configuration error: ANON_LOG_LEVEL must be one of ...` | use `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG` or `NOTSET` (not `WARN`) |
| `configuration error: ... must be greater than zero` / `must be at most` | a number in `.env` is 0, negative, `nan`/`inf` or too large |
| uploads over 20 MB still refused after raising `ANON_MAX_UPLOAD_MB` | that name is no longer read: set `ANON_MAX_UPLOAD_BYTES` (bytes, e.g. `40000000`; it must not exceed `ANON_MAX_ZIP_TOTAL_BYTES`, `60000000` by default) |
| `Address already in use` | port 8000 is taken: set `ANON_PORT=8001` in `.env` |
| many 502 / HTTP 429 | lower `ANON_LLM_CONCURRENCY` (e.g. 2) |
| `Unable to access jarfile` | run `mvn package` first, from the project folder |
| slow OneDrive syncing | keep the project outside OneDrive, e.g. `C:\dev\DED_Java` |

**Never** commit `.env`, and never put real documents in the repository.

## 6. A request with no `document_finished` line

Every document logs `document_started` when it begins and exactly one `document_finished` when it ends. The `outcome=` field says how it ended. The line is written for failures too (`timeout`, `cancelled`, `client_disconnected`, `internal_error`), so its name does not mean success. Read `outcome=`.

- **Started, never finished:** find `document_started` lines whose `request_id` has no `document_finished`.
- **`shutdown_inflight`:** logged when the service starts shutting down, once per document still running, with its `stage`, chunks done and failed provider attempts. A document that was cut off by the shutdown then ends with `outcome=cancelled`, `error_reason=shutdown`.
- **Failed documents** carry `failed_stage` (the last stage it began), `error_reason` (a deadline, a shutdown, or a provider failure class), `provider_http_status`, `last_failed_chunk`, `last_failed_pass` and `last_failure_recovered`. `last_failure_recovered=yes` means a rate limit was retried and the answer came later: that is not the cause of a failure.
- **Retries:** `llm_retry` (scheduled, with its wait), `llm_retry_started`, `llm_retry_succeeded`, `llm_retry_exhausted`, `llm_retry_aborted` (the deadline or a cancellation ended it) and `llm_retry_interrupted` (a shutdown ended the wait). Each carries `chunk`, `pass`, `transport_attempt` and `waited_ms`.
- **Neither `document_finished` nor `shutdown_inflight`:** the process was killed before it could log anything (out of memory, a container replaced or restarted, or the platform's termination grace period ended). The service cannot log its own death. Check the container platform's system logs for the same minute: a replica stopped or restarted, a new revision deployed, exit code 137 (out of memory). If the platform's termination grace period is shorter than `ANON_GRACEFUL_TIMEOUT` (default 120 s), a shutdown during a long document can be killed before its own lines, so set the grace period above it or lower `ANON_GRACEFUL_TIMEOUT`.
