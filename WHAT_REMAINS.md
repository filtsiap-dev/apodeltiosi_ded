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

## Work 3: Add API Authentication

Add one environment setting named `ANON_API_KEY`.

Every request to `POST /anonymize` must include:

```http
Authorization: Bearer <ANON_API_KEY>
```

The API must compare the supplied value with `ANON_API_KEY` using a constant-time comparison. If the header is missing, malformed, or incorrect, return HTTP `401` without processing the document. Do not include the expected key in the response or logs.

Leave `GET /healthz` unauthenticated so another service can check that the application is running. Add `ANON_API_KEY` to `.env.example`, but never place a real key in the repository.

## Work 4: Check the Anonymized File Before Returning It

The project already contains a post-redaction audit. Here, "audit" only means a final scan of the produced DOCX for personal information that may still be visible, such as an AFM, AMKA, IBAN, private email, or other suspicious identifier. It is not a legal audit and it does not send information anywhere.

Run this scan automatically after `write_redacted_docx` and before either the CLI saves the file or the API returns it.

If the scan finds a HIGH-severity item, do not return or save the document as a successful result. Report that the document needs manual review. Lower-severity warnings may be returned in the summary without blocking the file.

This changes the flow to:

```text
receive DOCX -> anonymize DOCX -> scan anonymized DOCX -> return it only when no HIGH finding remains
```

## Work 5: Reject Files the Parser Did Not Really Read

The current initial check mainly confirms that the upload is a ZIP package containing the usual DOCX filenames. A broken file can contain those filenames while its main document XML is unreadable. In that case, the pipeline could see no text even though the package contains data.

For the API release, parse the required DOCX XML strictly. Reject the input when `word/document.xml` is invalid or when the parser cannot extract a valid Word document. Do not continue with an empty redaction plan for a file that could not actually be read.

This work is only about rejecting broken or misleading uploads. It does not require adding support for every possible Microsoft Word feature.

## Work 6: Make LLM Responses Complete

The LLM is asked to return a JSON list of decisions. Sometimes an LLM can return incomplete JSON or omit a candidate that it was asked to review.

Require the second LLM pass to return valid structured JSON. Validate every returned item before using it, and confirm that every rule-based item marked `REVIEW` received a final `REDACT` or `PRESERVE` decision. If the response is incomplete, retry the LLM call once. If it is still incomplete, stop processing that document instead of silently treating the missing decision as safe.

Keep the existing rule-based redactions in the final plan even when the LLM does not repeat them.

## Completion Order

Implement the remaining work in this order:

1. Confirm the current CLI on accepted real documents.
2. Confirm the existing API accepts and returns the same documents.
3. Add bearer API-key authentication.
4. Make the post-redaction scan mandatory.
5. Reject DOCX files that were not parsed correctly.
6. Enforce complete structured output from the second LLM pass.

After these steps, the application will have one consistent path: it can anonymize accepted DOCX files locally through the CLI or remotely through an authenticated API, and it will check the output before releasing it.
