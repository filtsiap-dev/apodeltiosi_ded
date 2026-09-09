"""HTTP transport for the anonymizer.

One endpoint contract, stable for calling applications:

    POST /anonymize   multipart/form-data, field ``file`` -> the redacted DOCX
                      requires ``Authorization: Bearer <ANON_API_KEY>``
    GET  /healthz     unauthenticated liveness probe

This module is transport only. It parses the upload, calls the SAME
``anonymize_document`` pipeline the CLI calls (one shared implementation, so
CLI and API results cannot drift apart), and serializes the result. No
detection, policy, or redaction logic lives here.
"""

import base64
import dataclasses
import logging
import secrets
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from starlette.datastructures import UploadFile

from anonymizer.config import load_file_config, load_runtime_config
from anonymizer.errors import (
    AIProviderError,
    AITimeoutError,
    AIUnavailableError,
    AnonymizerError,
    ConfigurationError,
    DocumentProcessingError,
    InvalidDocumentError,
    ResidualPIIError,
)
from anonymizer.llm.client import build_client
from anonymizer.pipeline import anonymize_document
from anonymizer.postcheck import PostcheckSummary

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load runtime and file configuration, configure logging, and attach the LLM client to app state for the app's lifetime, closing the client on shutdown. Raises ConfigurationError when ANON_API_KEY is unset, so the service never starts unauthenticated."""
    cfg = load_runtime_config()
    if not cfg.anon_api_key:
        # Fail closed. Starting without a key would expose an unauthenticated
        # POST /anonymize; there is no "no auth" mode for the HTTP transport.
        raise ConfigurationError(
            "ANON_API_KEY is required to serve the HTTP API "
            "(POST /anonymize is bearer-authenticated)"
        )
    files = load_file_config(Path("config"))
    logging.basicConfig(level=cfg.log_level, stream=sys.stdout)
    client = build_client(cfg)
    app.state.cfg = cfg
    app.state.files = files
    app.state.client = client
    yield
    client.close()


app = FastAPI(lifespan=lifespan)


_ERROR_STATUS_CODES: dict[type[AnonymizerError], int] = {
    InvalidDocumentError: 400,
    DocumentProcessingError: 422,
    # The document was redacted, but its mandatory scan still found HIGH
    # residual PII: nothing is returned, the caller must review it by hand.
    ResidualPIIError: 422,
    AIProviderError: 502,
    ConfigurationError: 503,
    AIUnavailableError: 503,
    AITimeoutError: 504,
}


def _unauthorized() -> HTTPException:
    """Build the single 401 every authentication failure returns.

    One response for a missing, malformed, or wrong credential: the caller
    learns that the request was not authenticated and nothing else. The
    expected key never appears in a response body, a header, or a log line.
    """
    return HTTPException(
        status_code=401,
        detail="missing or invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_api_key(request: Request) -> None:
    """Authenticate the request against ``ANON_API_KEY``.

    Wired as a route-level dependency on POST /anonymize, so it runs BEFORE
    ``_read_payload``: a rejected request never has its body parsed and the
    document is never processed. The comparison is constant-time
    (``secrets.compare_digest`` over UTF-8 bytes, which also keeps a non-ASCII
    header from raising). ``GET /healthz`` does not depend on this.
    """
    expected = request.app.state.cfg.anon_api_key
    if not expected:
        # Unreachable through the lifespan, which refuses to start without a
        # key; reachable only if app.state was assembled by hand. Never serve.
        logger.error("ANON_API_KEY is not configured; refusing every request")
        raise HTTPException(status_code=503, detail="server authentication is not configured")

    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.strip().casefold() != "bearer":
        logger.warning("rejected request with missing or non-bearer Authorization header")
        raise _unauthorized()
    if not secrets.compare_digest(token.strip().encode("utf-8"), expected.encode("utf-8")):
        logger.warning("rejected request with an incorrect API key")
        raise _unauthorized()


async def _read_payload(request: Request) -> bytes:
    """Extract the uploaded DOCX bytes from a multipart form or raw request body, enforcing content type and size limits. Returns the raw payload bytes."""
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is None:
            raise InvalidDocumentError("multipart form is missing the 'file' field")
        if not isinstance(upload, UploadFile):
            # A plain text field named "file" — a client contract error, not a
            # server fault: answer 400 rather than raising AttributeError.
            raise InvalidDocumentError("multipart field 'file' must be a file part")
        data = await upload.read()
    elif content_type.startswith(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ) or content_type.startswith("application/octet-stream"):
        data = await request.body()
    else:
        raise HTTPException(status_code=415, detail="unsupported content type")
    if not data:
        raise InvalidDocumentError("empty request body")
    if len(data) > request.app.state.cfg.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="upload exceeds ANON_MAX_UPLOAD_MB")
    return data


def _postcheck_headers(postcheck: PostcheckSummary | None) -> dict[str, str]:
    """Render the mandatory scan's non-blocking findings as response headers.

    A returned document has already passed the scan, so these are advisory:
    ``X-Postcheck-Findings`` is the total count and ``X-Postcheck-Kinds`` the
    per-kind breakdown (kind names only — never matched document text, which
    could itself be personal information). Callers that want the full list use
    ``?summary=1``.
    """
    if postcheck is None:
        return {}
    kinds = ",".join(f"{kind}={count}" for kind, count in sorted(postcheck.by_kind.items()))
    return {
        "X-Postcheck-Findings": str(postcheck.findings_total),
        "X-Postcheck-Kinds": kinds or "none",
    }


@app.post("/anonymize", dependencies=[Depends(require_api_key)])
def anonymize(
    request: Request,
    summary: int = 0,
    payload: bytes = Depends(_read_payload),
) -> Response:
    """Anonymize the uploaded Greek DOCX document and return the redacted file, or a JSON summary with the base64-encoded DOCX when the summary query flag is set. Requires a valid bearer API key; see ``require_api_key``."""
    result = anonymize_document(
        payload,
        config=request.app.state.cfg,
        files=request.app.state.files,
        client=request.app.state.client,
    )
    if not summary:
        return Response(
            content=result.redacted_docx,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={
                "Content-Disposition": f'attachment; filename="{result.document_id}_redacted.docx"',
                # The file passed its scan (a HIGH finding never reaches here).
                # These report what the scan flagged without blocking.
                **_postcheck_headers(result.postcheck),
            },
        )
    return JSONResponse(
        content={
            "document_id": result.document_id,
            "summary": dataclasses.asdict(result.summary),
            "warnings": result.warnings,
            "model": result.model,
            "postcheck": dataclasses.asdict(result.postcheck) if result.postcheck else None,
            "provenance": result.provenance,
            "docx_base64": base64.b64encode(result.redacted_docx).decode("ascii"),
        }
    )


@app.get("/healthz")
def healthz(request: Request) -> dict:
    """Return a health-check dict with service status and the configured AI provider and model. Unauthenticated by design, so another service can probe liveness; it exposes no secret."""
    return {
        "status": "ok",
        "provider": request.app.state.cfg.provider,
        "model": request.app.state.cfg.model_handle,
    }


@app.exception_handler(AnonymizerError)
def handle_anonymizer_error(request: Request, exc: AnonymizerError) -> JSONResponse:
    """Map a raised AnonymizerError to its HTTP status code and return a JSON error response with the error name and detail."""
    status_code = _ERROR_STATUS_CODES.get(type(exc), 500)
    return JSONResponse(
        status_code=status_code,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


@app.exception_handler(Exception)
def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Return a generic 500 JSON error response for any unhandled exception without leaking details."""
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "detail": "internal error"},
    )
