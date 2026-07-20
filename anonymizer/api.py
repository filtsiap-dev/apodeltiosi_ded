import base64
import dataclasses
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from anonymizer.config import load_file_config, load_runtime_config
from anonymizer.errors import (
    AIProviderError,
    AITimeoutError,
    AIUnavailableError,
    AnonymizerError,
    ConfigurationError,
    DocumentProcessingError,
    InvalidDocumentError,
)
from anonymizer.llm.client import build_client
from anonymizer.pipeline import anonymize_document


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load runtime and file configuration, configure logging, and attach the LLM client to app state for the app's lifetime, closing the client on shutdown."""
    cfg = load_runtime_config()
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
    AIProviderError: 502,
    ConfigurationError: 503,
    AIUnavailableError: 503,
    AITimeoutError: 504,
}


async def _read_payload(request: Request) -> bytes:
    """Extract the uploaded DOCX bytes from a multipart form or raw request body, enforcing content type and size limits. Returns the raw payload bytes."""
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is None:
            raise InvalidDocumentError("multipart form is missing the 'file' field")
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


@app.post("/anonymize")
def anonymize(
    request: Request,
    summary: int = 0,
    payload: bytes = Depends(_read_payload),
) -> Response:
    """Anonymize the uploaded Greek DOCX document and return the redacted file, or a JSON summary with the base64-encoded DOCX when the summary query flag is set."""
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
                "Content-Disposition": f'attachment; filename="{result.document_id}_redacted.docx"'
            },
        )
    return JSONResponse(
        content={
            "document_id": result.document_id,
            "summary": dataclasses.asdict(result.summary),
            "warnings": result.warnings,
            "model": result.model,
            "docx_base64": base64.b64encode(result.redacted_docx).decode("ascii"),
        }
    )


@app.get("/healthz")
def healthz(request: Request) -> dict:
    """Return a health-check dict with service status and the configured AI provider and model."""
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
