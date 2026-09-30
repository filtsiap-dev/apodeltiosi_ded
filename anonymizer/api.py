"""HTTP transport for the anonymizer.

One endpoint contract, stable for calling applications:

    POST /anonymize   the DOCX bytes as the request body
                      Content-Type: <the DOCX media type>
                      Authorization: Bearer <ANON_API_KEY>
                      -> the redacted DOCX bytes as the response body
    GET  /healthz     unauthenticated liveness probe

THE BODY IS THE DOCUMENT, IN BOTH DIRECTIONS:

    DOCX bytes -> request body -> anonymize_document -> response body -> DOCX bytes

and that is the entire payload contract. The request carries no form, no field
name and no envelope; the successful response carries no JSON, no base64, no
path and no wrapper object. A caller writes the response body straight to a
``.docx`` and opens it, with nothing to decode first.

ONE ACCEPTED SHAPE, on purpose. ``multipart/form-data`` (a ``file`` field) and
``application/octet-stream`` were both accepted once and are now refused with
415. Three ways in meant three code paths, three sets of failure modes and three
things to document for the same bytes; the header now says DOCX or the request
does not proceed. Anything the endpoint has to report beyond the file — the
post-redaction scan's non-blocking counts — travels in response headers, where
it cannot get between the caller and the bytes.

This module is transport only. It reads the body, calls the SAME
``anonymize_document`` pipeline the CLI calls (one shared implementation, so
CLI and API results cannot drift apart), and returns its bytes. No detection,
policy, or redaction logic lives here.

LOGS GO TO STDOUT, NEVER INTO THE RESPONSE. ``configure_logging`` points the
root logger at stdout with a timestamped format, so the pipeline's stage lines,
the LLM detector's chunk and retry lines, and this module's failure lines all
land in the terminal the server is running in, as they happen. The response body
is unaffected by any of it: on success it is the DOCX, on failure a fixed JSON
error, and a traceback appears in neither.

There is deliberately NO request-logging middleware. Uvicorn and gunicorn
already log every request line (``accesslog = "-"`` in ``gunicorn.conf.py``
puts gunicorn's on stdout too), and the application already logs the work it
does; a third layer would repeat both. Nothing here correlates requests with
ids either — one process logging its stages in order is legible without them.

AUTHENTICATION HAPPENS BEFORE THE BODY IS TOUCHED. The order is:

    request -> read Authorization header -> validate -> 401, or
    -> read body -> validate size/type -> anonymize

and it is enforced by what the route does NOT declare. FastAPI reads and parses
the body BEFORE it solves dependencies, so any ``File``/``Form``/``Body``
parameter on this route would make an unauthenticated caller pay for that work
before ``require_api_key`` ever ran. There is therefore no body parameter here:
the endpoint takes ``Request``, and reads the body itself once the dependency
has let it through. The dependency reads only headers and ``app.state`` —
nothing that needs a body.

Keep it that way. Adding ``file: UploadFile = File(...)`` back would be a
one-line change that looks tidier and silently restores pre-auth parsing;
``tests/test_api_auth_before_body.py`` fails if it does.

THE REQUEST PATH IS SYNCHRONOUS. Every function that handles a POST
/anonymize request — the dependency, the body reader, the endpoint — is a
plain ``def``. There is no ``async def`` and no ``await`` in the application
code, and the pipeline it calls is synchronous throughout (its chunk
concurrency is a thread pool, not asyncio). FastAPI runs a ``def`` endpoint in
a worker thread, so a slow document occupies a thread rather than blocking the
event loop.

The one call the framework offers no synchronous form of is reading the request
body; ``_await_sync`` bridges that single coroutine from the worker thread.
``lifespan`` is ``async`` because FastAPI accepts no other form, but it is
startup/shutdown, not the request path.
"""

import logging
import secrets
import sys
import time
import traceback
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Coroutine

import anyio.from_thread

from fastapi import Depends, FastAPI, HTTPException, Request
# JSONResponse serves the ERROR bodies only. A successful /anonymize response is
# a bare Response carrying the DOCX bytes, so there is no base64, no dataclasses
# and nothing multipart anywhere in this module — the absent imports are the
# cheapest guarantee of that.
from fastapi.responses import JSONResponse, Response

from anonymizer.config import load_file_config, load_runtime_config
from anonymizer.deadline import RunContext
from anonymizer.errors import (
    AIProviderError,
    AITimeoutError,
    AIUnavailableError,
    AnonymizerError,
    ConfigurationError,
    DocumentProcessingError,
    DocumentTimeoutError,
    InternalError,
    InvalidDocumentError,
    PromptInjectionError,
    ResidualPIIError,
    ResourceLimitExceededError,
    UnsupportedDocumentFormatError,
)
from anonymizer.llm.client import build_client
from anonymizer.logsetup import clamp_third_party_loggers
from anonymizer.pipeline import anonymize_document
from anonymizer.postcheck import PostcheckSummary
from anonymizer.upload import read_body_limited

logger = logging.getLogger(__name__)


# One readable line per event: when, how bad, who said it, what happened.
#
#   2026-09-10 17:10:32 INFO anonymizer.pipeline stage=parse document_id=abc123 ...
#   2026-09-10 17:10:35 WARNING anonymizer.llm.detector llm_retry chunk=2 pass=1 ...
#
# The logger name is the module path, so a line says which stage produced it and
# `ANON_LOG_LEVEL` plus a grep are enough to follow one concern. Messages
# themselves are already `key=value` throughout the application.
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(level: str) -> None:
    """Send this process's application logs to stdout, formatted and readable.

    Called once from ``lifespan``. Stdout rather than stderr because that is
    where a container's log collector looks and where an operator running the
    server in a terminal is already watching; gunicorn is configured to put its
    own access and error lines in the same place.

    ``force=True`` is the load-bearing argument. ``basicConfig`` does nothing at
    all if the root logger already has a handler — so a single library that
    logged during import, or any future change to how the server starts, would
    silently leave this formatting unapplied and the symptom would be "the logs
    look different", not an error. Forcing makes the outcome the same either
    way: this configuration, or a visible failure.

    It is safe against the servers in front of us. Neither uvicorn nor gunicorn
    installs a root handler, and gunicorn sets ``propagate = False`` on its
    ``gunicorn.access`` / ``gunicorn.error`` loggers, so replacing the root
    handler cannot swallow or duplicate their lines.

    NOT called by the CLI, which configures its own quiet bare-message console
    on purpose (see ``run_anonymizer.main``): a person watching one file being
    processed wants the progress lines, not timestamps and logger names.
    """
    logging.basicConfig(
        level=level,
        stream=sys.stdout,
        format=_LOG_FORMAT,
        datefmt=_LOG_DATEFMT,
        force=True,
    )
    # Raising OUR verbosity must not raise anybody else's. The OpenAI SDK
    # logs its request options at DEBUG, and those options contain the
    # prompt — which is the document. See anonymizer/logsetup.py.
    clamp_third_party_loggers()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load runtime and file configuration, configure logging, and attach the LLM client
    to app state for the app's lifetime, closing the client on shutdown.

    Raises ConfigurationError when ANON_API_KEY is unset, so the service never
    starts unauthenticated.

    This is the only ``async def`` in the module, and it is not part of the
    request path: FastAPI accepts a lifespan only as an async context manager.
    It awaits nothing — the body is ordinary synchronous setup around one
    ``yield``.
    """
    cfg = load_runtime_config()
    if not cfg.anon_api_key:
        # Fail closed. Starting without a key would expose an unauthenticated
        # POST /anonymize; there is no "no auth" mode for the HTTP transport.
        raise ConfigurationError(
            "ANON_API_KEY is required to serve the HTTP API "
            "(POST /anonymize is bearer-authenticated)"
        )
    files = load_file_config(Path("config"))
    configure_logging(cfg.log_level)
    client = build_client(cfg)
    app.state.cfg = cfg
    app.state.files = files
    app.state.client = client
    yield
    client.close()


app = FastAPI(lifespan=lifespan)


_ERROR_STATUS_CODES: dict[type[AnonymizerError], int] = {
    InvalidDocumentError: 400,
    # A real document in a format this service does not take. Nothing is
    # wrong with the file, so it is not a 400.
    UnsupportedDocumentFormatError: 415,
    ResourceLimitExceededError: 413,
    # The document carries text shaped like an instruction to the model.
    PromptInjectionError: 422,
    # The document was redacted, but its mandatory scan still found HIGH
    # residual PII: nothing is returned, the caller must review it by hand.
    ResidualPIIError: 422,
    # Valid input that this service could not turn into valid output. Ours.
    DocumentProcessingError: 500,
    AIProviderError: 502,
    # A provider call that timed out is a provider failure, like any other:
    # 504 is reserved for ONE thing, so that a caller seeing it knows exactly
    # which limit they hit and what to do about it.
    AITimeoutError: 502,
    ConfigurationError: 503,
    AIUnavailableError: 503,
    # The five-minute end-to-end budget, and nothing else.
    DocumentTimeoutError: 504,
    InternalError: 500,
}


def _status_for(exc: AnonymizerError) -> int:
    """The HTTP status for a domain failure, honouring subclasses.

    Walks the MRO rather than looking the exact type up, so a subclass added
    later inherits its parent's status instead of silently becoming a 500.
    """
    for cls in type(exc).__mro__:
        status = _ERROR_STATUS_CODES.get(cls)
        if status is not None:
            return status
    return 500


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

    Wired as a route-level dependency on POST /anonymize, and the route declares
    no body parameter, so this runs before ANY body handling: a rejected request
    never has its upload read, parsed, or spooled to disk, and the document is
    never processed. It reads only the request headers and ``app.state``, both
    available without touching the body — which is what makes that ordering
    possible. The comparison is constant-time
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


def _await_sync(operation: Callable[..., Coroutine[Any, Any, Any]], *args: Any) -> Any:
    """Run Starlette's body-reading coroutine from this sync request path.

    Used for exactly one call, ``request.body()``. Starlette exposes the request
    body only as a coroutine and offers no synchronous accessor, so there is
    nothing else to call.

    FastAPI runs a ``def`` endpoint in an anyio worker thread, and
    ``anyio.from_thread.run`` is anyio's supported way to hand one awaitable
    back to the event loop that owns the request and block for its result here.

    So this is a call *into* framework machinery in the one place the framework
    provides nothing else, not application-level async: no ``async def`` and no
    ``await`` appear anywhere in this module's request handling, and nothing
    downstream of it is a coroutine.

    The precondition — that the caller is on a worker thread started by the
    running loop — holds because every handler on this path is a plain ``def``,
    which is exactly what makes FastAPI use a worker thread. Turning one of
    them into an ``async def`` would break this, which is the other reason not
    to.
    """
    return anyio.from_thread.run(operation, *args)


_DOCX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
)

# The Word media types a request may declare. The header decides only whether
# the body is worth reading; what the bytes actually ARE is decided by
# `anonymizer.word_formats.sniff_format` from the package itself, and the
# response is always a plain .docx whatever came in.
#
# Stored CASEFOLDED, because `_media_type` casefolds what the caller sent and
# two of these are spelled with a capital in the registry ("macroEnabled").
# Comparing a folded header against an unfolded set silently refuses every
# macro-enabled document.
_ACCEPTED_MEDIA_TYPES = frozenset({
    _DOCX_MEDIA_TYPE,
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.ms-word.template.macroenabled.12",
})


def _media_type(content_type: str) -> str:
    """The bare media type from a Content-Type header: parameters off, lowercased.

    ``application/vnd...document; charset=utf-8`` and
    ``Application/VND...Document`` both reduce to the media type, which is what
    is compared. Parameters are ignored rather than rejected — they are legal
    and say nothing about the payload — but the media type itself must match
    EXACTLY. A prefix test would accept ``...wordprocessingml.document-ish``.
    """
    return content_type.split(";", 1)[0].strip().casefold()


def _read_upload(request: Request, deadline=None) -> bytes:
    """Return the request body as the DOCX to anonymize, enforcing type and size.

    THE BODY IS THE DOCUMENT. There is no envelope, no form and no field name:
    the bytes a caller sends are the bytes the pipeline parses. Anything that is
    not declared as a DOCX is refused with 415 before the body is read at all —
    including ``multipart/form-data`` and ``application/octet-stream``, both of
    which this endpoint used to accept and deliberately no longer does. One
    accepted shape means one code path to reason about, and a caller cannot
    half-succeed by picking the wrong one.

    Called from the endpoint, so it runs only after ``require_api_key`` has
    passed: an unauthenticated caller's body is never read.
    """
    if _media_type(request.headers.get("content-type", "")) not in _ACCEPTED_MEDIA_TYPES:
        raise UnsupportedDocumentFormatError(
            "send the Word document as the request body with one of these "
            f"content types: {', '.join(sorted(_ACCEPTED_MEDIA_TYPES))}"
        )
    # Streamed and counted, so the size limit costs one chunk rather than the
    # whole body. The one coroutine lives in `anonymizer.upload` to keep this
    # module free of async, and is bridged here exactly as `request.body` was.
    data = _await_sync(
        read_body_limited, request,
        request.app.state.cfg.limits.max_upload_bytes, deadline,
    )
    if not data:
        raise InvalidDocumentError("empty request body")
    return data


def _postcheck_headers(postcheck: PostcheckSummary | None) -> dict[str, str]:
    """Render the mandatory scan's non-blocking findings as response headers.

    A returned document has already passed the scan, so these are advisory:
    ``X-Postcheck-Findings`` is the total count and ``X-Postcheck-Kinds`` the
    per-kind breakdown (kind names only — never matched document text, which
    could itself be personal information).

    Headers, not body: the response body is the DOCX and nothing else, so
    anything else this endpoint has to say travels alongside it. Callers wanting
    the full finding list run the CLI, which prints it.
    """
    if postcheck is None:
        return {}
    kinds = ",".join(f"{kind}={count}" for kind, count in sorted(postcheck.by_kind.items()))
    return {
        "X-Postcheck-Findings": str(postcheck.findings_total),
        "X-Postcheck-Kinds": kinds or "none",
    }


# Request and response bodies, described by hand. The route deliberately
# declares no body PARAMETER — that is what would make FastAPI parse the upload
# before authentication — so the schema callers read is written here instead. It
# is documentation only: nothing in this dict affects how a request is handled.
_BINARY_DOCX = {"schema": {"type": "string", "format": "binary"}}
_OPENAPI_BODIES = {
    "requestBody": {
        "required": True,
        "description": "the Word document to anonymize, as the raw request body",
        "content": {
            media_type: _BINARY_DOCX for media_type in sorted(_ACCEPTED_MEDIA_TYPES)
        },
    },
    "responses": {
        "200": {
            "description": "the redacted DOCX, as the raw response body",
            "content": {_DOCX_MEDIA_TYPE: _BINARY_DOCX},
        }
    },
}


@app.post(
    "/anonymize",
    dependencies=[Depends(require_api_key)],
    openapi_extra=_OPENAPI_BODIES,
    response_class=Response,
)
def anonymize(request: Request) -> Response:
    """Anonymize the DOCX in the request body and return the redacted DOCX as the
    response body.

    BYTES IN, BYTES OUT. The request body is the document; the response body is
    the redacted document, and nothing else — no JSON envelope, no base64, no
    path or URL, no metadata carrying the file. A caller writes the response
    body straight to a ``.docx`` and opens it. Everything the endpoint has to
    say beyond the file travels in headers, where it cannot get between the
    caller and the bytes.

    NO BODY PARAMETER, deliberately. FastAPI reads and parses the body before it
    solves dependencies, so a ``File``/``Form``/``Body`` parameter here would
    have an unauthenticated caller paying for that work before
    ``require_api_key`` ran. The body is read below, by which point the
    dependency has already rejected anyone without a valid key.

    A plain ``def``, so FastAPI runs the whole request on a worker thread: the
    body read, the pipeline (parse, detect, both LLM passes, resolve, apply,
    scan) and the response assembly. Nothing here is a coroutine and nothing
    blocks the event loop.
    """
    cfg = request.app.state.cfg
    # The clock starts HERE: after authentication has passed, before a byte of
    # the body is read. Everything the document costs this service is inside
    # the budget, including receiving it.
    ctx = RunContext.start(cfg.document_deadline_s)
    started = time.perf_counter()
    outcome, status, error_code, unresolved = "internal_error", 500, "INTERNAL_ERROR", 0

    try:
        data = _read_upload(request, ctx.deadline)
        result = anonymize_document(
            data,
            config=cfg,
            files=request.app.state.files,
            client=request.app.state.client,
            ctx=ctx,
        )
        # A document finished after the deadline is still a document nobody
        # finished in time. Returning it would make the budget advisory.
        ctx.deadline.check("respond")
        response = _docx_response(result)
    except AnonymizerError as exc:
        outcome, status, error_code = exc.outcome, _status_for(exc), exc.code
        raise
    except Exception as exc:
        # Wrapped so it leaves by the typed path: an exception that escapes
        # this function is re-raised by Starlette after the 500 is sent, and
        # the server then logs its full text — which for a failure deep in the
        # document path can quote the document.
        _log_unexpected(ctx, exc)
        raise InternalError("unexpected failure") from exc
    else:
        outcome = "needs_review" if result.needs_review else "success"
        status, error_code = 200, "-"
        unresolved = result.unresolved_count
        return response
    finally:
        # EXACTLY ONE of these per document, on every path. It is what lets an
        # operator count outcomes and see how long they took without
        # reconstructing anything from stage lines.
        logger.log(
            logging.INFO if status < 400
            else logging.WARNING if status < 500
            else logging.ERROR,
            "document_finished %s outcome=%s status=%d elapsed_s=%.2f "
            "unresolved_count=%d error_code=%s",
            ctx.tag(), outcome, status, time.perf_counter() - started,
            unresolved, error_code,
        )


def _docx_response(result) -> Response:
    """The success response: the bytes, and what the caller has to know.

    THE BODY IS THE DOCUMENT AND NOTHING ELSE, so everything the endpoint
    has to report travels in headers. Wrapping the DOCX in a JSON envelope
    to carry three short values would put a decode step between every
    caller and their file, for metadata most of them will read once.

    THE ONE A CALLER MUST NOT IGNORE is ``X-Anonymization-Status``. A
    ``needs-review`` response is a SUCCESS — the file is complete, built
    only from evidence that was validated, and nothing was invented for the
    findings pass 2 could not settle. It is a 200 because there IS a
    document, and a person has to look at ``X-Unresolved-Count`` locations
    in it before it is published. An integrator who treats 200 as 'done'
    will publish documents nobody checked, which is why the status is a
    header on every response rather than a flag on some of them.

    Every value is an id, an enum or an integer. No count, no id and no
    status is derived from the document's text, so nothing here can carry
    any of it into a proxy log.
    """
    return Response(
        content=result.redacted_docx,
        media_type=_DOCX_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{result.document_id}_redacted.docx"',
            # The opaque per-document id that every log line for this
            # request also carries. A caller reporting a problem can quote
            # it, and an operator can grep the whole document's history by
            # it. It is NOT the filename: filenames are chosen by whoever
            # sent the document and can contain somebody's name.
            "X-Document-ID": result.document_id,
            "X-Anonymization-Status": result.status,
            "X-Unresolved-Count": str(result.unresolved_count),
            # The file passed its scan (a HIGH finding never reaches here).
            # These report what the scan flagged without blocking.
            **_postcheck_headers(result.postcheck),
        },
    )


def _frames(exc: BaseException) -> str:
    """The traceback as file, line and function only — never the source line.

    ``traceback.format_tb`` would include the source of each frame. That is
    usually harmless and occasionally not: a literal in a raise statement ends
    up in the log verbatim, and this service raises from inside document
    handling. The file and line number locate the bug just as well.
    """
    return "\n".join(
        f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}'
        for frame in traceback.extract_tb(exc.__traceback__)
    )


def _log_unexpected(ctx: RunContext, exc: BaseException) -> None:
    """Record a bug with enough detail to fix it and none to leak.

    File, line and function for every frame — the shape of the failure — and
    nothing else. Two things are deliberately left out:

    * ``str(exc)``, which ``logger.exception`` would append. An exception raised
      from inside document handling can quote the document: a ZIP member name,
      a parser error carrying a fragment of XML.
    * the SOURCE LINE of each frame, which ``traceback.format_tb`` includes.
      Source is usually harmless but is not guaranteed to be — a literal in a
      raise statement reaches the log verbatim — and the file and line number
      already say where to look.
    """
    logger.error(
        "unhandled_exception %s error=%s cause=%s\n%s",
        ctx.tag(),
        type(exc).__name__,
        type(exc.__cause__).__name__ if exc.__cause__ else "-",
        _frames(exc),
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
    """Map a raised AnonymizerError to its HTTP status code and return a JSON error response with the error name and detail.

    Logs the failure as operational metadata: method, path, status and exception
    CLASS. Not the message — an ``AnonymizerError`` is raised from deep in the
    document path and, while today's messages are machine-written and carry no
    document text, the difference between "no message contains text" and "no
    message can contain text" is one future f-string. The class and the status
    are what an operator needs to see a pattern; a single request's detail
    already goes to the caller, who sent the document in the first place.

    5xx logs at ERROR (something on this side went wrong), 4xx at WARNING (the
    request was wrong), so the levels sort the way an operator expects.
    """
    status_code = _status_for(exc)
    # NOT logged here. The endpoint emits exactly one `document_finished`
    # line per document, on every path including this one, and a second
    # final event would have to be reconciled with it by whoever reads the
    # logs. Failures that never reach the endpoint — a bad health probe, a
    # misconfigured app — still surface through the unexpected handler below.
    #
    # `public_detail`, NEVER `str(exc)`. The message is raised from deep in
    # the document path and quotes what it found there: an lxml parser error
    # carries a fragment of the XML, a corrupt-member failure carries the
    # member name, a limit failure carries sizes measured from the upload.
    # Those belong in the operator's log, where the document's sender can
    # already see them; they do not belong in a response body that may cross
    # a proxy, a browser console and a ticketing system on its way to
    # somebody who never had the file.
    return JSONResponse(
        status_code=status_code,
        content={
            "error": type(exc).__name__,
            "code": exc.code,
            "detail": exc.public_detail,
        },
    )


@app.exception_handler(Exception)
def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Return a generic 500 JSON error response for any unhandled exception without leaking details.

    THE TRACEBACK GOES TO THE SERVER LOG AND NOWHERE ELSE. An unexpected
    exception is a bug in this service, and the two audiences want opposite
    things from it: whoever has to fix it needs the stack, and the caller must
    not be told anything about our internals — an exception string here is
    unreviewed text from an unknown code path and could name a file, a config
    value or a piece of the document. So ``logger.exception`` writes the full
    traceback to stdout, and the response stays the fixed generic body it has
    always been.
    """
    # Frames only, never `str(exc)`: see `_log_unexpected`. This handler is
    # now the LAST resort — anything raised inside the endpoint is already
    # wrapped as InternalError — so reaching it means a failure outside the
    # document path entirely.
    logger.error(
        "unhandled_exception method=%s path=%s error=%s\n%s",
        request.method,
        request.url.path,
        type(exc).__name__,
        _frames(exc),
    )
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "detail": "internal error"},
    )
