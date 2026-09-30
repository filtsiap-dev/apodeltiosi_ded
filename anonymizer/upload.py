"""Reading the request body without agreeing to hold all of it first.

``request.body()`` buffers the whole upload and hands it over; checking its
length afterwards is a size limit that has already been paid for. This module
reads the stream instead, counting as it goes, and stops at the first chunk that
crosses the line.

It exists as a separate module for a reason worth keeping: ``anonymizer.api`` is
deliberately free of ``async def`` and ``await`` — its whole request path is
synchronous, and a test asserts that — so the one coroutine the framework
requires lives here and is bridged into the worker thread by the api's
``_await_sync``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from anonymizer.errors import InvalidDocumentError, ResourceLimitExceededError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.requests import Request

    from anonymizer.deadline import Deadline


async def read_body_limited(
    request: "Request", limit: int, deadline: "Deadline | None" = None
) -> bytes:
    """Return the request body, refusing to buffer more than ``limit`` bytes.

    Two guards, because one is not enough:

    1. A ``Content-Length`` that is already over the limit is refused BEFORE any
       body is read. This is the cheap case and the common one — an honest
       client that sent too much learns so immediately, having transferred
       nothing.
    2. A running byte count while streaming. Content-Length is a claim by the
       sender: it can be absent (a chunked upload), or it can be a lie. The
       counter is what makes the limit true either way, and it stops at the
       first chunk that crosses — the rest of the body is never read, so an
       oversized upload costs the memory of one chunk rather than all of it.

    Raises :class:`ResourceLimitExceededError` (413) when the body is too large
    and :class:`InvalidDocumentError` (400) when the declared length is not a
    length at all. Called only after authentication has passed, so an
    unauthenticated caller's body is never read at any size.

    ``deadline`` is the document's budget. It is checked between chunks, so a
    client that sends its body slowly cannot hold a worker past the deadline
    by never finishing — the upload is inside the budget, not before it.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            announced = int(declared)
        except ValueError:
            raise InvalidDocumentError(
                "malformed Content-Length header",
                code="MALFORMED_CONTENT_LENGTH",
            ) from None
        if announced < 0:
            raise InvalidDocumentError(
                "negative Content-Length header",
                code="MALFORMED_CONTENT_LENGTH",
            )
        if announced > limit:
            raise ResourceLimitExceededError(
                f"declared upload size {announced} exceeds the {limit}-byte limit",
                code="UPLOAD_TOO_LARGE",
            )

    buffer = bytearray()
    async for chunk in request.stream():
        if deadline is not None:
            deadline.check("upload")
        buffer += chunk
        if len(buffer) > limit:
            # Drop what was read before raising, and do NOT drain the rest of
            # the stream: continuing to read a body we have already refused is
            # the exact work the limit exists to avoid.
            buffer.clear()
            raise ResourceLimitExceededError(
                f"upload exceeds the {limit}-byte limit",
                code="UPLOAD_TOO_LARGE",
            )
    return bytes(buffer)


__all__ = ["read_body_limited"]
