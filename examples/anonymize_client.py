"""Minimal reference client for the anonymizer HTTP API.

Standard library only — nothing here is imported by the service, so a calling
application can copy this single file as-is. It shows the whole contract: the
API address, and the DOCX file.

Usage:

    python examples/anonymize_client.py \
        --url http://localhost:8000 \
        --file decision.docx \
        --out decision_redacted.docx
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def build_multipart_body(field_name: str, filename: str, payload: bytes) -> tuple[bytes, str]:
    """Encode one file as a multipart/form-data body.

    Returns the body bytes and the matching Content-Type header value. Written
    out by hand so the example needs no third-party HTTP library.
    """
    boundary = uuid.uuid4().hex
    disposition = (
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
    )
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            disposition.encode("utf-8"),
            b"\r\n",
            f"Content-Type: {DOCX_MIME}\r\n\r\n".encode(),
            payload,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    return body, f"multipart/form-data; boundary={boundary}"


def anonymize(url: str, api_key: str, source: Path) -> bytes:
    """POST ``source`` to ``<url>/anonymize`` and return the redacted DOCX bytes.

    ``api_key`` is sent as ``Authorization: Bearer <key>``; without a valid one
    the server answers 401 and never reads the document. Raises RuntimeError
    carrying the server's JSON error detail on any non-2xx response.
    """
    body, content_type = build_multipart_body("file", source.name, source.read_bytes())
    request = urllib.request.Request(
        url.rstrip("/") + "/anonymize",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": content_type,
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            detail = json.loads(raw).get("detail", raw)
        except json.JSONDecodeError:
            detail = raw
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from None


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, call the API once, and write the redacted DOCX to --out."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000", help="API base address")
    parser.add_argument(
        "--api-key",
        default=os.environ.get("ANON_API_KEY"),
        help="bearer credential; defaults to the ANON_API_KEY environment variable",
    )
    parser.add_argument("--file", required=True, help="path to the .docx to anonymize")
    parser.add_argument("--out", required=True, help="path to write the redacted .docx")
    args = parser.parse_args(argv)

    if not args.api_key:
        print("error: no API key (pass --api-key or set ANON_API_KEY)", file=sys.stderr)
        return 2

    source = Path(args.file)
    if not source.is_file():
        print(f"error: no such file: {source}", file=sys.stderr)
        return 2

    try:
        redacted = anonymize(args.url, args.api_key, source)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    Path(args.out).write_bytes(redacted)
    print(f"wrote {args.out} ({len(redacted)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
