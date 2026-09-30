"""Minimal reference client for the anonymizer HTTP API.

Standard library only — nothing here is imported by the service, so a calling
application can copy this single file as-is. It shows the whole contract, which
is short: the document bytes are the request body, and the redacted DOCX bytes
are the response body.

    source.read_bytes() -> request body -> response body -> out.write_bytes()

There is no form to build, no field name to agree on, and nothing to decode on
the way back.

Four input formats are accepted — ``.docx``, ``.docm``, ``.dotx``, ``.dotm`` —
and the media type must match the file, so the extension picks it. The output
is always a ``.docx``.

WHAT THIS FILE DEMONSTRATES BEYOND THE HAPPY PATH, because a calling
application needs all of it:

* **A timeout.** The server's own budget is 300 seconds per document; a client
  with no timeout waits forever on a network that dropped the connection. The
  default here is 330 — the server's budget plus a margin — so a client
  timeout means the network, and a 504 means the document.
* **The three review headers.** ``X-Anonymization-Status`` is ``processed`` or
  ``needs-review``; the latter is a SUCCESS with unsettled findings that a
  person must look at before publication. An application that ignores this
  header will publish documents nobody checked.
* **Verifying the response is a DOCX before writing it.** A proxy that returns
  an HTML error page with status 200 is a real thing.
* **Writing atomically**, so an interrupted download cannot leave a file that
  looks like a result.

Usage:

    python examples/anonymize_client.py \
        --url http://localhost:8000 \
        --file decision.docx \
        --out decision_redacted.docx
"""

from __future__ import annotations

import argparse
import json
import math
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

# The media type must match the file: the server checks it and answers 415 on a
# mismatch rather than sniffing the bytes and guessing.
MEDIA_TYPES = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docm": "application/vnd.ms-word.document.macroEnabled.12",
    ".dotx": "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    ".dotm": "application/vnd.ms-word.template.macroEnabled.12",
}

# The server's document budget is 300 s. Wait a little longer than that, so a
# client-side timeout means the NETWORK and a 504 means the DOCUMENT — two
# different problems with two different fixes.
DEFAULT_TIMEOUT_S = 330.0

# Every OOXML package is a ZIP, and every ZIP starts with this.
ZIP_MAGIC = b"PK\x03\x04"


class ApiError(RuntimeError):
    """A request that did not produce a document, with the server's own reason."""

    def __init__(self, message: str, *, status: int | None = None, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


def anonymize(
    url: str, api_key: str, source: Path, *, timeout: float = DEFAULT_TIMEOUT_S
) -> tuple[bytes, dict[str, str]]:
    """POST ``source`` to ``<url>/anonymize``; return its bytes and headers.

    The file's bytes go out as the request body and the redacted file's bytes
    come back as the response body — the returned bytes are already a complete
    DOCX package, ready to write to disk.

    ``api_key`` is sent as ``Authorization: Bearer <key>``; without a valid one
    the server answers 401 and never reads the document.

    Raises :class:`ApiError` for every failure — an HTTP error carrying the
    server's own ``code`` and ``detail``, a timeout, a refused connection, or a
    response whose body is not a package.
    """
    media_type = MEDIA_TYPES.get(source.suffix.lower())
    if media_type is None:
        raise ApiError(
            f"unsupported file type {source.suffix or '(none)'}; expected one of "
            f"{', '.join(sorted(MEDIA_TYPES))}"
        )

    request = urllib.request.Request(
        url.rstrip("/") + "/anonymize",
        data=source.read_bytes(),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": media_type,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            headers = {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        detail, code = raw, ""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(parsed, dict):
                detail = str(parsed.get("detail", raw))
                code = str(parsed.get("code", ""))
        raise ApiError(f"HTTP {exc.code}: {detail}", status=exc.code, code=code) from None
    except socket.timeout:
        # Distinct from the server's 504 on purpose: this one means the request
        # never came back, so the document's fate is unknown.
        raise ApiError(f"no response within {timeout:g}s") from None
    except urllib.error.URLError as exc:
        # Covers a refused connection, DNS failure and TLS problems. urlopen
        # also raises a bare socket.timeout via URLError on some versions.
        reason = exc.reason
        if isinstance(reason, socket.timeout):
            raise ApiError(f"no response within {timeout:g}s") from None
        raise ApiError(f"cannot reach {url}: {reason}") from None
    except OSError as exc:
        raise ApiError(f"cannot reach {url}: {exc}") from None

    # A 200 whose body is not a package means something between here and the
    # service answered — a proxy error page, a captive portal, a login form.
    # Writing it to a .docx would produce a file that fails to open much later.
    if not body.startswith(ZIP_MAGIC):
        raise ApiError(
            f"the response body is not a DOCX package ({len(body)} bytes); "
            f"something other than the anonymizer answered"
        )
    return body, headers


def write_atomically(target: Path, payload: bytes) -> None:
    """Write ``payload`` so ``target`` is never left partially written."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, call the API once, and write the redacted DOCX to --out."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000", help="API base address")
    parser.add_argument(
        "--api-key",
        default=os.environ.get("ANON_API_KEY"),
        help="bearer credential; defaults to the ANON_API_KEY environment variable",
    )
    parser.add_argument("--file", required=True, help="path to the document to anonymize")
    parser.add_argument("--out", required=True, help="path to write the redacted .docx")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"seconds to wait for the response (default {DEFAULT_TIMEOUT_S:g})",
    )
    args = parser.parse_args(argv)

    if not args.api_key:
        print("error: no API key (pass --api-key or set ANON_API_KEY)", file=sys.stderr)
        return 2

    source = Path(args.file)
    if not source.is_file():
        print(f"error: no such file: {source}", file=sys.stderr)
        return 2

    # A non-finite or non-positive timeout is a wait that never ends, which is
    # the failure mode this argument exists to prevent. NaN needs the explicit
    # isfinite: every comparison against it is False, so `> 0` alone lets it
    # through.
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        print("error: --timeout must be a positive number of seconds", file=sys.stderr)
        return 2

    try:
        redacted, headers = anonymize(
            args.url, args.api_key, source, timeout=args.timeout
        )
    except ApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: cannot read {source}: {exc}", file=sys.stderr)
        return 1

    try:
        write_atomically(Path(args.out), redacted)
    except OSError as exc:
        print(f"error: cannot write {args.out}: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {args.out} ({len(redacted)} bytes)")

    # The review headers. Printed always, because a caller who does not know a
    # document needs review is a caller who publishes it unchecked.
    status = headers.get("x-anonymization-status", "unknown")
    print(f"  status={status}")
    print(f"  document_id={headers.get('x-document-id', '-')}")
    if status == "needs-review":
        print(
            f"  unresolved={headers.get('x-unresolved-count', '?')}"
            f" — a person must settle these before publication"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
