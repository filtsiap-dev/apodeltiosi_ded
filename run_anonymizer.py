"""Isolated, removable CLI runner for the DED anonymizer v2.

This file is the ENTIRE command-line surface of the project. It imports only
the public pipeline API (`load_runtime_config`, `load_file_config`,
`build_client`, `anonymize_document`, and the typed error hierarchy) — no
private names, no internals. Deleting this one file removes the CLI completely
with zero edits to any pipeline module; the HTTP service
(`anonymizer.api:app`) is unaffected either way.

ONE DOCUMENT PER INVOCATION, matching the HTTP service exactly. There is no
folder mode and no batch loop: the shell already has one (`Get-ChildItem`,
`xargs`), it composes better than anything this script could offer, and a batch
loop inside the process meant one document's deadline, one document's exit code
and one document's usage totals all had to be reconciled against the others.
A run that processes one file has one outcome, and the exit code says what it
was.

Configuration comes from the project `.env` file, always: the `.env` next to
this script is loaded into the process environment automatically (via the
shared dependency-free loader `anonymizer.config.load_env_file` — not the
python-dotenv package). The HTTP API loads the same file. A variable already
set in the real environment is never overridden by `.env` — the file only
fills in what is missing.

Usage (PowerShell, from the project root):

    # fill in .env once, then just run — no need to set $env: vars yourself
    python .\\run_anonymizer.py --file "C:\\path\\to\\decision.docx"
    python .\\run_anonymizer.py .\\decision.docx --out .\\redacted\\decision.docx --qa

    # several documents: let the shell do what shells do
    Get-ChildItem *.docx | ForEach-Object { python .\\run_anonymizer.py $_.FullName }

Accepted inputs are the four OOXML Word formats — `.docx`, `.docm`, `.dotx`,
`.dotm` — and the output is always a `.docx`. Legacy binary `.doc`/`.dot` is
not supported; convert it in Word first.

THE OUTPUT IS WRITTEN ATOMICALLY. The bytes go to a temporary file beside the
destination, are flushed and fsynced, and only then replace the destination in
a single operation. A crash, a full disk or a Ctrl+C therefore leaves either
the previous file or no file — never a half-written DOCX that looks like a
result. The temporary file is removed on any failure.

Every document is scanned for residual personal information by the pipeline
itself, after redaction and before this script writes anything. The scan runs
exactly once, and what a finding does depends on whether it names document
TEXT: one that does is put back to LLM pass 2 and, if pass 2 says so, redacted
before this script ever sees the bytes; one that does not — a surviving macro,
a tracked change, a comment part, residue of the write path — raises
`ResidualPIIError` when it is HIGH, and no output is written. `--qa` only
controls how much of that scan is printed; it cannot turn the scan off.

The findings `--qa` prints therefore describe the document BEFORE any such
correction, because it is not scanned a second time. The warning lines above
them say how many were re-adjudicated and how many further redactions were
applied.

Separately, a document can come back `status=needs-review`: the LLM left one
or more findings unsettled after its corrective retry, so nothing was written
for them and the locations are printed for a person to check. The file IS
produced and the exit code is 0 — human review is part of the normal workflow,
and this is how the CLI says which documents need it. A residual the scan found
and pass 2 then failed to settle arrives the same way. Exit code 4 is the
different, harder failure: the scan found something no redaction could settle,
so nothing was written.

Exit codes:
    0  processed (including status=needs-review — the file was written)
    1  processing failed
    2  usage error: no input, both argument forms, a missing path, a directory,
       or an unsupported extension
    3  configuration error (missing/invalid environment or config/ files)
    4  blocked by the mandatory post-redaction scan; nothing was written
    5  the document exceeded its end-to-end processing budget
    130  interrupted by the user (Ctrl+C)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
import time
from pathlib import Path

from anonymizer.config import load_env_file, load_file_config, load_runtime_config
from anonymizer.deadline import RunContext
from anonymizer.errors import (
    AnonymizerError,
    ConfigurationError,
    DocumentTimeoutError,
    ResidualPIIError,
)
from anonymizer.llm.client import build_client
from anonymizer.logsetup import clamp_third_party_loggers
from anonymizer.pipeline import anonymize_document

logger = logging.getLogger("run_anonymizer")

EXIT_OK = 0
EXIT_PROCESSING_FAILED = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_QA_HIGH = 4  # blocked by the mandatory post-redaction scan
EXIT_TIMEOUT = 5  # the document exceeded its end-to-end processing budget

_REDACTED_SUFFIX = "_redacted.docx"

# The four OOXML Word formats the pipeline accepts. Checked here so a legacy
# .doc gets a usage error naming the problem, rather than travelling all the
# way into the package validator to come back as "not a ZIP".
ACCEPTED_SUFFIXES = frozenset({".docx", ".docm", ".dotx", ".dotm"})


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser. Returns the configured ArgumentParser."""
    parser = argparse.ArgumentParser(
        prog="run_anonymizer",
        description=(
            "Anonymize ONE Greek DED decision document via the v2 pipeline "
            "(deterministic detectors + mandatory two-pass LLM). For several "
            "documents, loop in the shell."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=None,
        help=(
            "Path to one .docx/.docm/.dotx/.dotm file. Alternative to --file; "
            "give exactly one of the two."
        ),
    )
    parser.add_argument(
        "--file",
        default=None,
        help=(
            "Path to one .docx/.docm/.dotx/.dotm file. Alternative to the "
            "positional argument; give exactly one of the two."
        ),
    )
    parser.add_argument(
        "--out",
        default=None,
        help=(
            "Path of the redacted output file. Default: <input stem>_redacted.docx "
            "next to the input. Parent directories are created."
        ),
    )
    parser.add_argument(
        "--config-dir",
        default=None,
        help=(
            "Directory holding policy.yaml / regex_patterns.yaml / allowlists/. "
            "Default: the config/ folder next to this script."
        ),
    )
    parser.add_argument(
        "--qa",
        action="store_true",
        help=(
            "Print every finding of the post-redaction residual-leak scan. "
            "The scan itself always runs — this flag only makes it verbose."
        ),
    )
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Print the document's counts-only summary as one JSON line.",
    )
    return parser


def _resolve_input(args: argparse.Namespace) -> tuple[Path | None, str]:
    """Turn the two argument forms into one path, or explain what is wrong.

    Returns ``(path, "")`` when the input is usable, or ``(None, message)``
    when it is not. Every rejection here is a usage error — the caller has not
    named one processable document — and each says which of the five things
    went wrong rather than a single generic sentence.
    """
    if args.file and args.input:
        return None, "pass the input as either the positional argument or --file, not both"
    raw = args.file or args.input
    if not raw:
        return None, "no input given (pass a path, or use --file <path>)"

    path = Path(raw)
    if path.is_dir():
        # Named specifically. This used to be folder mode, so an operator with
        # the old habit deserves to be told where it went rather than being
        # shown "not a file".
        return None, (
            f"{path} is a directory; this command processes ONE document. "
            f"Loop in the shell to process several."
        )
    if not path.exists():
        return None, f"no such file: {path}"
    if not path.is_file():
        return None, f"not a regular file: {path}"
    if path.suffix.lower() not in ACCEPTED_SUFFIXES:
        return None, (
            f"unsupported file type {path.suffix or '(none)'}; expected one of "
            f"{', '.join(sorted(ACCEPTED_SUFFIXES))}. Legacy .doc/.dot must be "
            f"converted in Word first."
        )
    return path, ""


def _write_atomically(target: Path, payload: bytes) -> None:
    """Write ``payload`` to ``target`` so the path is never partially written.

    Three steps, none of them optional:

    1. write to a temporary file IN THE SAME DIRECTORY (``os.replace`` is only
       atomic within one filesystem, and a temp directory is often another);
    2. ``flush`` then ``os.fsync``, so the bytes are on the device and not only
       in the OS cache — a power loss between write and rename would otherwise
       leave a correctly-named file full of zeros;
    3. ``os.replace``, which is atomic on POSIX and on Windows.

    The consequence worth stating: a failed run can never masquerade as a
    success, and it can never truncate an output that was already there.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        # BaseException, not Exception: a Ctrl+C during the write must not
        # leave the temporary file behind either.
        tmp.unlink(missing_ok=True)
        raise


def _print_qa(qa, source_name: str) -> None:
    """Print the findings of the scan the pipeline already ran.

    Takes the PostcheckSummary carried on the result — the scan is never run a
    second time, here or anywhere. A summary reaching this function may well
    contain HIGH findings: those that named a slice of document text were put
    back to LLM pass 2, and this is the record of what was found, not of what
    is still there. What a HIGH finding here does NOT mean is that the document
    was released unaudited — one that nothing could settle aborts it before it
    can be written or printed.

    No matched text is printed: severity, kind, location and a counts-only
    detail. The slice a finding carries exists for pass 2 and stops here.
    """
    if qa is None:
        return
    status = "CLEAN" if qa.clean else "FINDINGS"
    print(
        f"  qa[{source_name}]: {status} total={qa.findings_total} "
        f"by_severity={qa.by_severity} by_kind={qa.by_kind}"
    )
    for finding in qa.findings:
        print(
            f"    {finding.severity:6} {finding.kind:28} {finding.location}: "
            f"{finding.detail}"
        )


def _log_finished(
    ctx: RunContext,
    outcome: str,
    started: float,
    unresolved: int,
    error_code: str,
) -> None:
    """One final event per document, exactly as the HTTP service emits.

    Same shape on purpose: whoever reads the logs should not have to learn
    two formats depending on which entry point produced the document.
    """
    logger.info(
        "document_finished %s outcome=%s elapsed_s=%.2f unresolved_count=%d "
        "error_code=%s",
        ctx.tag(), outcome, time.perf_counter() - started, unresolved, error_code,
    )


def _report(result, target: Path, args: argparse.Namespace, source_name: str) -> None:
    """Print everything a person wants to see about a finished document."""
    summary = result.summary
    print(f"done: {target}")
    if result.needs_review:
        # The file IS written: it is built from evidence that was validated,
        # and everything the LLM could not settle was left exactly as it was
        # rather than guessed at. What a person has to do is look at these
        # locations before publishing.
        print(
            f"  status=needs-review unresolved_count={result.unresolved_count}"
            f" — a person must settle these before publication"
        )
        for finding in result.unresolved:
            where = ", ".join(
                f"{unit_id}[{start}:{end}]"
                for unit_id, start, end in finding.locations
            ) or "no location — the finding could not be quoted"
            print(
                f"    unresolved: chunk {finding.chunk_number} "
                f"{finding.kind} ({where})"
            )
    else:
        print("  status=processed")
    print(
        f"  spans={summary.spans_total} by_action={summary.by_action} "
        f"model={result.model} elapsed={result.timings.get('total', 0.0):.1f}s"
    )
    usage = result.llm_usage
    if usage is not None:
        print(
            f"  llm_calls={usage.calls} tokens_in={usage.input_tokens} "
            f"tokens_out={usage.output_tokens} tokens_total={usage.total_tokens}"
        )
        if usage.calls_missing_usage:
            print(
                f"  note: {usage.calls_missing_usage} call(s) reported no token "
                f"usage, so the totals above are incomplete"
            )
        for call in usage.truncated:
            print(
                f"  warning: chunk {call.chunk_number} pass {call.pass_number} "
                f"({call.attempt} attempt) hit the output limit "
                f"({call.output_tokens}/{call.limit} tokens) — raise "
                f"ANON_MAX_COMPLETION_TOKENS"
            )
    for warning in result.warnings:
        print(f"  warning: {warning}")
    if args.summary_json:
        print(json.dumps(
            {
                **dataclasses.asdict(summary),
                "status": result.status,
                "unresolved_count": result.unresolved_count,
                "provenance": result.provenance,
                "timings": result.timings,
                "llm_usage": (
                    dataclasses.asdict(result.llm_usage)
                    if result.llm_usage is not None
                    else None
                ),
            },
            ensure_ascii=False,
        ))
    if args.qa:
        _print_qa(result.postcheck, source_name)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: parse args, load config, process ONE document.

    Returns one of the module-level EXIT_* codes; never raises to the shell.
    """
    args = _build_arg_parser().parse_args(argv)
    # Quiet console: bare messages only, and only the pipeline/LLM progress
    # loggers at INFO — httpx request lines, timestamps, and logger names are
    # all suppressed. Errors from any library still show (root is WARNING).
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    for name in ("anonymizer.pipeline", "anonymizer.llm.detector", "run_anonymizer"):
        logging.getLogger(name).setLevel(logging.INFO)
    # The CLI can be run with a raised level too, and the SDK would then log
    # the prompts — which are the document.
    clamp_third_party_loggers()

    # Always load the project .env (next to this script) first, so the CLI
    # works from any working directory. Real environment variables win.
    load_env_file(Path(__file__).resolve().parent / ".env")

    source, problem = _resolve_input(args)
    if source is None:
        print(f"error: {problem}", file=sys.stderr)
        return EXIT_USAGE

    target = (
        Path(args.out)
        if args.out
        else source.with_name(f"{source.stem}{_REDACTED_SUFFIX}")
    )

    config_dir = (
        Path(args.config_dir)
        if args.config_dir
        else Path(__file__).resolve().parent / "config"
    )

    try:
        runtime = load_runtime_config()
        files = load_file_config(config_dir)
        client = build_client(runtime)
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    print(f"started: {source.name}")
    # One budget for this document, started here. The id is opaque and
    # generated: a filename is chosen by whoever sent the document and can
    # contain anything, including somebody's name, and correlation ids end up
    # in every log line.
    ctx = RunContext.start(runtime.document_deadline_s)
    started = time.perf_counter()
    try:
        try:
            result = anonymize_document(
                source.read_bytes(),
                config=runtime,
                files=files,
                client=client,
                ctx=ctx,
            )
        except DocumentTimeoutError as exc:
            print(f"TIMED OUT  {source.name}: {exc}", file=sys.stderr)
            print(f"  no file written to {target}", file=sys.stderr)
            _log_finished(ctx, exc.outcome, started, 0, exc.code)
            return EXIT_TIMEOUT
        except ResidualPIIError as exc:
            # The pipeline redacted the file, but its mandatory scan still
            # found HIGH-severity personal information. Nothing is written: a
            # document that failed its own check must not be left looking like
            # a result.
            print(f"NEEDS MANUAL REVIEW  {source.name}: {exc}", file=sys.stderr)
            print(f"  no file written to {target}", file=sys.stderr)
            _log_finished(ctx, exc.outcome, started, 0, exc.code)
            return EXIT_QA_HIGH
        except AnonymizerError as exc:
            print(f"FAILED  {source.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            _log_finished(ctx, exc.outcome, started, 0, exc.code)
            return EXIT_PROCESSING_FAILED
        except OSError as exc:
            # Reading the input, not processing it: a permission problem or an
            # unreadable device is the operator's, and it is not a pipeline
            # failure. The filename is theirs and already on their screen.
            print(f"FAILED  {source.name}: cannot read input ({exc.strerror})",
                  file=sys.stderr)
            _log_finished(ctx, "error", started, 0, "INPUT_UNREADABLE")
            return EXIT_PROCESSING_FAILED

        try:
            _write_atomically(target, result.redacted_docx)
        except OSError as exc:
            print(f"FAILED  {source.name}: cannot write output ({exc.strerror})",
                  file=sys.stderr)
            _log_finished(ctx, "error", started, result.unresolved_count,
                          "OUTPUT_UNWRITABLE")
            return EXIT_PROCESSING_FAILED

        _log_finished(
            ctx,
            "needs_review" if result.needs_review else "success",
            started,
            result.unresolved_count,
            "-",
        )
        _report(result, target, args, source.name)
        return EXIT_OK
    finally:
        # The SDK client owns an HTTP connection pool. One CLI invocation is
        # short-lived enough that the interpreter would clean it up anyway, but
        # closing it explicitly means no ResourceWarning, no sockets held open
        # while a slow postcheck finishes, and the same shape as the API's
        # lifespan shutdown.
        close = getattr(client, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # pragma: no cover - closing must never fail a run
                logger.debug("client close failed", exc_info=False)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl+C mid-run (usually while waiting on an LLM call): exit cleanly
        # with the conventional SIGINT code instead of dumping a traceback.
        print("\ninterrupted by user", file=sys.stderr)
        sys.exit(130)
