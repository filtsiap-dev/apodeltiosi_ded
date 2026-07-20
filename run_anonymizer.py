"""Isolated, removable CLI runner for the DED anonymizer v2.

This file is the ENTIRE command-line surface of the project. It imports only
the public pipeline API (`load_runtime_config`, `load_file_config`,
`build_client`, `anonymize_document`, `scan_redacted_docx_bytes`, and the typed
error hierarchy) — no private names, no internals. Deleting this one file
removes the CLI completely with zero edits to any pipeline module; the HTTP
service (`anonymizer.api:app`) is unaffected either way.

Configuration comes from the project `.env` file, always: the `.env` next to
this script is loaded into the process environment automatically (via the
shared dependency-free loader `anonymizer.config.load_env_file` — not the
python-dotenv package). The HTTP API loads the same file. A variable already
set in the real environment is never overridden by `.env` — the file only
fills in what is missing.

Usage (PowerShell, from the project root):

    # fill in .env once, then just run — no need to set $env: vars yourself
    python .\\run_anonymizer.py --file "C:\\absolute\\path\\to\\decision.docx"
    python .\\run_anonymizer.py --file "C:\\absolute\\path\\to\\folder_of_docx" --out-dir .\\redacted --qa

    # a plain positional path works the same way, as an alternative to --file:
    python .\\run_anonymizer.py .\\path\\to\\decision.docx

Exit codes:
    0  every document processed successfully (and, with --qa, no HIGH findings)
    1  at least one document failed to process
    2  usage error: no input given, both --file and the positional argument given,
       input path missing, or no .docx files found
    3  configuration error (missing/invalid environment or config/ files)
    4  all documents processed, but --qa found HIGH-severity residual findings
    130  interrupted by the user (Ctrl+C)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from pathlib import Path

from anonymizer.config import load_env_file, load_file_config, load_runtime_config
from anonymizer.errors import AnonymizerError, ConfigurationError
from anonymizer.llm.client import build_client
from anonymizer.pipeline import anonymize_document
from anonymizer.postcheck import scan_redacted_docx_bytes

logger = logging.getLogger("run_anonymizer")

EXIT_OK = 0
EXIT_PROCESSING_FAILED = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_QA_HIGH = 4

_REDACTED_SUFFIX = "_redacted.docx"


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser. Returns the configured ArgumentParser."""
    parser = argparse.ArgumentParser(
        prog="run_anonymizer",
        description=(
            "Anonymize one Greek DED decision DOCX, or every .docx in a folder, "
            "via the v2 pipeline (deterministic detectors + mandatory two-pass LLM)."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=None,
        help=(
            "Path to a .docx file, or a folder containing .docx files (non-recursive). "
            "Alternative to --file; give exactly one of the two."
        ),
    )
    parser.add_argument(
        "--file",
        default=None,
        help=(
            "Path to a .docx file, or a folder containing .docx files (non-recursive). "
            "Alternative to the positional argument; give exactly one of the two."
        ),
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help=(
            "Directory for redacted outputs. Default: next to each input file. "
            "Outputs are named <stem>_redacted.docx."
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
            "After redacting, run the out-of-band postcheck residual-leak audit "
            "on each output and report its findings."
        ),
    )
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Print each document's counts-only summary as one JSON line.",
    )
    return parser


def _collect_inputs(input_path: Path) -> list[Path]:
    """Resolve the input argument to a list of .docx files to process.

    A file input yields itself; a folder yields its .docx children
    (non-recursive), skipping prior *_redacted.docx outputs. Returns the sorted
    list, which may be empty.
    """
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        return sorted(
            p
            for p in input_path.glob("*.docx")
            if p.is_file() and not p.name.endswith(_REDACTED_SUFFIX)
        )
    return []


def _output_path(source: Path, out_dir: Path | None) -> Path:
    """Compute the redacted-output path for a source document.

    Uses <stem>_redacted.docx inside out_dir when given, else next to source.
    """
    target_dir = out_dir if out_dir is not None else source.parent
    return target_dir / f"{source.stem}{_REDACTED_SUFFIX}"


def _report_qa(redacted_bytes: bytes, files_config, source_name: str) -> int:
    """Run the postcheck audit on redacted bytes and print its findings.

    Returns the number of HIGH-severity findings; prints a per-kind breakdown
    so the caller's log shows what survived redaction.
    """
    qa = scan_redacted_docx_bytes(redacted_bytes, files_config)
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
    return qa.by_severity.get("HIGH", 0)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: parse args, load config once, process each document.

    Returns one of the module-level EXIT_* codes; never raises to the shell.
    """
    args = _build_arg_parser().parse_args(argv)
    # Quiet console: bare messages only, and only the pipeline/LLM progress
    # loggers at INFO — httpx request lines, timestamps, and logger names are
    # all suppressed. Errors from any library still show (root is WARNING).
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    for name in ("anonymizer.pipeline", "anonymizer.llm.detector"):
        logging.getLogger(name).setLevel(logging.INFO)

    # Always load the project .env (next to this script) first, so the CLI
    # works from any working directory. Real environment variables win.
    load_env_file(Path(__file__).resolve().parent / ".env")

    if args.file and args.input:
        print(
            "error: pass the input as either the positional argument or --file, not both",
            file=sys.stderr,
        )
        return EXIT_USAGE
    input_arg = args.file or args.input
    if not input_arg:
        print("error: no input given (pass a path, or use --file <path>)", file=sys.stderr)
        return EXIT_USAGE

    input_path = Path(input_arg)
    sources = _collect_inputs(input_path)
    if not sources:
        print(f"error: no .docx input found at {input_path}", file=sys.stderr)
        return EXIT_USAGE

    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

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

    failures = 0
    qa_high_total = 0
    for source in sources:
        target = _output_path(source, out_dir)
        print(f"started: {source.name}")
        try:
            result = anonymize_document(
                source.read_bytes(),
                config=runtime,
                files=files,
                client=client,
                document_id=source.stem,
            )
        except AnonymizerError as exc:
            failures += 1
            print(f"FAILED  {source.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue

        target.write_bytes(result.redacted_docx)
        summary = result.summary
        print(f"done: {target}")
        print(
            f"  spans={summary.spans_total} by_action={summary.by_action} "
            f"model={result.model} elapsed={result.timings.get('total', 0.0):.1f}s"
        )
        if result.warnings:
            for warning in result.warnings:
                print(f"  warning: {warning}")
        if args.summary_json:
            print(json.dumps(dataclasses.asdict(summary), ensure_ascii=False))
        if args.qa:
            qa_high_total += _report_qa(result.redacted_docx, files, source.name)

    if failures:
        return EXIT_PROCESSING_FAILED
    if args.qa and qa_high_total:
        return EXIT_QA_HIGH
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl+C mid-run (usually while waiting on an LLM call): exit cleanly
        # with the conventional SIGINT code instead of dumping a traceback.
        print("\ninterrupted by user", file=sys.stderr)
        sys.exit(130)
