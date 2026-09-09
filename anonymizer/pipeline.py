from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from anonymizer.config import FileConfig, RuntimeConfig
from anonymizer.detectors import detect_all
from anonymizer.docx_engine import (
    parse_docx,
    validate_docx_bytes,
    write_redacted_docx,
)
from anonymizer.errors import ResidualPIIError
from anonymizer.llm.detector import run_llm_detection
from anonymizer.llm.prompts import PROMPTS_SHA256
from anonymizer.models import AnonymizeResult
from anonymizer.postcheck import scan_redacted_docx_bytes
from anonymizer.resolver import resolve_redactions
from anonymizer.summary import build_summary

logger = logging.getLogger(__name__)

_FINAL_ACTIONS = {"REDACT", "PRESERVE"}


def anonymize_document(
    docx_bytes: bytes,
    *,
    config: RuntimeConfig,
    files: FileConfig,
    client: Any,
    document_id: str | None = None,
) -> AnonymizeResult:
    """Transport-neutral anonymization pipeline over raw DOCX bytes.

    Runs parse -> detect -> llm -> resolve -> apply -> scan, timing each stage,
    and returns the redacted bytes plus a counts-only summary.

    The final scan is MANDATORY and there is no flag to skip it: every caller
    (CLI and API alike) gets output that has been audited for residual personal
    information. A HIGH-severity finding raises :class:`ResidualPIIError`, so no
    such document is ever returned as a successful result — a result object can
    only exist for a document that passed. Lower-severity findings do not block;
    they ride along in ``result.postcheck`` and in ``result.warnings``.

    Catches nothing; every callee exception propagates. The exceptions this
    function itself raises are the invariant-1 RuntimeError below and
    ResidualPIIError.
    """
    if document_id is None:
        document_id = uuid.uuid4().hex[:12]

    timings: dict[str, float] = {}
    t_total = time.perf_counter()

    # Stage: parse
    t0 = time.perf_counter()
    validate_docx_bytes(docx_bytes)
    document = parse_docx(docx_bytes, document_id)
    timings["parse"] = time.perf_counter() - t0
    logger.info(
        "stage=parse document_id=%s units=%d elapsed=%.3fs",
        document_id,
        len(document.text_units),
        timings["parse"],
    )

    # Stage: detect
    t0 = time.perf_counter()
    detection = detect_all(document, files.rules)
    timings["detect"] = time.perf_counter() - t0
    logger.info(
        "stage=detect document_id=%s candidate_spans=%d review_hints=%d elapsed=%.3fs",
        document_id,
        len(detection.resolver_spans),
        len(detection.review_hints),
        timings["detect"],
    )

    # Stage: llm
    t0 = time.perf_counter()
    llm_spans = run_llm_detection(
        document,
        deterministic_spans=detection.resolver_spans,
        review_hints=detection.review_hints,
        client=client,
        cfg=config,
    )
    timings["llm"] = time.perf_counter() - t0
    logger.info(
        "stage=llm document_id=%s llm_spans=%d elapsed=%.3fs",
        document_id,
        len(llm_spans),
        timings["llm"],
    )

    # Stage: resolve — review_hints are LLM input only and never reach the resolver.
    t0 = time.perf_counter()
    plan = resolve_redactions(document, llm_spans + detection.resolver_spans, files.policy)
    timings["resolve"] = time.perf_counter() - t0
    if any(span.action not in _FINAL_ACTIONS for span in plan.spans):
        raise RuntimeError("plan contains a non-final action — programming bug")
    logger.info(
        "stage=resolve document_id=%s plan_spans=%d elapsed=%.3fs",
        document_id,
        len(plan.spans),
        timings["resolve"],
    )

    # Stage: apply
    t0 = time.perf_counter()
    redacted = write_redacted_docx(docx_bytes, document, plan)
    validate_docx_bytes(redacted)
    timings["apply"] = time.perf_counter() - t0
    logger.info(
        "stage=apply document_id=%s redacted_bytes=%d elapsed=%.3fs",
        document_id,
        len(redacted),
        timings["apply"],
    )

    # Stage: scan — the mandatory post-redaction audit of the produced file.
    # Runs on the bytes that are about to be handed back, after
    # write_redacted_docx and before any caller can save or return them.
    t0 = time.perf_counter()
    postcheck = scan_redacted_docx_bytes(redacted, files)
    timings["scan"] = time.perf_counter() - t0
    high = postcheck.by_severity.get("HIGH", 0)
    logger.info(
        "stage=scan document_id=%s findings=%d high=%d by_kind=%s elapsed=%.3fs",
        document_id,
        postcheck.findings_total,
        high,
        postcheck.by_kind,
        timings["scan"],
    )
    if high:
        # Fail closed. The document is not returned and not saved: the leak has
        # to be looked at by a person. Locations and kinds only — the finding
        # details are not echoed, so the error text carries no document text.
        locations = ", ".join(
            f"{f.kind}@{f.location}" for f in postcheck.findings if f.severity == "HIGH"
        )
        raise ResidualPIIError(
            f"post-redaction scan found {high} HIGH-severity finding(s); "
            f"the document needs manual review ({locations})"
        )

    # Non-blocking findings travel with the result so a caller can surface them.
    warnings = list(plan.warnings)
    if postcheck.findings_total:
        warnings.append(
            f"post-redaction scan: {postcheck.findings_total} non-blocking "
            f"finding(s) {postcheck.by_kind}"
        )

    timings["total"] = time.perf_counter() - t_total

    # Reproducibility stamp: enough to answer "which rules, prompts, model and
    # package produced this published document?" after the fact.
    try:
        from importlib.metadata import version

        package_version = version("ded-anonymizer")
    except Exception:
        package_version = "unknown"
    provenance = {
        "provider": config.provider,
        "model": config.model_handle,
        "config_sha256": files.config_sha256,
        "prompts_sha256": PROMPTS_SHA256,
        "package_version": package_version,
    }

    return AnonymizeResult(
        document_id=document_id,
        redacted_docx=redacted,
        summary=build_summary(plan),
        warnings=warnings,
        model=config.model_handle,
        timings=timings,
        postcheck=postcheck,
        provenance=provenance,
    )
