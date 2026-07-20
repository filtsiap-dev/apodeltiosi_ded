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
from anonymizer.llm.detector import run_llm_detection
from anonymizer.models import AnonymizeResult
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

    Runs parse -> detect -> llm -> resolve -> apply, timing each stage, and
    returns the redacted bytes plus a counts-only summary. Catches nothing;
    every callee exception propagates. The only exception this function itself
    raises is the invariant-1 RuntimeError below.
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

    timings["total"] = time.perf_counter() - t_total

    return AnonymizeResult(
        document_id=document_id,
        redacted_docx=redacted,
        summary=build_summary(plan),
        warnings=list(plan.warnings),
        model=config.model_handle,
        timings=timings,
    )
