"""Two-pass LLM detection engine for the Greek document-anonymization service.

Pass 1 reads each chunk BLIND (no deterministic suggestions of any kind) and
proposes candidate decisions from scratch. Pass 2 is an INFORMED VALIDATION
pass: it receives the chunk text plus ALL known spans — the deterministic
REDACT / PRESERVE / REVIEW detections and the located pass-1 proposals — in one
uniform ``{"text", "category", "action", "context"}`` shape, and must confirm,
correct, or add. Only pass-2 output is located into ``Span`` objects; pass-1
findings are advisory context only and never become spans.

In pass-2 handling the category is validated FIRST, before the action switch,
so REVIEW→REDACT coercion warnings fire only for entries that survive to
produce spans.

The LLM stage is MANDATORY: there is no enabled/disabled switch and no
no-client fallback. ``client`` is duck-typed; ``openai`` is imported only for
its exception types.
"""

from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import openai

from anonymizer.config import RuntimeConfig
from anonymizer.errors import AIProviderError, AITimeoutError, AIUnavailableError
from anonymizer.llm.prompts import (
    SYSTEM_PROMPT_PASS1,
    SYSTEM_PROMPT_PASS2,
    build_pass1_message,
    build_pass2_message,
)
from anonymizer.models import ALL_CATEGORIES, DocumentData, Span, TextUnit

logger = logging.getLogger(__name__)


# Normalizes model category improvisations back onto the schema. Copied verbatim
# from the task spec — do not edit without a matching change to the schema.
_CATEGORY_ALIASES = {
    "PERSON": "POSSIBLE_PERSON",
    "COMPANY": "POSSIBLE_COMPANY",
    "ADDRESS": "POSSIBLE_PRIVATE_LOCATION",
    "PROTOCOL": "PROTOCOL_NUMBER",
    "TAXPAYER": "APPELLANT_NAME",
    "APPELLANT": "APPELLANT_NAME",
    "FATHER": "FATHER_NAME",
    "PATRONYMIC": "FATHER_NAME",
    "COMPANY_NAME": "PRIVATE_COMPANY_NAME",
    "BUSINESS_ADDRESS": "BUSINESS_SEAT",
    "DEVICE_ID": "FISCAL_DEVICE_ID",
    "FISCAL_DEVICE": "FISCAL_DEVICE_ID",
    "INVOICE_ID": "INVOICE_TABLE_ID",
    "INVOICE": "INVOICE_TABLE_ID",
    "BENEFICIARY": "PRIVATE_BENEFICIARY",
    "BANK": "BANK_ACCOUNT",
    "CASE_REF": "CASE_REF_NUMBER",
    "ACT_REF": "CHALLENGED_ACT_NUMBER",
    "SIGNATORY": "OFFICIAL_SIGNATORY",
    "AUTHORITY_HEADER": "PUBLIC_AUTHORITY_HEADER",
    "DECISION_NUMBER": "DECISION_METADATA",
}

_CONTEXT_WINDOW = 40


# ---------------------------------------------------------------------------
# Chunk
# ---------------------------------------------------------------------------

@dataclass
class Chunk:
    """One LLM work item: a table (whole) or a run of paragraph units."""

    units: list[TextUnit]
    is_table: bool
    table_index: int | None = None

    @property
    def unit_ids(self) -> set[str]:
        """Return the set of unit_ids contained in this chunk."""
        return {u.unit_id for u in self.units}

    @property
    def text(self) -> str:
        """Render the chunk as the text sent to the model.

        Tables render as a "TABLE:" header plus one pipe-joined line per row;
        paragraph chunks render as newline-joined unit texts.
        """
        if self.is_table:
            rows: dict[int, list[TextUnit]] = {}
            for unit in self.units:
                row_idx = int(unit.location["row_index"])
                rows.setdefault(row_idx, []).append(unit)
            lines = ["TABLE:"]
            for row_idx in sorted(rows):
                cells = sorted(rows[row_idx], key=lambda u: int(u.location["col_index"]))
                lines.append(" | ".join(cell.normalized_text for cell in cells))
            return "\n".join(lines)
        return "\n".join(u.normalized_text for u in self.units)


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def split_into_chunks(document: DocumentData, chunk_size_chars: int) -> list[Chunk]:
    """Split a document into table chunks (one per table) then paragraph chunks.

    Tables are emitted first, grouped by ``(part_name, table_index)`` in
    first-seen order; each table is a single chunk regardless of size. Non-table
    units with non-empty ``normalized_text`` are then accumulated, in document
    order, into paragraph chunks whose joined text stays within
    ``chunk_size_chars``. A unit longer than the limit becomes its own oversized
    chunk; a unit is never split.
    """
    chunks: list[Chunk] = []

    # Tables first, one chunk per table, first-seen order.
    table_order: list[tuple[str, int]] = []
    table_groups: dict[tuple[str, int], list[TextUnit]] = {}
    for unit in document.text_units:
        if unit.unit_type != "table_cell":
            continue
        key = (unit.part_name, int(unit.location["table_index"]))
        if key not in table_groups:
            table_groups[key] = []
            table_order.append(key)
        table_groups[key].append(unit)

    for part_name, table_index in table_order:
        chunks.append(
            Chunk(
                units=table_groups[(part_name, table_index)],
                is_table=True,
                table_index=table_index,
            )
        )

    # Paragraph chunks, accumulated by joined-text length.
    current: list[TextUnit] = []
    current_len = 0
    for unit in document.text_units:
        if unit.unit_type == "table_cell":
            continue
        if not unit.normalized_text:
            continue
        unit_len = len(unit.normalized_text)
        if current and current_len + 1 + unit_len > chunk_size_chars:
            chunks.append(Chunk(units=current, is_table=False))
            current = []
            current_len = 0
        current_len = unit_len if not current else current_len + 1 + unit_len
        current.append(unit)

    if current:
        chunks.append(Chunk(units=current, is_table=False))

    return chunks


# ---------------------------------------------------------------------------
# JSON extraction (shared two-step)
# ---------------------------------------------------------------------------

def _extract_json_array(raw: str) -> list | None:
    """Two-step extraction: ``json.loads`` then a bracketed-array fallback.

    Returns the parsed list, or ``None`` when parsing fails or the result is not
    a list. Callers decide whether ``None`` is lenient (empty) or fatal.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\[.*\]", raw or "", re.DOTALL)
        if match is None:
            return None
        try:
            parsed = json.loads(match.group())
        except json.JSONDecodeError:
            return None
    if not isinstance(parsed, list):
        return None
    return parsed


# ---------------------------------------------------------------------------
# Pass-1 parsing (LENIENT)
# ---------------------------------------------------------------------------

def parse_pass1_findings(raw: str) -> list[dict]:
    """Parse pass-1 output leniently into advisory findings.

    A failed pass 1 degrades to a blind pass 2 rather than aborting: on
    unparseable or non-list output a single warning is logged and ``[]`` is
    returned. Kept entries are dicts with keys exactly ``text``, ``action``,
    ``category``. These are NEVER located into resolver spans and NEVER become
    ``Span`` objects; they re-enter pass 2 only as known-span context.
    """
    decisions = _extract_json_array(raw)
    if decisions is None:
        logger.warning("pass-1 output unparseable; continuing with empty findings")
        return []

    findings: list[dict] = []
    for entry in decisions:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("text", "")).strip()
        if not text:
            continue
        action = str(entry.get("action", "")).strip().upper()
        if action == "SKIP":
            continue
        if action not in {"REDACT", "PRESERVE", "REVIEW"}:
            logger.debug("pass-1 dropping entry with unknown action")
            continue
        category = str(entry.get("category", "")).strip().upper()
        category = _CATEGORY_ALIASES.get(category, category)
        if category not in ALL_CATEGORIES:
            logger.debug("pass-1 dropping entry with invalid category")
            continue
        findings.append({"text": text, "action": action, "category": category})

    return findings


# ---------------------------------------------------------------------------
# Pass-2 parsing (STRICT) — produces spans
# ---------------------------------------------------------------------------

def parse_pass2_spans(raw: str, chunk: Chunk) -> list[Span]:
    """Parse pass-2 output strictly into located spans.

    Unparseable or non-list output raises ``AIProviderError``. The category is
    validated FIRST — alias-resolved and checked against ``ALL_CATEGORIES`` —
    before the action switch, so the REVIEW→REDACT coercion warning fires only
    for entries that survive validation AND locate at least one span. Each kept
    entry is located in every unit of the chunk via repeated ``str.find``;
    short REDACT texts (< 4 chars) are accepted only as standalone tokens.
    """
    decisions = _extract_json_array(raw)
    if decisions is None:
        raise AIProviderError("pass-2 output could not be parsed as a JSON array")

    spans: list[Span] = []
    for entry in decisions:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("text", "")).strip()
        if not text:
            continue

        # Category first: an entry with an invalid category is dropped before
        # any action handling, so it can never trigger a coercion warning.
        category = str(entry.get("category", "")).strip().upper()
        category = _CATEGORY_ALIASES.get(category, category)
        if category not in ALL_CATEGORIES:
            logger.debug("pass-2 dropping entry with invalid category")
            continue

        action = str(entry.get("action", "")).strip().upper()
        if action == "SKIP":
            continue
        was_coerced = False
        if action == "REVIEW":
            action = "REDACT"
            was_coerced = True
        if action not in {"REDACT", "PRESERVE"}:
            logger.debug("pass-2 dropping entry with unsupported action")
            continue

        guard_short = action == "REDACT" and len(text) < 4

        located = 0
        for unit in chunk.units:
            ntext = unit.normalized_text
            pos = 0
            while True:
                idx = ntext.find(text, pos)
                if idx == -1:
                    break
                end = idx + len(text)
                if guard_short:
                    before = ntext[idx - 1] if idx > 0 else ""
                    after = ntext[end] if end < len(ntext) else ""
                    if (before and before.isalnum()) or (after and after.isalnum()):
                        pos = idx + 1
                        continue
                spans.append(
                    Span(
                        unit_id=unit.unit_id,
                        start=idx,
                        end=end,
                        text=text,
                        category=category,
                        detector="llm_pass2",
                        confidence=0.9,
                        action=action,
                        reason=f"LLM pass-2 decision: {action}",
                    )
                )
                located += 1
                pos = end

        if was_coerced and located:
            logger.warning("pass-2 coerced REVIEW to REDACT for category %s", category)

    return spans


# ---------------------------------------------------------------------------
# Known-span rendering (uniform pass-2 payload)
# ---------------------------------------------------------------------------

def _span_context(span: Span, units_by_id: dict[str, TextUnit]) -> str:
    """Return ±``_CONTEXT_WINDOW`` chars around the span, ellipsized where cut."""
    unit = units_by_id.get(span.unit_id)
    if unit is None:
        return span.text
    text = unit.normalized_text
    lo = max(0, span.start - _CONTEXT_WINDOW)
    hi = min(len(text), span.end + _CONTEXT_WINDOW)
    snippet = text[lo:hi]
    if lo > 0:
        snippet = "..." + snippet
    if hi < len(text):
        snippet = snippet + "..."
    return snippet


def _suggestion(span: Span, units_by_id: dict[str, TextUnit]) -> dict:
    """Render a deterministic span as one uniform known-span payload entry.

    Returns ``{"text", "category", "action", "context"}`` — the same shape used
    for located pass-1 proposals, so pass 2 sees one homogeneous list.
    """
    return {
        "text": span.text,
        "category": span.category,
        "action": span.action,
        "context": _span_context(span, units_by_id),
    }


def _finding_known_span(finding: dict, chunk: Chunk) -> dict:
    """Render a pass-1 finding as a known-span entry with surrounding context.

    Locates the finding's text at its first occurrence in the chunk's units to
    extract a ±``_CONTEXT_WINDOW`` context window; an unlocatable text falls
    back to itself as context. This location is payload-only — pass-1 findings
    still never become ``Span`` objects.
    """
    text = finding["text"]
    context = text
    for unit in chunk.units:
        idx = unit.normalized_text.find(text)
        if idx == -1:
            continue
        ntext = unit.normalized_text
        lo = max(0, idx - _CONTEXT_WINDOW)
        hi = min(len(ntext), idx + len(text) + _CONTEXT_WINDOW)
        snippet = ntext[lo:hi]
        if lo > 0:
            snippet = "..." + snippet
        if hi < len(ntext):
            snippet = snippet + "..."
        context = snippet
        break
    return {
        "text": text,
        "category": finding["category"],
        "action": finding["action"],
        "context": context,
    }


# ---------------------------------------------------------------------------
# Provider call
# ---------------------------------------------------------------------------

def _call(
    client: Any,
    cfg: RuntimeConfig,
    system_prompt: str,
    user_message: str,
    chunk_index: int,
    pass_number: int,
) -> str:
    """Make one provider call and return its text content.

    ``system_prompt`` selects the pass-specific system prompt (blind pass 1 vs
    informed pass 2). SDK errors are translated in a load-bearing order
    (``APITimeoutError`` subclasses ``APIConnectionError``). The first error
    aborts the whole run; there is no local retry loop (the SDK's built-in
    retries are already active).
    """
    try:
        response = client.chat.completions.create(
            model=cfg.model_handle,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_completion_tokens=cfg.max_completion_tokens,
        )
    except openai.APITimeoutError as e:
        raise AITimeoutError(
            f"LLM call timed out after {cfg.llm_timeout_s}s "
            f"(chunk {chunk_index}, pass {pass_number})"
        ) from e
    except openai.APIConnectionError as e:
        raise AIUnavailableError(
            f"LLM provider unreachable (chunk {chunk_index}, pass {pass_number})"
        ) from e
    except openai.APIStatusError as e:
        raise AIProviderError(
            f"provider returned HTTP {e.status_code} "
            f"(chunk {chunk_index}, pass {pass_number})"
        ) from e
    except openai.OpenAIError as e:
        raise AIProviderError(
            f"provider error (chunk {chunk_index}, pass {pass_number})"
        ) from e

    content = response.choices[0].message.content
    if not content:
        raise AIProviderError(
            f"empty completion (possible content filter) "
            f"(chunk {chunk_index}, pass {pass_number})"
        )
    return content


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_llm_detection(
    document: DocumentData,
    deterministic_spans: list[Span],
    review_hints: list[Span],
    client: Any,
    cfg: RuntimeConfig,
) -> list[Span]:
    """Run the mandatory two-pass LLM detection over the whole document.

    Chunks are processed CONCURRENTLY on a thread pool of
    ``cfg.llm_concurrency`` workers (the OpenAI client is thread-safe; the
    core stays synchronous — no asyncio outside api.py). Within each chunk the
    order is strict: blind pass 1 proposes from scratch, then pass 2 receives
    the chunk text plus ALL known spans (deterministic detections and the
    located pass-1 proposals, each with category, action, and context) and
    confirms, corrects, or adds. Results are collected in chunk order, so the
    returned spans are deterministic regardless of completion order. The first
    chunk failure cancels not-yet-started chunks and aborts the run. Only
    pass-2 spans are collected and returned.
    """
    units_by_id = {u.unit_id: u for u in document.text_units}
    chunks = split_into_chunks(document, cfg.chunk_size_chars)
    total = len(chunks)
    if total == 0:
        return []

    def _process_chunk(chunk_index: int, chunk: Chunk) -> list[Span]:
        """Run pass 1 then pass 2 for one chunk and return its located spans."""
        start_time = time.time()
        unit_ids = chunk.unit_ids

        chunk_deterministic = [s for s in deterministic_spans if s.unit_id in unit_ids]
        chunk_hints = [s for s in review_hints if s.unit_id in unit_ids]

        # Pass 1 — blind, no suggestions of any kind.
        logger.info("chunk %d/%d: pass 1 (blind reading)", chunk_index + 1, total)
        raw1 = _call(
            client, cfg, SYSTEM_PROMPT_PASS1, build_pass1_message(chunk.text),
            chunk_index, 1,
        )
        findings = parse_pass1_findings(raw1)

        # One uniform known-spans list: deterministic REDACT/PRESERVE spans,
        # deterministic REVIEW hints, then the located pass-1 proposals.
        known_spans = (
            [_suggestion(s, units_by_id) for s in chunk_deterministic]
            + [_suggestion(s, units_by_id) for s in chunk_hints]
            + [_finding_known_span(f, chunk) for f in findings]
        )

        # Pass 2 — informed validation over the known spans.
        logger.info(
            "chunk %d/%d: pass 2 (validation of %d known spans)",
            chunk_index + 1, total, len(known_spans),
        )
        raw2 = _call(
            client, cfg, SYSTEM_PROMPT_PASS2,
            build_pass2_message(chunk.text, known_spans),
            chunk_index, 2,
        )
        chunk_spans = parse_pass2_spans(raw2, chunk)
        logger.info(
            "chunk %d/%d: done — %d spans located (%.1fs)",
            chunk_index + 1, total, len(chunk_spans), time.time() - start_time,
        )
        return chunk_spans

    workers = min(max(1, int(cfg.llm_concurrency)), total)
    logger.info("LLM detection: %d chunks, %d workers", total, workers)

    all_spans: list[Span] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_process_chunk, i, c) for i, c in enumerate(chunks)]
        try:
            # Collect in submission (chunk) order for deterministic output.
            for future in futures:
                all_spans.extend(future.result())
        except BaseException:
            # First failure: stop queued chunks; in-flight ones finish, then
            # the error propagates and aborts the run (mandatory-LLM design).
            for other in futures:
                other.cancel()
            raise

    return all_spans


__all__ = [
    "Chunk",
    "split_into_chunks",
    "run_llm_detection",
    "parse_pass1_findings",
    "parse_pass2_spans",
]
