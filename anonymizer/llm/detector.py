"""Two-pass LLM detection engine for the Greek document-anonymization service.

Pass 1 is DISCOVERY, and it is BLIND. Its only input is the raw chunk text:
no deterministic recommendations, no rule REDACT/PRESERVE/REVIEW spans, no
hard-preserve knowledge, no prior candidates, no resolver output. It proposes
from scratch, which is what makes its agreement with the rules worth
anything.

Both passes see the whole chunk, and both can find something nobody else did.
The difference is what their answers are WORTH: pass 1 is evidence, and pass 2
is the decision.

That blindness is architectural, not stylistic. The service runs two detection
paths over the same raw text —

    raw chunk -> deterministic detectors  ─┐
                                           ├─> merge -> drop hard preserves -> pass 2
    raw chunk -> blind pass 1             ─┘

— and they are merged only after pass 1 has finished. Two sources agreeing means
something precisely because neither saw the other's answer; a hint from the rules
would turn the second opinion into an echo, which nothing in the output would
reveal. The pass-1 request is therefore a pure function of the chunk text, and
``tests/test_pass1_blindness.py`` pins exactly that: run the same document with
and without deterministic input and the bytes sent for pass 1 must be identical.

Pass 2 is ADJUDICATION, and it READS. It receives the COMPLETE rendered chunk
and a queue of candidates — everything the deterministic detectors and pass 1
proposed for that chunk — and it has two jobs: return exactly one final REDACT
or PRESERVE per candidate, and report any sensitive span in the chunk that no
candidate covers. Each candidate carries a transient id, its exact text, what
every source recommended for it, and up to ``_CONTEXT_WINDOW`` characters of
document text on either side.

The chunk is there because the QUEUE IS A RECORD OF WHAT TWO FALLIBLE STAGES
NOTICED. The rules match only the patterns they were written for. Pass 1 is one
reading, and it can miss a span, name it in output too malformed to parse, or
quote it across a table join so it cannot be located — and every one of those
ends the same way, with nothing in the queue. A pass 2 that saw only the queue
inherited all four failures and could correct none of them, because a span
nobody proposed is not a question it was ever asked. It is the last stage that
can see the document, so it is asked to look.

The windows survive the chunk's return, and they earn their place differently
now: with the whole excerpt in view, ``before``/``after`` are what say WHICH
occurrence a candidate is when its text appears several times. They are also
still the candidate's identity for deduplication (see ``_identity``).

A NEW FINDING ARRIVES AS TEXT AND IS LOCATED BY MAP, NOT BY SEARCH. Pass 2
quotes a string out of the excerpt; ``locate_in_rendered`` finds it in the
RENDERED chunk and walks ``RenderedChunk.segments`` back to ``(unit_id, start,
end)``. Searching the units one by one instead would lose exactly the findings
worth having — anything read across a paragraph newline or a table ``" | "``
exists in no single unit — so a finding that crosses a synthetic separator is
translated into one span per unit it really covers rather than dropped. A
finding that cannot be mapped at all is rejected, which sends the attempt to the
same retry as any other unusable entry; it is never silently discarded.

A CANDIDATE CARRIES ITS LOCATIONS. The pipeline already knows, exactly, where
every proposal sits — ``(unit_id, start, end)`` — and that knowledge is never
thrown away and re-derived. ``build_pass2_candidates`` holds those coordinates
in ``Pass2Candidate``; the id in the prompt is only a handle for them. When the
answer comes back, ``spans_from_decisions`` looks the id up and writes the span
where the detectors said it was. The discarded alternative — know the location,
send only text, then search the chunk for the text the model echoed — is what
makes a repeated string ambiguous, and it is gone: the only text search left in
this module locates a pass-1 finding once, at candidate-build time, because a
finding arrives as a bare string and has no coordinates until someone gives it
some.

DEDUPLICATION IS PYTHON'S JOB, AND IT IS EXACT. The model is never asked to
merge anything. ``build_pass2_candidates`` collapses proposals in four staged
passes — deterministic results within themselves, pass-1 results within
themselves, then a merge, then a grouping of locations whose entire question is
identical — and every comparison is exact equality. No case folding, no
whitespace normalisation, no substring rule, no similarity: ``ΜΑΡΙΑ ΚΩΣΤΑ`` and
``Μαρία Κώστα`` are different candidates, and overlap is never a reason to
merge.

So one candidate may hold several locations, but only when those locations pose
a question that is identical down to the surrounding text. The same ten digits
in an authority contact line and in the appellant's details keep their own
candidates and can be answered differently; the same boilerplate repeated
verbatim asks one question and gets one answer applied to every copy.

Deterministic HARD PRESERVE spans (``resolver.is_hard_preserve``: a PRESERVE in
one of ``policy.hard_preserve_categories``) are the one class of span that never
enters the queue. They are decisions, not recommendations, so pass 2 is never
handed one and is never asked to adjudicate it. Their text is not hidden — pass
1 reads it as part of the chunk, and it still turns up inside the context window
of neighbouring candidates — but no decision is solicited for it, and the span
travels straight to the resolver with its original location intact. An ordinary
PRESERVE is only a recommendation and does go into the queue.

Pass-2 output is required to be FINISHED, COMPLETE and ACCOUNTED FOR, and the
pass-2 system prompt states exactly the rules enforced here.

FINISHED COMES FIRST, AND IT IS NOT A PROPERTY OF THE TEXT. A body the
provider cut short at the output-token ceiling, or ended with a content
filter or a refusal, is a FRAGMENT — and a fragment of a decision list is
indistinguishable, by reading it, from a complete list of fewer decisions.
Both parse; both can answer every id that happens to appear in them. So the
finish reason is consulted BEFORE the body, and a response that did not
finish is not read at all: not its decisions, not its new findings. The whole
queue is asked again instead.

An attempt that did finish is usable only when every entry passed validation
AND every candidate came back decided. Nothing is quietly dropped:

* the payload must be a JSON array, or the attempt is rejected;
* an entry is keyed by candidate id. An entry that is not an object, carries no
  id, names an id this queue never issued, repeats an id already answered, or
  whose candidate no longer maps to a location, is REJECTED — it does not
  invalidate only itself, it invalidates the response. A model that answers
  about a candidate that does not exist is not tracking the queue, and the
  entries that happen to look right deserve no more trust than the one that
  visibly is not;
* a REPEATED id additionally voids the candidate itself. Both answers are
  dropped, the candidate counts as undecided, and it goes back into the retry
  queue with its original payload. Nothing picks a winner between them: first,
  last and most-cautious are all just the order the model emitted them in, and
  the point of the retry is that the model can say which it meant. Ids are
  TALLIED BEFORE ANY ENTRY IS JUDGED, which is load-bearing: validating first
  meant an id whose first copy was rejected for some other reason never
  reached the duplicate check, so a second copy could still be accepted and
  the candidate came back 'decided' by a response that had contradicted
  itself about it;
* the one id that may be absent from the queue is the reserved ``NEW``, which
  introduces a finding of pass 2's own. It carries ``text`` instead of an id,
  and it is rejected on the same terms as anything else: no text, the same text
  twice, a category outside the schema, or text that is not an exact substring
  of the excerpt. An INVENTED id is still a rejection — discovery has its own
  door, so it did not have to be paid for by weakening that rule. A rejected
  discovery is not a dropped one: when its text can still be located it is
  PROMOTED to a candidate with a fresh id and the model's own answers as its
  recommendations, so the retry is asked about it by name and the ordinary
  completeness machinery tracks it. Only a finding that cannot be located at
  all has nowhere to go, and that one is RECORDED rather than forgotten;
* ``REVIEW`` is coerced to ``REDACT`` (the fail-safe direction); any other
  non-final action, ``SKIP`` included, is no answer at all and is rejected;
* a category outside the schema falls back to the candidate's recommended
  category — the one forgiving field, so a bad label never costs a good
  decision;
* EVERY candidate must come back decided, matched BY ID. There is no textual or
  containment matching anywhere in this module: a decision about one candidate
  is never evidence that a different one was decided.

A response that is a reading but left things open is retried exactly once, and
the retry is TARGETED: every decision that already passed validation is kept,
and only the outstanding items are re-asked. Decide 67 of 70 and the second
call carries 3 candidates, not 70 — regenerating good work costs output tokens
and is its own chance to drop something new. The retry is a correction, not a
restart, and it is scoped: an id that was not re-asked is not in its queue, so
the model cannot use the correction to reopen a settled answer.

WHAT SURVIVES THAT RETRY IS A QUESTION, NOT A GUESS. A finding still without
an answer becomes an ``UnresolvedFinding`` on the result: it is not decided,
not defaulted to PRESERVE, and not defaulted to REDACT. The text stays exactly
as it was, whatever ordinary deterministic evidence covers it still applies,
and the document comes back flagged for human review with the locations to
look at. Both defaults would be lies — a silent PRESERVE hides something
nobody judged, a silent REDACT blots something nobody judged — and the
alternative to a person reading three spans is a machine inventing three
answers.

That leniency is for INDIVIDUAL FINDINGS INSIDE A CHUNK THAT WAS READ, and
nothing else. A chunk whose pass 2 never produced a usable reading — neither
attempt finished, or neither parsed, or both answered about candidates that do
not exist — has been read by nobody, and that still abandons the document with
AIProviderError. So do provider exhaustion and a HIGH post-redaction finding.

WHAT A PASS-2 SPAN IS WORTH downstream is settled by the resolver, and the
spans built here carry ``origin="llm_pass2"`` so it can tell. A pass-2 decision
outranks every ORDINARY deterministic span covering the same characters — that
is what makes it the final adjudication and not a fourth opinion — and it
outranks no HARD one, in either direction. The queue and the ladder therefore
say the same thing from two ends: a hard preserve is never asked about and
could not be overturned if it were, while an ordinary rule PRESERVE is asked
about precisely because pass 2 may overturn it.

Deterministic spans stay in the plan either way. A hard redact survives
whatever pass 2 says; an ordinary one is fallback evidence, and it holds the
characters no pass-2 decision reached.

THE TWO PASSES ARE JUDGED BY OPPOSITE STANDARDS, and the reason is what each
one's answer is worth. A pass-1 completion that cannot be used — empty,
truncated at the output ceiling, filtered, refused, not a JSON array, or an
array with no usable entry — yields no findings, is COUNTED, and the chunk
carries on to pass 2 with the full text (``read_pass1``). Losing it costs
recommendations, not coverage; failing the document over it would trade a
formatting problem for no anonymization at all. The same body from pass 2
costs the chunk its reading, because pass 2's answer IS the decision.

THAT ARGUMENT ONLY HOLDS IF PASS 2 ACTUALLY RUNS, which is why a degraded pass
1 FORCES it — even when the deterministic rules also found nothing and the
queue is empty. An empty queue is not evidence that the chunk is clean; it is
the absence of evidence either way, and the only case where skipping pass 2 is
honest is a pass 1 that COMPLETED and reported nothing, with rules that agree.
Skipping it after an unusable pass 1 published chunks that nobody had read.

That leniency covers UNUSABLE CONTENT FROM A CALL THAT COMPLETED, and nothing
else. Timeouts, unreachable endpoints and HTTP errors raise out of ``_call``
for either pass and abort the run — degrading those would report a clean
document during an outage.

PASS 2 IS ALSO THE REMEDIATION PASS. After the document has been redacted and
the mandatory post-redaction audit has read the OUTPUT, whatever it found still
visible comes back here through ``run_pass2_remediation`` — the same
``_adjudicate``, the same prompt, the same validation, the same one corrective
retry, the same ``UsageRecorder`` and the same document deadline. Pass 1 is NOT
re-run: there is nothing to discover blind, because the audit has already said
exactly which slices are in question and where they are.

What differs is only the document and one instruction line. The chunks are cut
from the REDACTED parse, so the coordinates are coordinates in the file the
remediation is written to; the candidates are built by
``build_pass2_candidates`` with ``source="postcheck"``, so a residual arrives as
an ordinary located proposal; and ``remediation=True`` tells the model that the
runs of dots it can see are earlier redactions rather than missing text. Pass 2
keeps its second job throughout — it reads the redacted excerpt and may report
spans nobody asked about — and its answers are ordinary ``origin="llm_pass2"``
spans that go through the ordinary resolver.

THE AUDIT RUNS ONCE. Nothing here re-scans what the remediation produces, and
there is no loop: the audit's findings are asked about exactly once, the
answers are applied, and the document is returned.

The LLM stage is MANDATORY: there is no enabled/disabled switch and no
no-client fallback. ``client`` is duck-typed; ``openai`` is imported only for
its exception types.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Literal

import openai

from anonymizer.config import PolicySettings, RuntimeConfig
from anonymizer.deadline import RunContext
from anonymizer.errors import (
    AIProviderError,
    AITimeoutError,
    AIUnavailableError,
    AnonymizerError,
    DocumentTimeoutError,
    ResourceLimitExceededError,
)
from anonymizer.llm.prompts import (
    SYSTEM_PROMPT_PASS1,
    SYSTEM_PROMPT_PASS2,
    build_pass1_message,
    build_pass2_message,
    build_pass2_retry_message,
)
from anonymizer.llm.usage import (
    PASS1_OUTPUT_TRUNCATED,
    PASS1_PARSE_FAILURE,
    PASS1_SUCCESS,
    PASS2_EXECUTED,
    PASS2_FAILED,
    PASS2_SKIPPED,
    UsageRecorder,
)
from anonymizer.models import (
    ALL_CATEGORIES,
    DocumentData,
    FinalAction,
    Span,
    SpanCategory,
    TextUnit,
    UnresolvedFinding,
    UnresolvedKind,
    is_category,
    is_final_action,
)
from anonymizer.resolver import is_hard_preserve
from anonymizer.span_trim import narrow_redaction

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

# Characters of document text sent on each side of a candidate. This is the
# whole of pass 2's context, so it is a contract with the prompt, not a knob.
_CONTEXT_WINDOW = 40

# A candidate text shorter than this is only ever matched as a standalone token,
# never inside a longer word.
_STANDALONE_ONLY_BELOW = 4

# Every pass-2 span carries the same confidence: the model's decisions are not
# self-scored, and the resolver ranks them as ordinary (never hard) either way.
_LLM_CONFIDENCE = 0.9

# The shape of a transient candidate id. Only used to decide whether a
# model-supplied id is safe to quote back in a rejection phrase.
_CANDIDATE_ID_RE = re.compile(r"^C\d+$")

# The reserved id a pass-2 entry uses to report a span nobody proposed. A word
# rather than a number, so it can never collide with an issued "C<n>" id, and
# one fixed token rather than "any id we do not recognise", so an INVENTED id
# stays the rejection it has always been.
_NEW_FINDING_ID = "NEW"


def _chunk_label(chunk_index: int, total: int | None = None) -> str:
    """Name a chunk for a human: ALWAYS 1-based, and the only way to do it.

    Chunks are indexed from 0 internally and counted from 1 everywhere a person
    reads them — a log line, a warning, an exception, an HTTP error body. Those
    two conventions drifted apart once already: the logs said "chunk 6/19" while
    the exception raised from the same call said "chunk 5", so the same failure
    had two names and neither pointed at the other. Every message goes through
    here now, so the mismatch cannot come back one f-string at a time.

    Pass ``total`` for the "6/19" form used in progress logs, omit it for the
    bare "chunk 6" used in errors.
    """
    return f"chunk {chunk_index + 1}" + (f"/{total}" if total is not None else "")


# ---------------------------------------------------------------------------
# Chunk
# ---------------------------------------------------------------------------

Location = tuple[str, int, int]
"""``(unit_id, start, end)`` — one exact slice of one text unit."""


@dataclass(frozen=True)
class RenderedChunk:
    """The chunk as the model sees it, and the map back to where it came from.

    ``text`` is what both passes read. ``segments`` is the inverse of the
    rendering: one ``(start, end, unit_id)`` per unit, in text order, covering
    exactly the characters that unit contributed. The characters between
    segments are SYNTHETIC — the ``"TABLE:"`` header, the newlines joining
    paragraphs and rows, the ``" | "`` between cells — and belong to no unit.
    They exist only to make the chunk readable, so nothing may ever be written
    to them.

    Keeping this map is what lets a span the model quotes out of ``text`` be
    written back to the document exactly, without searching the units for it.
    ``offsets`` (unit_id -> first offset) is the same information collapsed to
    one number per unit, which is all the context-window arithmetic needs.
    """

    text: str
    offsets: dict[str, int]
    segments: tuple[tuple[int, int, str], ...]

    def locate(self, start: int, end: int) -> list[Location]:
        """Map the rendered slice ``[start, end)`` back to source-unit slices.

        Returns one ``Location`` per unit the slice touches, in text order, with
        synthetic characters dropped. A slice inside one unit yields one
        location; a slice crossing a paragraph newline or a table ``" | "``
        yields one per unit — TRANSLATED into the units it really covers rather
        than discarded, because a model that quotes across a join has still told
        us something true about every unit it quoted.

        Returns ``[]`` for a slice that lands entirely on synthetic characters,
        which is the caller's signal that it cannot be written anywhere.
        """
        found: list[Location] = []
        for segment_start, segment_end, unit_id in self.segments:
            low = max(start, segment_start)
            high = min(end, segment_end)
            if low < high:
                found.append((unit_id, low - segment_start, high - segment_start))
        return found


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

    def render(self) -> RenderedChunk:
        """Render the chunk once, with the map back to the source units.

        The single rendering both passes are shown: pass 1 reads it blind, and
        pass 2 reads it as the authoritative context for the candidate queue.
        The per-unit offsets are what let a candidate's context window run past
        its own unit — across a paragraph break, or into the neighbouring cells
        and header row of a table — instead of being clipped at the unit
        boundary, and ``RenderedChunk.segments`` is what lets a span pass 2
        found for itself be written back where it belongs.

        Tables render as a "TABLE:" header plus one pipe-joined line per row;
        paragraph chunks render as newline-joined unit texts.
        """
        offsets: dict[str, int] = {}
        segments: list[tuple[int, int, str]] = []

        def place(unit: TextUnit, cursor: int) -> int:
            """Record where ``unit`` starts and return the cursor past its text."""
            offsets[unit.unit_id] = cursor
            end = cursor + len(unit.normalized_text)
            if end > cursor:
                segments.append((cursor, end, unit.unit_id))
            return end

        if self.is_table:
            rows: dict[int, list[TextUnit]] = {}
            for unit in self.units:
                rows.setdefault(int(unit.location["row_index"]), []).append(unit)

            lines = ["TABLE:"]
            cursor = len(lines[0])
            for row_index in sorted(rows):
                cells = sorted(rows[row_index], key=lambda u: int(u.location["col_index"]))
                cursor += 1  # the newline that starts this row
                for position, cell in enumerate(cells):
                    if position:
                        cursor += 3  # the " | " separator
                    cursor = place(cell, cursor)
                lines.append(" | ".join(cell.normalized_text for cell in cells))
            return RenderedChunk("\n".join(lines), offsets, tuple(segments))

        cursor = 0
        for position, unit in enumerate(self.units):
            if position:
                cursor += 1  # the newline joining it to the previous unit
            cursor = place(unit, cursor)
        return RenderedChunk(
            "\n".join(u.normalized_text for u in self.units), offsets, tuple(segments)
        )

    @property
    def text(self) -> str:
        """The rendered chunk text, without the source map."""
        return self.render().text


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
    """Parse pass-1 output leniently into candidate proposals.

    Entry-level leniency only: blank text, ``SKIP``, an unknown action or an
    off-schema category drop that ENTRY, and the rest of the array survives. On
    unparseable or non-list output a single warning is logged and ``[]`` is
    returned. Kept entries are dicts with keys exactly ``text``, ``action``,
    ``category``. They are proposals, never spans — a pass-1 finding only ever
    reaches the plan by being adjudicated in pass 2.

    WHAT AN EMPTY RESULT MEANS is decided by ``read_pass1``, not here: this
    function cannot tell "the model found nothing" from "the model's answer was
    unusable", and the two are counted differently. Call ``read_pass1`` on a
    ``Completion`` unless you specifically want the raw parse.
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


@dataclass(frozen=True)
class Pass1Reading:
    """What one chunk's pass 1 was worth, and a phrase saying why.

    ``outcome`` is one of ``usage.PASS1_OUTCOMES``. ``detail`` is a short
    machine-written phrase for the log — counts and shapes only. NEITHER FIELD
    EVER CARRIES MODEL OR DOCUMENT TEXT: the whole point of a failed pass 1 is
    that its body could not be trusted, and a body nobody could parse is the
    last thing that should be echoed into a log line, since whatever else it is,
    it is text the model read out of a document full of personal data.
    """

    findings: list[dict]
    outcome: str
    detail: str

    @property
    def degraded(self) -> bool:
        return self.outcome != PASS1_SUCCESS


def read_pass1(completion: Completion) -> Pass1Reading:
    """Decide what a completed pass-1 call contributes. NEVER raises.

    Pass 1 is discovery EVIDENCE, not a gate. Pass 2 receives the complete chunk
    and scans it independently, so a pass 1 whose output cannot be used costs
    recommendations and nothing else — the text is still read, by the pass that
    makes the final decision. Failing a document over it would turn a formatting
    problem in one model response into a refusal to anonymize, while the safety
    argument for failing runs the other way: the alternative to degrading here
    is not a better answer, it is no answer.

    So every unusable body maps to "no findings, say so, carry on":

    * TRUNCATED — the provider stopped at the output ceiling, so the body is a
      fragment. Its surviving entries are dropped rather than kept, because a
      prefix of a list of findings looks exactly like a complete list of fewer
      findings, and there is no way to tell from the text which it is. Raising
      ``ANON_MAX_COMPLETION_TOKENS`` is the fix, and the counter is how anyone
      would know to;
    * EMPTY — a content filter, or a response shaped unfamiliarly;
    * NOT A JSON ARRAY — prose, an object, a fenced block that did not survive
      ``_extract_json_array``;
    * STRUCTURALLY UNUSABLE — a JSON array whose every entry was dropped for a
      missing text, an unknown action or an off-schema category. An array that
      was genuinely EMPTY is different, and counts as success: "I found nothing"
      is an answer, and the commonest one on boilerplate.

    The one thing that is not handled here is a call that did not complete.
    Timeouts, unreachable endpoints and HTTP errors raise out of ``_call``
    before this is reached, and they still abort the run — degrading those would
    be reporting a healthy pipeline during an outage.
    """
    if completion.truncated:
        return Pass1Reading([], PASS1_OUTPUT_TRUNCATED, "output stopped at the token limit")

    if not completion.complete:
        # Filtered, refused, or stopped for a reason this code does not know.
        # Counted with the parse failures because the effect is identical —
        # no usable recommendations — and because the three pass-1 outcomes
        # exist to say what an operator should DO, and the answer here is the
        # same as for malformed output: nothing, unless it becomes frequent.
        return Pass1Reading(
            [], PASS1_PARSE_FAILURE, completion.problem or "the provider did not finish"
        )

    if not completion.text.strip():
        return Pass1Reading([], PASS1_PARSE_FAILURE, "the completion was empty")

    entries = _extract_json_array(completion.text)
    if entries is None:
        return Pass1Reading([], PASS1_PARSE_FAILURE, "the output was not a JSON array")

    # Parsed twice — once above for the entry count, once here for the findings.
    # The cost is a second json.loads of one small completion, and it buys a
    # single parsing entry point instead of a copy of the entry rules.
    findings = parse_pass1_findings(completion.text)
    if entries and not findings:
        return Pass1Reading(
            [], PASS1_PARSE_FAILURE, f"{len(entries)} entry/entries, none usable"
        )
    return Pass1Reading(findings, PASS1_SUCCESS, f"{len(findings)} finding(s)")


# ---------------------------------------------------------------------------
# The pass-2 candidate queue
# ---------------------------------------------------------------------------

@dataclass
class Pass2Candidate:
    """One question put to pass 2, and every location the answer applies to.

    A candidate is a question, and its identity is the *whole* question:
    ``text`` + ``recommendations`` + ``before`` + ``after``. Two places in the
    chunk that would produce byte-identical entries in the CANDIDATES array are
    the same question — the model could not tell them apart if it tried — so
    they share one candidate and one answer. Anything less than that, and they
    stay separate questions. See ``build_pass2_candidates``.

    ``locations`` therefore holds one or more exact slices, always the
    coordinates the deterministic detectors and the resolver use, carried
    through the adjudication unchanged. The transient ``candidate_id`` is only
    a handle the model can name the question by; it means nothing outside one
    chunk's adjudication, is not written to the document, never reaches a user,
    and is not stored anywhere.
    """

    candidate_id: str
    text: str
    # The category the decision falls back to when the model's is unusable —
    # the first recommendation's, so the rules outrank pass 1. None on a
    # PROMOTED candidate, where the only previous answer was pass 2's own and
    # its category was the unusable part: there is nothing to fall back TO, so
    # the retry has to supply a real one rather than inherit a fiction.
    category: SpanCategory | None
    recommendations: list[dict] = field(default_factory=list)
    # Every slice this one answer will be written to. `text` is the document's
    # own slice at each of them, so text and locations cannot drift apart.
    locations: list[Location] = field(default_factory=list)
    before: str = ""
    after: str = ""
    # Set when this candidate is not a proposal at all but a pass-2 DISCOVERY
    # that came back unusable and was given an id so the corrective retry can
    # be asked about it by name. The value is the kind it would be recorded
    # under if the retry does not settle it either.
    promoted_from: UnresolvedKind | None = None

    @property
    def has_location(self) -> bool:
        """Whether this candidate still maps to usable slices of the document.

        Checked before a decision is accepted for it. A candidate that lost its
        locations could not be applied, and a decision for one must not be
        counted as an answer — that would be the "resolved, then vanished"
        failure the id contract exists to make impossible.
        """
        return bool(self.text) and bool(self.locations) and all(
            unit_id and end > start for unit_id, start, end in self.locations
        )

    def as_payload(self) -> dict:
        """Render the candidate as one entry of the pass-2 CANDIDATES array.

        The locations are deliberately NOT sent. The model has no use for
        offsets and no way to improve on them; keeping them on this side is what
        makes the answer applicable without a search. Nor is the *number* of
        locations sent: it would tell the model how often the string repeats,
        which is not evidence about whether to redact it, and it would make two
        otherwise identical questions look different.
        """
        return {
            "id": self.candidate_id,
            "text": self.text,
            "recommendations": self.recommendations,
            "before": self.before,
            "after": self.after,
        }


def _read_category(entry: dict) -> SpanCategory | None:
    """Read an entry's category, resolving aliases. None when it is off-schema.

    The single place model-supplied category strings enter this module, so
    the alias table and the vocabulary check cannot drift between the entry
    kinds that use them.
    """
    category = str(entry.get("category", "")).strip().upper()
    category = _CATEGORY_ALIASES.get(category, category)
    # The narrowing happens HERE, once, at the JSON boundary: everything
    # downstream holds a category rather than a string that was checked
    # somewhere.
    return category if is_category(category) else None


def _windows_at(render: RenderedChunk, location: Location) -> tuple[str, str]:
    """The document text immediately around one location, cut to the window.

    Read off the RENDERED chunk, so a window can cross a paragraph break or
    reach into the neighbouring cells of a table row — which is what makes it
    able to say WHICH occurrence a repeated string is. Returns empty strings
    for a unit the render does not place.
    """
    unit_id, start, end = location
    origin = render.offsets.get(unit_id)
    if origin is None:
        return "", ""
    position = origin + start
    before = render.text[max(0, position - _CONTEXT_WINDOW):position]
    tail = position + (end - start)
    after = render.text[tail:tail + _CONTEXT_WINDOW]
    return before, after


def _occurrences(chunk: Chunk, text: str) -> list[tuple[str, int, int]]:
    """Find every position of ``text`` in the chunk's units.

    A pass-1 finding arrives as a bare string, so it has to be located once
    before it can become a candidate. A deterministic span never comes through
    here — it already knows where it is.

    Deliberately per-unit, and NOT the rendered-chunk search
    ``locate_in_rendered`` performs for pass-2 discoveries. A pass-1 finding
    becomes a candidate: it acquires a context window and an identity, and two
    occurrences merge only when their whole question matches. Cross-unit
    proposals have no single unit to be a candidate in, so they are dropped here
    with a warning — and a dropped pass-1 finding is now recoverable, because
    pass 2 reads the same chunk and can propose the span itself.

    A text shorter than ``_STANDALONE_ONLY_BELOW`` characters is accepted only
    as a standalone token, so a two-letter abbreviation can never claim the
    middle of a longer word — in either direction, since a PRESERVE that landed
    inside a name would shield it just as wrongly as a REDACT would blot it.
    """
    standalone_only = len(text) < _STANDALONE_ONLY_BELOW
    found: list[tuple[str, int, int]] = []
    for unit in chunk.units:
        unit_text = unit.normalized_text
        position = 0
        while True:
            start = unit_text.find(text, position)
            if start == -1:
                break
            end = start + len(text)
            if standalone_only and not _standalone(unit_text, start, end):
                position = start + 1
                continue
            found.append((unit.unit_id, start, end))
            position = end
    return found


def _standalone(haystack: str, start: int, end: int) -> bool:
    """Whether ``haystack[start:end]`` is a standalone token rather than part of
    a longer word. Only consulted for texts shorter than
    ``_STANDALONE_ONLY_BELOW``."""
    before = haystack[start - 1] if start > 0 else ""
    after = haystack[end] if end < len(haystack) else ""
    return not ((before and before.isalnum()) or (after and after.isalnum()))


def locate_in_rendered(render: RenderedChunk, text: str) -> list[Location]:
    """Locate a span pass 2 quoted out of the excerpt, in the excerpt it read.

    This is the mapping for spans pass 2 found for ITSELF — the ones no earlier
    stage proposed, so no stored coordinates exist for them. It searches the
    RENDERED chunk, which is the text the model was actually shown, and then
    walks ``RenderedChunk.segments`` back to source units. Searching each
    ``TextUnit`` separately instead would silently lose exactly the findings
    worth having: anything the model read across a paragraph break or a table
    ``" | "`` join exists in no single unit and would match nowhere.

    Every occurrence is returned, as with a pass-1 finding: the model quoted a
    string, not a position, and it is not told which of several identical
    occurrences it hit. A text shorter than ``_STANDALONE_ONLY_BELOW`` is
    accepted only as a standalone token, so a two-letter finding can never claim
    the middle of a longer word — in either direction, since a stray PRESERVE
    inside a name would shield it as wrongly as a stray REDACT would blot it.

    Returns ``[]`` when the text appears nowhere, or only on synthetic
    characters. The caller must treat that as unresolved output, never as
    nothing having happened.
    """
    if not text:
        # ``"".find`` matches at every position and advances nothing, so an
        # empty needle would spin forever. Callers reject empty text before
        # reaching here; this keeps the function safe on its own terms.
        return []
    haystack = render.text
    standalone_only = len(text) < _STANDALONE_ONLY_BELOW
    found: list[Location] = []
    position = 0
    while True:
        start = haystack.find(text, position)
        if start == -1:
            break
        end = start + len(text)
        if standalone_only and not _standalone(haystack, start, end):
            position = start + 1
            continue
        found.extend(render.locate(start, end))
        position = end
    return found


def _collect_by_location(
    proposals: list[tuple[Location, str, str]],
) -> tuple[list[Location], dict[Location, list[tuple[str, str]]]]:
    """Group one source's proposals by exact location, dropping exact repeats.

    Returns the locations in first-seen order and, per location, its
    ``(action, category)`` pairs — also in first-seen order, with an exact
    repeat of a pair collapsed. "Exact" means exact: same string, same case,
    same spacing, same offsets. Nothing here normalises, folds case, trims, or
    compares substrings.

    A pair that differs in either field is kept. Two detectors calling the same
    slice ``APPELLANT_NAME``/REDACT and ``FATHER_NAME``/REDACT disagree about
    what it is, and that disagreement is information pass 2 should see, not
    noise to be tidied away.
    """
    order: list[Location] = []
    pairs: dict[Location, list[tuple[str, str]]] = {}
    for location, action, category in proposals:
        if location not in pairs:
            order.append(location)
            pairs[location] = []
        if (action, category) not in pairs[location]:
            pairs[location].append((action, category))
    return order, pairs


def _merge_recommendations(
    deterministic: list[tuple[str, str]],
    pass1: list[tuple[str, str]],
    *,
    source: str = "deterministic",
) -> list[dict]:
    """Merge two sources' ``(action, category)`` pairs for one location.

    A pair both sources produced becomes ONE recommendation listing both of
    them — agreement is recorded as agreement, not as two lines the model has
    to notice are the same. A pair only one source produced keeps that source
    alone, so a disagreement survives as two recommendations and pass 2 decides
    it.

    Deterministic pairs come first, which also makes the rules' category the
    fallback when the model returns one that is off-schema.

    ``source`` NAMES the first source in the payload the model reads. It is
    ``deterministic`` for the rule engine, and ``postcheck`` when the queue was
    built from the post-redaction audit's findings — the two propose spans the
    same way and are told apart by this string alone, which is what lets one
    queue builder serve both instead of two that could drift.
    """
    order: list[tuple[str, str]] = []
    sources: dict[tuple[str, str], list[str]] = {}
    for name, pairs in ((source, deterministic), ("pass1", pass1)):
        for pair in pairs:
            if pair not in sources:
                order.append(pair)
                sources[pair] = []
            if name not in sources[pair]:
                sources[pair].append(name)
    return [
        {"sources": sources[(action, category)], "action": action, "category": category}
        for action, category in order
    ]


def _identity(text: str, recommendations: list[dict], before: str, after: str) -> tuple:
    """The key two locations must match on to become one logical candidate.

    It is the entire question as pass 2 will see it — the text, every
    recommendation in order, and both context windows — so two locations share
    a candidate only when their CANDIDATES entries would be byte-identical
    apart from the id. The model could not tell such a pair apart if it tried,
    which is exactly why one answer provably serves both.

    Including the windows is the strict reading of "100% identical", and it is
    load-bearing rather than pedantic: the same ten digits in an authority
    contact line and in the appellant's details are the same text with the same
    rule recommendation, and they must not collapse into one question, because
    the right answers differ. Drop ``before``/``after`` from this key and that
    distinction is gone. Comparison is exact — no casefolding, no stripping, no
    normalisation: "MARIA KOSTA" and "Maria Kosta" are different candidates.
    """
    return (
        text,
        tuple(
            (tuple(r["sources"]), r["action"], r["category"]) for r in recommendations
        ),
        before,
        after,
    )


def build_pass2_candidates(
    chunk: Chunk,
    deterministic_spans: list[Span],
    review_hints: list[Span],
    findings: list[dict],
    render: RenderedChunk | None = None,
    *,
    source: str = "deterministic",
) -> list[Pass2Candidate]:
    """Build the chunk's pass-2 decision queue — the transient candidate registry.

    Every proposal for this chunk becomes a candidate: the deterministic REDACT
    and ordinary-PRESERVE spans, the deterministic REVIEW hints, and the pass-1
    findings. Hard preserves are expected to have been filtered out before this
    is called — they are decisions, not questions.

    **Python deduplicates; the model is never asked to.** In four stages:

    1. *Deterministic, internally.* Each rule span arrives already located, so
       its coordinates are taken verbatim and never searched for again. Two
       spans on the same slice proposing the same ``(action, category)`` collapse
       to one; proposing different ones do not.
    2. *Pass 1, internally, and independently.* A finding arrives as a bare
       string, so it is located once — here, and nowhere later — and every match
       becomes a location. The same collapse rule then applies within pass 1's
       own results.
    3. *Merge.* The two sets are joined location by location. A pair both
       sources produced is recorded once, naming both; a pair only one produced
       keeps that source, so a disagreement reaches pass 2 intact as two
       recommendations on one candidate.
    4. *Group identical questions.* Locations whose entire CANDIDATES entry
       would be identical — same text, same recommendations, same context
       windows (see ``_identity``) — become ONE logical candidate holding all of
       them. Pass 2 answers once and ``spans_from_decisions`` writes that answer
       to every location.

    Every comparison in all four stages is exact equality. There is no fuzzy
    matching, case folding, whitespace normalisation, substring rule, or
    similarity measure anywhere in this function, and overlap is not a reason to
    merge: ``ΜΑΡΙΑ ΚΩΣΤΑ``, ``ΚΩΣΤΑ`` and ``ΜΑΡΙΑ ΚΩΣΤΑ του ΠΑΠΑΔΟΠΟΥΛΟΥ`` are
    three candidates. The resolver settles overlapping final decisions later.

    A pass-1 finding that matches nowhere is dropped with a warning: nothing
    could be applied for it. Context is read off the rendered chunk, so a window
    can cross a paragraph break or reach into neighbouring cells of a table row.

    ``source`` names who proposed the located spans, and it is the only thing
    that differs when this builds the POST-REDACTION REMEDIATION queue instead
    of the ordinary one. A residual the audit found is a located proposal like
    any rule span — exact coordinates, one recommendation, a context window read
    off the render — so it is built here, by this function, and reaches pass 2
    labelled ``postcheck``. Everything that makes a candidate a candidate,
    including the rule that two locations merge only when their entire question
    is identical, therefore applies to it unchanged.
    """
    # THE SAME RENDERING THE CALLER READ, when it has one. ``_process_chunk``
    # renders the chunk once and passes it down, so the text pass 1 saw, the
    # text pass 2 sees and the map that writes pass 2's findings back to their
    # units are one object rather than three separate renderings that are
    # merely expected to agree. Rendering here when none is given keeps the
    # function callable on its own, which is how the tests use it.
    if render is None:
        render = chunk.render()
    units_by_id = {u.unit_id: u for u in chunk.units}

    # --- Stage 1: deterministic results, deduplicated within their own source.
    deterministic_proposals: list[tuple[Location, str, str]] = [
        ((span.unit_id, int(span.start), int(span.end)), span.action, span.category)
        for span in list(deterministic_spans) + list(review_hints)
        if span.unit_id in units_by_id
    ]
    deterministic_order, deterministic_pairs = _collect_by_location(
        deterministic_proposals
    )

    # --- Stage 2: pass-1 results, located first, then deduplicated the same way
    #     and independently — pass 1 agreeing with itself twice is one proposal,
    #     and it says nothing about what the rules found.
    pass1_proposals: list[tuple[Location, str, str]] = []
    for finding in findings:
        located = _occurrences(chunk, finding["text"])
        if not located:
            # Practically always a finding quoted across a table-cell join or
            # paraphrased. Dropped, but never silently.
            logger.warning(
                "pass-1 finding matched nothing in the chunk and was dropped "
                "(%d chars)",
                len(finding["text"]),
            )
            continue
        pass1_proposals.extend(
            (location, finding["action"], finding["category"]) for location in located
        )
    pass1_order, pass1_pairs = _collect_by_location(pass1_proposals)

    # --- Stage 3: merge the two sets, location by location.
    merged_order = deterministic_order + [
        location for location in pass1_order if location not in deterministic_pairs
    ]

    # --- Stage 4: group locations whose question is identical.
    candidates: list[Pass2Candidate] = []
    by_identity: dict[tuple, Pass2Candidate] = {}
    for location in merged_order:
        unit_id, start, end = location
        # The unit's own slice is the authority on what sits at this location,
        # so a span whose `text` field ever disagreed with its offsets cannot
        # send the wrong string to the model.
        text = units_by_id[unit_id].normalized_text[start:end]
        if not text:
            logger.debug("dropping a candidate whose location holds no text")
            continue

        recommendations = _merge_recommendations(
            deterministic_pairs.get(location, []),
            pass1_pairs.get(location, []),
            source=source,
        )

        before, after = _windows_at(render, location)

        identity = _identity(text, recommendations, before, after)
        existing = by_identity.get(identity)
        if existing is not None:
            existing.locations.append(location)
            continue

        candidate = Pass2Candidate(
            candidate_id=f"C{len(candidates) + 1}",
            text=text,
            category=recommendations[0]["category"],
            recommendations=recommendations,
            locations=[location],
            before=before,
            after=after,
        )
        by_identity[identity] = candidate
        candidates.append(candidate)

    grouped = sum(len(c.locations) for c in candidates) - len(candidates)
    if grouped:
        logger.debug(
            "pass-2 queue: %d location(s) folded into identical candidates", grouped
        )
    return candidates


# ---------------------------------------------------------------------------
# Pass-2 parsing (STRICT) — one final decision per candidate
# ---------------------------------------------------------------------------

@dataclass
class Pass2Decision:
    """One validated pass-2 answer, addressed to a candidate by id.

    ``action`` is always final (REDACT or PRESERVE): the illegal REVIEW action
    has already been coerced to REDACT, which ``coerced`` records.
    """

    candidate_id: str
    category: SpanCategory
    action: FinalAction
    coerced: bool


@dataclass
class Pass2Discovery:
    """One span pass 2 found in the excerpt that nobody had proposed.

    The recoveries the queue alone cannot make: a span the rules have no pattern
    for, that pass 1 missed, that pass 1 named in output too malformed to parse,
    or that pass 1 quoted across a table join so it could not be located. Pass 2
    reads the same chunk pass 1 did, so it is the last stage able to catch any
    of them.

    ``locations`` is already resolved — ``locate_in_rendered`` mapped the quoted
    text back through the render before this object was built, so a discovery
    only exists once it is known to be writable. There is no such thing here as
    a discovery with nowhere to go.
    """

    text: str
    category: SpanCategory
    action: FinalAction
    coerced: bool
    locations: list[Location] = field(default_factory=list)


@dataclass(frozen=True)
class UnusableDiscovery:
    """A pass-2 finding that could not even be given an id to ask about again.

    A discovery arrives as TEXT, so everything downstream depends on finding
    that text in the excerpt. When it is not there — a paraphrase, a
    translation, a tidied-up quote — there is no location to write to and no
    handle to re-ask by, so the only honest thing left is to record that pass 2
    saw something it could not express. That record is what stops the finding
    from being silently dropped, which is the behaviour this type exists to
    replace.

    Carries no text: ``detail`` is a counts-only phrase, for the same reason the
    rejection phrases are.
    """

    kind: UnresolvedKind
    category: str | None
    detail: str


@dataclass
class Pass2Validation:
    """What one pass-2 response yielded, and everything wrong with it.

    ``decisions`` are the candidate answers that passed every check, and
    ``discoveries`` the new spans that did. ``rejections`` names, one short
    machine-written phrase each, the entries that did not.

    The rest of the fields exist so that nothing a response mishandled can
    vanish between here and the retry:

    * ``voided`` — candidate ids answered more than once. Every answer for them
      was discarded, so they are UNDECIDED, not decided badly;
    * ``promotions`` — unusable discoveries that could still be LOCATED, turned
      into candidates with fresh ids so the corrective retry can be asked about
      them by name, exactly like any other candidate;
    * ``unusable_discoveries`` — the ones that could not be located, so there is
      nothing to re-ask and nothing to write. They are retained and reported,
      never dropped;
    * ``distrusted`` — the response contained an entry belonging to no candidate
      and no discovery: an id that was never issued, an entry with no id, an
      entry that is not an object. That is a model answering a queue it was not
      given, and the entries that happen to look right deserve no more trust
      than the one that visibly is not.

    A response carrying ANY rejection is unusable as it stands, even when every
    candidate happens to have been decided somewhere in it.
    """

    decisions: list[Pass2Decision]
    discoveries: list[Pass2Discovery] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)
    voided: list[str] = field(default_factory=list)
    promotions: list[Pass2Candidate] = field(default_factory=list)
    unusable_discoveries: list[UnusableDiscovery] = field(default_factory=list)
    distrusted: bool = False


def _safe_id(value: str) -> str:
    """Echo a model-supplied id only when it looks like one we could have issued.

    Rejection phrases reach the retry prompt and the log. A model that put
    document text in the ``id`` field must not turn that into a leak path.
    """
    return value if _CANDIDATE_ID_RE.match(value) else "<malformed id>"


def _next_candidate_number(candidates_by_id: dict[str, Pass2Candidate]) -> int:
    """The first ``C<n>`` number free in this queue.

    Promoted discoveries are numbered from here, so a promoted id can never
    collide with one already issued — including with a candidate that was NOT
    re-asked, whose id is absent from a retry's subset dictionary.
    """
    highest = 0
    for candidate_id in candidates_by_id:
        if _CANDIDATE_ID_RE.match(candidate_id):
            highest = max(highest, int(candidate_id[1:]))
    return highest + 1


def validate_pass2_entries(
    raw: str,
    candidates_by_id: dict[str, Pass2Candidate],
    *,
    render: RenderedChunk | None = None,
    known_locations: frozenset[Location] = frozenset(),
    next_candidate_number: int | None = None,
) -> Pass2Validation:
    """Validate pass-2 output item by item into final decisions and discoveries.

    Raises ``AIProviderError`` when the payload is not a JSON array — that is a
    malformed response, not a set of decisions. Within a well-formed array each
    entry is judged on its own, and the rules are exactly the ones
    ``SYSTEM_PROMPT_PASS2`` states.

    DUPLICATES ARE COUNTED BEFORE ANYTHING IS VALIDATED. The whole array is read
    once to tally candidate ids and to group ``NEW`` entries by their text,
    BEFORE any entry is judged. That ordering is the point: validating first
    meant an id whose first copy was rejected for some other reason — an illegal
    action, say — never reached the duplicate check at all, so a second copy
    could still be accepted and the candidate came back "decided" by a response
    that had contradicted itself about it. Counting first makes the outcome
    independent of which copy was the broken one and of the order they arrived
    in.

    An entry addressed to a CANDIDATE is REJECTED — not quietly dropped — when:

    * it is not a JSON object, or carries no ``id``, or names an ``id`` this
      queue never issued. None of those belongs to anything, so each also marks
      the response DISTRUSTED;
    * its ``id`` appears more than once in this response. Every answer for it is
      discarded, including ones that were individually valid, and the candidate
      comes back UNRESOLVED to be asked again. Nothing picks a winner between
      them: first, last and most-cautious are all just the order the model
      emitted them in;
    * the candidate behind its ``id`` no longer maps to a location;
    * its ``action`` is not a decision. ``REVIEW`` is first coerced to
      ``REDACT`` (recorded in ``coerced``), the fail-safe direction; ``SKIP``
      and anything else are no answer at all.

    A ``category`` outside the schema falls back to the candidate's recommended
    category rather than costing an otherwise good decision — unless the
    candidate has none to fall back to, which is true of exactly one kind of
    candidate: a PROMOTED discovery, whose only previous answer was pass 2's own
    and whose category was the unusable part of it.

    An entry whose ``id`` is the literal ``NEW`` is a DISCOVERY — a span pass 2
    found in the excerpt that nobody proposed. It carries ``text`` instead of
    coordinates, and it is rejected when it has no text, when the same text is
    answered more than once, when its ``action`` is not final, when its
    ``category`` is outside the schema, or when its text is not an exact
    substring of the excerpt.

    A REJECTED DISCOVERY IS NOT A DROPPED ONE. Whenever the text can still be
    located, the finding is PROMOTED: it becomes a ``Pass2Candidate`` with a
    fresh id and the model's own answers as its recommendations, so the
    corrective retry is asked about it by id, against the same excerpt, and the
    ordinary completeness machinery tracks it from there. Only a finding that
    cannot be located at all has nowhere to go, and that one is recorded in
    ``unusable_discoveries`` rather than forgotten.

    ``known_locations`` are the slices this chunk's candidates already own. A
    discovery landing entirely on them is not new; it is the queue's question
    asked again, and the id-addressed answer governs that slice, so it is
    dropped. Nothing is lost: the location is decided either way.
    """
    entries = _extract_json_array(raw)
    if entries is None:
        raise AIProviderError("pass-2 output could not be parsed as a JSON array")

    validated: list[Pass2Decision] = []
    discoveries: list[Pass2Discovery] = []
    rejections: list[str] = []
    voided: list[str] = []
    promotions: list[Pass2Candidate] = []
    unusable: list[UnusableDiscovery] = []
    handled_texts: set[str] = set()
    distrusted = False

    next_number = (
        _next_candidate_number(candidates_by_id)
        if next_candidate_number is None
        else next_candidate_number
    )

    def read_action(entry: dict) -> tuple[str, bool]:
        """The shared action rule: REVIEW coerces to REDACT, nothing else bends."""
        action = str(entry.get("action", "")).strip().upper()
        if action == "REVIEW":
            return "REDACT", True
        return action, False

    # --- the pre-scan. Nothing is judged until everything is counted. --------
    id_counts: Counter[str] = Counter()
    new_answers: dict[str, list[dict]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id", "")).strip().upper()
        if not entry_id:
            continue
        if entry_id == _NEW_FINDING_ID:
            text = str(entry.get("text", "")).strip()
            if not text:
                continue
            action, coerced = read_action(entry)
            new_answers.setdefault(text, []).append(
                {"action": action, "category": _read_category(entry), "coerced": coerced}
            )
        else:
            id_counts[entry_id] += 1

    duplicated_ids = {cid for cid, count in id_counts.items() if count > 1}
    duplicated_texts = {text for text, answers in new_answers.items() if len(answers) > 1}

    def promote(text: str, kind: UnresolvedKind) -> None:
        """Give an unusable discovery an id, so the retry can be asked about it.

        Records it as unlocatable instead when there is nowhere to write it, and
        drops it silently when every occurrence is a slice a candidate already
        owns — there the queue's own answer governs and nothing is outstanding.
        """
        nonlocal next_number
        answers = new_answers.get(text, [])
        category = next((a["category"] for a in answers if a["category"]), None)
        if render is None:
            unusable.append(UnusableDiscovery(
                kind="discovery_unlocatable",
                category=category,
                detail=f"a new finding ({len(text)} chars) arrived with no excerpt to locate it in",
            ))
            return
        located = locate_in_rendered(render, text)
        if not located:
            unusable.append(UnusableDiscovery(
                kind="discovery_unlocatable",
                category=category,
                detail=f"a new finding ({len(text)} chars) is not an exact substring of the excerpt",
            ))
            return
        fresh = [location for location in located if location not in known_locations]
        if not fresh:
            logger.debug(
                "pass-2 returned an unusable new finding that only covers candidate "
                "locations; the candidates' own answers stand"
            )
            return

        recommendations: list[dict] = []
        for answer in answers:
            # An entry with no usable action is recorded as REVIEW, which is what
            # every other source uses to say "I could not decide this".
            recommendation = {
                "sources": ["pass2"],
                "action": answer["action"] if answer["action"] in {"REDACT", "PRESERVE"} else "REVIEW",
                "category": answer["category"],
            }
            if recommendation not in recommendations:
                recommendations.append(recommendation)
        if not recommendations:
            recommendations = [{"sources": ["pass2"], "action": "REVIEW", "category": None}]

        before, after = _windows_at(render, fresh[0])
        promotions.append(Pass2Candidate(
            candidate_id=f"C{next_number}",
            text=text,
            category=category,
            recommendations=recommendations,
            locations=fresh,
            before=before,
            after=after,
            promoted_from=kind,
        ))
        next_number += 1

    for position, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            rejections.append(f"entry {position} is not a JSON object")
            distrusted = True
            continue

        candidate_id = str(entry.get("id", "")).strip().upper()
        if not candidate_id:
            rejections.append(f"entry {position} carries no candidate id")
            distrusted = True
            continue

        if candidate_id == _NEW_FINDING_ID:
            # Stripped, as a pass-1 finding is: surrounding whitespace is the
            # model's formatting, not part of the span.
            text = str(entry.get("text", "")).strip()
            if not text:
                rejections.append(f"entry {position} is a new finding with no text")
                unusable.append(UnusableDiscovery(
                    kind="discovery_malformed",
                    category=None,
                    detail="a new finding carried no text",
                ))
                continue
            if text in handled_texts:
                # Already settled by the first entry carrying this text.
                continue

            if text in duplicated_texts:
                handled_texts.add(text)
                rejections.append(
                    f"entry {position} repeats a new finding ({len(text)} chars) "
                    f"answered more than once; every answer for it was discarded "
                    f"and it comes back as a candidate to decide again"
                )
                promote(text, "discovery_conflicting")
                continue

            answer = new_answers[text][0]
            if answer["action"] not in {"REDACT", "PRESERVE"}:
                handled_texts.add(text)
                rejections.append(
                    f"entry {position} is a new finding with no final "
                    f"REDACT/PRESERVE action"
                )
                promote(text, "discovery_malformed")
                continue

            if answer["category"] is None:
                handled_texts.add(text)
                rejections.append(
                    f"entry {position} is a new finding with a category outside "
                    f"the vocabulary"
                )
                promote(text, "discovery_malformed")
                continue

            if render is None:
                handled_texts.add(text)
                rejections.append(
                    f"entry {position} is a new finding, and no excerpt was "
                    f"provided to locate it in"
                )
                unusable.append(UnusableDiscovery(
                    kind="discovery_unlocatable",
                    category=answer["category"],
                    detail=f"a new finding ({len(text)} chars) arrived with no excerpt",
                ))
                continue

            located = locate_in_rendered(render, text)
            if not located:
                handled_texts.add(text)
                # Length only: the text is the model's, quoted out of the
                # document, and this phrase reaches the retry prompt and the log.
                rejections.append(
                    f"entry {position} is a new finding whose text ({len(text)} "
                    f"chars) is not an exact substring of the excerpt"
                )
                unusable.append(UnusableDiscovery(
                    kind="discovery_unlocatable",
                    category=answer["category"],
                    detail=f"a new finding ({len(text)} chars) is not in the excerpt",
                ))
                continue

            handled_texts.add(text)
            fresh = [location for location in located if location not in known_locations]
            if not fresh:
                logger.debug(
                    "pass-2 returned a new finding that only covers candidate "
                    "locations; the candidates' own answers stand"
                )
                continue
            discoveries.append(Pass2Discovery(
                text=text,
                category=answer["category"],
                action=answer["action"],
                coerced=answer["coerced"],
                locations=fresh,
            ))
            continue

        candidate = candidates_by_id.get(candidate_id)
        if candidate is None:
            rejections.append(
                f"{_safe_id(candidate_id)} is not a candidate in this queue"
            )
            distrusted = True
            continue

        if candidate_id in duplicated_ids:
            # Known from the pre-scan, so EVERY copy is skipped here — including
            # the first, and including one that would have validated. The
            # candidate is undecided, and the retry asks it again.
            if candidate_id not in voided:
                voided.append(candidate_id)
                rejections.append(
                    f"{candidate_id} is answered more than once; every answer "
                    f"for it was discarded and it must be decided again"
                )
            continue

        if not candidate.has_location:
            # Defensive: a queued candidate always has one. If that ever stops
            # being true, the decision must not be counted as an answer.
            rejections.append(f"{candidate_id} no longer maps to a location")
            continue

        category = _read_category(entry)
        if category is None:
            if candidate.category is None:
                # A promoted discovery: the model's own category was what made
                # it unusable, so there is nothing behind it to fall back to.
                # Inventing one would put a fiction in the audit trail.
                rejections.append(
                    f"{candidate_id} has a category outside the vocabulary and "
                    f"no recommended one to fall back to"
                )
                continue
            category = candidate.category

        action, coerced = read_action(entry)
        if not is_final_action(action):
            rejections.append(f"{candidate_id} has no final REDACT/PRESERVE action")
            continue

        validated.append(Pass2Decision(
            candidate_id=candidate_id,
            category=category,
            action=action,
            coerced=coerced,
        ))

    if voided:
        logger.warning(
            "pass-2: %d candidate id(s) answered more than once; their answers "
            "were discarded and they will be re-asked",
            len(voided),
        )
    if promotions:
        logger.warning(
            "pass-2: %d unusable new finding(s) were given ids and will be "
            "re-asked as candidates",
            len(promotions),
        )
    if rejections:
        logger.warning(
            "pass-2: %d unusable entry/entries — %s",
            len(rejections),
            "; ".join(rejections[:5]) + (" ..." if len(rejections) > 5 else ""),
        )
    return Pass2Validation(
        decisions=validated,
        discoveries=discoveries,
        rejections=rejections,
        voided=voided,
        promotions=promotions,
        unusable_discoveries=unusable,
        distrusted=distrusted,
    )


def unresolved_candidates(
    decisions: list[Pass2Decision],
    candidates: list[Pass2Candidate],
) -> list[str]:
    """Return the ids of candidates pass 2 left undecided.

    Completeness is decided on IDS ALONE — an exact set difference, no text
    comparison of any kind. A candidate counts as resolved only when a validated
    decision carries *its own* id with a final REDACT or PRESERVE. A decision
    about some other candidate is never evidence about this one, however similar
    the two strings look: the containment rule this replaced ("a name is inside
    the header line, so deciding the line decided the name") could mark a
    candidate resolved whose decision then landed nowhere.

    Pass 2 is the final adjudicator for everything in its queue, so the bar is
    every candidate, not just the ones the rules were unsure about. An omission
    is a missing decision, never a safe one. An empty list means every candidate
    was answered.
    """
    decided = {d.candidate_id for d in decisions if d.action in {"REDACT", "PRESERVE"}}
    return [c.candidate_id for c in candidates if c.candidate_id not in decided]


def spans_from_decisions(
    decisions: list[Pass2Decision],
    candidates_by_id: dict[str, Pass2Candidate],
    units_by_id: dict[str, TextUnit] | None = None,
    regions: frozenset[str] = frozenset(),
) -> list[Span]:
    """Map each decision straight back onto its candidate's stored location.

    This is a dictionary lookup and nothing else. The id the model returned is
    the id we issued, the candidate behind it still holds the
    ``(unit_id, start, end)`` slices the detectors established, and a span is
    written at each of them. No text is searched for, and no offsets from the
    model are read — it is never given any.

    One decision can therefore produce several spans: a candidate holds more
    than one location exactly when those locations posed an identical question
    (see ``build_pass2_candidates``), so applying the single answer to all of
    them is applying it to the places it was actually about. Occurrences that
    differed in any way were separate candidates and got their own answers.
    """
    units_by_id = units_by_id or {}
    spans: list[Span] = []
    for decision in decisions:
        candidate = candidates_by_id.get(decision.candidate_id)
        if candidate is None or not candidate.has_location:
            # Unreachable via the orchestrator: validate_pass2_entries rejects
            # both cases before a decision exists. Kept because writing a span
            # at a location we are not sure of is the one mistake in this module
            # that would corrupt the document instead of merely failing.
            logger.warning(
                "pass-2 decision for %s has no usable candidate location; dropped",
                decision.candidate_id,
            )
            continue
        if decision.coerced:
            logger.warning(
                "pass-2 coerced REVIEW to REDACT for candidate %s (category %s)",
                decision.candidate_id,
                decision.category,
            )
        for unit_id, start, end in candidate.locations:
            span_text = candidate.text
            if decision.action == "REDACT":
                # The candidate's geometry came from whichever stage proposed
                # it, and pass 2 answered the question rather than redrawing the
                # span. Narrow it to the value here so the PLAN records what was
                # actually redacted; see anonymizer.span_trim.
                unit = units_by_id.get(unit_id)
                if unit is not None:
                    narrowed = narrow_redaction(
                        unit.normalized_text, start, end, decision.category,
                        regions,
                    )
                    if narrowed is None:
                        continue
                    start, end = narrowed
                    # Re-read the text at the NEW offsets. Keeping the
                    # candidate's original string beside narrowed coordinates
                    # would make the span describe something it no longer
                    # covers, and that string is what the summary reports.
                    span_text = unit.normalized_text[start:end]
            spans.append(
                Span(
                    unit_id=unit_id,
                    start=start,
                    end=end,
                    text=span_text,
                    category=decision.category,
                    detector="llm_pass2",
                    confidence=_LLM_CONFIDENCE,
                    action=decision.action,
                    reason=f"LLM pass-2 decision: {decision.action}",
                    # The provenance the resolver arbitrates on. `detector` is a
                    # diagnostic name; THIS is what makes the span outrank the
                    # ordinary rule spans it was asked to settle.
                    origin="llm_pass2",
                )
            )
    return spans


def spans_from_discoveries(
    discoveries: list[Pass2Discovery],
    units_by_id: dict[str, TextUnit],
    regions: frozenset[str] = frozenset(),
) -> list[Span]:
    """Turn pass-2's own findings into spans at the locations already resolved for them.

    A discovery reaches this function only after ``locate_in_rendered`` mapped
    its text back through the render, so this is a write, not a search. One
    discovery can produce several spans: every occurrence of the quoted text,
    and one per unit where an occurrence crossed a join.

    Each span's ``text`` is read off the UNIT at its location, never copied from
    what the model quoted. The two differ exactly when a finding crossed a join,
    where the quoted string spans two units and neither one contains it — the
    unit is the authority on what sits at a location, the same rule
    ``build_pass2_candidates`` follows.

    They carry the same ``origin="llm_pass2"`` authority as an adjudicated
    candidate — the model decided both, and the resolver ranks them alike — and
    a distinct ``detector`` name, so the plan's summary shows how much of a
    document was caught by pass 2 reading for itself rather than by the queue.
    """
    spans: list[Span] = []
    for discovery in discoveries:
        if discovery.coerced:
            logger.warning(
                "pass-2 coerced REVIEW to REDACT for a new finding (category %s)",
                discovery.category,
            )
        for unit_id, start, end in discovery.locations:
            unit = units_by_id.get(unit_id)
            if unit is None:
                # Unreachable: the location came out of this chunk's own render.
                logger.warning("pass-2 discovery names a unit not in the chunk; dropped")
                continue
            if discovery.action == "REDACT":
                # A discovery is quoted by the model, so this is where an
                # over-wide quote ("με Α.Φ.Μ. 037173570") becomes the value it
                # was supposed to be.
                narrowed = narrow_redaction(
                    unit.normalized_text, start, end, discovery.category, regions
                )
                if narrowed is None:
                    continue
                start, end = narrowed
            spans.append(
                Span(
                    unit_id=unit_id,
                    start=start,
                    end=end,
                    text=unit.normalized_text[start:end],
                    category=discovery.category,
                    detector="llm_pass2_discovery",
                    confidence=_LLM_CONFIDENCE,
                    action=discovery.action,
                    reason=f"LLM pass-2 discovery: {discovery.action}",
                    origin="llm_pass2",
                )
            )
    return spans


# ---------------------------------------------------------------------------
# Provider call
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Provider retry policy
# ---------------------------------------------------------------------------
#
# THE PROVIDER RETRY AND THE PASS-2 CORRECTIVE RETRY ARE DIFFERENT MECHANISMS,
# and this is the first of the two. They answer different questions:
#
#   provider retry (here)   the call did not complete. Network, timeout, 429,
#                           a 5xx. Nothing was said, so say it again.
#   pass-2 retry (_adjudicate)  the call completed and the ANSWER was unusable.
#                           Retrying the transport would change nothing; the
#                           model is re-asked, once, about what it got wrong.
#
# They compose rather than merge: a pass-2 corrective call is itself a provider
# call, so it gets the full retry ladder below on its way out.
#
# Attempt 1 fails -> retry after 0s, then 1s, then 2s. Four attempts, three
# retries. The first retry is immediate because the commonest transient failure
# is a single dropped connection, and making that request wait a second buys
# nothing; the backoff after it is for the case where something is actually
# busy.
_RETRY_DELAYS_S: tuple[int, ...] = (0, 1, 2)
_MAX_PROVIDER_RETRIES = len(_RETRY_DELAYS_S)
_MAX_PROVIDER_ATTEMPTS = _MAX_PROVIDER_RETRIES + 1

# HTTP statuses worth repeating a request for. Everything else in 4xx is the
# request itself being wrong — a bad key, a missing deployment, a malformed
# body — and repeating it three times only makes the same mistake four times,
# more slowly, while hiding the real cause behind a delay.
#   408 request timeout, 409 conflict (Azure raises it for transient
#   concurrency on a deployment), 429 rate limited, 5xx server-side.
_RETRYABLE_STATUS_CODES = frozenset({408, 409, 429})

# A retry sleep is only worth starting if there is room for the call that
# follows it. This is that room.
_MIN_SLEEP_HEADROOM_S = 1.0


def _call_tag(
    ctx: RunContext | None,
    chunk_index: int,
    pass_number: int,
    attempt: str,
) -> str:
    """The correlation fields every provider log line starts with.

    Without ``ctx`` — a direct call from a unit test — the ids are simply
    absent rather than faked, and the chunk and pass still identify the line.
    """
    if ctx is not None:
        return ctx.chunk_tag(chunk_index, pass_number, attempt)
    return f"chunk={chunk_index + 1} pass={pass_number} attempt={attempt}"


def _sleep(seconds: float) -> None:
    """Wait between provider retries.

    Indirected through a module-level function so tests can replace it: a suite
    that really slept would spend three seconds per exhausted-retry case and
    prove nothing extra. ``time.sleep`` releases the GIL, so a chunk worker
    waiting here does not hold up the other workers in the pool.
    """
    time.sleep(seconds)


@dataclass(frozen=True)
class _ProviderFailure:
    """One failed provider call, classified once so the caller need not re-ask.

    ``label`` is the grep-friendly name that goes in the logs — ``timeout``,
    ``connection``, ``http_503`` — and carries no message text from the provider
    and nothing from the document. ``error`` is the typed exception to raise if
    this attempt turns out to be the last one, so the application's exception
    hierarchy is decided here and unchanged by retrying.
    """

    label: str
    retryable: bool
    error: AnonymizerError
    # The provider's HTTP status, when it gave one. Reported separately from
    # the label so a log can be filtered on either.
    http_status: int | None = None


def _classify_provider_error(
    exc: openai.OpenAIError,
    chunk_index: int,
    pass_number: int,
    cfg: RuntimeConfig,
) -> _ProviderFailure:
    """Map an SDK exception to a retry decision and the typed error it becomes.

    The order is load-bearing: ``APITimeoutError`` subclasses
    ``APIConnectionError``, so it has to be tested first or a timeout would be
    reported as an unreachable provider.
    """
    where = f"({_chunk_label(chunk_index)}, pass {pass_number})"

    if isinstance(exc, openai.APITimeoutError):
        return _ProviderFailure(
            label="timeout",
            retryable=True,
            error=AITimeoutError(f"LLM call timed out after {cfg.llm_timeout_s}s {where}"),
        )
    if isinstance(exc, openai.APIConnectionError):
        return _ProviderFailure(
            label="connection",
            retryable=True,
            error=AIUnavailableError(f"LLM provider unreachable {where}"),
        )
    if isinstance(exc, openai.APIStatusError):
        status = int(getattr(exc, "status_code", 0) or 0)
        retryable = status in _RETRYABLE_STATUS_CODES or 500 <= status <= 599
        # 429 gets its own label. Rate limiting is an operational condition
        # with a specific remedy — send less, or send it slower — and burying
        # it in a generic http_429 makes it invisible in exactly the incident
        # where somebody is looking for it. Nothing else is called rate
        # limiting: a timeout is a timeout and a 503 is a 503.
        label = "rate_limited" if status == 429 else f"http_{status}"
        return _ProviderFailure(
            label=label,
            retryable=retryable,
            error=AIProviderError(f"provider returned HTTP {status} {where}"),
            http_status=status,
        )
    return _ProviderFailure(
        label="provider_error",
        retryable=False,
        error=AIProviderError(f"provider error {where}"),
    )


def _call_with_retries(
    client: Any,
    cfg: RuntimeConfig,
    system_prompt: str,
    user_message: str,
    chunk_index: int,
    pass_number: int,
    *,
    ctx: RunContext | None = None,
    attempt_label: str = "first",
) -> Any:
    """Make one provider request, retrying transient failures, and return the raw response.

    Up to ``_MAX_PROVIDER_ATTEMPTS`` attempts with ``_RETRY_DELAYS_S`` between
    them. A non-retryable failure stops on the spot — waiting three seconds to
    ask a second time with the same bad API key helps nobody — and an exhausted
    ladder raises the same typed exception the first attempt would have.

    Every outcome that is not a plain success leaves a line in the log, keyed by
    1-based chunk and pass so an operator can grep one chunk's history:

        llm_retry chunk=2 pass=1 retry=1/3 delay_s=0 error=timeout
        llm_retry_succeeded chunk=2 pass=1 attempt=2
        llm_retry_exhausted chunk=2 pass=1 attempts=4 error=http_503
        llm_not_retryable chunk=2 pass=1 attempt=1 error=http_401

    They carry counts, positions and an error label only: no key, no header, no
    prompt, no response body, no document text.

    Anything that is not an ``openai.OpenAIError`` propagates untouched — it is
    a bug in this code or in the caller's client, not a provider failure, and
    dressing it up as one would hide it.
    """
    tag = _call_tag(ctx, chunk_index, pass_number, attempt_label)
    stage = f"llm pass {pass_number}"
    for attempt_number in range(1, _MAX_PROVIDER_ATTEMPTS + 1):
        if ctx is not None and ctx.deadline.cancelled:
            raise DocumentTimeoutError(stage)
        # The per-request timeout is the smaller of the configured call
        # timeout and what is left of the document's budget, so an in-flight
        # call ends AT the deadline rather than beyond it. Below the floor it
        # is not started at all: the round trip would only spend time
        # discovering what the clock already says.
        timeout = (
            cfg.llm_timeout_s if ctx is None
            else ctx.deadline.budget(cfg.llm_timeout_s, stage=stage)
        )
        try:
            response = client.chat.completions.create(
                model=cfg.model_handle,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                max_completion_tokens=cfg.max_completion_tokens,
                timeout=timeout,
            )
        except openai.OpenAIError as exc:
            failure = _classify_provider_error(exc, chunk_index, pass_number, cfg)
            status = "-" if failure.http_status is None else failure.http_status

            if ctx is not None and ctx.deadline.expired():
                logger.warning(
                    "llm_deadline_expired %s transport_attempt=%d error=%s",
                    tag, attempt_number, failure.label,
                )
                raise DocumentTimeoutError(stage) from exc

            if not failure.retryable:
                logger.warning(
                    "llm_not_retryable %s transport_attempt=%d error=%s "
                    "provider=%s http_status=%s will_retry=no",
                    tag, attempt_number, failure.label, cfg.provider, status,
                )
                raise failure.error from exc

            if attempt_number == _MAX_PROVIDER_ATTEMPTS:
                logger.error(
                    "llm_retry_exhausted %s attempts=%d error=%s provider=%s "
                    "http_status=%s will_retry=no",
                    tag, attempt_number, failure.label, cfg.provider, status,
                )
                raise failure.error from exc

            delay = _RETRY_DELAYS_S[attempt_number - 1]
            if ctx is not None and ctx.deadline.remaining() < delay + _MIN_SLEEP_HEADROOM_S:
                # Sleeping through the rest of the budget to make a call that
                # cannot finish is the worst of both.
                logger.warning(
                    "llm_retry_skipped %s reason=deadline delay_s=%d "
                    "remaining_s=%.1f error=%s",
                    tag, delay, ctx.deadline.remaining(), failure.label,
                )
                raise DocumentTimeoutError(stage) from exc

            logger.warning(
                "llm_retry %s transport_attempt=%d retry=%d/%d delay_s=%d "
                "error=%s provider=%s http_status=%s will_retry=yes",
                tag, attempt_number, attempt_number, _MAX_PROVIDER_RETRIES,
                delay, failure.label, cfg.provider, status,
            )
            _sleep(delay)
            continue

        if attempt_number > 1:
            logger.info(
                "llm_retry_succeeded %s transport_attempt=%d",
                tag, attempt_number,
            )
        return response

    # Unreachable: the loop returns on success and raises on the final attempt.
    raise AIProviderError(f"provider retry loop ended without a result ({_chunk_label(chunk_index)})")


# Finish reasons that mean the model said everything it meant to say. A
# reason NOT in here makes the body a fragment of an answer rather than an
# answer, however complete it happens to look.
#
# ``None`` is treated as complete, deliberately: a provider that reports no
# finish reason at all is not reporting a PROBLEM, and refusing those would
# fail every response from an endpoint that omits the field. The risk runs the
# other way for anything it does report — an unfamiliar reason is treated as
# incomplete, so a provider inventing a new one fails closed and visibly.
_COMPLETE_FINISH_REASONS = frozenset({"stop"})


@dataclass(frozen=True)
class Completion:
    """One provider response, reduced to what a caller judges it by.

    ``text`` is the completion body, or ``""`` when the response carried none.
    ``finish_reason`` is what the provider said about why it stopped, and
    ``refused`` whether the model returned an explicit refusal instead of an
    answer. Those two are the difference between a short answer and a
    truncated one, which NOTHING in the body itself can tell you: a list of
    decisions cut off at the token ceiling is indistinguishable from a
    complete list of fewer decisions.

    The two passes read these fields and reach opposite conclusions, which is
    the whole reason ``_call`` reports instead of deciding: an unusable pass-1
    body costs recommendations, an unusable pass-2 body costs the document.
    """

    text: str
    finish_reason: str | None = None
    refused: bool = False

    @property
    def truncated(self) -> bool:
        """The provider stopped at the output-token ceiling."""
        return self.finish_reason == "length"

    @property
    def filtered(self) -> bool:
        """A content filter or an explicit refusal cut the answer short."""
        return self.refused or self.finish_reason == "content_filter"

    @property
    def complete(self) -> bool:
        """Whether this body is the whole of what the model meant to say."""
        if self.refused:
            return False
        return (
            self.finish_reason is None
            or self.finish_reason in _COMPLETE_FINISH_REASONS
        )

    @property
    def problem(self) -> str | None:
        """A counts-only phrase naming why this is not a complete answer.

        None when it is one. Safe for logs, retry prompts and error messages:
        it names the provider's own status word and nothing from the body.
        """
        if self.complete:
            return None
        if self.truncated:
            return "the completion stopped at the output-token limit (finish_reason=length)"
        if self.refused:
            return "the model returned a refusal instead of an answer"
        if self.filtered:
            return "the completion was cut short by a content filter (finish_reason=content_filter)"
        return f"the completion did not finish normally (finish_reason={self.finish_reason})"


def _completion_text(response: Any) -> str:
    """The first choice's content, or ``""`` when the response shape is unfamiliar.

    Defensive on purpose. A response with no choices, or a content field that is
    not a string, is a provider returning something unusable — the same class of
    problem as an empty body — and it must reach the caller's policy as such
    rather than as an ``IndexError`` from inside the detector.
    """
    try:
        content = response.choices[0].message.content
    except (AttributeError, IndexError, KeyError, TypeError):
        return ""
    return content if isinstance(content, str) else ""


def _completion_refused(response: Any) -> bool:
    """Whether the first choice carries an explicit refusal string.

    A refusal is the model declining to answer, which providers report beside
    the content rather than through the finish reason. Read defensively for
    the same reason ``_completion_text`` is: a response shaped unfamiliarly
    must reach the caller's policy as an unusable answer, not as an
    ``AttributeError`` from inside the detector.
    """
    try:
        refusal = response.choices[0].message.refusal
    except (AttributeError, IndexError, KeyError, TypeError):
        return False
    return isinstance(refusal, str) and bool(refusal.strip())


def _call(
    client: Any,
    cfg: RuntimeConfig,
    system_prompt: str,
    user_message: str,
    chunk_index: int,
    pass_number: int,
    usage: UsageRecorder,
    *,
    attempt: str = "first",
    ctx: RunContext | None = None,
) -> Completion:
    """Make one provider request — retrying transient failures — and report what came back.

    RAISES for transport and provider failures — timeout, unreachable endpoint,
    HTTP status, SDK error — once the retry ladder in ``_call_with_retries`` has
    been exhausted or the failure was never retryable. A request that COMPLETED
    always returns a ``Completion``, however useless its body: an empty
    completion and a truncated one are answers about the model's output, not
    outages, and the difference matters because the two passes treat them
    differently. Deciding that here would force one policy on both.

    ONE ``Completion`` PER LOGICAL REQUEST, not per attempt. The retries happen
    below this line, so a caller sees a request that either worked or did not.
    The pass-2 corrective retry sits ABOVE this line and calls it again for its
    own reasons — see the note over ``_RETRY_DELAYS_S`` for why the two are
    separate mechanisms rather than one.

    Accounting counts the request that produced a response, not the attempts
    that failed before it: failed attempts return no usage block to read, and
    the retry logs are where their cost shows up. Every response this function
    receives is booked against ``usage`` — the document's own recorder — so pass
    1, pass-2 first attempts and pass-2 corrective retries all land in the same
    per-document total. Only the response's usage block and finish reason are
    read; no prompt or completion text is inspected for accounting.

    ``system_prompt`` selects the pass-specific system prompt (blind pass 1 vs
    adjudicating pass 2).
    """
    response = _call_with_retries(
        client, cfg, system_prompt, user_message, chunk_index, pass_number,
        ctx=ctx, attempt_label=attempt,
    )

    # Booked before the content is judged: a truncated or empty completion
    # still cost tokens, and a truncation is exactly the diagnostic that
    # explains whatever the caller decides about the body.
    # THREE SEPARATE CONCERNS, IN THIS ORDER: the response arrived (above),
    # what it SAYS is extracted (here), and only then is it counted. The
    # ordering is structural rather than incidental: accounting is
    # bookkeeping, and bookkeeping must never be what decides whether a
    # document can be produced.
    text = _completion_text(response)
    refused = _completion_refused(response)

    finish_reason = usage.record(
        response,
        chunk_index=chunk_index,
        pass_number=pass_number,
        attempt=attempt,
        limit=cfg.max_completion_tokens,
    )
    if finish_reason == "length":
        # Logged the moment it is known, not after the stage succeeds. An
        # incomplete answer with a truncation against it is a budget problem;
        # the same answer without one is the model omitting things. A
        # document that fails needs that distinction more than one that
        # succeeds, and it used to be reported only on success.
        logger.warning(
            "llm_truncated %s limit=%d",
            _call_tag(ctx, chunk_index, pass_number, attempt),
            cfg.max_completion_tokens,
        )
    return Completion(text=text, finish_reason=finish_reason, refused=refused)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

AttemptOutcome = Literal[
    "complete",            # a reading: parsed, and every entry accounted for
    "incomplete_length",   # the provider stopped at the output-token ceiling
    "incomplete_filtered", # a content filter or an explicit refusal
    "incomplete_other",    # some other finish reason this code does not know
    "incomplete_empty",    # the call completed and said nothing
    "unparseable",         # a body that is not a JSON array of decisions
]
"""What one pass-2 call was WORTH, before anything in it is believed.

Only ``complete`` is a reading. The rest are a response that arrived without
being an answer, and the distinction is the reason this type exists: a
truncated list of decisions is indistinguishable from a complete list of fewer
decisions by looking at the text, so the judgement has to be made from the
provider's own status rather than from the body.
"""


@dataclass
class _Pass2Attempt:
    """One pass-2 call and the verdict on it.

    ``reason`` is None exactly when the response is usable: a complete reading
    in which every entry passed validation AND every candidate came back
    decided. Otherwise it is a short counts-only phrase — safe to put in the
    error that reaches the caller, since it carries no document text — while the
    remaining fields carry the detail the retry needs.
    """

    decisions: list[Pass2Decision]
    reason: str | None
    outcome: AttemptOutcome = "complete"
    rejections: list[str] = field(default_factory=list)
    discoveries: list[Pass2Discovery] = field(default_factory=list)
    voided: list[str] = field(default_factory=list)
    promotions: list[Pass2Candidate] = field(default_factory=list)
    unusable_discoveries: list[UnusableDiscovery] = field(default_factory=list)
    distrusted: bool = False

    @property
    def usable(self) -> bool:
        """Whether this response was a READING at all.

        Distinct from ``reason is None``, which additionally asks whether the
        reading was COMPLETE. A usable attempt can still have left candidates
        undecided; an unusable one has told us nothing, and nothing in its body
        may be believed.
        """
        return self.outcome == "complete"


def _pass2_attempt(
    client: Any,
    cfg: RuntimeConfig,
    asked: list[Pass2Candidate],
    chunk_index: int,
    usage: UsageRecorder,
    *,
    render: RenderedChunk,
    known_locations: frozenset[Location],
    retry: bool,
    next_candidate_number: int,
    previous: _Pass2Attempt | None = None,
    kept_previous: bool = True,
    remediation: bool = False,
    ctx: RunContext | None = None,
) -> _Pass2Attempt:
    """Make one pass-2 call over ``asked`` and judge whether its output is usable.

    THE PROVIDER'S STATUS IS READ BEFORE THE BODY IS. A completion the provider
    cut short — at the output-token ceiling, by a content filter, or with a
    refusal — is not treated as a reading at all, and NOTHING in it is parsed:
    not the decisions it appears to contain, not the new findings it appears to
    report. A fragment that happens to end in a bracket parses exactly like a
    complete answer, and accepting one would mean a chunk was adjudicated on the
    first few decisions the model got out before it ran out of room.

    ``asked`` is the queue for THIS call, not necessarily the whole chunk: a
    retry is handed only the candidates still missing a decision, plus any
    finding promoted out of the previous response. Validation is scoped to it,
    which is what enforces "the candidate was actually unresolved" — an id that
    exists in the chunk but was not re-asked is not in this call's queue and is
    rejected like any other unknown id.

    An attempt is USABLE only when the call completed and its body parsed. It is
    additionally COMPLETE (``reason is None``) only when nothing in the response
    was rejected and every candidate in ``asked`` came back decided.

    ``render`` is the WHOLE chunk, sent as the authoritative context for the
    queue and used to locate whatever the model finds in it that nobody
    proposed. ``asked`` may be a subset on a retry; the excerpt never is.

    ``remediation`` says the excerpt is an ALREADY-REDACTED document and the
    queue came from its post-redaction audit. It selects one instruction line in
    the message builders and changes nothing else: same system prompt, same
    payload shape, same validation, same corrective retry.

    Provider and transport failures are NOT judged here: ``_call`` raises for
    those and the exception aborts the run.
    """
    by_id = {c.candidate_id: c for c in asked}
    payload = [c.as_payload() for c in asked]
    if retry and previous is not None:
        message = build_pass2_retry_message(
            render.text,
            payload,
            previous.rejections,
            previous.reason or "",
            kept_previous=kept_previous,
            remediation=remediation,
        )
    else:
        message = build_pass2_message(render.text, payload, remediation=remediation)

    completion = _call(
        client, cfg, SYSTEM_PROMPT_PASS2, message, chunk_index, 2, usage,
        attempt="retry" if retry else "first", ctx=ctx,
    )

    def unusable(outcome: AttemptOutcome, reason: str) -> _Pass2Attempt:
        """Record and return an attempt whose body must not be read."""
        usage.record_pass2_attempt(complete=False)
        logger.warning(
            "%s: pass 2 %s attempt unusable: outcome=%s (%s)",
            _chunk_label(chunk_index), "retry" if retry else "first", outcome, reason,
        )
        return _Pass2Attempt(
            decisions=[],
            reason=reason,
            outcome=outcome,
        )

    if not completion.complete:
        if completion.truncated:
            outcome: AttemptOutcome = "incomplete_length"
        elif completion.filtered:
            outcome = "incomplete_filtered"
        else:
            outcome = "incomplete_other"
        return unusable(
            outcome, completion.problem or "the provider did not finish the completion"
        )

    if not completion.text.strip():
        # Pass 2 does NOT get pass 1's leniency. Pass 1's answer is evidence
        # another pass can do without; pass 2's answer IS the decision, so a
        # body with nothing in it leaves every candidate undecided. It gets the
        # one corrective retry every other unusable reading gets, and fails the
        # chunk only if that retry is unusable too.
        return unusable(
            "incomplete_empty",
            f"empty completion (possible content filter) "
            f"({_chunk_label(chunk_index)}, pass 2)",
        )

    try:
        validation = validate_pass2_entries(
            completion.text,
            by_id,
            render=render,
            known_locations=known_locations,
            next_candidate_number=next_candidate_number,
        )
    except AIProviderError as exc:
        return unusable("unparseable", str(exc))

    usage.record_pass2_attempt(complete=True)
    unresolved = unresolved_candidates(validation.decisions, asked)

    problems: list[str] = []
    if validation.rejections:
        problems.append(f"{len(validation.rejections)} unusable entry/entries")
    if unresolved:
        problems.append(
            f"{len(unresolved)} of {len(asked)} candidate(s) received "
            f"no REDACT or PRESERVE decision"
        )

    return _Pass2Attempt(
        decisions=validation.decisions,
        reason="; ".join(problems) if problems else None,
        outcome="complete",
        rejections=validation.rejections,
        discoveries=validation.discoveries,
        voided=validation.voided,
        promotions=validation.promotions,
        unusable_discoveries=validation.unusable_discoveries,
        distrusted=validation.distrusted,
    )


def _merge_discoveries(*groups: list[Pass2Discovery]) -> list[Pass2Discovery]:
    """Concatenate discovery lists, dropping ones already carried.

    A retry re-reads the same excerpt, so it can legitimately return a finding
    the kept attempt already made. Two identical discoveries would write two
    identical spans; keeping one says the same thing.
    """
    merged: list[Pass2Discovery] = []
    seen: set[tuple] = set()
    for group in groups:
        for discovery in group:
            key = (
                discovery.text,
                discovery.action,
                discovery.category,
                tuple(discovery.locations),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(discovery)
    return merged


def _as_discovery(candidate: Pass2Candidate, decision: Pass2Decision) -> Pass2Discovery:
    """Turn a decided PROMOTED candidate back into the discovery it always was.

    A promotion is a bookkeeping device — it exists so an unusable finding can
    be re-asked BY ID — and this undoes it once the answer arrives. The span is
    then written by ``spans_from_discoveries``, which reads its text off the
    unit rather than from the model's quote, so a finding that crossed a table
    join is still written correctly.
    """
    return Pass2Discovery(
        text=candidate.text,
        category=decision.category,
        action=decision.action,
        coerced=decision.coerced,
        locations=list(candidate.locations),
    )


def _candidate_from_discovery(
    discovery: Pass2Discovery, render: RenderedChunk, candidate_id: str
) -> Pass2Candidate:
    """Give an accepted discovery an id, so a full re-ask cannot lose it.

    Used when a response has to be thrown away WHOLE — it answered about
    candidates that do not exist, so none of its decisions can be trusted. Its
    READING of the excerpt is a different matter: the span it found is still
    there, and asking about it by id is how the retry gets a chance to confirm
    it instead of the finding quietly disappearing with the response.
    """
    before, after = (
        _windows_at(render, discovery.locations[0]) if discovery.locations else ("", "")
    )
    return Pass2Candidate(
        candidate_id=candidate_id,
        text=discovery.text,
        category=discovery.category,
        recommendations=[{
            "sources": ["pass2"],
            "action": discovery.action,
            "category": discovery.category,
        }],
        locations=list(discovery.locations),
        before=before,
        after=after,
        promoted_from="discovery_undecided",
    )


@dataclass
class ChunkAdjudication:
    """One chunk's settled pass-2 outcome.

    ``decisions`` and ``discoveries`` become spans. ``unresolved`` is what a
    person has to look at: it is never turned into a decision, and nothing is
    written for it. ``attempts`` is 1 or 2 — the corrective retry is allowed
    once, and there is no third call.
    """

    decisions: list[Pass2Decision]
    discoveries: list[Pass2Discovery]
    unresolved: list[UnresolvedFinding]
    attempts: int


@dataclass
class LlmDetectionResult:
    """What the LLM stage produced for a whole document.

    ``spans`` are pass-2's decisions and its own findings. ``unresolved`` are
    the questions it could not close, carried out of the stage so the pipeline
    can put them on the result and a person can settle them.
    """

    spans: list[Span]
    unresolved: tuple[UnresolvedFinding, ...] = ()


@dataclass
class _ChunkResult:
    """One chunk worker's return value: spans, plus what it could not settle."""

    spans: list[Span]
    unresolved: list[UnresolvedFinding]


def _adjudicate(
    client: Any,
    cfg: RuntimeConfig,
    candidates: list[Pass2Candidate],
    chunk_index: int,
    total_chunks: int,
    usage: UsageRecorder,
    *,
    render: RenderedChunk,
    remediation: bool = False,
    ctx: RunContext | None = None,
) -> ChunkAdjudication:
    """Adjudicate one chunk's queue, with at most one corrective retry.

    THREE THINGS CAN BE WRONG WITH A PASS-2 RESPONSE, and they are not the same
    problem, so they do not get the same answer:

    1. IT IS NOT A READING — truncated, filtered, refused, empty, unparseable.
       Nothing in it may be believed, so the WHOLE queue is asked again. If the
       retry is not a reading either, the chunk has never been read by the pass
       that decides, and the document is abandoned with ``AIProviderError``
       rather than published on the strength of the deterministic rules alone.
    2. IT IS NOT TRACKING THE QUEUE — it answered about candidates that were
       never issued. Its decisions are not trusted (a model that invents ids is
       not carefully answering the ones it was given), so the whole queue is
       asked again — but its DISCOVERIES are promoted to candidates first, so a
       span it genuinely found in the excerpt is re-asked by id instead of
       vanishing with the response that mentioned it.
    3. IT IS A READING THAT LEFT THINGS OPEN — some candidate undecided, some id
       answered twice, some new finding unusable. Everything it got right is
       KEPT, and the retry is TARGETED: only the outstanding items, with the
       full excerpt still attached. Decide 67 of 70 and the second call carries
       3 candidates, not 70.

    WHAT SURVIVES RETRY EXHAUSTION IS A QUESTION, NOT A GUESS. After the one
    retry, anything still outstanding becomes an ``UnresolvedFinding``: it is
    not decided, not defaulted to PRESERVE, and not defaulted to REDACT. The
    text stays exactly as it was, whatever ordinary deterministic evidence
    covers it still applies, and the document comes back flagged for human
    review with the locations to look at. That is deliberate: the alternative to
    a person reading three spans is a machine silently inventing three answers.

    It applies ONLY to individual findings. It does not weaken the hard-policy
    tiers, the post-redaction scan, provider exhaustion, or case 1 above — a
    chunk with no usable reading at all still fails the document.

    ``remediation`` is passed through to every attempt this makes. It is the ONE
    difference between adjudicating a chunk of the incoming document and
    re-adjudicating a chunk of the redacted one, and it reaches only the
    instruction line of the user message.
    """
    label = _chunk_label(chunk_index, total_chunks)
    known_locations = frozenset(
        location for c in candidates for location in c.locations
    )
    next_number = _next_candidate_number({c.candidate_id: c for c in candidates})

    first = _pass2_attempt(
        client, cfg, candidates, chunk_index, usage,
        render=render, known_locations=known_locations, retry=False,
        next_candidate_number=next_number, remediation=remediation, ctx=ctx,
    )
    accepted: dict[str, Pass2Decision] = {d.candidate_id: d for d in first.decisions}

    def abandon(second: _Pass2Attempt) -> AIProviderError:
        """The chunk was never read, or never answered about. Name which."""
        headline = (
            "pass 2 produced no usable reading after one retry"
            if not second.usable
            else "pass 2 never tracked its queue, after one retry"
        )
        return AIProviderError(
            f"{headline} ({_chunk_label(chunk_index)}): "
            f"first attempt: {first.reason}; retry: {second.reason}"
        )

    def settle(
        kept: dict[str, Pass2Decision],
        kept_discoveries: list[Pass2Discovery],
        promoted: list[Pass2Candidate],
        final: _Pass2Attempt | None,
        carried: list[UnusableDiscovery],
        attempts: int,
    ) -> ChunkAdjudication:
        """Combine what was kept with what the retry settled, and name the rest."""
        merged = dict(kept)
        # A candidate voided by EITHER attempt and still unresolved is
        # reported as duplicated: that is what actually happened to it, and
        # it is a different thing for a reviewer than a plain omission.
        voided_ids: set[str] = set(first.voided)
        final_voided: list[str] = []
        final_promotions: list[Pass2Candidate] = []
        final_unusable: list[UnusableDiscovery] = []
        final_discoveries: list[Pass2Discovery] = []
        if final is not None:
            final_voided = final.voided
            voided_ids |= set(final_voided)
            final_promotions = final.promotions
            final_unusable = final.unusable_discoveries
            if not final.distrusted:
                merged.update({d.candidate_id: d for d in final.decisions})
                final_discoveries = final.discoveries

        decisions = [
            merged[c.candidate_id] for c in candidates if c.candidate_id in merged
        ]
        discoveries = _merge_discoveries(
            kept_discoveries,
            final_discoveries,
            [
                _as_discovery(candidate, merged[candidate.candidate_id])
                for candidate in promoted
                if candidate.candidate_id in merged
            ],
        )

        unresolved: list[UnresolvedFinding] = []
        for candidate in candidates:
            if candidate.candidate_id in merged:
                continue
            unresolved.append(UnresolvedFinding(
                chunk_index=chunk_index,
                kind=(
                    "candidate_duplicated"
                    if candidate.candidate_id in voided_ids
                    else "candidate_undecided"
                ),
                category=candidate.category,
                locations=tuple(candidate.locations),
                candidate_id=candidate.candidate_id,
                detail="no final decision after the corrective retry",
            ))
        for candidate in promoted:
            if candidate.candidate_id in merged:
                continue
            unresolved.append(UnresolvedFinding(
                chunk_index=chunk_index,
                kind=(
                    "discovery_conflicting"
                    if candidate.candidate_id in voided_ids
                    else (candidate.promoted_from or "discovery_undecided")
                ),
                category=candidate.category,
                locations=tuple(candidate.locations),
                candidate_id=candidate.candidate_id,
                detail="a pass-2 finding was re-asked and not settled",
            ))
        for candidate in final_promotions:
            # Raised by the RETRY, so there is no third call to settle it in.
            unresolved.append(UnresolvedFinding(
                chunk_index=chunk_index,
                kind=candidate.promoted_from or "discovery_malformed",
                category=candidate.category,
                locations=tuple(candidate.locations),
                candidate_id=candidate.candidate_id,
                detail="a pass-2 finding from the corrective retry was unusable",
            ))
        seen_unusable: set[tuple[str, str | None, str]] = set()
        for entry in list(carried) + list(final_unusable):
            # The retry re-reads the same excerpt, so it can report the same
            # unquotable finding again. That is one finding, not two.
            key = (entry.kind, entry.category, entry.detail)
            if key in seen_unusable:
                continue
            seen_unusable.add(key)
            unresolved.append(UnresolvedFinding(
                chunk_index=chunk_index,
                kind=entry.kind,
                category=entry.category,
                locations=(),
                detail=entry.detail,
            ))

        if unresolved:
            logger.warning(
                "%s: pass 2 left %d finding(s) unresolved after the corrective "
                "retry; they are retained for human review",
                label, len(unresolved),
            )
        return ChunkAdjudication(decisions, discoveries, unresolved, attempts)

    # --- the first attempt settled everything -------------------------------
    if first.reason is None:
        return ChunkAdjudication(
            decisions=[accepted[c.candidate_id] for c in candidates],
            discoveries=first.discoveries,
            unresolved=[],
            attempts=1,
        )

    # --- case 1: not a reading ---------------------------------------------
    if not first.usable:
        logger.warning(
            "%s: pass 2 was not a usable reading (%s); asking the whole queue "
            "again (%d candidate(s))",
            label, first.reason, len(candidates),
        )
        if ctx is not None:
            ctx.deadline.check("llm pass 2 corrective retry")
        second = _pass2_attempt(
            client, cfg, candidates, chunk_index, usage,
            render=render, known_locations=known_locations, retry=True,
            previous=first, next_candidate_number=next_number, kept_previous=False,
            remediation=remediation, ctx=ctx,
        )
        if not second.usable or second.distrusted:
            raise abandon(second)
        return settle({}, [], [], second, [], attempts=2)

    # --- case 2: a reading that was not tracking the queue ------------------
    if first.distrusted:
        promoted = list(first.promotions)
        number = next_number + len(promoted)
        for discovery in first.discoveries:
            promoted.append(_candidate_from_discovery(discovery, render, f"C{number}"))
            number += 1
        logger.warning(
            "%s: pass 2 rejected (%s); it answered ids this queue never issued, "
            "so the whole queue is being asked again (%d candidate(s), %d "
            "promoted finding(s))",
            label, first.reason, len(candidates), len(promoted),
        )
        if ctx is not None:
            ctx.deadline.check("llm pass 2 corrective retry")
        second = _pass2_attempt(
            client, cfg, candidates + promoted, chunk_index, usage,
            render=render,
            known_locations=known_locations | frozenset(
                location for c in promoted for location in c.locations
            ),
            retry=True, previous=first, next_candidate_number=number,
            kept_previous=False, remediation=remediation, ctx=ctx,
        )
        if not second.usable or second.distrusted:
            raise abandon(second)
        return settle({}, [], promoted, second, first.unusable_discoveries, attempts=2)

    # --- case 3: a reading that left things open ----------------------------
    promoted = list(first.promotions)
    queue = [c for c in candidates if c.candidate_id not in accepted] + promoted
    if not queue and not first.unusable_discoveries:
        # Every rejection was already accounted for; nothing is outstanding.
        return settle(accepted, first.discoveries, promoted, None, [], attempts=1)

    logger.warning(
        "%s: pass 2 rejected (%s); retrying %d of %d candidate(s) plus %d "
        "promoted finding(s), keeping %d already decided",
        label, first.reason, len(queue) - len(promoted), len(candidates),
        len(promoted), len(accepted),
    )
    if ctx is not None:
        ctx.deadline.check("llm pass 2 corrective retry")
    second = _pass2_attempt(
        client, cfg, queue, chunk_index, usage,
        render=render,
        known_locations=known_locations | frozenset(
            location for c in promoted for location in c.locations
        ),
        retry=True, previous=first,
        next_candidate_number=next_number + len(promoted), kept_previous=True,
        remediation=remediation, ctx=ctx,
    )
    if not second.usable:
        # The FIRST attempt was a reading, so the chunk has been read; only the
        # correction failed. Keep what it decided and leave the rest for review.
        logger.warning(
            "%s: the corrective retry was not a usable reading (%s); keeping the "
            "first reading and leaving %d item(s) for human review",
            label, second.reason, len(queue),
        )
        return settle(
            accepted, first.discoveries, promoted, None,
            first.unusable_discoveries, attempts=2,
        )
    return settle(
        accepted, first.discoveries, promoted, second,
        first.unusable_discoveries, attempts=2,
    )


def run_llm_detection(
    document: DocumentData,
    deterministic_spans: list[Span],
    review_hints: list[Span],
    client: Any,
    cfg: RuntimeConfig,
    policy: PolicySettings,
    usage: UsageRecorder,
    ctx: RunContext | None = None,
    regions: frozenset[str] = frozenset(),
) -> LlmDetectionResult:
    """Run the mandatory two-pass LLM detection over the whole document.

    Chunks are processed CONCURRENTLY on a thread pool of
    ``cfg.llm_concurrency`` workers (the OpenAI client is thread-safe; the core
    stays synchronous, and so is the HTTP request path — there is no asyncio in
    the application at all). Within each chunk the order is strict: blind pass 1
    discovers candidates from the chunk text, then those candidates are merged
    with the deterministic ones into a queue, and pass 2 adjudicates the queue
    against the SAME chunk text — decided by id where a candidate exists, and
    reported as a ``NEW`` finding where one does not.

    ``policy`` is what separates a decision from a recommendation here:
    deterministic HARD PRESERVE spans are filtered out of the queue up front and
    never reach any chunk's CANDIDATES block, so neither pass is offered one to
    adjudicate. Everything else — an ordinary PRESERVE, a REDACT, a REVIEW hint,
    a pass-1 proposal — is queued.

    WHEN PASS 2 MAY BE SKIPPED is exactly one case: pass 1 COMPLETED, returned a
    usable answer, and found nothing, and the deterministic rules found nothing
    either. There is then no question to ask and no reason to believe one was
    missed, because a reading of the whole chunk has already said so.

    Any other combination runs pass 2, INCLUDING a chunk with an empty queue
    whose pass 1 was unusable. That case is the one this rule exists for: a
    truncated or filtered pass 1 tells us nothing about the chunk, and if the
    rules also matched nothing then NOBODY has read it. Skipping pass 2 there —
    which is what this code used to do — released such a chunk unexamined, and
    the cost of getting it wrong is a name published in a decision.

    Results are collected in chunk order, so the returned spans are
    deterministic regardless of completion order. The first chunk failure
    cancels not-yet-started chunks and aborts the run. Only pass-2 spans are
    collected and returned — its decisions on the queue, and its own findings —
    alongside whatever it could not settle.
    """
    # A context of its own when nobody supplied one, so a direct caller — a
    # test, a script — still runs under a budget rather than none at all.
    ctx = ctx or RunContext.start(
        cfg.document_deadline_s, document_id=document.document_id
    )
    chunks = split_into_chunks(document, cfg.chunk_size_chars)
    total = len(chunks)
    if total == 0:
        return LlmDetectionResult(spans=[], unresolved=())
    if total > cfg.limits.max_chunks:
        # Checked before the pool starts, so an oversized document costs no
        # provider calls at all. This is the bound the character limit does
        # not give: every table becomes its own chunk regardless of size, so
        # many small tables are many chunks from very little text.
        raise ResourceLimitExceededError(
            f"document splits into {total} chunks; the limit is "
            f"{cfg.limits.max_chunks}",
            code="TOO_MANY_CHUNKS",
        )

    # Hard preserves are authoritative and are dropped from the queue once, for
    # the whole document, rather than per chunk: they are not candidates, so no
    # pass ever sees one as a question.
    adjudicable_spans = [s for s in deterministic_spans if not is_hard_preserve(s, policy)]
    withheld = len(deterministic_spans) - len(adjudicable_spans)
    if withheld:
        logger.info(
            "LLM detection: %d hard-preserve span(s) withheld from the pass-2 queue",
            withheld,
        )

    def _process_chunk(chunk_index: int, chunk: Chunk) -> _ChunkResult:
        """Run pass 1 then pass 2 for one chunk and return its decided spans."""
        start_time = time.time()
        # The cooperative half of cancellation. A worker cannot be killed, so
        # it asks — here, and again before pass 2 — whether the document it
        # belongs to is still wanted. A chunk that has not started yet never
        # starts; one already in a provider call ends when that call's own
        # timeout, itself cut to the remaining budget, runs out.
        if ctx.deadline.done:
            raise DocumentTimeoutError(f"llm {_chunk_label(chunk_index, total)}")
        # Rendered once and shared: the text pass 1 reads, the text pass 2 reads,
        # and the map that writes pass 2's own findings back to their units. One
        # rendering means those three can never disagree about what the chunk is.
        render = chunk.render()

        # Pass 1 — blind discovery. The ONLY input is the chunk's own text.
        #
        # Nothing derived from the deterministic stage is read, or even brought
        # into scope, before this call returns: no rule spans, no REVIEW hints,
        # no hard-preserve knowledge, no prior candidates, no resolver output.
        # The two detection paths have to stay independent for their agreement
        # to mean anything, so the deterministic side of the chunk is not
        # fetched until pass 1 has finished speaking. Keep it that way — any
        # `adjudicable_spans` / `review_hints` read hoisted above this call
        # would put a leak one keystroke away.
        logger.info(
            "%s: pass 1 (blind reading) %s",
            _chunk_label(chunk_index, total), ctx.tag(),
        )
        completion1 = _call(
            client, cfg, SYSTEM_PROMPT_PASS1, build_pass1_message(render.text),
            chunk_index, 1, usage, ctx=ctx,
        )
        # Unusable pass-1 output degrades to no recommendations; it never fails
        # the chunk. Provider failures have already raised out of _call above.
        reading = read_pass1(completion1)
        usage.record_pass1(reading.outcome)
        if reading.degraded:
            logger.warning(
                "%s: pass 1 %s (%s) — continuing with no pass-1 recommendations; "
                "pass 2 will read the whole chunk even if the queue is empty %s",
                _chunk_label(chunk_index, total), reading.outcome, reading.detail,
                ctx.tag(),
            )
        else:
            logger.info(
                "%s: pass 1 %s — %s %s",
                _chunk_label(chunk_index, total), reading.outcome, reading.detail,
                ctx.tag(),
            )
        findings = reading.findings

        # --- the two independent paths meet here, and not before ------------
        unit_ids = chunk.unit_ids
        chunk_deterministic = [s for s in adjudicable_spans if s.unit_id in unit_ids]
        chunk_hints = [s for s in review_hints if s.unit_id in unit_ids]

        # The decision queue: rules + pass 1, keyed by location, hard
        # preserves already absent (see adjudicable_spans).
        candidates = build_pass2_candidates(
            chunk, chunk_deterministic, chunk_hints, findings, render
        )

        if not candidates and not reading.degraded:
            # The ONE case where nobody needs to read this chunk again: a
            # completed pass 1 found nothing and so did the rules. A degraded
            # pass 1 does not qualify, however empty the queue is — see the
            # function docstring.
            usage.record_pass2(PASS2_SKIPPED)
            logger.info(
                "%s: pass2=skipped reason=pass1_success_no_candidates %s (%.1fs)",
                _chunk_label(chunk_index, total), ctx.tag(),
                time.time() - start_time,
            )
            return _ChunkResult(spans=[], unresolved=[])

        candidates_by_id = {c.candidate_id: c for c in candidates}

        # Pass 2 — adjudication over the whole chunk. The response must be a
        # complete reading AND account for every candidate; one corrective retry
        # for whatever is missing, then the remainder goes to human review.
        logger.info(
            "%s: pass 2 (adjudicating %d candidate(s) against the full chunk%s) %s",
            _chunk_label(chunk_index, total), len(candidates),
            "" if candidates else " — empty queue, reading for new findings only",
            ctx.tag(),
        )
        ctx.deadline.check(f"llm pass 2 ({_chunk_label(chunk_index, total)})")
        try:
            adjudication = _adjudicate(
                client, cfg, candidates, chunk_index, total, usage,
                render=render, ctx=ctx,
            )
        except AnonymizerError as exc:
            usage.record_pass2(PASS2_FAILED)
            logger.error(
                "%s: pass2=failed error=%s code=%s %s",
                _chunk_label(chunk_index, total), type(exc).__name__,
                exc.code, ctx.tag(),
            )
            raise
        usage.record_pass2(PASS2_EXECUTED, retried=adjudication.attempts > 1)

        units_by_id = {u.unit_id: u for u in chunk.units}
        chunk_spans = spans_from_decisions(
            adjudication.decisions, candidates_by_id, units_by_id, regions
        )
        discovered_spans = spans_from_discoveries(
            adjudication.discoveries, units_by_id, regions
        )
        if discovered_spans:
            # Counts only. Worth a line of its own: these are the redactions the
            # queue could not have produced, so a document where the number is
            # persistently high is one whose rules are behind its content.
            logger.info(
                "%s: pass 2 added %d span(s) from %d finding(s) nobody proposed",
                _chunk_label(chunk_index, total),
                len(discovered_spans), len(adjudication.discoveries),
            )
        chunk_spans.extend(discovered_spans)
        logger.info(
            "%s: pass2=executed attempts=%d decided=%d/%d discoveries=%d "
            "unresolved=%d spans=%d %s (%.1fs)",
            _chunk_label(chunk_index, total), adjudication.attempts,
            len(adjudication.decisions), len(candidates),
            len(adjudication.discoveries), len(adjudication.unresolved),
            len(chunk_spans), ctx.tag(), time.time() - start_time,
        )
        return _ChunkResult(spans=chunk_spans, unresolved=adjudication.unresolved)

    workers = min(max(1, int(cfg.llm_concurrency)), total)
    logger.info("LLM detection: %d chunks, %d workers", total, workers)

    # RESULTS ARE STORED BY INDEX, BUT WAITED FOR BY COMPLETION.
    #
    # Awaiting the futures in submission order means a failure in chunk 2 is
    # not noticed until chunk 1 finishes, and every queued chunk in between
    # keeps spending provider calls on a document that is already lost. So
    # the wait is on whichever finishes first, and the assembly is by
    # original index — the output stays deterministic either way.
    results: list[_ChunkResult | None] = [None] * total
    pool = ThreadPoolExecutor(max_workers=workers)
    index_of: dict[Future, int] = {}
    try:
        for index, chunk in enumerate(chunks):
            index_of[pool.submit(_process_chunk, index, chunk)] = index
        pending = set(index_of)
        while pending:
            done, pending = wait(
                pending,
                timeout=ctx.deadline.remaining(),
                return_when=FIRST_EXCEPTION,
            )
            if not done:
                # Nothing finished in the time that was left.
                ctx.deadline.check("llm")
                continue
            for future in done:
                results[index_of[future]] = future.result()
    except BaseException:
        # Tell the workers to stop at their next checkpoint, drop everything
        # still queued, and do not wait for the in-flight ones: each is
        # already bounded by the remaining budget, and the caller should not
        # be held while they wind down.
        ctx.deadline.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        logger.warning(
            "llm_run_aborted %s pending=%d", ctx.tag(), len(index_of) - sum(
                1 for result in results if result is not None
            ),
        )
        raise
    pool.shutdown(wait=True)

    all_spans: list[Span] = []
    unresolved: list[UnresolvedFinding] = []
    for result in results:
        if result is None:  # pragma: no cover - every future is awaited above
            continue
        all_spans.extend(result.spans)
        unresolved.extend(result.unresolved)
    return LlmDetectionResult(spans=all_spans, unresolved=tuple(unresolved))


# ---------------------------------------------------------------------------
# Post-redaction remediation: pass 2 again, over the document it produced
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RemediationResult:
    """What one post-redaction re-adjudication produced.

    ``spans`` are pass-2's decisions and its own findings, in the coordinates of
    the REDACTED document, ready for the ordinary resolver. ``unresolved`` is
    what it still could not settle, carried out so a person is told rather than
    a default invented.

    The other two fields exist for the single log line the pipeline writes about
    this stage. They are an id list and a number: no document text, no matched
    value, nothing derived from either.
    """

    spans: list[Span]
    unresolved: tuple[UnresolvedFinding, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    pass2_calls: int = 0


def run_pass2_remediation(
    document: DocumentData,
    residual_spans: list[Span],
    client: Any,
    cfg: RuntimeConfig,
    usage: UsageRecorder,
    ctx: RunContext | None = None,
    regions: frozenset[str] = frozenset(),
) -> RemediationResult:
    """Re-adjudicate the post-redaction audit's findings. PASS 2 ONLY.

    ``document`` is the parse of the ALREADY-REDACTED bytes, and
    ``residual_spans`` are the audit's findings as located proposals in it —
    ``(unit_id, start, end)`` exactly as the scan found them, never a string to
    be searched for afterwards. That is the whole reason the audit computes
    coordinates at all: two identical values in two places are two residuals,
    and a text search could not say which one a finding meant.

    PASS 1 IS NOT RUN, and this is not an omission. Pass 1 is blind DISCOVERY,
    and there is nothing left to discover blind: the audit has already read the
    output and named the slices in question, and pass 2 reads the whole excerpt
    for itself anyway — which is what still lets it report something the audit
    did not mention. Running pass 1 again would buy recommendations for spans
    that already have one, at the price of a second call per chunk.

    Everything else is the ordinary machinery, called as it stands:
    ``split_into_chunks`` cuts the redacted document, ``build_pass2_candidates``
    turns the residuals into a queue (labelled ``postcheck``, so the model is
    told what proposed them), and ``_adjudicate`` makes the call with its usual
    validation, its usual ONE corrective retry, and its usual refusal to believe
    a response that never finished. ``usage`` and ``ctx`` are the DOCUMENT'S
    own recorder and deadline, so these calls are counted in the same totals and
    bounded by the same clock as every call before them.

    Chunks are adjudicated one after another rather than on a pool: only the
    chunks that actually hold a residual are visited, so the work is a small
    fraction of the main stage's and the ordering makes the log readable.

    Returns the spans for the ordinary resolver. Raises exactly what the main
    stage raises — ``AIProviderError`` for a chunk pass 2 never read,
    ``DocumentTimeoutError`` when the budget is gone — so a failure here is a
    failure of the document, never a half-written file.
    """
    ctx = ctx or RunContext.start(
        cfg.document_deadline_s, document_id=document.document_id
    )
    if not residual_spans:
        return RemediationResult(spans=[])

    chunks = split_into_chunks(document, cfg.chunk_size_chars)
    total = len(chunks)
    chunk_of_unit: dict[str, int] = {}
    for index, chunk in enumerate(chunks):
        for unit_id in chunk.unit_ids:
            chunk_of_unit[unit_id] = index

    queued: dict[int, list[Span]] = {}
    for span in residual_spans:
        chunk_index = chunk_of_unit.get(span.unit_id)
        if chunk_index is None:
            # A residual in a unit no chunk holds — an empty paragraph, which
            # split_into_chunks skips. There is nothing to show the model as
            # context, so there is nothing to ask.
            logger.warning(
                "postcheck_remediation: a residual names a unit no chunk holds; "
                "it was not put to pass 2"
            )
            continue
        queued.setdefault(chunk_index, []).append(span)

    spans: list[Span] = []
    unresolved: list[UnresolvedFinding] = []
    candidate_ids: list[str] = []
    calls = 0

    for index in sorted(queued):
        chunk = chunks[index]
        render = chunk.render()
        # The residuals enter as REVIEW hints: located proposals nobody has
        # decided. Same builder, same grouping rule, same context windows as an
        # ordinary queue — only the source label differs.
        candidates = build_pass2_candidates(
            chunk, [], queued[index], [], render, source="postcheck"
        )
        if not candidates:
            continue
        candidate_ids.extend(c.candidate_id for c in candidates)
        ctx.deadline.check(
            f"postcheck remediation ({_chunk_label(index, total)})"
        )
        logger.info(
            "%s: postcheck remediation pass 2 (%d candidate(s)) %s",
            _chunk_label(index, total), len(candidates), ctx.tag(),
        )
        adjudication = _adjudicate(
            client, cfg, candidates, index, total, usage,
            render=render, remediation=True, ctx=ctx,
        )
        calls += adjudication.attempts
        units_by_id = {u.unit_id: u for u in chunk.units}
        spans.extend(spans_from_decisions(
            adjudication.decisions,
            {c.candidate_id: c for c in candidates},
            units_by_id,
            regions,
        ))
        spans.extend(spans_from_discoveries(
            adjudication.discoveries, units_by_id, regions
        ))
        unresolved.extend(adjudication.unresolved)

    return RemediationResult(
        spans=spans,
        unresolved=tuple(unresolved),
        candidate_ids=tuple(candidate_ids),
        pass2_calls=calls,
    )


__all__ = [
    "Chunk",
    "RenderedChunk",
    "Completion",
    "Pass1Reading",
    "read_pass1",
    "Pass2Candidate",
    "Pass2Decision",
    "Pass2Discovery",
    "Pass2Validation",
    "UnusableDiscovery",
    "ChunkAdjudication",
    "LlmDetectionResult",
    "RemediationResult",
    "split_into_chunks",
    "parse_pass1_findings",
    "build_pass2_candidates",
    "locate_in_rendered",
    "validate_pass2_entries",
    "unresolved_candidates",
    "spans_from_decisions",
    "spans_from_discoveries",
    "run_llm_detection",
    "run_pass2_remediation",
]
