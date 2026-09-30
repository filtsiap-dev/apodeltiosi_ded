"""Mandatory post-redaction audit.

Scans REDACTED output for residual leaks. ``anonymize_document`` calls this on
every document, ONCE, after ``write_redacted_docx`` and before any caller can
save or return the bytes. Nothing here contacts the network or writes anything.

WHAT THE PIPELINE DOES WITH A FINDING depends on whether it points at document
TEXT. A finding that does carries a :class:`ResidualSpan` — the exact
``(unit_id, start, end)`` slice of the scanned output it was found at — and the
pipeline puts that slice to LLM pass 2 as an ordinary candidate rather than
failing the document on the spot. A finding with no span keeps the handling it
always had: package- and structure-level problems (macros, tracked changes,
comments, embedded objects) and the over-redaction reports, where there is
nothing for a language model to decide and a HIGH still aborts the document
with ``ResidualPIIError``.

THE SPAN IS COMPUTED HERE, WHERE THE MATCH IS. It is never re-derived later by
searching the document for the matched string: two identical values in two
places are two different residuals, and a search cannot tell which one a finding
meant. See ``REMEDIABLE_CATEGORIES`` for exactly which kinds carry one.

``detail`` never echoes matched document text, except for ``wrong_placeholder``
and ``over_redaction`` where the match cannot be PII by construction. The
matched text DOES live on ``ResidualSpan.text``, because pass 2 cannot be asked
about a span without being shown it; it is kept out of ``repr`` for that reason,
and this module does not log.
"""

from __future__ import annotations

import bisect
import io
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

from lxml import etree

from anonymizer.config import FileConfig
from anonymizer.models import DocumentData, SpanCategory
from anonymizer.docx_engine import parse_docx, validate_docx_bytes
from anonymizer.postcheck_support import (
    qa_patterns,
    _label_counts,
    _residual_property_ids,
    _WRONG_PLACEHOLDER_RE,
    _ELLIPSIS_RUN_RE,
    _CASE_REF_LEAK_RE,
    _BENEFICIARY_LEAK_RE,
    _PARTIAL_STAR_RESIDUE_RE,
    _PERSON_LEAK_RE,
    _OVER_REDACT_RE,
    _INVOICE_COLUMN_HEADERS,
    _afm_checksum_ok,
    _iban_checksum_ok,
    _normalized_greek_phone,
    _looks_like_official_contact_phone,
)

_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_CP_NS = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
_DC_NS = "{http://purl.org/dc/elements/1.1/}"

# Alphanumeric token longer than 12 characters (Unicode word chars, no underscore run).
_LONG_TOKEN_RE = re.compile(r"[^\W_]{13,}", re.UNICODE)

# The parts that carry macro code. Named here rather than imported from
# anonymizer.word_formats ON PURPOSE, for the same reason this module keeps
# its own copies of the AFM and IBAN checksums: it is the INDEPENDENT audit of
# the output, and an auditor that imports its expectations from the code it is
# auditing cannot catch that code being wrong about them.
_MACRO_PARTS = frozenset({"word/vbaProject.bin", "word/vbaData.xml"})


# WHICH FINDING KINDS CAN BE PUT BACK TO PASS 2, and what each one is called
# when it gets there. A kind in this table points at a run of document TEXT that
# appears to have survived redaction; the category is what the plan records if
# the model answers with a label outside the vocabulary.
#
# Every kind NOT in this table keeps its existing handling, and the omissions
# are deliberate rather than incidental:
#
#   * ``wrong_placeholder`` and ``ellipsis_residue`` are residue of OUR OWN
#     write path — a stale glyph, a placeholder from a code path that should not
#     exist. They are bug signatures, not personal data somebody has to judge,
#     and asking a model about one would replace a loud failure with a quiet
#     opinion;
#   * ``over_redaction`` and ``label_removed`` report the opposite problem, text
#     that is MISSING. Redaction is destructive and this scan runs after it, so
#     there is nothing left to restore;
#   * ``nonempty_comments``, ``tracked_change``, ``hidden_text``,
#     ``macro_part_survived``, ``embedded_object`` and
#     ``long_token_header_footer`` are package- and structure-level: each names a
#     PART, not a slice of text, and no decision about document text fixes any
#     of them;
#   * ``table_invoice_leak`` names a CELL, and a cell is not a value. The check
#     fires on "this cell under an invoice header still holds digits", which is
#     the right thing to warn about and the wrong thing to blank: a cell reading
#     "ΤΙΜ. 190 σειρά Β εξοφλήθηκε κανονικά" would lose the payment status along
#     with the identifier. A decision carries an id, an action and a category —
#     never offsets — so pass 2 cannot narrow a candidate it is answering, and
#     segmenting the cell here would be the auditor guessing where the value
#     ends. It stays the non-blocking warning it always was; the invoice
#     identifier itself is the detectors' and pass 2's job, and pass 2 still
#     reads the whole table.
REMEDIABLE_CATEGORIES: dict[str, SpanCategory] = {
    "residual_afm": "AFM",
    "afm_shape": "AFM",
    "residual_amka": "AMKA",
    "residual_iban": "IBAN",
    "residual_email": "EMAIL",
    "phone_shape": "PHONE",
    # A 9-11 digit run that is neither an AFM length, an AMKA, nor a Greek
    # phone. Nothing here knows what it identifies, which is exactly why it is
    # worth a second reading.
    "digit_run": "TRANSACTION_ID",
    "case_ref_leak": "CASE_REF_NUMBER",
    "beneficiary_leak": "PRIVATE_BENEFICIARY",
    "partial_star_residue": "FISCAL_DEVICE_ID",
    "person_name_leak": "POSSIBLE_PERSON",
    "residual_property_id": "PROPERTY_ID",
}


@dataclass(frozen=True)
class ResidualSpan:
    """Where a residual is, in the parse of the bytes this scan ran on.

    ``unit_id``/``start``/``end`` are coordinates in ``parse_docx`` of the
    REDACTED output — the document the remediation pass reads and the one any
    further redaction is written to. They are exact, and they are CARRIED rather
    than recomputed: the same value in two places gives two residuals with two
    slices, and nothing downstream has to guess which of them a finding meant.

    ``text`` is the document's own slice at those coordinates, because pass 2
    cannot be asked about a span without being shown it. It is kept OUT of
    ``repr`` so that logging, asserting on or printing a finding cannot spill
    it; every other field here is an id, an offset or a category name.
    """

    unit_id: str
    start: int
    end: int
    text: str = field(repr=False)
    category: SpanCategory = "POSSIBLE_PERSON"


@dataclass(frozen=True)
class PostcheckFinding:
    severity: Literal["HIGH", "MEDIUM"]
    kind: str
    location: str
    detail: str
    #: The exact slice this finding names, when it names one — None for every
    #: package-level finding and for the over-redaction reports (see
    #: ``REMEDIABLE_CATEGORIES``). A finding WITH a span is one the pipeline can
    #: put back to pass 2; a HIGH finding without one still stops the document.
    span: "ResidualSpan | None" = None


@dataclass
class PostcheckSummary:
    clean: bool
    findings_total: int
    by_severity: dict[str, int]
    by_kind: dict[str, int]
    findings: list[PostcheckFinding]

    @property
    def remediable(self) -> list[PostcheckFinding]:
        """The findings that name a slice of document text, in scan order.

        These are what the pipeline puts to LLM pass 2. Everything else keeps
        the handling it has always had.
        """
        return [f for f in self.findings if f.span is not None]

    @property
    def blocking(self) -> list[PostcheckFinding]:
        """The HIGH findings nothing downstream can act on.

        A HIGH that names a text slice is a question for pass 2; a HIGH that
        does not is the end of the document, exactly as before.
        """
        return [f for f in self.findings if f.severity == "HIGH" and f.span is None]


def _is_text_part(name: str) -> bool:
    """Return True when ``name`` is a DOCX part that carries body text worth scanning (document, headers, footers, footnotes, endnotes)."""
    return (
        name == "word/document.xml"
        or (name.startswith("word/header") and name.endswith(".xml"))
        or (name.startswith("word/footer") and name.endswith(".xml"))
        or name in ("word/footnotes.xml", "word/endnotes.xml")
    )


def _is_header_footer_part(name: str) -> bool:
    """Return True when ``name`` is a header or footer XML part in the DOCX package."""
    return (
        name.startswith("word/header") or name.startswith("word/footer")
    ) and name.endswith(".xml")


def _overlaps(span: tuple[int, int], ranges: list[tuple[int, int]]) -> bool:
    """Return True when the ``(start, end)`` span overlaps any range in ``ranges``."""
    s, e = span
    for rs, re_ in ranges:
        if s < re_ and rs < e:
            return True
    return False


def scan_redacted_docx_bytes(
    redacted_bytes: bytes,
    files: FileConfig,
    source_document: "DocumentData | None" = None,
) -> PostcheckSummary:
    """Audit redacted DOCX bytes for residual Greek PII leaks (AFM/AMKA/IBAN, emails, phones, names, placeholder and metadata residue) and package-level issues, honoring ``files`` preservation rules. Return a PostcheckSummary with severity- and kind-bucketed findings."""
    validate_docx_bytes(redacted_bytes)
    document = parse_docx(redacted_bytes, "postcheck")

    findings: list[PostcheckFinding] = []
    units = document.text_units

    # Joined text + parallel cumulative-offset list (one entry per unit start).
    parts: list[str] = []
    offsets: list[int] = []
    cursor = 0
    for u in units:
        offsets.append(cursor)
        parts.append(u.normalized_text)
        cursor += len(u.normalized_text) + 1  # +1 for the "\n" join separator
    text = "\n".join(parts)

    def locate(pos: int) -> str:
        if not units:
            return "unknown"
        idx = bisect.bisect_right(offsets, pos) - 1
        idx = max(0, min(idx, len(units) - 1))
        u = units[idx]
        return f"{u.part_name}:{u.unit_id}"

    def slice_at(kind: str, start: int, end: int) -> ResidualSpan | None:
        """The exact text-unit slice a match sits in, or None when it has none.

        The inverse of the join above: the cumulative offsets say which unit a
        position fell in, and subtracting that unit's own offset turns a
        position in the joined text back into a position in the unit. Computing
        it HERE is the whole point — the alternative, handing the matched string
        downstream and searching for it later, cannot tell two identical values
        apart.

        None for a kind nothing downstream can act on, and None for a match that
        runs past its unit into the ``"\n"`` joining it to the next one: that
        match belongs to no single unit, so there is nowhere exact to write a
        decision, and it stays a warning and nothing more.
        """
        category = REMEDIABLE_CATEGORIES.get(kind)
        if category is None or not units or end <= start:
            return None
        index = bisect.bisect_right(offsets, start) - 1
        if not 0 <= index < len(units):
            return None
        unit = units[index]
        local_start = start - offsets[index]
        local_end = end - offsets[index]
        if local_start < 0 or local_end > len(unit.normalized_text):
            return None
        # Surrounding whitespace belongs to the sentence, not to the value. The
        # phone pattern in particular absorbs the spaces on either side of a
        # number, and this is a WRITE BOUNDARY now: a span is what pass 2 is
        # shown and what a REDACT blanks, so it starts and ends on the value.
        while local_start < local_end and unit.normalized_text[local_start].isspace():
            local_start += 1
        while local_end > local_start and unit.normalized_text[local_end - 1].isspace():
            local_end -= 1
        if local_start >= local_end:
            return None
        return ResidualSpan(
            unit_id=unit.unit_id,
            start=local_start,
            end=local_end,
            text=unit.normalized_text[local_start:local_end],
            category=category,
        )

    def residual(
        severity: Literal["HIGH", "MEDIUM"],
        kind: str,
        start: int,
        end: int,
        detail: str,
        *,
        at: int | None = None,
    ) -> PostcheckFinding:
        """A finding for the value at ``[start, end)``, carrying that slice.

        ``at`` is where the human-readable location is read from when it differs
        from the value's own start — the CUE, for the checks that match a label
        and capture what follows it, so the reported location does not move.
        """
        return PostcheckFinding(
            severity,
            kind,
            locate(start if at is None else at),
            detail,
            slice_at(kind, start, end),
        )

    amka_ranges: list[tuple[int, int]] = []
    phone_ranges: list[tuple[int, int]] = []

    # --- Text checks -------------------------------------------------------
    for m in qa_patterns["AFM"].finditer(text):
        value = m.group(1)
        if _afm_checksum_ok(value):
            findings.append(
                residual("HIGH", "residual_afm", m.start(1), m.end(1),
                         "valid-checksum 9-digit AFM survives")
            )
        else:
            findings.append(
                residual("MEDIUM", "afm_shape", m.start(1), m.end(1),
                         "9-digit AFM-shaped run survives")
            )

    for m in qa_patterns["AMKA"].finditer(text):
        amka_ranges.append((m.start(1), m.end(1)))
        findings.append(
            residual("HIGH", "residual_amka", m.start(1), m.end(1),
                     "11-digit AMKA-shaped value survives")
        )

    for m in qa_patterns["IBAN_GR"].finditer(text):
        if _iban_checksum_ok(m.group(0)):
            findings.append(
                residual("HIGH", "residual_iban", m.start(), m.end(),
                         "valid Greek IBAN survives")
            )

    for m in qa_patterns["EMAIL"].finditer(text):
        domain = m.group(0).rsplit("@", 1)[-1].casefold()
        if domain in files.rules.preserve_email_domains:
            continue
        findings.append(
            residual("HIGH", "residual_email", m.start(), m.end(),
                     "email address survives")
        )

    for m in qa_patterns["PHONE"].finditer(text):
        if _normalized_greek_phone(m.group(0)) is None:
            continue
        phone_ranges.append((m.start(), m.end()))
        if _looks_like_official_contact_phone(text, m.start()):
            continue
        findings.append(
            residual("MEDIUM", "phone_shape", m.start(), m.end(),
                     "Greek phone-shaped number survives")
        )

    for m in qa_patterns["DIGIT_RUN"].finditer(text):
        run = m.group(0)
        if len(run) == 9:
            continue  # AFM checks own that length
        span = (m.start(), m.end())
        if _overlaps(span, amka_ranges) or _overlaps(span, phone_ranges):
            continue
        if _normalized_greek_phone(run) is not None:
            continue
        findings.append(
            residual("MEDIUM", "digit_run", m.start(), m.end(),
                     f"suspicious {len(run)}-digit run survives")
        )

    for m in _WRONG_PLACEHOLDER_RE.finditer(text):
        findings.append(
            PostcheckFinding("HIGH", "wrong_placeholder", locate(m.start()),
                             f"placeholder residue survives: {m.group(0)}")
        )

    for m in _ELLIPSIS_RUN_RE.finditer(text):
        n = len(m.group(0))
        severity: Literal["HIGH", "MEDIUM"] = "HIGH" if n >= 2 else "MEDIUM"
        findings.append(
            PostcheckFinding(severity, "ellipsis_residue", locate(m.start()),
                             f"run of {n} U+2026 ellipsis chars — old glyph applied char-by-char")
        )

    for m in _CASE_REF_LEAK_RE.finditer(text):
        if "." in m.group(1):
            continue
        findings.append(
            residual("MEDIUM", "case_ref_leak", m.start(1), m.end(1),
                     "case reference value survives after its label",
                     at=m.start())
        )

    for m in _BENEFICIARY_LEAK_RE.finditer(text):
        findings.append(
            residual("MEDIUM", "beneficiary_leak", m.start(1), m.end(1),
                     "beneficiary name survives after δικαιούχο",
                     at=m.start())
        )

    for m in _PARTIAL_STAR_RESIDUE_RE.finditer(text):
        findings.append(
            residual("MEDIUM", "partial_star_residue", m.start(), m.end(),
                     "partial-star masked identifier survives")
        )

    for m in _PERSON_LEAK_RE.finditer(text):
        findings.append(
            residual("MEDIUM", "person_name_leak", m.start(1), m.end(1),
                     "capitalized person name survives after identity context",
                     at=m.start())
        )

    for m in _OVER_REDACT_RE.finditer(text):
        findings.append(
            PostcheckFinding("MEDIUM", "over_redaction", locate(m.start()),
                             f"over-redacted preserved metadata: {m.group(0)}")
        )

    # HIGH, and list-aware. PROPERTY_ID is a hard-redact category, so a value
    # that survives is not a judgement call that went the other way — it is a
    # miss by every stage at once, and only a HIGH stops the document. The scan
    # walks the whole comma/"και"-joined run after each label, because the
    # interesting failure is the SECOND value in a list surviving while the
    # first was blanked.
    for name, position, end in _residual_property_ids(text):
        findings.append(
            residual("HIGH", "residual_property_id", position, end,
                     f"{name} value survives after its label")
        )

    # The over-redaction counterpart, and the only general one in the service.
    # A structural label is never personal data and the published decisions keep
    # every one of them, so a label that is in the input and gone from the output
    # was eaten by a span that reached too far. Counts only: no document text.
    if source_document is not None:
        source_text = "\n".join(u.normalized_text for u in source_document.text_units)
        before = _label_counts(source_text)
        after = _label_counts(text)
        for label, count in before.items():
            if count > after[label]:
                findings.append(
                    PostcheckFinding(
                        "MEDIUM", "label_removed", "document",
                        f"{count - after[label]} of {count} occurrence(s) of a "
                        f"structural label were redacted with their value",
                    )
                )

    # --- Table check -------------------------------------------------------
    for u in units:
        if u.unit_type != "table_cell":
            continue
        header = u.location.get("column_header", "") or ""
        if " ".join(header.split()).casefold() not in _INVOICE_COLUMN_HEADERS:
            continue
        if not any(ch.isdigit() for ch in u.normalized_text):
            continue
        t = u.location.get("table_index")
        r = u.location.get("row_index")
        c = u.location.get("col_index")
        findings.append(
            PostcheckFinding("MEDIUM", "table_invoice_leak", f"table {t} row {r} col {c}",
                             "digits survive under an invoice column header")
        )

    # --- ZIP-level checks --------------------------------------------------
    parser = etree.XMLParser(resolve_entities=False, recover=True)
    with zipfile.ZipFile(io.BytesIO(redacted_bytes)) as zf:
        names = zf.namelist()

        if "word/comments.xml" in names:
            root = etree.fromstring(zf.read("word/comments.xml"), parser)
            if root is not None and root.find(f".//{_W_NS}comment") is not None:
                findings.append(
                    PostcheckFinding("HIGH", "nonempty_comments", "word/comments.xml",
                                     "comments part still contains comment elements")
                )

        for name in names:
            if not _is_text_part(name):
                continue
            root = etree.fromstring(zf.read(name), parser)
            if root is None:
                continue
            if root.find(f".//{_W_NS}ins") is not None or root.find(f".//{_W_NS}del") is not None:
                findings.append(
                    PostcheckFinding("HIGH", "tracked_change", name,
                                     "tracked-change markup survives")
                )
            if root.find(f".//{_W_NS}rPr/{_W_NS}vanish") is not None:
                findings.append(
                    PostcheckFinding("MEDIUM", "hidden_text", name,
                                     "hidden (vanish) run survives")
                )

        # dc:creator and cp:lastModifiedBy are NOT checked. The published ΔΕΔ
        # decisions keep both, so the write path deliberately preserves them
        # (see docx_engine._cleanup_core_properties) and failing a document for
        # carrying them would refuse every correct output. This is the one place
        # the auditor knowingly agrees with the code it audits, and it is a
        # compatibility decision rather than a privacy guarantee.

        for name in names:
            if name in _MACRO_PARTS:
                # The service accepts macro-enabled Word packages and strips
                # the macros while normalising them to .docx. This is the
                # independent check that it actually did: a surviving macro
                # part means the output can still execute code, which is a
                # far worse thing to hand back than any text leak.
                findings.append(
                    PostcheckFinding("HIGH", "macro_part_survived", name,
                                     "macro project survived normalization")
                )

        for name in names:
            low = name.lower()
            is_ole = (
                name.startswith("word/embeddings/oleObject") and low.endswith(".bin")
            )
            if is_ole or name.startswith("word/media/"):
                findings.append(
                    PostcheckFinding("MEDIUM", "embedded_object", name,
                                     "embedded object present in package")
                )

        for name in names:
            if not _is_header_footer_part(name):
                continue
            root = etree.fromstring(zf.read(name), parser)
            if root is None:
                continue
            joined = "".join(root.itertext())
            for token in _LONG_TOKEN_RE.findall(joined):
                findings.append(
                    PostcheckFinding("MEDIUM", "long_token_header_footer", name,
                                     f"alphanumeric token of length {len(token)} survives")
                )

    clean = len(findings) == 0
    # Built as dict[str, int] explicitly: dict is invariant in its key
    # type, so a dict[Literal[...], int] is not a dict[str, int] however
    # obviously every key is a string.
    by_severity: dict[str, int] = dict(Counter[str](f.severity for f in findings))
    by_kind: dict[str, int] = dict(Counter[str](f.kind for f in findings))
    return PostcheckSummary(
        clean=clean,
        findings_total=len(findings),
        by_severity=by_severity,
        by_kind=by_kind,
        findings=findings,
    )
