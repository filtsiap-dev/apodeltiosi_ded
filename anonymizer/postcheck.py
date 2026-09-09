"""Mandatory post-redaction audit.

Scans REDACTED output for residual leaks. ``anonymize_document`` calls this on
every document as its final stage, after ``write_redacted_docx`` and before any
caller can save or return the bytes: a HIGH-severity finding aborts the document
with ``ResidualPIIError`` instead of releasing it, and lower-severity findings
ride along on the result. Nothing here contacts the network or writes anything.

``detail`` never echoes matched document text, except for ``wrong_placeholder``
and ``over_redaction`` where the match cannot be PII by construction. This
module does not log.
"""

from __future__ import annotations

import bisect
import io
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from lxml import etree

from anonymizer.config import FileConfig
from anonymizer.docx_engine import parse_docx, validate_docx_bytes
from anonymizer.postcheck_support import (
    qa_patterns,
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


@dataclass(frozen=True)
class PostcheckFinding:
    severity: Literal["HIGH", "MEDIUM"]
    kind: str
    location: str
    detail: str


@dataclass
class PostcheckSummary:
    clean: bool
    findings_total: int
    by_severity: dict[str, int]
    by_kind: dict[str, int]
    findings: list[PostcheckFinding]


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


def scan_redacted_docx_bytes(redacted_bytes: bytes, files: FileConfig) -> PostcheckSummary:
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

    amka_ranges: list[tuple[int, int]] = []
    phone_ranges: list[tuple[int, int]] = []

    # --- Text checks -------------------------------------------------------
    for m in qa_patterns["AFM"].finditer(text):
        value = m.group(1)
        if _afm_checksum_ok(value):
            findings.append(
                PostcheckFinding("HIGH", "residual_afm", locate(m.start(1)),
                                 "valid-checksum 9-digit AFM survives")
            )
        else:
            findings.append(
                PostcheckFinding("MEDIUM", "afm_shape", locate(m.start(1)),
                                 "9-digit AFM-shaped run survives")
            )

    for m in qa_patterns["AMKA"].finditer(text):
        amka_ranges.append((m.start(1), m.end(1)))
        findings.append(
            PostcheckFinding("HIGH", "residual_amka", locate(m.start(1)),
                             "11-digit AMKA-shaped value survives")
        )

    for m in qa_patterns["IBAN_GR"].finditer(text):
        if _iban_checksum_ok(m.group(0)):
            findings.append(
                PostcheckFinding("HIGH", "residual_iban", locate(m.start()),
                                 "valid Greek IBAN survives")
            )

    for m in qa_patterns["EMAIL"].finditer(text):
        domain = m.group(0).rsplit("@", 1)[-1].casefold()
        if domain in files.rules.preserve_email_domains:
            continue
        findings.append(
            PostcheckFinding("HIGH", "residual_email", locate(m.start()),
                             "email address survives")
        )

    for m in qa_patterns["PHONE"].finditer(text):
        if _normalized_greek_phone(m.group(0)) is None:
            continue
        phone_ranges.append((m.start(), m.end()))
        if _looks_like_official_contact_phone(text, m.start()):
            continue
        findings.append(
            PostcheckFinding("MEDIUM", "phone_shape", locate(m.start()),
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
            PostcheckFinding("MEDIUM", "digit_run", locate(m.start()),
                             f"suspicious {len(run)}-digit run survives")
        )

    for m in _WRONG_PLACEHOLDER_RE.finditer(text):
        findings.append(
            PostcheckFinding("HIGH", "wrong_placeholder", locate(m.start()),
                             f"placeholder residue survives: {m.group(0)}")
        )

    for m in _ELLIPSIS_RUN_RE.finditer(text):
        n = len(m.group(0))
        severity = "HIGH" if n >= 2 else "MEDIUM"
        findings.append(
            PostcheckFinding(severity, "ellipsis_residue", locate(m.start()),
                             f"run of {n} U+2026 ellipsis chars — old glyph applied char-by-char")
        )

    for m in _CASE_REF_LEAK_RE.finditer(text):
        if "." in m.group(1):
            continue
        findings.append(
            PostcheckFinding("MEDIUM", "case_ref_leak", locate(m.start()),
                             "case reference value survives after its label")
        )

    for m in _BENEFICIARY_LEAK_RE.finditer(text):
        findings.append(
            PostcheckFinding("MEDIUM", "beneficiary_leak", locate(m.start()),
                             "beneficiary name survives after δικαιούχο")
        )

    for m in _PARTIAL_STAR_RESIDUE_RE.finditer(text):
        findings.append(
            PostcheckFinding("MEDIUM", "partial_star_residue", locate(m.start()),
                             "partial-star masked identifier survives")
        )

    for m in _PERSON_LEAK_RE.finditer(text):
        findings.append(
            PostcheckFinding("MEDIUM", "person_name_leak", locate(m.start()),
                             "capitalized person name survives after identity context")
        )

    for m in _OVER_REDACT_RE.finditer(text):
        findings.append(
            PostcheckFinding("MEDIUM", "over_redaction", locate(m.start()),
                             f"over-redacted preserved metadata: {m.group(0)}")
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

        if "docProps/core.xml" in names:
            root = etree.fromstring(zf.read("docProps/core.xml"), parser)
            if root is not None:
                creator = root.find(f"{_DC_NS}creator")
                if creator is not None and (creator.text or "").strip():
                    findings.append(
                        PostcheckFinding("HIGH", "metadata_creator", "docProps/core.xml",
                                         "dc:creator is non-blank")
                    )
                lmb = root.find(f"{_CP_NS}lastModifiedBy")
                if lmb is not None and (lmb.text or "").strip():
                    findings.append(
                        PostcheckFinding("HIGH", "metadata_last_modified_by", "docProps/core.xml",
                                         "cp:lastModifiedBy is non-blank")
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
    by_severity = dict(Counter(f.severity for f in findings))
    by_kind = dict(Counter(f.kind for f in findings))
    return PostcheckSummary(
        clean=clean,
        findings_total=len(findings),
        by_severity=by_severity,
        by_kind=by_kind,
        findings=findings,
    )
