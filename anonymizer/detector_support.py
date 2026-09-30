"""Private helper layer for the deterministic detection pass (Task 04B).

Pure, file-free helpers shared by the deterministic detectors. All regex/data
constants are owned by ``anonymizer.detector_patterns`` (Task 04A) and are
re-exported here so ``anonymizer.detectors`` can import both the constants and
these helpers from a single module.

No file access lives in this module: no yaml, no Path loads, no module-level
allowlist globals. Everything data-driven arrives via the ``rules:
DetectorRules`` parameter.
"""

from __future__ import annotations

import re
from typing import Callable
from datetime import date

from anonymizer.config import DetectorRules
from anonymizer.models import Span, SpanAction, SpanCategory, TextUnit

# Re-exported constants owned by Task 04A. Inferred from the v1 monolith;
# this block MUST mirror detector_patterns' actual exports/__all__ exactly —
# any name absent there is an ImportError. `_TABLE_HEADER_ACTIONS` is
# deliberately NOT imported (see module note below).
from anonymizer.detector_patterns import (
    _ELISION_APOSTROPHES,
    _DEFAULT_PATTERNS,
    _GREEK_CAPITALIZED,
    _MEDICAL_TERMS,
    _DATE_SUFFIX_RE,
    _CHALLENGED_ACT_RE,
    _CHALLENGED_ACT_CONTEXT_RE,
    _APPELLANT_NAME_RE,
    _FATHER_NAME_RE,
    _PRIVATE_ADDRESS_RE,
    _BUSINESS_SEAT_RE,
    _COMPANY_NAME_AFTER_CTX,
    _BANK_ACCOUNT_RE,
    _BENEFICIARY_RE,
    _FISCAL_ID_RE,
    _PARTIAL_STAR_RE,
    _INVOICE_CELL_RE,
    _INVOICE_PARAGRAPH_RE,
    _SIGNATURE_TITLE_RE,
    _ISOLATED_ALLCAPS_NAME_RE,
    _PRIVATE_PARTY_CUE_RE,
    _AUTHORITY_HEADER_CUES,
    _DECISION_TITLE_RE,
    _DECISION_NUMBER_RE,
    _DECISION_PLACE_DATE_RE,
    _RESIDENT_CUE,
    _ADDRESS_NUMBER_RE,
    _POSTAL_CODE_RE,
    _LOCALITY_AUTHORITY_RE,
    _LOCALITY_CONTEXT_RE,
    _CASE_COURT_SERIAL_RE,
    _COURT_CHAMBER_RE,
    _PROCEDURAL_DATE_CUE_RE,
    _PROCEDURAL_DATE_WINDOW,
)

# Optional dependency guard: primary IBAN validation uses python-stdnum when
# available, with a self-contained mod-97 fallback otherwise.
_stdnum_iban_is_valid: Callable[[str], bool] | None
try:
    from stdnum.iban import is_valid as _stdnum_iban_imported

    _stdnum_iban_is_valid = _stdnum_iban_imported
except Exception:  # pragma: no cover - dependency fallback
    _stdnum_iban_is_valid = None


# ---------------------------------------------------------------------------
# Pattern resolution — all pattern-driven detectors go through these two.
# ---------------------------------------------------------------------------

def _body(rules: DetectorRules, name: str) -> str:
    """Return the ``body`` regex string for pattern ``name``, taking the rules override when present and falling back to ``_DEFAULT_PATTERNS``."""
    return str(rules.patterns.get(name, {}).get("body", _DEFAULT_PATTERNS[name]["body"]))


def _prefix(rules: DetectorRules, name: str) -> str:
    """Return the ``prefix`` regex string for pattern ``name`` from the rules override or ``_DEFAULT_PATTERNS``, defaulting to an empty string."""
    return str(
        rules.patterns.get(name, {}).get("prefix", _DEFAULT_PATTERNS[name].get("prefix", ""))
    )


def _iter_allowlist_matches(text: str, entries):
    """Yield case-insensitive regex matches for each gazetteer entry.

    Entries are tried longest-first so a longer allowlist name wins over a
    shorter prefix of it. This is how deterministic PRESERVE locates known
    public-service / legal-reference names in a text unit.
    """
    for entry in sorted(entries, key=len, reverse=True):
        if not entry:
            continue
        yield from re.finditer(re.escape(entry), text, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Span construction
# ---------------------------------------------------------------------------

def _make_span(
    unit: TextUnit,
    start: int,
    end: int,
    category: SpanCategory,
    detector: str,
    confidence: float,
    action: SpanAction,
    reason: str,
) -> Span:
    """Build a ``Span`` over ``unit.normalized_text[start:end]`` with the given category, detector, confidence, action, and reason."""
    return Span(
        unit_id=unit.unit_id,
        start=start,
        end=end,
        text=unit.normalized_text[start:end],
        category=category,
        detector=detector,
        confidence=confidence,
        action=action,
        reason=reason,
    )


def _regex_spans(
    unit: TextUnit,
    regex: str | re.Pattern[str],
    category: SpanCategory,
    detector: str,
    confidence: float,
    action: SpanAction,
    reason: str,
    flags: int = re.IGNORECASE,
) -> list[Span]:
    """One span per full match. Accepts a string or precompiled pattern.

    When a precompiled pattern is passed, ``flags`` is ignored.
    """
    compiled = regex if isinstance(regex, re.Pattern) else re.compile(regex, flags)
    return [
        _make_span(unit, match.start(), match.end(), category, detector, confidence, action, reason)
        for match in compiled.finditer(unit.normalized_text)
    ]


def _capture_spans(
    unit: TextUnit,
    pattern: str | re.Pattern[str],
    group: int,
    category: SpanCategory,
    detector: str,
    confidence: float,
    action: SpanAction,
    reason: str,
    flags: int = re.IGNORECASE,
) -> list[Span]:
    """One span per capture GROUP.

    Matches where the group did not participate (start/end == -1) or is empty
    (start >= end) are skipped. Accepts a string or precompiled pattern; when a
    precompiled pattern is passed, ``flags`` is ignored.
    """
    compiled = pattern if isinstance(pattern, re.Pattern) else re.compile(pattern, flags)
    spans: list[Span] = []
    for match in compiled.finditer(unit.normalized_text):
        try:
            gs, ge = match.start(group), match.end(group)
        except IndexError:
            continue
        if 0 <= gs < ge:
            spans.append(_make_span(unit, gs, ge, category, detector, confidence, action, reason))
    return spans


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _valid_afm(value: str) -> bool:
    """Return True when ``value`` is a valid Greek tax number (AFM): nine digits whose power-of-two weighted checksum mod 11 mod 10 equals the last digit."""
    if len(value) != 9 or not value.isdigit():
        return False
    digits = [int(ch) for ch in value]
    total = sum(digits[i] * (2 ** (8 - i)) for i in range(8))
    return total % 11 % 10 == digits[8]


def _valid_amka_birth_date(value: str) -> bool:
    """Return True when ``value`` is an 11-digit Greek social security number (AMKA) whose leading DDMMYY digits form a real birth date between 1900 and the current year."""
    if len(value) != 11 or not value.isdigit():
        return False
    day = int(value[:2])
    month = int(value[2:4])
    year_suffix = int(value[4:6])
    current_year = date.today().year
    current_suffix = current_year % 100
    year = 2000 + year_suffix if year_suffix <= current_suffix else 1900 + year_suffix
    if year < 1900 or year > current_year:
        return False
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


def _iban_is_valid(value: str) -> bool:
    """Return True when ``value`` (spaces/hyphens ignored) is a valid IBAN, using python-stdnum when installed and a mod-97 checksum fallback otherwise."""
    stripped = re.sub(r"[\s-]+", "", value).upper()
    if _stdnum_iban_is_valid is not None:
        return bool(_stdnum_iban_is_valid(stripped))
    if len(stripped) < 5 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", stripped):
        return False
    rearranged = stripped[4:] + stripped[:4]
    digits = ""
    for ch in rearranged:
        digits += ch if ch.isdigit() else str(ord(ch) - 55)
    remainder = 0
    for ch in digits:
        remainder = (remainder * 10 + int(ch)) % 97
    return remainder == 1


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def _split_serial_date(value: str):
    """Return (serial_part, date_part) or None when the structure is ambiguous."""
    match = _DATE_SUFFIX_RE.match(value.strip())
    if match and match.group(1).strip("/\\-"):
        return match.group(1), match.group(3)
    return None


_YEAR_SUFFIX_RE = re.compile(r"^(.*?\S)\s*/\s*((?:19|20)\d{2})$")


def _split_year_suffix(value: str):
    """Return ``(serial, year)`` when ``value`` ends in a bare ``/YYYY``, else None.

    The sibling of :func:`_split_serial_date`, which only peels a trailing FULL
    date (``/14-10-2024``). A ΔΕΔ reference just as often ends in the year alone
    (``34519/2026``), and the gold keeps that year visible while blanking the
    serial — so without this the year is redacted as part of the identifier.

    Whitespace around the separator is tolerated because the documents contain
    it: ΓΕΩΡΓΟΠΟΥΛΟΥ ¶32 reads ``υπ’ αριθ. 193660 /13-07-2021``.

    DELIBERATELY NOT APPLIED EVERYWHERE. Only the detectors whose ΔΕΔ convention
    calls for it use this; "anything ending in /YYYY keeps its year" is not a
    safe global rule, since another identifier may carry the year as an
    integral component.
    """
    match = _YEAR_SUFFIX_RE.match(value.strip())
    if match:
        return match.group(1), match.group(2)
    return None


def _normalize_header(value: str) -> str:
    """Return ``value`` with whitespace collapsed to single spaces and casefolded, for table-header comparison."""
    return " ".join(value.split()).casefold()


__all__ = [
    # Re-exported Task 04A constants
    "_ELISION_APOSTROPHES",
    "_DEFAULT_PATTERNS",
    "_GREEK_CAPITALIZED",
    "_MEDICAL_TERMS",
    "_DATE_SUFFIX_RE",
    "_CHALLENGED_ACT_RE",
    "_CHALLENGED_ACT_CONTEXT_RE",
    "_APPELLANT_NAME_RE",
    "_FATHER_NAME_RE",
    "_PRIVATE_ADDRESS_RE",
    "_BUSINESS_SEAT_RE",
    "_COMPANY_NAME_AFTER_CTX",
    "_BANK_ACCOUNT_RE",
    "_BENEFICIARY_RE",
    "_FISCAL_ID_RE",
    "_PARTIAL_STAR_RE",
    "_INVOICE_CELL_RE",
    "_INVOICE_PARAGRAPH_RE",
    "_SIGNATURE_TITLE_RE",
    "_ISOLATED_ALLCAPS_NAME_RE",
    "_PRIVATE_PARTY_CUE_RE",
    "_AUTHORITY_HEADER_CUES",
    "_DECISION_TITLE_RE",
    "_DECISION_NUMBER_RE",
    "_DECISION_PLACE_DATE_RE",
    "_RESIDENT_CUE",
    "_ADDRESS_NUMBER_RE",
    "_POSTAL_CODE_RE",
    "_LOCALITY_AUTHORITY_RE",
    "_LOCALITY_CONTEXT_RE",
    "_CASE_COURT_SERIAL_RE",
    "_COURT_CHAMBER_RE",
    "_PROCEDURAL_DATE_CUE_RE",
    "_PROCEDURAL_DATE_WINDOW",
    # Support helpers owned by this module
    "_body",
    "_prefix",
    "_iter_allowlist_matches",
    "_make_span",
    "_regex_spans",
    "_capture_spans",
    "_valid_afm",
    "_valid_amka_birth_date",
    "_iban_is_valid",
    "_split_serial_date",
    "_split_year_suffix",
    "_normalize_header",
]
