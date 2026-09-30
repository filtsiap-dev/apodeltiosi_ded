from __future__ import annotations

import re
from dataclasses import dataclass

from anonymizer.config import DetectorRules
from anonymizer.models import (
    DocumentData,
    Span,
    SpanAction,
    SpanCategory,
    TextUnit,
)
from anonymizer.detector_support import (
    # accessors + shared helpers
    _body,
    _prefix,
    _make_span,
    _regex_spans,
    _capture_spans,
    _split_serial_date,
    _split_year_suffix,
    _iter_allowlist_matches,
    _valid_afm,
    _valid_amka_birth_date,
    _iban_is_valid,
    _normalize_header,
    # shared regex fragment + gazetteer
    _GREEK_CAPITALIZED,
    _MEDICAL_TERMS,
    # 04C contextual regexes
    _CHALLENGED_ACT_RE,
    _CHALLENGED_ACT_CONTEXT_RE,
    _DECISION_NUMBER_RE,
    _DECISION_PLACE_DATE_RE,
    # 04D contextual regexes
    _APPELLANT_NAME_RE,
    _FATHER_NAME_RE,
    _PRIVATE_ADDRESS_RE,
    _RESIDENT_CUE,
    _BUSINESS_SEAT_RE,
    _COMPANY_NAME_AFTER_CTX,
    _BANK_ACCOUNT_RE,
    _BENEFICIARY_RE,
    _FISCAL_ID_RE,
    _PARTIAL_STAR_RE,
    _INVOICE_CELL_RE,
    _INVOICE_PARAGRAPH_RE,
    _AUTHORITY_HEADER_CUES,
    _DECISION_TITLE_RE,
    _SIGNATURE_TITLE_RE,
    _ISOLATED_ALLCAPS_NAME_RE,
    _PRIVATE_PARTY_CUE_RE,
    # address / locality / court / procedural-date additions
    _ADDRESS_NUMBER_RE,
    _POSTAL_CODE_RE,
    _LOCALITY_AUTHORITY_RE,
    _LOCALITY_CONTEXT_RE,
    _CASE_COURT_SERIAL_RE,
    _COURT_CHAMBER_RE,
    _PROCEDURAL_DATE_CUE_RE,
    _PROCEDURAL_DATE_WINDOW,
)


# ---------------------------------------------------------------------------
# Module-local constants (small, detector-specific — not "large constants",
# so kept here rather than imported from detector_support).
# ---------------------------------------------------------------------------

# DOU prefix + fallback. In v1 these were inline literals inside _detect_dou;
# hoisted to module scope here. _DOU_FALLBACK_RE is built from the imported
# _GREEK_CAPITALIZED at module load.
_DOU_PREFIX_RE = re.compile(r"(?:Δ\.Ο\.Υ\.|ΔΟΥ)\s+", re.IGNORECASE)
_DOU_FALLBACK_RE = re.compile(rf"{_GREEK_CAPITALIZED}(?:\s+{_GREEK_CAPITALIZED})*")

# _MEDICAL_TERMS is imported from detector_support (canonical copy lives in
# detector_patterns), so there is a single source of truth.

# Whole-cell action map for table headers. Built here (per spec) with the
# imported _normalize_header applied to every key.
_HEADER_ACTION_SPECS: dict[str, tuple[SpanCategory, SpanAction, float, str]] = {
    "ΑΦΜ": ("AFM", "REDACT", 0.9, "AFM table column"),
    "Τηλέφωνο": ("PHONE", "REVIEW", 0.85, "Phone table column; AI must decide official vs private context"),
    "Email": ("EMAIL", "REDACT", 0.95, "Email table column"),
    "Όνομα": ("POSSIBLE_PERSON", "REVIEW", 0.6, "Name table column"),
    "Διεύθυνση": ("POSSIBLE_PRIVATE_LOCATION", "REVIEW", 0.6, "Address table column"),
    "ΠΑΡΑΣΤΑΤΙΚΟ": ("INVOICE_TABLE_ID", "REDACT", 0.9, "Invoice column"),
    "ΠΑΡΑ ΣΤΑΤΙΚΟ": ("INVOICE_TABLE_ID", "REDACT", 0.9, "Invoice column (split)"),
    "ΑΡ. ΠΑΡΑΣΤΑΤΙΚΟΥ": ("INVOICE_TABLE_ID", "REDACT", 0.9, "Invoice number column"),
    "ΤΙΜΟΛΟΓΙΟ": ("INVOICE_TABLE_ID", "REDACT", 0.9, "Invoice column"),
    "ΤΙΜ.": ("INVOICE_TABLE_ID", "REDACT", 0.9, "Invoice abbrev column"),
    "ΑΡΙΘΜΟΣ": ("INVOICE_TABLE_ID", "REDACT", 0.85, "Number column"),
    "ΣΤΟΙΧΕΙΟ": ("INVOICE_TABLE_ID", "REDACT", 0.85, "Document element column"),
    "ΚΑΘΑΡΗ ΑΞΙΑ": ("MONEY", "PRESERVE", 0.95, "Net value column"),
    "ΦΠΑ": ("MONEY", "PRESERVE", 0.95, "VAT column"),
    "ΣΥΝΟΛΟ": ("MONEY", "PRESERVE", 0.95, "Total column"),
    "ΗΜ/ΝΙΑ": ("DATE", "PRESERVE", 0.95, "Date column"),
}

_TABLE_HEADER_ACTIONS: dict[str, tuple[SpanCategory, SpanAction, float, str]] = {
    _normalize_header(header): spec
    for header, spec in _HEADER_ACTION_SPECS.items()
}


# ===========================================================================
# 04C — functions 1..6 (reconstructed against v1, threaded with `rules`)
# ===========================================================================

# 1
def detect_structured_ids(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect Greek structured identifiers (AFM, AMKA, IBAN) in a text unit using
    checksum/date validation from `rules`. Return REDACT spans with confidence scaled
    by validation and label presence."""
    spans: list[Span] = []
    text = unit.normalized_text

    afm_re = rf"(?<!\d)(?:{_prefix(rules, 'afm')})?{_body(rules, 'afm')}(?!\d)"
    for match in re.finditer(afm_re, text, re.IGNORECASE):
        body = match.group(1)
        valid = _valid_afm(body)
        has_prefix = match.start() < match.start(1)
        if valid:
            confidence = 1.0
            reason = "AFM checksum passed"
        elif has_prefix:
            confidence = 0.75
            reason = "AFM label present but checksum failed"
        else:
            confidence = 0.4
            reason = "AFM shape matched but checksum failed"
        spans.append(
            # GROUP 1, not the whole match. The prefix is the "Α.Φ.Μ." label and
            # the ΔΕΔ convention keeps it visible; redacting the full match ate it,
            # and because AFM is hard-redact that was unrecoverable — no pass-2
            # decision or preserve span could win those characters back.
            _make_span(unit, match.start(1), match.end(1), "AFM", "afm_checksum", confidence, "REDACT", reason)
        )

    amka_re = rf"(?<!\d)(?:{_prefix(rules, 'amka')})?{_body(rules, 'amka')}(?!\d)"
    for match in re.finditer(amka_re, text, re.IGNORECASE):
        body = match.group(1)
        valid = _valid_amka_birth_date(body)
        has_prefix = match.start() < match.start(1)
        if valid:
            confidence = 0.95
            reason = "AMKA birth date is plausible"
        elif has_prefix:
            confidence = 0.75
            reason = "AMKA label present but birth date invalid"
        else:
            confidence = 0.5
            reason = "AMKA shape matched"
        spans.append(
            # Group 1 for the same reason as AFM above: the "ΑΜΚΑ" label stays.
            _make_span(unit, match.start(1), match.end(1), "AMKA", "amka_date", confidence, "REDACT", reason)
        )

    for match in re.finditer(rf"\b{_body(rules, 'iban')}\b", text, re.IGNORECASE):
        valid = _iban_is_valid(match.group(0))
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "IBAN",
                "iban_checksum",
                1.0 if valid else 0.3,
                "REDACT",
                "IBAN checksum passed" if valid else "IBAN shape matched",
            )
        )

    return spans


# 2
def detect_contacts(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect email addresses and Greek phone numbers in a text unit. Return PRESERVE
    spans for allowlisted public email domains, REDACT spans for other emails, and
    REVIEW spans for phone numbers."""
    spans: list[Span] = []
    for match in re.finditer(rf"\b{_body(rules, 'email')}\b", unit.normalized_text, re.IGNORECASE):
        value = match.group(0)
        domain = value.rsplit("@", 1)[-1].casefold() if "@" in value else ""
        if domain in rules.preserve_email_domains:
            spans.append(
                _make_span(
                    unit,
                    match.start(),
                    match.end(),
                    "PUBLIC_SERVICE",
                    "public_email_domain",
                    0.95,
                    "PRESERVE",
                    "Public email domain allowlist",
                )
            )
        else:
            spans.append(
                _make_span(
                    unit,
                    match.start(),
                    match.end(),
                    "EMAIL",
                    "email_regex",
                    0.95,
                    "REDACT",
                    "Email address matched",
                )
            )
    for pattern_name, confidence in (
        ("phone_intl", 0.9),
        ("phone_00", 0.9),
        ("phone_local", 0.7),
    ):
        spans.extend(
            _regex_spans(
                unit,
                rf"(?<!\d){_body(rules, pattern_name)}(?!\d)",
                "PHONE",
                pattern_name,
                confidence,
                "REVIEW",
                "Greek phone number matched; AI must decide official vs private context",
                flags=0,
            )
        )
    return spans


# 3
def detect_protocols_and_acts(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect contextual identifiers (protocol numbers, audit orders, act, invoice and
    transaction numbers) in a text unit using patterns from `rules`. Return REDACT spans,
    keeping trailing dates visible and splitting "&"/"/"-joined serial lists per component."""
    spans: list[Span] = []
    # Patterns with a separate trigger prefix: redact only the captured value
    # (group 1). Shrink the span so a trailing date stays visible, and emit a
    # separate span per number component in "&"/"/" joined lists.
    contextual: tuple[tuple[str, SpanCategory], ...] = (
        ("protocol_number", "PROTOCOL_NUMBER"),
        ("audit_order", "AUDIT_ORDER"),
    )
    for pattern_name, category in contextual:
        regex = _prefix(rules, pattern_name) + _body(rules, pattern_name)
        for value_span in _capture_spans(
            unit,
            regex,
            1,
            category,
            pattern_name,
            0.85,
            "REDACT",
            "Contextual identifier matched",
        ):
            parts = _split_serial_date(value_span.text)
            serial = parts[0] if parts else value_span.text
            # Then peel a bare trailing "/YYYY". _split_serial_date only strips a
            # FULL trailing date, so "34519/2026" kept its year inside the
            # identifier and the component loop below redacted it as a separate
            # number. The gold keeps the year: "αριθμό πρωτοκόλλου ……/30-03-2026".
            year_parts = _split_year_suffix(serial)
            if year_parts:
                serial = year_parts[0]
            for component in re.finditer(r"[^/&\s]+", serial):
                spans.append(
                    _make_span(
                        unit,
                        value_span.start + component.start(),
                        value_span.start + component.end(),
                        category,
                        pattern_name,
                        0.85,
                        "REDACT",
                        "Contextual identifier matched",
                    )
                )
    # These three carry their trigger word INSIDE `body` rather than in a
    # `prefix` key, so they look prefix-less — but the value is still group 1 and
    # the trigger is still a label the ΔΕΔ convention keeps ("με αριθ.
    # ……./26-02-2026 Οριστική Πράξη", ΜΙΧΟΣ ¶42). The old full-match span
    # redacted "Πράξη", "Τιμολόγιο", "Α/Α" and "Συναλλαγή" along with it.
    for pattern_name, category in (
        ("act_number", "ACT_NUMBER"),
        ("invoice_number", "INVOICE_NUMBER"),
        ("transaction_id", "TRANSACTION_ID"),
    ):
        regex = _prefix(rules, pattern_name) + _body(rules, pattern_name)
        spans.extend(
            _capture_spans(
                unit,
                regex,
                1,
                category,
                pattern_name,
                0.85,
                "REDACT",
                "Contextual identifier matched",
            )
        )
    return spans


# 4
def detect_challenged_act_numbers(unit: TextUnit) -> list[Span]:
    """Detect numbers of challenged tax acts in a text unit, requiring a tax-act
    context cue within 100 characters after the match. Return REDACT spans covering
    only the serial part (excluding any trailing date)."""
    spans: list[Span] = []
    text = unit.normalized_text
    for match in _CHALLENGED_ACT_RE.finditer(text):
        window = text[match.end(): match.end() + 100]
        if not _CHALLENGED_ACT_CONTEXT_RE.search(window):
            continue
        value = match.group(1)
        parts = _split_serial_date(value) or _split_year_suffix(value)
        if parts:
            serial, _ = parts
            gs = match.start(1)
            ge = gs + len(serial)
        else:
            gs, ge = match.start(1), match.end(1)
        if gs < ge:
            spans.append(
                _make_span(
                    unit,
                    gs,
                    ge,
                    "CHALLENGED_ACT_NUMBER",
                    "challenged_act_ctx",
                    0.9,
                    "REDACT",
                    "Act number with tax-act context",
                )
            )
    return spans


# 5 — internal decomposition (module-private, not exported)
def _procedural_cue_before(text: str, start: int) -> bool:
    """Whether a date at ``start`` is introduced by an explicit procedural cue.

    POSITIVE EVIDENCE ONLY, and this is the whole point of the function. A date
    promoted to ``PROCEDURAL_DATE`` becomes hard-preserved, which means pass 2
    is never asked about it and cannot repair a mistake — so the test may never
    be "nothing nearby says date of birth". A line like "Παπαδόπουλος Ιωάννης,
    03/05/1981, ΑΦΜ …" carries no birth cue at all, and under a negative test
    its date of birth would be hard-preserved on the strength of that absence.

    Only a cue that actually names the procedure counts, and only when it ends
    within one short clause of the date.
    """
    window = text[max(0, start - _PROCEDURAL_DATE_WINDOW):start]
    return bool(_PROCEDURAL_DATE_CUE_RE.search(window))


def _detect_dates(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect numeric and Greek textual dates in a text unit using patterns from
    `rules`. Return PRESERVE spans.

    Two categories, not one. A date with an explicit procedural cue in front of
    it is a ``PROCEDURAL_DATE`` and is hard-preserved; every other date stays an
    ordinary ``DATE`` that pass 2 adjudicates, because it may be a date of birth
    and nothing here can tell.
    """
    spans: list[Span] = []
    text = unit.normalized_text
    for match in re.finditer(_body(rules, "date_numeric"), text, re.IGNORECASE):
        procedural = _procedural_cue_before(text, match.start())
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "PROCEDURAL_DATE" if procedural else "DATE",
                "procedural_date" if procedural else "date_numeric",
                0.95,
                "PRESERVE",
                "Date introduced by a procedural cue" if procedural
                else "Numeric date matched",
            )
        )
    for match in re.finditer(_body(rules, "date_greek"), text, re.IGNORECASE):
        procedural = _procedural_cue_before(text, match.start())
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "PROCEDURAL_DATE" if procedural else "DATE",
                "procedural_date" if procedural else "date_greek",
                0.9,
                "PRESERVE",
                "Date introduced by a procedural cue" if procedural
                else "Greek textual date matched",
            )
        )
    return spans


def _detect_dou(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect tax office (Δ.Ο.Υ.) references in a text unit, matching the DOU
    allowlist in `rules` first and falling back to capitalized Greek words after
    the label. Return PRESERVE spans."""
    spans: list[Span] = []
    text = unit.normalized_text
    for prefix_match in _DOU_PREFIX_RE.finditer(text):
        value_start = prefix_match.end()
        suffix = text[value_start:]
        matched_entry = None
        for entry in sorted(rules.dou_allowlist, key=len, reverse=True):
            if re.match(re.escape(entry) + r"\b", suffix, re.IGNORECASE):
                matched_entry = entry
                break
        if matched_entry:
            end = value_start + len(matched_entry)
            confidence = 0.95
            reason = "DOU gazetteer match"
        else:
            fallback = _DOU_FALLBACK_RE.match(suffix)
            if fallback is None:
                continue
            end = value_start + fallback.end()
            confidence = 0.7
            reason = "DOU label with capitalized Greek words"
        spans.append(
            _make_span(
                unit,
                prefix_match.start(),
                end,
                "DOU",
                "dou_gazetteer",
                confidence,
                "PRESERVE",
                reason,
            )
        )
    return spans


def _detect_public_services(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect public service names in a text unit via the gazetteer in `rules`.
    Return PRESERVE spans."""
    spans: list[Span] = []
    for match in _iter_allowlist_matches(unit.normalized_text, rules.public_services):
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "PUBLIC_SERVICE",
                "public_service_gazetteer",
                0.9,
                "PRESERVE",
                "Public service gazetteer match",
            )
        )
    return spans


def _detect_legal_refs(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect legal references (laws, presidential decrees, FEK, POL, StE, NSK, AADE,
    articles, court decisions) in a text unit using patterns and the gazetteer from
    `rules`. Return PRESERVE spans."""
    spans: list[Span] = []
    legal_refs: tuple[tuple[str, SpanCategory, float], ...] = (
        ("legal_ref_law", "LEGAL_REF", 0.95),
        ("legal_ref_pd", "LEGAL_REF", 0.9),
        ("legal_ref_short", "LEGAL_REF", 0.9),
        ("legal_ref_fek", "LEGAL_REF", 0.95),
        ("legal_ref_pol", "LEGAL_REF", 0.95),
        ("legal_ref_ste", "LEGAL_REF", 0.95),
        ("legal_ref_nsk", "LEGAL_REF", 0.95),
        ("legal_ref_aade", "LEGAL_REF", 0.95),
        ("article_ref", "ARTICLE_REF", 0.9),
        ("court_decision", "COURT_DECISION", 0.85),
    )
    for pattern_name, category, confidence in legal_refs:
        spans.extend(
            _regex_spans(
                unit,
                _body(rules, pattern_name),
                category,
                pattern_name,
                confidence,
                "PRESERVE",
                "Legal reference matched",
            )
        )
    for match in _iter_allowlist_matches(unit.normalized_text, rules.legal_refs):
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "LEGAL_REF",
                "legal_ref_gazetteer",
                0.9,
                "PRESERVE",
                "Legal abbreviation gazetteer match",
            )
        )
    return spans


def detect_preserve_spans(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect all preserve-worthy content in a text unit: dates, DOU references,
    public services, legal references, money amounts, tax years, percentages and
    fiscal periods. Return PRESERVE spans."""
    spans: list[Span] = []
    spans.extend(_detect_dates(unit, rules))
    spans.extend(_detect_dou(unit, rules))
    spans.extend(_detect_public_services(unit, rules))
    spans.extend(_detect_legal_refs(unit, rules))
    spans.extend(
        _regex_spans(
            unit,
            _body(rules, "money"),
            "MONEY",
            "money_amount",
            0.95,
            "PRESERVE",
            "Money amount matched",
        )
    )
    spans.extend(
        _regex_spans(
            unit,
            _body(rules, "tax_year"),
            "TAX_YEAR",
            "tax_year",
            0.9,
            "PRESERVE",
            "Tax year or fiscal period matched",
        )
    )
    spans.extend(
        _regex_spans(
            unit,
            _body(rules, "percentage"),
            "PERCENTAGE",
            "percentage",
            0.95,
            "PRESERVE",
            "Percentage matched",
        )
    )
    spans.extend(
        _regex_spans(
            unit,
            _body(rules, "fiscal_period"),
            "FISCAL_PERIOD",
            "fiscal_period",
            0.9,
            "PRESERVE",
            "Fiscal period matched",
        )
    )
    return spans


# 6
def detect_decision_metadata(unit: TextUnit) -> list[Span]:
    """Detect the decision's own number and place/date line in a text unit.
    Return high-confidence PRESERVE spans."""
    spans: list[Span] = []
    for match in _DECISION_NUMBER_RE.finditer(unit.normalized_text):
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "DECISION_METADATA",
                "decision_number",
                0.98,
                "PRESERVE",
                "Decision number matched",
            )
        )
    for match in _DECISION_PLACE_DATE_RE.finditer(unit.normalized_text):
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "DECISION_METADATA",
                "decision_place_date",
                0.98,
                "PRESERVE",
                "Decision place/date matched",
            )
        )
    return spans


# ===========================================================================
# 04D — functions 7..14
# ===========================================================================

# The appeal cue that makes a following article STRUCTURAL rather than
# relational. "προσφυγή του ΜΙΧΟΥ ΝΙΚΟΛΑΟΥ με ΑΦΜ …" has no patronymic at all:
# the "του" belongs to "προσφυγή", and the gold keeps it visible.
_APPEAL_CUE_BEFORE_RE = re.compile(r"προσφυγ\w*\s*$", re.IGNORECASE)


def _father_name_span(text: str, match: re.Match[str]) -> tuple[int, int]:
    """Where a patronymic span starts, given that group 1 includes the article.

    The regex captures "τ(ου|ης) <NAME>" as one unit because the ΔΕΔ convention
    blanks the whole phrase — ΜΙΧΟΣ ¶35 publishes "του ΔΗΜΗΤΡΙΟΥ" as one run of
    dots. But the SAME two words appear right after the appeal cue, where the
    article is structural and the gold keeps it: "προσφυγή του ………………".

    A fixed-width lookbehind cannot separate those, because the cue varies
    ("προσφυγή", "προσφυγής", "ενδικοφανή προσφυγή"). So the decision is made
    here, on the text actually in front of the match.
    """
    start, end = match.start(1), match.end(1)
    if _APPEAL_CUE_BEFORE_RE.search(text[max(0, start - 24):start]):
        # Structural: hand back the name without its article.
        name = match.group(1)
        offset = len(name) - len(re.sub(r"^τ(?:ου|ης)\s+", "", name, flags=re.IGNORECASE))
        return start + offset, end
    return start, end


# Which cue introduced an address capture. The region rule below belongs to a
# RESIDENCE ("κατοίκου Χαλανδρίου Αττικής" — municipality, then the region it
# sits in) and to nothing else. Applied to a street it is simply wrong: a street
# may be NAMED after a region, and "οδός Βορείου Ηπείρου" was trimmed to
# "Βορείου", publishing half the address the span had correctly claimed.
_RESIDENCE_CUE_BEFORE_RE = re.compile(rf"(?:{_RESIDENT_CUE})\s*$", re.IGNORECASE)


def _trim_trailing_region(text: str, start: int, rules: DetectorRules) -> int:
    """Return the end offset of ``text`` with a trailing region name removed.

    Longest entry first, so "Ανατολικής Μακεδονίας και Θράκης" wins over a
    shorter entry that is a suffix of it. When the capture is nothing BUT a
    region the span collapses to empty and the caller drops it, which is the
    right outcome: there is nothing private left to redact.
    """
    stripped = text.rstrip()
    for entry in sorted(rules.regions, key=len, reverse=True):
        if not entry:
            continue
        if not stripped.casefold().endswith(entry.casefold()):
            continue
        head = stripped[: len(stripped) - len(entry)].rstrip()
        if not head:
            # The capture is NOTHING BUT the region name, which means this is
            # not a "municipality + region" pair at all. Two ways that happens,
            # and trimming is wrong in both: "κατοίκου Θεσσαλονίκης" names the
            # city a person lives in, and "οδός Κρήτης" is a street called
            # Crete. Trimming here deleted the whole candidate, so pass 2 was
            # never even asked.
            break
        return start + len(head)
    return start + len(stripped)


# 7
def detect_appellant_identity(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect appellant identity details in a text unit: name after the ενδικοφανή
    προσφυγή cue, father name in genitive, private address and business seat.
    Return REDACT spans."""
    spans: list[Span] = []
    spans.extend(
        _capture_spans(
            unit,
            _APPELLANT_NAME_RE,
            1,
            "APPELLANT_NAME",
            "appellant_name_ctx",
            0.9,
            "REDACT",
            "Appellant name after ενδικοφανή προσφυγή",
        )
    )
    for match in _FATHER_NAME_RE.finditer(unit.normalized_text):
        start, end = _father_name_span(unit.normalized_text, match)
        if start < end:
            spans.append(
                _make_span(
                    unit,
                    start,
                    end,
                    "FATHER_NAME",
                    "father_name_ctx",
                    0.85,
                    "REDACT",
                    "Father name in genitive before ΑΦΜ/κάτοικ",
                )
            )
    for address_span in _capture_spans(
        unit,
        _PRIVATE_ADDRESS_RE,
        1,
        "PRIVATE_ADDRESS",
        "private_address_ctx",
        0.85,
        "REDACT",
        "Private address after κάτοικος/οδός",
    ):
        # Leave the administrative region visible. The gold blanks the
        # municipality and keeps the region — "κατοίκου Χαλανδρίου Αττικής"
        # becomes "κατοίκου …………. Αττικής" — because a region names an area of
        # millions and identifies nobody.
        #
        # Only for a residence, though. The cue is re-read here rather than
        # threaded through _capture_spans: a street named after a region keeps
        # its whole name.
        residence = _RESIDENCE_CUE_BEFORE_RE.search(
            unit.normalized_text[:address_span.start]
        )
        end = (
            _trim_trailing_region(address_span.text, address_span.start, rules)
            if residence
            else address_span.end
        )
        if end > address_span.start:
            spans.append(
                _make_span(
                    unit,
                    address_span.start,
                    end,
                    "PRIVATE_ADDRESS",
                    "private_address_ctx",
                    0.85,
                    "REDACT",
                    "Private address after κάτοικος/οδός",
                )
            )
    # The street number and the postal code get spans of their own, so that
    # "αρ." and "Τ.Κ." survive as labels while their values do not.
    spans.extend(
        _capture_spans(
            unit,
            _ADDRESS_NUMBER_RE,
            1,
            "PRIVATE_ADDRESS",
            "address_number",
            0.8,
            "REDACT",
            "Street number after αρ.",
        )
    )
    spans.extend(
        _capture_spans(
            unit,
            _POSTAL_CODE_RE,
            1,
            "PRIVATE_ADDRESS",
            "postal_code",
            0.9,
            "REDACT",
            "Postal code after Τ.Κ.",
        )
    )
    spans.extend(
        _capture_spans(
            unit,
            _BUSINESS_SEAT_RE,
            1,
            "BUSINESS_SEAT",
            "business_seat_ctx",
            0.85,
            "REDACT",
            "Business seat after με έδρα",
        )
    )
    return spans


# 8
def detect_private_companies(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect private company names after explicit context cues in a text unit,
    skipping names matching the public-services gazetteer in `rules`.
    Return REDACT spans."""
    spans: list[Span] = []
    public_services_cf = {entry.casefold() for entry in rules.public_services if entry}
    for match in _COMPANY_NAME_AFTER_CTX.finditer(unit.normalized_text):
        name = match.group(1).strip()
        if not name:
            continue
        name_cf = name.casefold()
        if name_cf in public_services_cf:
            continue
        if any(entry in name_cf for entry in public_services_cf if entry):
            continue
        # Align to the STRIPPED name at both ends. Taking the length of the
        # stripped text while leaving `gs` at the unstripped start shifted the
        # span left by however much leading whitespace the capture held.
        gs = match.start(1) + (len(match.group(1)) - len(match.group(1).lstrip()))
        ge = gs + len(name)
        spans.append(
            _make_span(
                unit,
                gs,
                ge,
                "PRIVATE_COMPANY_NAME",
                "company_ctx",
                0.85,
                "REDACT",
                "Company name with explicit context cue",
            )
        )
    return spans


# 9
def detect_bank_payment_ids(unit: TextUnit) -> list[Span]:
    """Detect bank account numbers after λογ./λογαριασμό cues and beneficiary names
    after δικαιούχο in a text unit. Return REDACT spans."""
    spans: list[Span] = []
    spans.extend(
        _capture_spans(
            unit,
            _BANK_ACCOUNT_RE,
            1,
            "BANK_ACCOUNT",
            "bank_account_ctx",
            0.85,
            "REDACT",
            "Bank account after λογ./λογαριασμό",
        )
    )
    spans.extend(
        _capture_spans(
            unit,
            _BENEFICIARY_RE,
            1,
            "PRIVATE_BENEFICIARY",
            "beneficiary_ctx",
            0.9,
            "REDACT",
            "Beneficiary name after δικαιούχο",
        )
    )
    return spans


# 10
def detect_fiscal_device_ids(unit: TextUnit) -> list[Span]:
    """Detect fiscal device (cash register) identifiers with context cues and
    partial-star masked identifiers in a text unit. Return REDACT spans."""
    spans: list[Span] = []
    spans.extend(
        _capture_spans(
            unit,
            _FISCAL_ID_RE,
            1,
            "FISCAL_DEVICE_ID",
            "fiscal_device_ctx",
            0.85,
            "REDACT",
            "Fiscal device ID with context",
        )
    )
    for match in _PARTIAL_STAR_RE.finditer(unit.normalized_text):
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "FISCAL_DEVICE_ID",
                "partial_star",
                0.9,
                "REDACT",
                "Partial-star masked identifier",
            )
        )
    return spans


# 11
def detect_table_sensitive_values(unit: TextUnit) -> list[Span]:
    """Detect sensitive values in table cells via the column-header action map, with
    a cell-level fallback for invoice-like values; for non-cell units, detect inline
    invoice identifiers in running text. Return spans with header-mapped or REDACT actions."""
    spans: list[Span] = []
    if unit.unit_type != "table_cell":
        # Paragraph-level fallback: redact only the identifier (group 1) and the
        # series letter (group 2), one span per non-empty captured group.
        for match in _INVOICE_PARAGRAPH_RE.finditer(unit.normalized_text):
            for group in (1, 2):
                gs, ge = match.start(group), match.end(group)
                if 0 <= gs < ge:
                    spans.append(
                        _make_span(
                            unit,
                            gs,
                            ge,
                            "INVOICE_TABLE_ID",
                            "invoice_inline",
                            0.85,
                            "REDACT",
                            "Invoice identifier in running text",
                        )
                    )
        return spans
    if not unit.normalized_text.strip():
        return []

    header = _normalize_header(str(unit.location.get("column_header", "")))
    mapped = _TABLE_HEADER_ACTIONS.get(header)
    if mapped is not None:
        category, action, confidence, reason = mapped
        return [
            _make_span(
                unit,
                0,
                len(unit.normalized_text),
                category,
                "table_cell_header",
                confidence,
                action,
                reason,
            )
        ]
    # Cell-level fallback regardless of header: redact invoice-like values.
    for match in _INVOICE_CELL_RE.finditer(unit.normalized_text):
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "INVOICE_TABLE_ID",
                "invoice_cell_shape",
                0.85,
                "REDACT",
                "Invoice-like value in table cell",
            )
        )
    return spans


# 12A
def detect_field_labels(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Preserve the structural LABEL that introduces a value, never the value.

    The ΔΕΔ convention is mechanical — "με Α.Φ.Μ. 037173570" is published as
    "με Α.Φ.Μ. ……………" — and nothing in this pipeline used to say so, so every
    span that was a little too wide destroyed the label along with the number.

    Fixing the detectors' own geometry is not enough on its own: pass 2 quotes
    its own spans and can perfectly well quote "με Α.Φ.Μ. 037173570" as one
    string. The resolver awards ownership PER CHARACTER, so a span covering the
    label alone, sitting on a tier above pass 2, carves the label back out of
    any wider REDACT — whatever produced it.

    FIELD_LABEL is hard-preserved, which is a strong claim, so the vocabulary
    behind it is deliberately narrow: a token is admitted only if it can never
    itself be, or begin, personal data (see detector_patterns). The ambiguous
    cue words — "Τράπεζα", "κ.", "Πράξη", "Τμήμα" — are handled by the
    detectors' capture geometry and by span_trim instead, where getting one
    wrong costs a visible cue word rather than a shielded name.
    """
    return _regex_spans(
        unit,
        _body(rules, "field_label"),
        "FIELD_LABEL",
        "field_label",
        1.0,
        "PRESERVE",
        "Structural field label; the value after it is what gets redacted",
        # case-sensitive: the alternation spells out the forms it accepts, and
        # IGNORECASE would let a lowercase "αφμ" inside prose anchor one.
        flags=0,
    )


# One value of each property identifier, used to split a captured LIST into one
# span per value.
#
# Per-pattern rather than one generic "run of digits": Ο.Τ. numbers carry a
# suffix letter ("Ο.Τ. 12Α και 13Β") and a numeric-only splitter quietly dropped
# it, publishing "..Α και ..Β" — a partial redaction that no HIGH finding caught
# because the label was still followed by dots.
#
# The suffix letter is matched in BOTH cases. The outer capture is compiled with
# re.IGNORECASE (``_capture_spans``) and so accepts "Ο.Τ. 12α και 13β", but this
# splitter was written case-sensitively and stopped at the digits — leaving "α"
# and "β" visible with no HIGH finding, since the label was still followed by
# dots. An auditor narrower than the thing it audits reports clean on a leak.
_PROPERTY_VALUE_RES: dict[str, re.Pattern[str]] = {
    "atak": re.compile(r"\d{11}"),
    "kaek": re.compile(r"\d{12}(?:/\d+)*"),
    "ot": re.compile(r"\d+[Α-ΩA-Zα-ωά-ώa-z]?"),
    "axk": re.compile(r"\d+(?:/\d+)+|\d{3,}"),
    "notice_number": re.compile(r"\d[\d/\-]*"),
}

# A ΚΑΕΚ is a 12-digit property code, optionally followed by horizontal and
# vertical subdivision components. An ALL-ZERO suffix means "no subdivision" —
# it names nothing and distinguishes nothing — and the gold keeps it visible:
# ΣΚΟΥΛΑ ¶234 publishes "ΚΑΕΚ ………………/0/0". The root stays hard-redacted.
#
# Only all-zero, and only as the WHOLE suffix. A non-zero component identifies a
# particular horizontal or vertical property and the gold shows no example of one
# surviving, so those are still redacted with the root.
_KAEK_ROOT_ZERO_SUFFIX_RE = re.compile(r"^(\d{12})((?:/0+)+)$")


# 12B
def detect_property_ids(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect cadastral / property-register identifiers: ΑΤΑΚ, ΚΑΕΚ, Ο.Τ., Α.Χ.Κ.
    and the notice number that behaves like them.

    None of these existed anywhere in the codebase before — no regex, no
    category, no mention in either prompt — which is why ΣΚΟΥΛΑ ¶43 shipped with
    three ΑΤΑΚ values fully visible: the rules had nothing to match, pass 1 had
    nothing to recognise, and pass 2's full-chunk scan had never been told they
    mattered.

    They appear in LISTS ("ΑΤΑΚ 00610643353, 00610643361 και 01188179990"), so
    the capture takes the whole list and it is split here into one span per
    value — the same shape ``detect_protocols_and_acts`` uses for "&"-joined
    serials. Splitting matters: a single span across the list would also cover
    the separators, and a partially-redacted list is precisely the failure mode
    the postcheck now hunts for.

    PROPERTY_ID is hard-redact, which is only safe because every pattern is
    cue-anchored and captures group 1 — so no span from here can reach across
    the label that ``detect_field_labels`` is protecting.
    """
    spans: list[Span] = []
    for pattern_name in ("atak", "kaek", "ot", "axk", "notice_number"):
        regex = _prefix(rules, pattern_name) + _body(rules, pattern_name)
        for value_span in _capture_spans(
            unit,
            regex,
            1,
            "PROPERTY_ID",
            pattern_name,
            1.0,
            "REDACT",
            "Property/registry identifier after its label",
        ):
            for component in _PROPERTY_VALUE_RES[pattern_name].finditer(value_span.text):
                start = value_span.start + component.start()
                end = value_span.start + component.end()
                if pattern_name == "kaek":
                    zero = _KAEK_ROOT_ZERO_SUFFIX_RE.match(component.group(0))
                    if zero:
                        end = start + len(zero.group(1))
                if pattern_name == "notice_number":
                    # A notice number keeps its trailing date, exactly as a
                    # protocol number does — "αριθμό ειδοποίησης ……/2026". It is
                    # the one property identifier shaped like a ΔΕΔ reference,
                    # and PROPERTY_ID is hard-redact, so a date swallowed here is
                    # a date pass 2 cannot give back.
                    #
                    # BOTH halves of the reference grammar, in the same order
                    # detect_protocols_and_acts uses them: a bare "/2026" is only
                    # one of the two shapes, and the live ΣΚΟΥΛΑ run showed the
                    # other one — "2221792/15-03-2026", whose whole date the
                    # year-only split left inside the identifier.
                    serial = component.group(0)
                    date_parts = _split_serial_date(serial)
                    if date_parts:
                        serial = date_parts[0]
                    year_parts = _split_year_suffix(serial)
                    if year_parts:
                        serial = year_parts[0]
                    end = start + len(serial)
                if start < end:
                    spans.append(
                        _make_span(
                            unit,
                            start,
                            end,
                            "PROPERTY_ID",
                            pattern_name,
                            1.0,
                            "REDACT",
                            "Property/registry identifier after its label",
                        )
                    )
    return spans


# 12C
def detect_case_court_references(unit: TextUnit) -> list[Span]:
    """Propose the parts of a court reference that belong to THIS case.

    ΣΚΟΥΛΑ ¶228 — "τη με αριθμό 231/2020 απόφαση του Διοικητικού Πρωτοδικείου
    Χαλκίδας (Τμήμα 1ο Τριμελές)" — is published with the serial and the
    chamber blanked and "/2020" kept, while "ΣτΕ 8721/1992" eleven paragraphs
    later is left entirely alone. The difference is not in the shape of the
    reference; it is whether the decision belongs to the appellant's own case or
    is cited as precedent, and no regex can see that.

    So these are proposed as PRESERVE and go into the pass-2 queue as ordinary
    candidates: the rule says WHERE to look, pass 2 says which of the two it is.
    That is also why the category is kept out of hard_preserve_categories — a
    hard preserve is withheld from the queue, and withholding this one would
    make the very judgement it exists to ask for impossible.

    The court's city is not handled here; ``_LOCALITY_AUTHORITY_RE`` already
    covers a toponym after "Πρωτοδικείου", and removes it. Neither the year nor the words
    "απόφαση"/"Τμήμα" are ever covered.
    """
    spans: list[Span] = []
    spans.extend(
        _capture_spans(
            unit,
            _CASE_COURT_SERIAL_RE,
            1,
            "CASE_COURT_REFERENCE",
            "case_court_serial",
            0.85,
            "PRESERVE",
            "Court serial in case history; pass 2 decides precedent vs own case",
        )
    )
    spans.extend(
        _capture_spans(
            unit,
            _COURT_CHAMBER_RE,
            1,
            "CASE_COURT_REFERENCE",
            "court_chamber",
            0.85,
            "PRESERVE",
            "Court chamber number; pass 2 decides precedent vs own case",
        )
    )
    return spans


# 12D
def detect_localities(unit: TextUnit) -> list[Span]:
    """Place names after a locality cue. Two cues, two different authorities.

    AFTER AN AUTHORITY CUE — "Δήμου Χαλκιδέων", "Πρωτοδικείου Χαλκίδας" — this
    is a DECISION, taken at confidence 1.0, and LOCALITY sits in the policy's
    hard-redact list so pass 2 cannot keep it. The gold blanks every one of
    them, and the single counter-example in the corpus was reviewed and
    confirmed an oversight rather than a distinction. It had to become
    deterministic because the model would not follow it: asked twice, in two
    wordings, pass 2 went on preserving "Δήμου Χαλκιδέων" — reasonably enough,
    since a Δήμος IS a public institution and the prompt says to keep those.

    AFTER A CONTEXT CUE — "συνοικία Η΄ Χαλκίδας" — it stays an ordinary
    proposal at 0.85. The gold KEEPS those, so the question is a real one and
    pass 2 is the stage that answers it.

    THE HARD TIER IS SAFE HERE ONLY BECAUSE OF THE CUE SPLIT. A hard redact
    outranks a hard preserve, so a locality pattern that could reach a Δ.Ο.Υ.
    name would start eating the office names the DOU allowlist protects. No
    Δ.Ο.Υ. cue appears in ``_LOCALITY_AUTHORITY_RE``, and that is exactly why it
    is a separate pattern rather than a flag on the old one.
    """
    spans = _capture_spans(
        unit,
        _LOCALITY_AUTHORITY_RE,
        1,
        "LOCALITY",
        "locality_authority",
        1.0,
        "REDACT",
        "Place name after an authority cue",
        flags=0,  # case-sensitive: capitalization marks where the name is
    )
    spans.extend(_capture_spans(
        unit,
        _LOCALITY_CONTEXT_RE,
        1,
        "LOCALITY",
        "locality_ctx",
        0.85,
        "REDACT",
        "Place name after a locality cue",
        flags=0,
    ))
    return spans


# 12
def detect_review_candidates(unit: TextUnit) -> list[Span]:
    """Detect low-confidence candidates in a text unit: possible person names, company
    names with legal-form suffixes, street-like addresses and medical terms.
    Return REVIEW spans for AI adjudication."""
    spans: list[Span] = []
    spans.extend(
        _regex_spans(
            unit,
            rf"\b{_GREEK_CAPITALIZED}\s+{_GREEK_CAPITALIZED}\b",
            "POSSIBLE_PERSON",
            "greek_name_shape",
            0.45,
            "REVIEW",
            "Two capitalized Greek words matched",
            flags=0,  # case-sensitive: _GREEK_CAPITALIZED uses capitalization as the signal;
            # under the _regex_spans IGNORECASE default it matches ANY two Greek words.
        )
    )
    spans.extend(
        _regex_spans(
            unit,
            # Trailing (?!\w) instead of \b: a \b cannot occur between a final "."
            # (non-word) and a following space, so dot-terminated suffixes
            # (Α.Ε., Ε.Π.Ε., Ο.Ε., Ι.Κ.Ε.) never matched before end/space. (?!\w)
            # accepts those yet still blocks a dotless suffix that is really the
            # prefix of a longer word (e.g. "ΑΕ" in "ΑΕΡΑΣ").
            rf"\b(?:{_GREEK_CAPITALIZED}(?:\s+{_GREEK_CAPITALIZED})*)\s+(?:ΑΕ|Α\.Ε\.|ΕΠΕ|Ε\.Π\.Ε\.|ΟΕ|Ο\.Ε\.|ΙΚΕ|Ι\.Κ\.Ε\.)(?!\w)",
            "POSSIBLE_COMPANY",
            "company_suffix",
            0.65,
            "REVIEW",
            "Company suffix matched",
            flags=0,  # case-sensitive: capitalized name + uppercase legal-form suffix
        )
    )
    spans.extend(
        _regex_spans(
            unit,
            rf"\b(?:οδός|Οδός|Λεωφ\.|Λεωφόρος)\s+{_GREEK_CAPITALIZED}(?:\s+{_GREEK_CAPITALIZED})*(?:\s+αρ\.?\s*\d+|\s+\d+)?",
            "POSSIBLE_PRIVATE_LOCATION",
            "street_shape",
            0.6,
            "REVIEW",
            "Street-like address matched",
            flags=0,  # case-sensitive: the trigger lists both οδός/Οδός on purpose
        )
    )
    for term in _MEDICAL_TERMS:
        for match in re.finditer(re.escape(term), unit.normalized_text, re.IGNORECASE):
            spans.append(
                _make_span(
                    unit,
                    match.start(),
                    match.end(),
                    "MEDICAL_TERM",
                    "medical_term_list",
                    0.5,
                    "REVIEW",
                    "Medical term list match",
                )
            )
    return spans


# 13 — document-level
def detect_authority_header(document: DocumentData) -> list[Span]:
    """Detect the issuing-authority header in the first 30 body paragraphs of a
    document, stopping at the decision title. Return whole-paragraph PRESERVE spans
    with confidence based on cue count."""
    para_units = [
        u
        for u in document.text_units
        if u.unit_type == "paragraph" and u.part_name == "word/document.xml"
    ]
    spans: list[Span] = []
    for unit in para_units[:30]:
        if _DECISION_TITLE_RE.match(unit.normalized_text.strip()):
            break
        cues = _AUTHORITY_HEADER_CUES.findall(unit.normalized_text)
        # PUBLIC_AUTHORITY_HEADER is not hard-preserved: both confidences below
        # are recommendations that pass 2 adjudicates, and a REDACT can take
        # either of them at the resolver.
        if len(cues) >= 2:
            confidence = 1.0
        elif len(cues) == 1:
            confidence = 0.7
        else:
            continue
        spans.append(
            _make_span(
                unit,
                0,
                len(unit.normalized_text),
                "PUBLIC_AUTHORITY_HEADER",
                "authority_header",
                confidence,
                "PRESERVE",
                "Authority header cue matched",
            )
        )
    return spans


# 14 — document-level
def detect_final_signatory(document: DocumentData) -> list[Span]:
    """Detect official signatory names (isolated all-caps paragraphs following a
    signature title) in the last 20% of a document's body paragraphs, skipping
    candidates near private-party cues. Return PRESERVE spans."""
    para_units = [
        u
        for u in document.text_units
        if u.unit_type == "paragraph" and u.part_name == "word/document.xml"
    ]
    if not para_units:
        return []
    threshold_index = int(len(para_units) * 0.80)
    final_units = para_units[threshold_index:]
    spans: list[Span] = []
    preserved: set[str] = set()
    for i, unit in enumerate(final_units):
        if not _SIGNATURE_TITLE_RE.search(unit.normalized_text):
            continue
        candidates = final_units[i + 1: i + 6]
        for cand in candidates:
            text = cand.normalized_text.strip()
            if not _ISOLATED_ALLCAPS_NAME_RE.match(text):
                continue
            if cand.unit_id in preserved:
                continue
            context = "".join(
                u.normalized_text
                for u in final_units[max(0, i - 1): i + 6]
                if u is not cand
            )
            if _PRIVATE_PARTY_CUE_RE.search(context):
                continue
            preserved.add(cand.unit_id)
            spans.append(
                _make_span(
                    cand,
                    0,
                    len(cand.normalized_text),
                    "OFFICIAL_SIGNATORY",
                    "final_signatory",
                    0.95,
                    "PRESERVE",
                    "Final signatory in signature block",
                )
            )
            break
    return spans


# ===========================================================================
# Result type + aggregator
# ===========================================================================

@dataclass
class DetectionResult:
    resolver_spans: list[Span]
    review_hints: list[Span]


def detect_all(document: DocumentData, rules: DetectorRules) -> DetectionResult:
    """Run every detector over the document (document-level first, then per text unit)
    using `rules`. Return a DetectionResult splitting spans by action into resolver
    spans (REDACT/PRESERVE) and review hints (REVIEW)."""
    all_spans: list[Span] = []

    # (1) document-level, first
    all_spans.extend(detect_final_signatory(document))
    all_spans.extend(detect_authority_header(document))

    for unit in document.text_units:
        # (2) preserves — hard (DOU, LEGAL_REF, MONEY, DECISION_METADATA, ...)
        # and ordinary (DATE) alike; policy.hard_preserve_categories, not the
        # detector, decides which of the two a span turns out to be.
        all_spans.extend(detect_decision_metadata(unit))
        all_spans.extend(detect_preserve_spans(unit, rules))
        # The label layer. Hard-preserved, so it never enters the pass-2 queue
        # and outranks any REDACT that tries to take a label with its value.
        all_spans.extend(detect_field_labels(unit, rules))
        # Court references in the case's own history: PRESERVE proposals that
        # pass 2 is expected to settle one way or the other.
        all_spans.extend(detect_case_court_references(unit))
        # (3) structured high-confidence redact
        all_spans.extend(detect_structured_ids(unit, rules))
        all_spans.extend(detect_property_ids(unit, rules))
        all_spans.extend(detect_contacts(unit, rules))
        # (4) case-specific reference redact
        all_spans.extend(detect_challenged_act_numbers(unit))
        all_spans.extend(detect_protocols_and_acts(unit, rules))
        # (5) party/entity identity redact
        all_spans.extend(detect_appellant_identity(unit, rules))
        all_spans.extend(detect_localities(unit))
        all_spans.extend(detect_private_companies(unit, rules))
        all_spans.extend(detect_bank_payment_ids(unit))
        all_spans.extend(detect_fiscal_device_ids(unit))
        # (6) table-aware redact
        all_spans.extend(detect_table_sensitive_values(unit))
        # (7) low-confidence review candidates, last
        all_spans.extend(detect_review_candidates(unit))

    # Split STRICTLY by action. No detector-name special-casing.
    review_hints = [s for s in all_spans if s.action == "REVIEW"]
    resolver_spans = [s for s in all_spans if s.action in ("REDACT", "PRESERVE")]

    return DetectionResult(resolver_spans=resolver_spans, review_hints=review_hints)


__all__ = [
    "DetectionResult",
    "detect_all",
    "detect_structured_ids",
    "detect_contacts",
    "detect_protocols_and_acts",
    "detect_challenged_act_numbers",
    "detect_preserve_spans",
    "detect_decision_metadata",
    "detect_appellant_identity",
    "detect_private_companies",
    "detect_bank_payment_ids",
    "detect_fiscal_device_ids",
    "detect_table_sensitive_values",
    "detect_field_labels",
    "detect_property_ids",
    "detect_case_court_references",
    "detect_localities",
    "detect_review_candidates",
    "detect_authority_header",
    "detect_final_signatory",
]
