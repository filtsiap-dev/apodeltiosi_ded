from __future__ import annotations

import re
from dataclasses import dataclass

from anonymizer.config import DetectorRules
from anonymizer.models import DocumentData, Span, TextUnit
from anonymizer.detector_support import (
    # accessors + shared helpers
    _body,
    _prefix,
    _make_span,
    _regex_spans,
    _capture_spans,
    _split_serial_date,
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
_TABLE_HEADER_ACTIONS = {
    _normalize_header(header): spec
    for header, spec in {
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
    }.items()
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
            _make_span(unit, match.start(), match.end(), "AFM", "afm_checksum", confidence, "REDACT", reason)
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
            _make_span(unit, match.start(), match.end(), "AMKA", "amka_date", confidence, "REDACT", reason)
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
    for pattern_name, category in (
        ("protocol_number", "PROTOCOL_NUMBER"),
        ("audit_order", "AUDIT_ORDER"),
    ):
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
    # Patterns without a separate prefix keep the full-match behaviour.
    for pattern_name, category in (
        ("act_number", "ACT_NUMBER"),
        ("invoice_number", "INVOICE_NUMBER"),
        ("transaction_id", "TRANSACTION_ID"),
    ):
        regex = _prefix(rules, pattern_name) + _body(rules, pattern_name)
        spans.extend(
            _regex_spans(
                unit,
                regex,
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
        parts = _split_serial_date(value)
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
def _detect_dates(unit: TextUnit, rules: DetectorRules) -> list[Span]:
    """Detect numeric and Greek textual dates in a text unit using patterns from
    `rules`. Return PRESERVE spans."""
    spans: list[Span] = []
    for match in re.finditer(_body(rules, "date_numeric"), unit.normalized_text, re.IGNORECASE):
        spans.append(
            _make_span(
                unit,
                match.start(),
                match.end(),
                "DATE",
                "date_numeric",
                0.95,
                "PRESERVE",
                "Numeric date matched",
            )
        )
    spans.extend(
        _regex_spans(
            unit,
            _body(rules, "date_greek"),
            "DATE",
            "date_greek",
            0.9,
            "PRESERVE",
            "Greek textual date matched",
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
    for pattern_name, category, confidence in (
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
    ):
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

# 7
def detect_appellant_identity(unit: TextUnit) -> list[Span]:
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
    spans.extend(
        _capture_spans(
            unit,
            _FATHER_NAME_RE,
            1,
            "FATHER_NAME",
            "father_name_ctx",
            0.85,
            "REDACT",
            "Father name in genitive before ΑΦΜ/κάτοικ",
        )
    )
    spans.extend(
        _capture_spans(
            unit,
            _PRIVATE_ADDRESS_RE,
            1,
            "PRIVATE_ADDRESS",
            "private_address_ctx",
            0.85,
            "REDACT",
            "Private address after κάτοικος/οδός",
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
        gs = match.start(1)
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
        if len(cues) >= 2:
            confidence = 1.0
        elif len(cues) == 1:
            confidence = 0.7  # soft preserve — still wins over soft REDACT
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
        # (2) hard preserves
        all_spans.extend(detect_decision_metadata(unit))
        all_spans.extend(detect_preserve_spans(unit, rules))
        # (3) structured high-confidence redact
        all_spans.extend(detect_structured_ids(unit, rules))
        all_spans.extend(detect_contacts(unit, rules))
        # (4) case-specific reference redact
        all_spans.extend(detect_challenged_act_numbers(unit))
        all_spans.extend(detect_protocols_and_acts(unit, rules))
        # (5) party/entity identity redact
        all_spans.extend(detect_appellant_identity(unit))
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
    "detect_review_candidates",
    "detect_authority_header",
    "detect_final_signatory",
]
