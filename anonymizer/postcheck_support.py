"""Independent audit constants and helpers for the optional post-redaction check
(Task 10A).

Out-of-band: nothing in the serving path imports this module. Stdlib ``re`` only;
no ``anonymizer.*`` imports and no logging.
"""

import re

qa_patterns = {
    "AFM": re.compile(r"\b(\d{9})\b"),
    # An AMKA starts with the holder's birth date as DDMMYY (the same reading detectors use).
    "AMKA": re.compile(r"\b((0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{2}\d{5})\b"),
    "IBAN_GR": re.compile(r"\bGR\d{2}\d{7}\d{16}\b", re.IGNORECASE),
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "PHONE": re.compile(r"(?<!\d)(?:\+?30|0030)?[\s\-]?(?:69|2\d)[\d\s\-]{8,14}(?!\d)"),
    "DIGIT_RUN": re.compile(r"\b\d{9,11}\b"),
}

# Wrong-placeholder residue (stale code paths or AI output): HIGH severity.
_WRONG_PLACEHOLDER_RE = re.compile(
    r"\[(?:NAME|AFM|ADDRESS|COMPANY|ACT_NUMBER|REDACTED)\]"
    r"|<REDACTED>"
    r"|(?:PERSON|COMPANY)_\d+"
    r"|\*{3,}\d+"
    r"|\*{5,}",
    re.IGNORECASE,
)

# U+2026 runs: 2+ consecutive is the signature of the old glyph applied char-by-char.
_ELLIPSIS_RUN_RE = re.compile("…+")

# Case-specific reference value surviving after a trigger label.
_CASE_REF_LEAK_RE = re.compile(
    r"(?:υπ['’]\s*αρ(?:ιθ)?\.?|αρ\.?\s*πρωτ\.?|αριθμ[οό]\s+πρωτοκόλλου"
    r"|εντολ[ήέ]ς?\s+(?:μερικού\s+)?ελέγχου|Γνωστοποίησ[ηεις]+"
    r"|Αίτημ[αα]\s+Παροχής\s+Πληροφοριών|ΑΒΜ|ΕΞ)\s+"
    r"(\d[0-9A-ZΑ-Ω./\-]{2,})",
    re.IGNORECASE,
)

# Beneficiary name surviving after δικαιούχο τον/την.
_BENEFICIARY_LEAK_RE = re.compile(
    r"δικαιούχ[οη]\s+τ(?:ον|ην)\s+[Α-ΩΆ-Ώ][α-ωά-ώ]+", re.IGNORECASE
)

# Partial-star masked identifier residue (e.g. DCX *****423).
_PARTIAL_STAR_RESIDUE_RE = re.compile(r"\b[A-ZΑ-Ω]{2,}\s*\*+[0-9A-ZΑ-Ω]+\b")

# Person name surviving after key context phrases.
_PERSON_LEAK_RE = re.compile(
    r"(?:ενδικοφανή\s+προσφυγή\s+τ(?:ης|ου)\s+|με\s+ΑΦΜ\s+\.+\s+)"
    r"([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+(?:\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+)+)",
    re.IGNORECASE,
)

# Over-anonymization: preserved metadata labels followed by dot runs,
# or a redacted percentage (2+ dots immediately before %).
_OVER_REDACT_RE = re.compile(
    r"Αριθμ[οό]ς\s+[Αα]πόφασης\s*:\s*\.{3,}"
    r"|ν\.\s*\.{3,}"
    r"|ΦΕΚ\s+\.{3,}"
    r"|ΠΟΛ\s*\.{3,}"
    r"|ΣτΕ\s*\.{3,}"
    r"|ΝΣΚ\s*\.{3,}"
    r"|\.{2,}%",
    re.IGNORECASE,
)

# Official-contact labels/header cues that legitimise a preserved phone/fax.
_OFFICIAL_CONTACT_LABEL_RE = re.compile(
    r"Τηλέφωνο|Τηλ\.?|τηλ\.?|Fax|Φαξ|Ταχ\.", re.IGNORECASE
)
_OFFICIAL_HEADER_CONTEXT_RE = re.compile(
    r"ΕΛΛΗΝΙΚΗ\s+ΔΗΜΟΚΡΑΤΙΑ|Α\.?\s*Α\.?\s*Δ\.?\s*Ε\.?|ΑΑΔΕ|"
    r"Δ\.?\s*Ε\.?\s*Δ\.?|ΔΕΔ|ΔΙΕΥΘΥΝΣΗ\s+ΕΠΙΛΥΣΗΣ\s+ΔΙΑΦΟΡΩΝ|"
    r"ΥΠΟΔΙΕΥΘΥΝΣΗ\s+ΕΠΑΝΕΞΕΤΑΣΗΣ",
    re.IGNORECASE,
)
_DECISION_BODY_START_RE = re.compile(r"\bΑΠΟΦΑΣΗ\b", re.IGNORECASE)

# Invoice/document column headers whose cells must be fully redacted.
_INVOICE_COLUMN_HEADERS = {
    " ".join(header.split()).casefold()
    for header in (
        "ΠΑΡΑΣΤΑΤΙΚΟ",
        "ΠΑΡΑ ΣΤΑΤΙΚΟ",
        "ΑΡ. ΠΑΡΑΣΤΑΤΙΚΟΥ",
        "ΤΙΜΟΛΟΓΙΟ",
        "ΤΙΜ.",
        "ΑΡΙΘΜΟΣ",
        "ΣΤΟΙΧΕΙΟ",
    )
}


def _afm_checksum_ok(s: str) -> bool:
    """Return True if *s* is a valid Greek AFM according to its checksum."""
    if len(s) != 9 or not s.isdigit():
        return False
    total = sum(int(s[i]) * (2 ** (8 - i)) for i in range(8))
    return (total % 11) % 10 == int(s[8])


def _iban_checksum_ok(s: str) -> bool:
    """Return True if *s* passes the standard IBAN mod-97 checksum."""
    s = s.replace(" ", "").upper()
    if len(s) < 4:
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _normalized_greek_phone(value: str) -> str | None:
    """Normalize *value* to a 10-digit Greek phone number (mobile 69x or landline 2x),
    stripping non-digits and a +30/0030 country prefix; return None if it does not qualify."""
    if "\n" in value or "\t" in value:
        return None
    digits = re.sub(r"\D+", "", value)
    if digits.startswith("0030"):
        digits = digits[4:]
    elif digits.startswith("30") and len(digits) == 12:
        digits = digits[2:]
    if len(digits) != 10:
        return None
    if not (digits.startswith("69") or digits.startswith("2")):
        return None
    return digits


def _looks_like_official_contact_phone(text: str, start: int) -> bool:
    """Return True when a phone appears on an official authority contact line."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    if _OFFICIAL_CONTACT_LABEL_RE.search(line):
        return True

    # Allow unlabeled phones only in the pre-decision authority header block.
    prefix = text[:start]
    if _DECISION_BODY_START_RE.search(prefix):
        return False
    header_window = prefix[-800:] + "\n" + line
    return bool(_OFFICIAL_HEADER_CONTEXT_RE.search(header_window))
