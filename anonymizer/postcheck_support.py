"""Independent audit constants and helpers for the MANDATORY post-redaction scan.

Independent, which is about what this module shares rather than when it runs.
Stdlib ``re`` only, no ``anonymizer.*`` imports, no logging — so the auditor
cannot inherit a blind spot from the detectors it audits. That is why the
checksum helpers here deliberately duplicate the ones in ``detector_support``
instead of importing them.

It is NOT out-of-band. ``postcheck.py`` uses these helpers on every document,
as the final stage of ``anonymize_document``, for the CLI and the HTTP API
alike. The CLI's ``--qa`` flag does not enable any of it; it only prints the
findings the scan already produced.
"""

import re

qa_patterns = {
    "AFM": re.compile(r"\b(\d{9})\b"),
    "AMKA": re.compile(r"\b(\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{5})\b"),
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

# A run of capitalised words: the NAME half of the two leak patterns below, and
# the exact slice a remediation REDACT would blank. Two scoping rules, both
# learned the hard way, both invisible until the span became a write boundary:
#
# ``(?-i:)`` — the cue around it is matched case-insensitively, because a
# document may write it either way. The name must NOT be: under the outer
# IGNORECASE the "capitalised word" class matches lower-case letters too, so the
# run walked past the name and through the rest of the sentence, and
# "ΜΙΧΟΥ ΝΙΚΟΛΑΟΥ κατά της πράξης του Προϊσταμένου" was one surviving name.
#
# ``[ \t]+`` between the words, never ``\s+`` — ``postcheck`` joins text units
# with "\n", and a name run that accepts any whitespace runs straight through
# that join into the next paragraph. It then spans two units, belongs to
# neither, and is dropped for having nowhere to be written: a name followed by a
# heading ("… ΜΙΧΟΥ ΝΙΚΟΛΑΟΥ\nΣΥΝΟΨΗ") produced no remediable finding at all.
# This is the same lesson ``_PROPERTY_LIST_SEP`` below records.
_NAME_RUN = (
    r"(?-i:([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+(?:[ \t]+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ]+)*))"
)

# Case-specific reference value surviving after a trigger label.
_CASE_REF_LEAK_RE = re.compile(
    r"(?:υπ['’]\s*αρ(?:ιθ)?\.?|αρ\.?\s*πρωτ\.?|αριθμ[οό]\s+πρωτοκόλλου"
    r"|εντολ[ήέ]ς?\s+(?:μερικού\s+)?ελέγχου|Γνωστοποίησ[ηεις]+"
    r"|Αίτημ[αα]\s+Παροχής\s+Πληροφοριών|ΑΒΜ|ΕΞ)\s+"
    r"(\d[0-9A-ZΑ-Ω./\-]{2,})",
    re.IGNORECASE,
)

# Beneficiary name surviving after δικαιούχο τον/την. Group 1 is the NAME on
# its own: the cue and its article are structural text that stays visible, and a
# remediation candidate built from the whole match would put them to pass 2 too.
#
# THE WHOLE NAME, not its first word. One word was enough while this only
# located a warning; as the slice a REDACT blanks it published the surname —
# "δικαιούχο τον Γεώργιο Παπαδόπουλο" redacted to "....... Παπαδόπουλο" and the
# document was reported clean. See ``_NAME_RUN`` for the two scoping rules the
# extra words need.
_BENEFICIARY_LEAK_RE = re.compile(
    r"δικαιούχ[οη]\s+τ(?:ον|ην)\s+" + _NAME_RUN, re.IGNORECASE
)

# Partial-star masked identifier residue (e.g. DCX *****423).
_PARTIAL_STAR_RESIDUE_RE = re.compile(r"\b[A-ZΑ-Ω]{2,}\s*\*+[0-9A-ZΑ-Ω]+\b")

# Person name surviving after key context phrases. Group 1 is the NAME.
_PERSON_LEAK_RE = re.compile(
    r"(?:ενδικοφανή\s+προσφυγή\s+τ(?:ης|ου)\s+|με\s+ΑΦΜ\s+\.+\s+)" + _NAME_RUN,
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

# --- property / cadastral identifiers --------------------------------------
#
# Independently spelled out, like the checksums above. An auditor that imported
# the detector's own patterns could not catch the detector being wrong about
# them, which is the whole point of this module.
#
# LIST-AWARE, and that is the load-bearing part. These identifiers arrive as
# "ΑΤΑΚ 00610643353, 00610643361 και 01188179990", and a partial failure leaves
#
#     ΑΤΑΚ ..........., 00610643361 και ...........
#
# where a plain "label followed by digits" test sees dots immediately after the
# label and reports nothing. So the cue is matched first, and then the bounded
# comma/"και"-joined run after it is walked item by item.
# EVERY SHAPE THE DETECTOR ACCEPTS, or the audit is narrower than the thing it
# audits and reports clean on a real leak. Each value shape below deliberately
# mirrors one in detectors._PROPERTY_VALUE_RES — arrived at independently, but
# checked against it: an Ο.Τ. may be a single digit with a suffix letter, an
# Α.Χ.Κ. may be a plain run of digits rather than "76/19062", and a notice
# number is a property identifier too.
_PROPERTY_ID_SPECS = (
    # (name, cue pattern, one value's shape)
    ("ΑΤΑΚ", r"Α\.?\s*Τ\.?\s*Α\.?\s*Κ\.?", r"\d{11}"),
    ("ΚΑΕΚ", r"Κ\.?\s*Α\.?\s*Ε\.?\s*Κ\.?", r"\d{12}(?:/\d+)*"),
    # Lower case too. The detector's outer capture is case-insensitive, so it
    # redacts "Ο.Τ. 12α"; a case-sensitive auditor would call the surviving "α"
    # clean.
    ("Ο.Τ.", r"Ο\.\s*Τ\.?", r"\d+[Α-ΩA-Zα-ωά-ώa-z]?"),
    ("Α.Χ.Κ.", r"Α\.?\s*Χ\.?\s*Κ\.?", r"\d+(?:/\d+)+|\d{3,}"),
    # The serial's POSITION, not its length. This used to be "\d{5,}", chosen so
    # that the "/2026" a correctly redacted "αριθμό ειδοποίησης ……/2026"
    # keeps would not read as a leak — but a minimum length is the wrong tool for
    # that, and it blinded the scan to a short one ("… 1234", "… 12/2026"), which
    # the detector does redact.
    #
    # Length is unnecessary here: the walk reaches the retained date only THROUGH
    # the dots that replaced the serial, and a dot-run item stops at the slash.
    # So a visible serial is a digit in the serial's own position, whatever its
    # length, and the date after a redacted one is never examined at all.
    ("αριθμό ειδοποίησης", r"αριθμ[οό]\s+ειδοποίησης", r"\d[\d/\-]*"),
)

# How far past the cue the list may run before we stop looking. Generous enough
# for three values and their separators, short enough that an unrelated number
# later in the sentence is not attributed to the label.
_PROPERTY_LIST_BUDGET = 160

# One item of such a list: a surviving value, or the glyphs that replaced one.
# A SINGLE dot counts — a one-character value redacts to one dot, and requiring
# two broke the run at that point and hid whatever came after it.
_PROPERTY_LIST_ITEM = r"(?:{value}|\.+|…+)"

# The separator must be EXPLICIT. It used to accept bare whitespace, which
# matches the "\n" this module joins text units with — so "Ο.Τ. ..." at the end
# of one paragraph ran into "2019 ήταν το φορολογικό έτος" at the start of the
# next and reported the year as a surviving identifier, failing a correctly
# redacted document. Horizontal space only, and never a newline.
_PROPERTY_LIST_SEP = r"[ \t]*(?:,|και)[ \t]*"

_PROPERTY_ID_PATTERNS = tuple(
    (
        name,
        re.compile(cue + r"\s*:?\s*", re.IGNORECASE),
        re.compile(value),
        re.compile(
            _PROPERTY_LIST_ITEM.format(value=value)
            + r"(?:" + _PROPERTY_LIST_SEP + _PROPERTY_LIST_ITEM.format(value=value) + r")*"
        ),
    )
    for name, cue, value in _PROPERTY_ID_SPECS
)


def _residual_property_ids(text: str):
    """Yield ``(name, start, end)`` for every property identifier still visible.

    Walks the bounded list after each cue rather than testing the one value that
    happens to sit closest to it, so a partially-redacted list is caught.

    The END travels with the start because a residual is not only something to
    warn about: ``postcheck`` turns each one into an exact slice of a text unit,
    which is what lets the remediation pass be asked about THIS occurrence
    rather than about a string that may also appear somewhere else.
    """
    for name, cue_re, value_re, list_re in _PROPERTY_ID_PATTERNS:
        for cue in cue_re.finditer(text):
            window = text[cue.end(): cue.end() + _PROPERTY_LIST_BUDGET]
            # A list never spans a text unit. Cutting at the join keeps a value
            # in the NEXT paragraph from being attributed to this label.
            window = window.split("\n", 1)[0]
            run = list_re.match(window)
            if run is None:
                continue
            for value in value_re.finditer(run.group(0)):
                yield name, cue.end() + value.start(), cue.end() + value.end()


# Structural labels whose disappearance is OVER-redaction. Counted in the source
# and again in the output: the label is not personal data and the published
# decisions keep every one of them, so a drop means a span took the label along
# with the value it was supposed to blank.
_LABEL_VOCABULARY = (
    "Α.Φ.Μ.", "ΑΦΜ", "ΑΜΚΑ", "ΙΒΑΝ", "ΑΤΑΚ", "Α.Τ.Α.Κ.", "ΚΑΕΚ", "Ο.Τ.", "Α.Χ.Κ.",
    "Τ.Κ.", "κάτοικος", "κατοίκου", "οδός", "οδού", "Λεωφ.", "αρ.",
    "αριθμό πρωτοκόλλου", "αρ. πρωτ.", "αριθμό ειδοποίησης", "Πράξη", "Τιμολόγιο",
    "Τράπεζα", "Τηλέφωνο", "Ταχ. Δ/νση", "E-mail", "Fax",
)


def _label_counts(text: str) -> dict:
    """How many times each structural label appears in ``text``."""
    counts = {}
    for label in _LABEL_VOCABULARY:
        counts[label] = len(re.findall(re.escape(label), text, re.IGNORECASE))
    return counts


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
