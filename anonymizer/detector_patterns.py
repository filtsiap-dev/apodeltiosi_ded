import re

# Apostrophe variants used for the Greek elision in "υπ' αριθ." and FEK series letters:
# U+2019 right single quote, U+0027 ASCII apostrophe, U+02BC modifier apostrophe,
# U+1FBD greek koronis, U+0384 greek tonos.
_ELISION_APOSTROPHES = chr(0x2019) + chr(0x0027) + chr(0x02BC) + chr(0x1FBD) + chr(0x0384)

_DEFAULT_PATTERNS = {
    "afm": {"prefix": r"(?:Α\.?Φ\.?Μ\.?|AFM)\s*[:.]?\s*", "body": r"(\d{9})"},
    "amka": {"prefix": r"(?:ΑΜΚΑ|AMKA)\s*[:.]?\s*", "body": r"(\d{11})"},
    "email": {"body": r"[\w.+-]+@[\w-]+\.[\w.-]+"},
    "iban": {"body": r"[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]){1,30}"},
    "phone_intl": {"body": r"\+30[\s-]?(?:\d[\s-]?){10}"},
    "phone_local": {"body": r"(?:2|6)\d{9}"},
    "phone_00": {"body": r"0030\d{10}"},
    "protocol_number": {
        "prefix": r"(?:αριθμ[οό]\s+πρωτοκόλλου|αριθ\.?\s*πρωτ\.?|αρ\.?\s*πρωτ\.?|Πρωτ\.?)\s*[:.]?\s*",
        "body": r"([A-Za-z0-9Α-Ωα-ωΆ-ώ/\-]*\d[A-Za-z0-9Α-Ωα-ωΆ-ώ/\-]*(?:/\d{2,4})?)",
    },
    "act_number": {"body": r"Πράξη\s+([A-Za-z0-9Α-Ωα-ωΆ-ώ/\-]*\d[A-Za-z0-9Α-Ωα-ωΆ-ώ/\-]*)"},
    "audit_order": {
        "prefix": (
            r"(?:εντολ[ήέ]ς?\s+(?:μερικού\s+)?ελέγχου|Γνωστοποίησ(?:η|εις)|"
            r"Αίτημ(?:α|ατα)\s+Παροχής\s+Πληροφοριών|Πρόσκλησ(?:η|εις)|"
            r"Πληροφοριακή\s+Έκθεση|ΑΒΜ|ΕΞ)\s+"
        ),
        "body": r"([0-9]{2,}(?:\s*[/&]\s*[0-9]+)*(?:[/\-]\d{2,4}(?:[/\-.]\d{2,4})*)?)",
    },
    "invoice_number": {"body": r"(?:Τιμολόγιο|Α/Α)\s+(\d+)"},
    "transaction_id": {"body": r"(?:Συναλλαγή|ID)\s*[:.]?\s*([A-Za-z0-9]{6,})"},
    "date_numeric": {"body": r"\b(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})\b"},
    "date_greek": {
        "body": (
            r"\b(\d{1,2})η?\s+"
            r"(Ιανουαρίου|Φεβρουαρίου|Μαρτίου|Απριλίου|Μαΐου|Ιουνίου|"
            r"Ιουλίου|Αυγούστου|Σεπτεμβρίου|Οκτωβρίου|Νοεμβρίου|Δεκεμβρίου)"
            r"\s+(\d{4})\b"
        )
    },
    "dou": {"body": r"(?:Δ\.Ο\.Υ\.|ΔΟΥ)\s+([Α-ΩΆΈΉΊΌΎΏΪΫ][\wΆ-ώ\s]*)"},
    "legal_ref_law": {"body": r"[Νν]\.?\s*(\d+/\d+)|νόμος\s+(\d+/\d+)"},
    "legal_ref_pd": {"body": r"Π\.Δ\.\s*(\d+/\d+)"},
    "legal_ref_short": {"body": r"(?:Κ\.Φ\.Δ\.|Κ\.Ν\.)"},
    "article_ref": {
        "body": (
            r"(?:άρθρο|άρ\.)\s+\d+(?:\s*(?:παρ\.|παράγραφος)\s*\d+)?|"
            r"(?:παρ\.|παράγραφος)\s+\d+|(?:εδάφιο|περ\.)\s+[α-ωΑ-Ω]"
        )
    },
    "court_decision": {"body": r"[ΑΑ]\.\d+/\d{4}"},
    "money": {"body": r"(?:€\s*[\d.,]+|[\d.,]+\s*(?:€|ευρώ))"},
    "tax_year": {"body": r"(?:οικονομικό|φορολογικό)\s+έτος\s+\d{4}|χρήση\s+\d{4}"},
    "legal_ref_fek": {
        "body": rf"ΦΕΚ\s+[Α-ΩA-Z{_ELISION_APOSTROPHES}]+\s*\d+(?:[/,.]\s*\d+(?:[./]\d+)*)?"
    },
    "legal_ref_pol": {"body": r"ΠΟΛ\.?\s*\d{4}(?:[-/]\d{2,4}[-/]\d{2,4})?"},
    "legal_ref_ste": {"body": r"ΣτΕ\s*\d+/\d{2,4}"},
    "legal_ref_nsk": {"body": r"ΝΣΚ\s*\d+/\d{2,4}"},
    "legal_ref_aade": {
        "body": (
            r"Α\.Α\.Δ\.Ε\.|\bΑ[ΑA]ΔΕ\b|Δ\.Ε\.Δ\.|\bΔΕΔ\b|"
            r"Κ\.Ε\.ΜΕ\.Φ\.|Κ\.Ε\.ΦΟ\.ΜΕ\.Π\.|Υ\.Ε\.Δ\.Δ\.Ε\."
        )
    },
    "percentage": {"body": r"\b\d+(?:[.,]\d+)?\s*%"},
    "fiscal_period": {
        "body": (
            r"\b\d{2}[-/.]\d{2}[-/.]\d{4}\s+έως\s+\d{2}[-/.]\d{2}[-/.]\d{4}"
            r"|\bφορολογική\s+περίοδος\s+\d{4}"
        )
    },
}

_GREEK_CAPITALIZED = r"[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+"
_MEDICAL_TERMS = {
    "διάγνωση", "ασθένεια", "νόσος", "θεραπεία",
    "φαρμακευτική", "χειρουργείο", "καρκίνος", "διαβήτης",
}

_DATE_SUFFIX_RE = re.compile(r"^(.*?)([/\-])(\d{2}[/\-.]\d{2}[/\-.]\d{4})$")

_CHALLENGED_ACT_RE = re.compile(
    rf"(?:υπ[{_ELISION_APOSTROPHES}]\s*αρ(?:ιθ)?\.?|με\s+αριθ\.?)\s+"
    r"([0-9Α-ΩA-Z][0-9Α-ΩA-Z./\-]+)",
    re.IGNORECASE,
)
_CHALLENGED_ACT_CONTEXT_RE = re.compile(
    r"Οριστικ|Πράξ[ηή]|Διορθωτικ|Φ\.Π\.Α|Τελών|φόρου|προστίμου|Επιβολής", re.IGNORECASE
)

_AUTHORITY_HEADER_CUES = re.compile(
    r"ΕΛΛΗΝΙΚΗ\s+ΔΗΜΟΚΡΑΤΙΑ"
    r"|ΔΙΕΥΘΥΝΣΗ\s+ΕΠΙΛΥΣΗΣ\s+ΔΙΑΦΟΡΩΝ"
    r"|ΥΠΟΔΙΕΥΘΥΝΣΗ\s+ΕΠΑΝΕΞΕΤΑΣΗΣ"
    r"|Α\.Α\.Δ\.Ε\.|Α[ΑA]ΔΕ"
    r"|Ταχ\.\s*Δ/νση"
    r"|Ταχ\.\s*Κώδικας"
    r"|Τηλέφωνο"
    r"|Fax"
    r"|E-mail",
    re.IGNORECASE,
)
_DECISION_TITLE_RE = re.compile(r"ΑΠΟΦΑΣΗ\b")

_DECISION_NUMBER_RE = re.compile(r"Αριθμ[οό]ς\s+[Αα]πόφασης\s*:\s*\d+", re.IGNORECASE)
_DECISION_PLACE_DATE_RE = re.compile(
    r"(?:Αθήνα|Καλλιθέα|Θεσσαλονίκη|Πάτρα|Ηράκλειο|Λάρισα|Βόλος|Ιωάννινα)"
    r"[,\s]+\d{2}[-/.]\d{2}[-/.]\d{4}",
    re.IGNORECASE,
)

_APPELLANT_NAME_RE = re.compile(
    r"(?i:(?:ενδικοφανή\s+προσφυγή|προσφυγή)\s+τ(?:ης|ου))\s+"
    r"((?:[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)(?:\s+(?:[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+))*)"
)
_FATHER_NAME_RE = re.compile(
    r"\b(?i:τ(?:ου|ης))\s+"
    r"([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*)"
    r"\s+(?i:με\s+ΑΦΜ|κάτοικ|οδός|ατομική)"
)
_PRIVATE_ADDRESS_RE = re.compile(
    r"(?:κάτοικ(?:ος|η)\s+|οδός\s+)"
    r"([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ\s,.\d]+?)(?=\s{2,}|\.|,\s*[Ττ][Κκ]|\n|$)",
    re.IGNORECASE,
)
_BUSINESS_SEAT_RE = re.compile(
    r"με\s+έδρα\s+(?:τ(?:ην|ον)\s+)?"
    r"([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώ,.\s\d]+?)(?=\s{2,}|\.|,\s*(?:οδός|αρ\.|\d)|\n|$)",
    re.IGNORECASE,
)

# Each word of the captured name must start with an uppercase letter so the capture stops
# at the next lowercase prose word (capitalization-as-signal).
_COMPANY_WORD = r"[Α-ΩΆΈΉΊΌΎΏΪΫA-Z][Α-Ωα-ωΆ-ώa-zA-Z.&\-]*"
_COMPANY_NAME_AFTER_CTX = re.compile(
    r"(?i:με\s+επωνυμία\s+|εταιρε?ία\s+|εκδότρια\s+(?:νομική\s+οντότητα\s+)?)"
    rf"({_COMPANY_WORD}(?:\s+(?:&\s+)?{_COMPANY_WORD})*"
    r"(?:\s+(?:Α\.?Ε\.?|Ε\.?Π\.?Ε\.?|Ι\.?Κ\.?Ε\.?|Ο\.?Ε\.?|Ε\.?Ε\.?))?)"
)

# Trigger is case-insensitive; the account body stays case-sensitive so the capture does not
# run into lowercase prose, and must end on an alphanumeric.
_BANK_ACCOUNT_RE = re.compile(
    r"(?i:λογ\.\s*|λογαριασμ[οό]ν?\s*)"
    r"([A-ZΑ-Ω]{2}[0-9A-ZΑ-Ω\s]{4,29}[0-9A-ZΑ-Ω]|[0-9]{6,26})"
)
_BENEFICIARY_RE = re.compile(
    r"(?i:δικαιούχ[οη]\s+τ(?:ον|ην))\s+"
    r"([Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+(?:\s+[Α-ΩΆΈΉΊΌΎΏΪΫ][Α-Ωα-ωΆ-ώϊϋΐΰ]+)*)"
)

_FISCAL_ID_RE = re.compile(
    r"(?:αριθμ[οό]\s+μητρώου|ταμειακ[ήη]\s+(?:μηχαν[ήη]\s+)?|ΦΗΜ\s+)"
    r"([A-ZΑ-Ω0-9*]{2,}[\s\-]*[A-ZΑ-Ω0-9*]{2,})",
    re.IGNORECASE,
)
_PARTIAL_STAR_RE = re.compile(r"\b[A-ZΑ-Ω]{2,}\s*\*+[0-9A-ZΑ-Ω]+\b")

# Case-SENSITIVE with a leading word boundary (v1 compiled these IGNORECASE and
# unanchored, which made the trigger match inside ordinary lowercase words —
# "τιμολογίου" → ΤΙΜ + captured "ολογ", "Επαμεινώνδα" → ΔΑ — mutilating running
# prose). Real references use uppercase abbreviations ("ΤΙΜ. 190 σειρά Β").
_INVOICE_CELL_RE = re.compile(
    r"\b(?:ΤΙΜ\.?|ΤΠΥ|ΔΑ|ΑΠΥ|ΤΔΑ|ΔΕΛΤΙΟ)\s*[0-9Α-ΩA-Z./-]+(?:\s*σειρά\s*[Α-ΩA-Z])?",
)
# Paragraph-level variant: capture only the numeric identifier (group 1) and the series letter
# (group 2) so the document-type abbreviation and the word "σειρά" stay visible in running text.
_INVOICE_PARAGRAPH_RE = re.compile(
    r"\b(?:ΤΙΜ\.?|ΤΠΥ|ΔΑ|ΑΠΥ|ΤΔΑ|ΔΕΛΤΙΟ)\s*([0-9Α-ΩA-Z./-]+)(?:\s*σειρά\s*([Α-ΩA-Z]))?",
)

_SIGNATURE_TITLE_RE = re.compile(
    r"Ακριβ[εέ]ς\s+[Αα]ντίγραφο"
    r"|ΜΕ\s+ΕΝΤΟΛΗ|Με\s+εντολή"
    r"|Ο\s+ΠΡΟΪΣΤΑΜΕΝΟΣ|Η\s+ΠΡΟΪΣΤΑΜΕΝΗ"
    r"|Ο\s+ΔΙΕΥΘΥΝΤΗΣ|Η\s+ΔΙΕΥΘΥΝΤΡΙΑ"
    r"|Υποδιεύθυνσης\s+Επανεξέτασης"
    r"|Διοικητικής\s+Υποστήριξης",
    re.IGNORECASE,
)
_ISOLATED_ALLCAPS_NAME_RE = re.compile(r"^[Α-ΩΆΈΉΊΌΎΏΪΫ]+(?:\s+[Α-ΩΆΈΉΊΌΎΏΪΫ]+){1,3}$")
_PRIVATE_PARTY_CUE_RE = re.compile(
    r"προσφεύγ|υπόχρε|ΑΦΜ|κάτοικ|έδρα|δικαιούχ|πατέρ|αδελφ|σύζυγ|λογαριασμ",
    re.IGNORECASE,
)
