from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:  # import-cycle-free: postcheck imports docx_engine, which imports this module
    from anonymizer.postcheck import PostcheckSummary


@dataclass(frozen=True)
class XmlCharRef:
    part_name: str
    text_node_path: str
    char_index: int


# NOTE: parse_docx currently emits ONLY "paragraph" and "table_cell" — text
# from headers/footers/footnotes/endnotes/textboxes is parsed but typed as
# "paragraph" (distinguishable via TextUnit.part_name). The remaining values
# are reserved for future finer typing and are not yet produced.
UnitType = Literal[
    "paragraph",
    "table_cell",
    "header",
    "footer",
    "footnote",
    "endnote",
    "comment",
    "textbox",
]


@dataclass
class TextUnit:
    unit_id: str
    part_name: str
    unit_type: UnitType
    text: str
    normalized_text: str
    char_map: list[XmlCharRef]
    location: dict


@dataclass
class DocumentData:
    document_id: str
    text_units: list[TextUnit]
    parts_inventory: list[str]
    warnings: list[str] = field(default_factory=list)


SpanCategory = Literal[
    "AFM",
    "AMKA",
    "IBAN",
    "EMAIL",
    "PHONE",
    "PROTOCOL_NUMBER",
    "ACT_NUMBER",
    "AUDIT_ORDER",
    "INVOICE_NUMBER",
    "TRANSACTION_ID",
    "PRIVATE_ADDRESS",
    "DATE",
    "DOU",
    "PUBLIC_SERVICE",
    "LEGAL_REF",
    "ARTICLE_REF",
    "COURT_DECISION",
    "MONEY",
    "TAX_YEAR",
    "FISCAL_PERIOD",
    "POSSIBLE_PERSON",
    "POSSIBLE_COMPANY",
    "POSSIBLE_PRIVATE_LOCATION",
    "MEDICAL_TERM",
    "CHALLENGED_ACT_NUMBER",
    "CASE_REF_NUMBER",
    "PUBLIC_AUTHORITY_HEADER",
    "DECISION_METADATA",
    "OFFICIAL_SIGNATORY",
    "APPELLANT_NAME",
    "FATHER_NAME",
    "PRIVATE_COMPANY_NAME",
    "BANK_ACCOUNT",
    "PRIVATE_BENEFICIARY",
    "FISCAL_DEVICE_ID",
    "INVOICE_TABLE_ID",
    "PERCENTAGE",
    "BUSINESS_SEAT",
]


SpanAction = Literal["REDACT", "PRESERVE", "REVIEW"]
"""REVIEW exists only before resolution (deterministic review hints and LLM pass-1 findings). It must never appear in a RedactionPlan."""


@dataclass
class Span:
    unit_id: str
    start: int
    end: int
    text: str
    category: SpanCategory
    detector: str
    confidence: float
    action: SpanAction
    reason: str


@dataclass
class RedactionPlan:
    document_id: str
    spans: list[Span]
    warnings: list[str] = field(default_factory=list)


@dataclass
class PlanSummary:
    spans_total: int
    by_action: dict[str, int]
    by_category: dict[str, int]
    by_detector: dict[str, int]
    warnings: list[str]


@dataclass
class AnonymizeResult:
    document_id: str
    redacted_docx: bytes
    summary: PlanSummary
    warnings: list[str]
    model: str
    timings: dict[str, float]
    # Counts from the mandatory post-redaction scan of THIS output. A result
    # only ever exists with zero HIGH findings — a HIGH raises ResidualPIIError
    # instead — so this reports the lower-severity warnings that did not block
    # the file.
    postcheck: "PostcheckSummary | None" = None
    # Reproducibility stamp: which rules and prompts produced this output.
    # Keys: provider, model, config_sha256, prompts_sha256, package_version.
    provenance: dict[str, str] = field(default_factory=dict)


REDACTION_GLYPH = "."

REDACT_CATEGORIES = {
    "AFM",
    "AMKA",
    "IBAN",
    "EMAIL",
    "PHONE",
    "PROTOCOL_NUMBER",
    "ACT_NUMBER",
    "AUDIT_ORDER",
    "INVOICE_NUMBER",
    "TRANSACTION_ID",
    "PRIVATE_ADDRESS",
    "CHALLENGED_ACT_NUMBER",
    "CASE_REF_NUMBER",
    "APPELLANT_NAME",
    "FATHER_NAME",
    "BUSINESS_SEAT",
    "PRIVATE_COMPANY_NAME",
    "BANK_ACCOUNT",
    "PRIVATE_BENEFICIARY",
    "FISCAL_DEVICE_ID",
    "INVOICE_TABLE_ID",
}

PRESERVE_CATEGORIES = {
    "DATE",
    "DOU",
    "PUBLIC_SERVICE",
    "LEGAL_REF",
    "ARTICLE_REF",
    "COURT_DECISION",
    "MONEY",
    "TAX_YEAR",
    "FISCAL_PERIOD",
    "PUBLIC_AUTHORITY_HEADER",
    "DECISION_METADATA",
    "OFFICIAL_SIGNATORY",
    "PERCENTAGE",
}

REVIEW_CATEGORIES = {
    "POSSIBLE_PERSON",
    "POSSIBLE_COMPANY",
    "POSSIBLE_PRIVATE_LOCATION",
    "MEDICAL_TERM",
}

ALL_CATEGORIES: frozenset[str] = frozenset(
    REDACT_CATEGORIES | PRESERVE_CATEGORIES | REVIEW_CATEGORIES
)
