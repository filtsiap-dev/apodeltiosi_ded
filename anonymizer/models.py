from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypeGuard, get_args

if TYPE_CHECKING:  # import-cycle-free: postcheck imports docx_engine, which imports this module
    from anonymizer.llm.usage import LlmUsage
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
    # The structural label that introduces a value — "Α.Φ.Μ.", "ΑΤΑΚ", "οδός".
    # Never personal data itself, and the ΔΕΔ convention keeps every one of them
    # visible while blanking what follows. Hard-preserved, so no span of any
    # width can take the label with the value.
    "FIELD_LABEL",
    # Cadastral / property-register identifiers: ΑΤΑΚ, ΚΑΕΚ, Ο.Τ., Α.Χ.Κ., and
    # the notice number that behaves like them. Always cue-anchored.
    "PROPERTY_ID",
    # A date established as procedural by an explicit cue ("ημερομηνία
    # κατάθεσης", "εκδόθηκε στις"). DISTINCT FROM `DATE` on purpose: only this
    # one is hard-preserved, because only this one has positive evidence that it
    # is not a date of birth.
    "PROCEDURAL_DATE",
    # A court decision referenced as part of THIS case's history, as opposed to
    # jurisprudence cited as precedent (which stays `COURT_DECISION`). Ordinary,
    # so pass 2 decides which of the two a given reference is.
    "CASE_COURT_REFERENCE",
    # A place name following a locality cue (Δήμου, Πρωτοδικείου, συνοικία).
    # Ordinary REDACT: a public authority's locality is preserved and a party's
    # is not, and only pass 2 can tell those apart.
    "LOCALITY",
]


SpanAction = Literal["REDACT", "PRESERVE", "REVIEW"]
"""REVIEW exists only before resolution (deterministic review hints and LLM pass-1 findings). It must never appear in a RedactionPlan."""


FinalAction = Literal["REDACT", "PRESERVE"]
"""A DECISION. REVIEW is excluded by construction rather than by checking.

Pass 2 and the resolver both deal only in final actions, and typing them
this way makes 'a REVIEW reached the plan' unrepresentable rather than
merely asserted against at runtime.
"""


SpanOrigin = Literal["deterministic", "llm_pass2"]
"""WHICH AUTHORITY PRODUCED A SPAN. The resolver arbitrates on this, so it is a
contract rather than a label.

* ``deterministic`` — a rule-engine detection. In one of the policy's
  ``hard_*_categories`` it is an authoritative POLICY DECISION; otherwise it is
  a recommendation, and pass 2 is the one asked to settle it.
* ``llm_pass2`` — a final pass-2 adjudication. It outranks every ordinary
  deterministic span and no hard-policy one.

Distinct from ``Span.detector``, which is a free-form diagnostic name that ends
up in the summary. Precedence must never be decided by string-matching a
detector name; this field exists so that it does not have to be.
"""


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
    # Defaults to deterministic: every producer but the LLM layer is a rule, and
    # a span that forgets to declare itself is treated as ordinary evidence
    # rather than silently borrowing pass-2 authority.
    origin: SpanOrigin = "deterministic"


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


UnresolvedKind = Literal[
    "candidate_undecided",
    "candidate_duplicated",
    "discovery_undecided",
    "discovery_conflicting",
    "discovery_malformed",
    "discovery_unlocatable",
]
"""WHY A FINDING WAS LEFT FOR A PERSON. One value per way pass 2 can fail to
settle something it was asked about, or that it raised itself:

* ``candidate_undecided`` — a queued candidate came back with no final decision,
  even after the corrective retry;
* ``candidate_duplicated`` — the final response answered one id twice, so every
  answer for it was voided and none replaced them;
* ``discovery_undecided`` — a span pass 2 found for itself was re-asked by id and
  still came back undecided;
* ``discovery_conflicting`` — pass 2 returned the same new text twice with
  different answers;
* ``discovery_malformed`` — a new finding with no usable action or category;
* ``discovery_unlocatable`` — a new finding whose text is not in the excerpt, so
  there is nowhere to write it and no id to re-ask it by.
"""


@dataclass(frozen=True)
class UnresolvedFinding:
    """One thing the LLM stage could not settle, described without quoting it.

    These are the reason a document can come back ``needs_review``. They are NOT
    decisions: nothing is written for them, and they are never turned into a
    PRESERVE — the text stays exactly as it was, covered by whatever ordinary
    deterministic evidence happens to reach it, and a person is told where to
    look.

    CARRIES NO DOCUMENT TEXT, EVER. ``locations`` says where to look and
    ``category`` what it was thought to be; the words themselves stay in the
    document. This object reaches logs, the CLI, and (as a count) an HTTP
    response header, so a ``text`` field here would be a leak in three places at
    once.
    """

    chunk_index: int
    kind: UnresolvedKind
    # The category the finding was thought to be, when anything knew. None for a
    # discovery whose category was the unusable part.
    category: str | None = None
    # Every slice a reviewer should look at: (unit_id, start, end). Empty when
    # the finding could not be located at all, which is itself why it is here.
    locations: tuple[tuple[str, int, int], ...] = ()
    # The transient C<n> handle from the chunk's adjudication. Correlates this
    # finding with the chunk's log lines; means nothing outside that chunk.
    candidate_id: str | None = None
    # A short machine-written phrase: counts and shapes only.
    detail: str = ""

    @property
    def chunk_number(self) -> int:
        """The chunk as a person counts it: 1-based, like every other report."""
        return self.chunk_index + 1


@dataclass
class AnonymizeResult:
    document_id: str
    redacted_docx: bytes
    summary: PlanSummary
    warnings: list[str]
    model: str
    timings: dict[str, float]
    # Counts from the mandatory post-redaction scan, which ran ONCE, BEFORE the
    # remediation pass that its own findings drive. So it is a record of what
    # was found, not a description of the bytes in ``redacted_docx``: a HIGH
    # finding here is normal on a result, and means the scan saw a slice of text
    # that was then put back to LLM pass 2 — which may have redacted it, may
    # have preserved it, and may have left it open (see ``unresolved``). The
    # HIGH findings that DO stop a document are the ones naming no text slice, a
    # macro or a tracked change, and those raise ResidualPIIError instead of
    # reaching here. ``result.warnings`` says how many were re-adjudicated.
    postcheck: "PostcheckSummary | None" = None
    # Token accounting for THIS document only — every pass-1 call, pass-2 first
    # attempt and pass-2 retry it made, and nothing from any other document.
    # None only if the LLM stage never ran.
    llm_usage: "LlmUsage | None" = None
    # Reproducibility stamp: which rules and prompts produced this output.
    # Keys: provider, model, config_sha256, prompts_sha256, package_version.
    provenance: dict[str, str] = field(default_factory=dict)
    # What pass 2 could not settle. A result can exist with these present: they
    # are handed to a person rather than guessed at, and nothing was written for
    # them. Empty on a document that was adjudicated completely.
    unresolved: tuple[UnresolvedFinding, ...] = ()

    @property
    def unresolved_count(self) -> int:
        """How many findings a person still has to settle."""
        return len(self.unresolved)

    @property
    def needs_review(self) -> bool:
        """Whether this document carries work for a human reviewer.

        It means the LLM stage left questions open that a person must close —
        either in its ordinary adjudication, or in the re-ask the post-redaction
        scan drives. Both leave the text exactly as it was rather than inventing
        an answer for it, so a ``True`` here can mean that a value the scan
        flagged is still visible: there is no second scan to turn that into a
        refusal, and the honest thing to do is hand over the file and say where
        to look. ``X-Unresolved-Count`` is the count and each finding carries
        its ``(unit_id, start, end)``.

        What it never means is that nobody looked. A document carrying a
        HIGH finding no redaction could settle raises instead of becoming a
        result.
        """
        return bool(self.unresolved)

    @property
    def status(self) -> Literal["processed", "needs-review"]:
        """The operational outcome, in the two words a caller acts on.

        ONE SPELLING, everywhere a caller can see it: this value is the
        ``X-Anonymization-Status`` header, the CLI's printed status line and
        the ``--summary-json`` field. An integrator who reads the header and
        a person who reads the console are looking at the same string.

        Not to be confused with the ``outcome=`` field in the one
        ``document_finished`` log line. That is a different vocabulary for a
        different reader — it also has to name timeouts, provider failures
        and refusals, none of which produce a status at all, because none of
        them produce a document.
        """
        return "needs-review" if self.unresolved else "processed"


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
    "PROPERTY_ID",
    "LOCALITY",
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
    "FIELD_LABEL",
    "PROCEDURAL_DATE",
    "CASE_COURT_REFERENCE",
}

REVIEW_CATEGORIES = {
    "POSSIBLE_PERSON",
    "POSSIBLE_COMPANY",
    "POSSIBLE_PRIVATE_LOCATION",
    "MEDICAL_TERM",
}

# DERIVED from the type, not maintained beside it. The three buckets above
# say what the service DOES with a category; this says which categories
# exist, and it cannot drift from `SpanCategory` because it is read off it.
# That the buckets partition it exactly is pinned by a test.
ALL_CATEGORIES: frozenset[str] = frozenset(get_args(SpanCategory))
FINAL_ACTIONS: frozenset[str] = frozenset(get_args(FinalAction))


def is_category(value: str) -> TypeGuard[SpanCategory]:
    """Whether ``value`` is a category, narrowing its type when it is.

    A ``TypeGuard`` rather than a ``cast``: the check is real at runtime AND
    the type narrows, so the boundary where a model-supplied string becomes
    a known category is one place that is checked rather than asserted.
    """
    return value in ALL_CATEGORIES


def is_final_action(value: str) -> TypeGuard[FinalAction]:
    """Whether ``value`` is a decision — REDACT or PRESERVE, never REVIEW."""
    return value in FINAL_ACTIONS
