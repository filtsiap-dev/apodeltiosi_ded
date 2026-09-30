"""The typed failures this service can produce, and the codes they answer with.

Every error carries a stable ``code``. The code is what a caller branches on and
what a log line is grepped by, so it is part of the interface in a way the
message is not: messages are written for people and change freely, codes do not.

``public_detail`` is the sentence a caller may be shown. It is deliberately
separate from the exception message, because the message is raised from deep in
the document path and can quote a parser error or a ZIP member name — text that
came from the uploaded file. One is for the operator, the other for the caller,
and they must not be the same string by accident.

The HTTP status for each class lives in ``anonymizer.api``, not here: these are
domain failures, and the transport decides how to say them.
"""


class AnonymizerError(Exception):
    """Base class for all anonymizer errors."""

    #: Stable, greppable identifier for this failure. Overridable per raise when
    #: one class covers several distinguishable causes.
    code: str = "ANONYMIZER_ERROR"
    #: Safe to return to a caller. Never contains document-derived text.
    public_detail: str = "the request could not be processed"
    #: How this failure is named in the one final log line a document
    #: produces. Coarser than ``code`` on purpose: an operator counting
    #: outcomes wants to know how many documents failed on input versus on
    #: the provider, not which of six input problems it was.
    outcome: str = "internal_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class InvalidDocumentError(AnonymizerError):
    """The upload is not a document this service can read.

    Structurally malformed rather than merely unsupported: a broken ZIP, a
    package missing required parts, XML that does not parse, a relationship that
    points nowhere.
    """

    outcome = "invalid_input"
    code = "INVALID_DOCUMENT"
    public_detail = "the request body is not a readable Word (OOXML) document"


class UnsupportedDocumentFormatError(AnonymizerError):
    """A real document, in a format this service does not accept.

    Distinct from ``InvalidDocumentError`` because the caller's remedy is
    different: nothing is wrong with the file, it simply has to arrive as one of
    the accepted OOXML formats.
    """

    outcome = "unsupported_format"
    code = "UNSUPPORTED_DOCUMENT_FORMAT"
    public_detail = (
        "unsupported document format; send a .docx, .docm, .dotx or .dotm file"
    )


class ResourceLimitExceededError(AnonymizerError):
    """The request exceeds a configured size or expansion limit.

    Raised before the work it would have cost is done — that is the whole point
    of the limits — so it says what was refused, never what was in it.
    """

    outcome = "resource_limit"
    code = "RESOURCE_LIMIT_EXCEEDED"
    public_detail = "the document exceeds a configured size or resource limit"


class PromptInjectionError(AnonymizerError):
    """The document carries text shaped like an instruction to the model.

    Deterministic, pattern-based, and deliberately narrow. It names the rule that
    matched and where, and never the text that matched — echoing that back would
    hand the attempt straight into the logs.
    """

    outcome = "prompt_injection"
    code = "PROMPT_INJECTION_DETECTED"
    public_detail = (
        "the document contains content matching a prompt-injection pattern "
        "and was refused"
    )


class DocumentProcessingError(AnonymizerError):
    """Valid input, and this service could not produce valid output from it.

    Ours, not the caller's: it maps to a 5xx. A document that arrives readable
    and leaves unreadable is a bug here, and saying so with a 4xx would send the
    caller looking at a file that is fine.
    """

    outcome = "output_failure"
    code = "DOCUMENT_PROCESSING_FAILED"
    public_detail = "the redacted document could not be produced"


class ResidualPIIError(AnonymizerError):
    """The redacted DOCX failed its mandatory post-redaction scan.

    Raised after redaction succeeded but the scan of the produced file still
    found HIGH-severity personal information. The document is never returned or
    saved as a successful result; it needs manual review.
    """

    outcome = "residual_pii"
    code = "RESIDUAL_PII_FOUND"
    public_detail = (
        "the redacted document failed its post-redaction scan and needs "
        "manual review"
    )


class ConfigurationError(AnonymizerError):
    """Missing or invalid runtime configuration."""

    outcome = "configuration_error"
    code = "CONFIGURATION_ERROR"
    public_detail = "the service is misconfigured"


class AIUnavailableError(AnonymizerError):
    """AI provider unreachable (connection errors)."""

    outcome = "provider_failure"
    code = "AI_UNAVAILABLE"
    public_detail = "the language-model provider is unreachable; retry later"


class AIProviderError(AnonymizerError):
    """AI provider API error or unusable output."""

    outcome = "provider_failure"
    code = "AI_PROVIDER_ERROR"
    public_detail = "the language-model provider failed; retry later"


class AITimeoutError(AnonymizerError):
    """Per-call AI timeout exceeded."""

    outcome = "provider_failure"
    code = "AI_TIMEOUT"
    public_detail = "the language-model provider timed out; retry later"


class DocumentTimeoutError(AnonymizerError):
    """The document ran out of its end-to-end processing budget.

    Distinct from :class:`AITimeoutError`, which is one provider call taking too
    long. This is the whole document taking too long, whatever it was doing, and
    it means no output is produced: a partial DOCX returned after the deadline
    would be a document nobody finished checking.
    """

    code = "DOCUMENT_TIMEOUT"
    outcome = "timeout"
    public_detail = "processing exceeded the document deadline"

    def __init__(self, stage: str) -> None:
        super().__init__(f"the document deadline expired during {stage}")
        #: The stage that was starting when the budget ran out. A fixed name
        #: from this code, never anything derived from the document.
        self.stage = stage


class InternalError(AnonymizerError):
    """An unexpected failure, wrapped so it leaves by the typed path.

    An exception that escapes the endpoint is re-raised by Starlette after the
    500 is sent, and the server then logs it with its full text — which for a
    failure deep in the document path can quote the document. Wrapping it here
    keeps the traceback in one place, logged in a controlled form, and gives the
    caller the same fixed body either way.
    """

    code = "INTERNAL_ERROR"
    outcome = "internal_error"
    public_detail = "internal error"
