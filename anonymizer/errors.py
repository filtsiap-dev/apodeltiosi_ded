class AnonymizerError(Exception):
    """Base class for all anonymizer errors."""


class InvalidDocumentError(AnonymizerError):
    """Bad, corrupt, or non-DOCX upload."""


class DocumentProcessingError(AnonymizerError):
    """Valid DOCX but a redaction plan cannot be produced or applied."""


class ResidualPIIError(AnonymizerError):
    """The redacted DOCX failed its mandatory post-redaction scan.

    Raised after redaction succeeded but the scan of the produced file still
    found HIGH-severity personal information. The document is never returned or
    saved as a successful result; it needs manual review.
    """


class ConfigurationError(AnonymizerError):
    """Missing or invalid runtime configuration."""


class AIUnavailableError(AnonymizerError):
    """AI provider unreachable (connection errors)."""


class AIProviderError(AnonymizerError):
    """AI provider API error or unusable output."""


class AITimeoutError(AnonymizerError):
    """Per-call AI timeout exceeded."""
