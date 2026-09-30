"""Configuration layer for the v2 Greek document-anonymization service.

Two independent configuration sources, each with its own loader:

* runtime config, read from the process environment (provider selection,
  secrets, tuning knobs) via :func:`load_runtime_config`;
* file config, read from a ``config/`` directory (policy thresholds, detector
  rules, allowlists) via :func:`load_file_config`.

Nothing is read from disk or the environment at import time — every read
happens inside a loader call, keeping the module import-safe and testable by
injecting an explicit ``env`` mapping or ``config_dir``.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Mapping, TypedDict, TypeGuard
from urllib.parse import urlsplit

import yaml

from anonymizer.detector_patterns import _DEFAULT_PATTERNS
from anonymizer.errors import ConfigurationError
from anonymizer.injection_screen import InjectionRule, compile_rules
from anonymizer.limits import DEFAULT_LIMITS, ResourceLimits
from anonymizer.models import ALL_CATEGORIES

logger = logging.getLogger(__name__)

# Level names logging accepts. Checked here so an unknown one is a typed
# configuration error rather than a ValueError from inside basicConfig.
_LOG_LEVELS = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"})


Provider = Literal["openai", "azure"]
PROVIDERS: frozenset[str] = frozenset(("openai", "azure"))


def is_provider(value: str) -> TypeGuard[Provider]:
    """Whether ``value`` names a supported provider, narrowing it when it does.

    ANON_PROVIDER arrives as an arbitrary environment string. This is the one
    place it is checked, and the check is what gives it its type — so no
    later code has to re-assert that the string is one of the two the client
    knows how to build.
    """
    return value in PROVIDERS


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

class _Tuning(TypedDict, total=False):
    """The optional knobs ``load_runtime_config`` may override.

    Collected in a mapping rather than passed as arguments because 'the
    variable was absent' and 'the variable was set to the default' must reach
    ``RuntimeConfig`` identically, and only an absent key does that. Typed
    rather than ``dict[str, object]`` so each assignment below is checked
    against the field it will land in: a float written into ``llm_concurrency``
    is now an error at the assignment, not an implausible value at runtime.
    """

    llm_timeout_s: float
    chunk_size_chars: int
    max_completion_tokens: int
    llm_concurrency: int
    log_level: str
    document_deadline_s: float
    limits: ResourceLimits


@dataclass(frozen=True)
class RuntimeConfig:
    provider: Provider
    openai_api_key: str | None
    openai_model: str | None
    azure_api_key: str | None
    azure_endpoint: str | None
    azure_deployment: str | None
    azure_api_version: str | None
    # Bearer token every POST /anonymize request must present. Optional here
    # because the CLI never needs it; the HTTP app refuses to start without it
    # (see anonymizer.api.lifespan). Never logged, never returned in a response.
    anon_api_key: str | None = None
    llm_timeout_s: float = 60.0
    chunk_size_chars: int = 3000
    max_completion_tokens: int = 3000
    llm_concurrency: int = 8
    log_level: str = "INFO"
    # The end-to-end budget for one document, from the moment it is
    # authenticated to the moment its bytes are ready. Covers the upload,
    # every stage, every provider call and every retry sleep.
    document_deadline_s: float = 300.0
    # Finite bounds on one document's size, expansion and processing cost.
    # See anonymizer/limits.py for what each one closes and why the
    # defaults are the numbers they are.
    limits: ResourceLimits = DEFAULT_LIMITS

    @property
    def model_handle(self) -> str:
        """The provider-appropriate model identifier used by the LLM client.

        For ``openai`` this is the OpenAI model name; for ``azure`` it is the
        deployment name. ``load_runtime_config`` guarantees the relevant field
        is populated for the selected provider.
        """
        handle = (
            self.openai_model if self.provider == "openai"
            else self.azure_deployment
        )
        if handle is None:
            # The loader guarantees the selected provider's field is set;
            # this turns 'guaranteed' into something the reader can see.
            raise ConfigurationError(
                f"no model handle configured for ANON_PROVIDER={self.provider}"
            )
        return handle


@dataclass(frozen=True)
class PolicySettings:
    preserve_high_confidence_threshold: float
    redact_high_confidence_threshold: float
    redact_threshold: float
    hard_preserve_categories: frozenset[str]
    hard_redact_categories: frozenset[str]


@dataclass(frozen=True)
class DetectorRules:
    patterns: dict[str, dict[str, str]]
    dou_allowlist: frozenset[str]
    public_services: frozenset[str]
    legal_refs: frozenset[str]
    preserve_email_domains: frozenset[str]
    # Administrative regions that stay visible inside an address capture. The
    # gold blanks the municipality and keeps the region ("κατοίκου Χαλανδρίου
    # Αττικής"), so this is a TRIM list, not a detection list — it never
    # produces a span of its own. Empty by default, which simply means no
    # trimming happens.
    regions: frozenset[str] = frozenset()


@dataclass(frozen=True)
class FileConfig:
    policy: PolicySettings
    rules: DetectorRules
    # Compiled prompt-injection screening rules. Compiled at LOAD time, so a
    # broken pattern stops the service starting rather than surfacing in the
    # middle of somebody's document.
    injection_rules: tuple[InjectionRule, ...] = ()
    # sha256 over the raw bytes of every config file loaded (policy.yaml,
    # regex_patterns.yaml, allowlists) — the "which rules produced this
    # output?" half of the result's provenance stamp.
    config_sha256: str = ""


# ---------------------------------------------------------------------------
# Runtime config (process environment)
# ---------------------------------------------------------------------------

def _require(env: Mapping[str, str], name: str, provider: str) -> str:
    """The value of ``name``, stripped, or a typed error naming the variable.

    STRIPPED, because a credential of three spaces is not a credential. It
    passes a truthiness test, reaches the provider, and fails there — at
    request time, on somebody's document, as a 502. Failing at startup says
    the same thing when it is still cheap to fix.

    The VALUE never appears in the message. These are secrets, the message
    reaches a log, and the variable name is what an operator needs anyway.
    """
    value = (env.get(name) or "").strip()
    if not value:
        raise ConfigurationError(
            f"{name} is required when ANON_PROVIDER={provider} "
            f"(it is unset or contains only whitespace)"
        )
    return value


def _number(
    name: str,
    value: float,
    *,
    maximum: float | None = None,
) -> float:
    """A configuration number that has to be finite and strictly positive.

    Zero is rejected as firmly as a negative: a timeout of zero is a call
    that cannot be made, a concurrency of zero is a pool that runs nothing,
    and a limit of zero is a limit that refuses everything. Each of those is
    a service that looks configured and does nothing.

    ``nan`` deserves its own mention: every comparison against it is False,
    so a NaN limit silently disables the check it belongs to rather than
    tripping it.
    """
    if not math.isfinite(value):
        raise ConfigurationError(f"{name} must be a finite number, got {value!r}")
    if value <= 0:
        raise ConfigurationError(f"{name} must be greater than zero, got {value!r}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(
            f"{name} must be at most {maximum:g}, got {value!r}"
        )
    return value


def _validate_limits(limits: ResourceLimits) -> ResourceLimits:
    """Every bound finite and positive, and coherent with the others."""
    _number("ANON_MAX_UPLOAD_BYTES", limits.max_upload_bytes)
    _number("ANON_MAX_ZIP_MEMBERS", limits.max_zip_members)
    _number("ANON_MAX_ZIP_MEMBER_BYTES", limits.max_zip_member_bytes)
    _number("ANON_MAX_ZIP_TOTAL_BYTES", limits.max_zip_total_bytes)
    _number("ANON_MAX_TEXT_CHARS", limits.max_text_chars)
    _number("ANON_MAX_CHUNKS", limits.max_chunks)
    if not math.isfinite(limits.max_compression_ratio) or limits.max_compression_ratio <= 1.0:
        raise ConfigurationError(
            "ANON_MAX_COMPRESSION_RATIO must be a finite number greater than 1, "
            f"got {limits.max_compression_ratio!r}"
        )
    if limits.compression_ratio_floor_bytes < 0:
        raise ConfigurationError(
            "ANON_COMPRESSION_RATIO_FLOOR_BYTES must not be negative, "
            f"got {limits.compression_ratio_floor_bytes!r}"
        )
    # Coherence. Each of these describes a limit that can never be reached,
    # which means the one behind it is doing all the work and the operator
    # believes otherwise.
    if limits.max_zip_member_bytes > limits.max_zip_total_bytes:
        raise ConfigurationError(
            "ANON_MAX_ZIP_MEMBER_BYTES must not exceed ANON_MAX_ZIP_TOTAL_BYTES"
        )
    if limits.max_upload_bytes > limits.max_zip_total_bytes:
        raise ConfigurationError(
            "ANON_MAX_UPLOAD_BYTES must not exceed ANON_MAX_ZIP_TOTAL_BYTES"
        )
    if limits.compression_ratio_floor_bytes > limits.max_zip_member_bytes:
        raise ConfigurationError(
            "ANON_COMPRESSION_RATIO_FLOOR_BYTES must not exceed "
            "ANON_MAX_ZIP_MEMBER_BYTES, or no member is ever ratio-checked"
        )
    return limits


# Every shape a pattern fragment is interpolated into by anonymizer.detectors.
# A fragment is compiled in ALL of them, because compiling it alone proves
# neither that it works in context (a body may rely on a wrapper supplying an
# opening group) nor that it is safe there (a trailing alternation compiles
# alone and changes meaning once wrapped).
_BODY_CONTEXTS = ("@@", r"\b@@\b", r"(?<!\d)@@(?!\d)")
_PREFIX_CONTEXTS = (r"(?:@@)?x", "@@x")


def _validate_patterns(patterns: dict[str, dict[str, str]], source: Path) -> None:
    """Compile every override the way the detectors will actually use it.

    Without this an invalid regex override is discovered while processing
    somebody's document, as a 500 from inside a detector.
    """
    for name in sorted(patterns):
        if name not in _DEFAULT_PATTERNS:
            # Harmless but useless: nothing reads it, so the operator thinks
            # they have changed a rule and have not.
            logger.warning(
                "%s defines pattern %r, which no detector uses", source, name
            )
            continue
        for key, contexts in (("body", _BODY_CONTEXTS), ("prefix", _PREFIX_CONTEXTS)):
            fragment = patterns[name].get(key)
            if fragment is None:
                continue
            for context in contexts:
                try:
                    re.compile(context.replace("@@", fragment))
                except re.error as exc:
                    raise ConfigurationError(
                        f"{source}: pattern {name!r} {key} does not compile "
                        f"in context: {exc}"
                    ) from None


def _optional_number(
    env: Mapping[str, str],
    name: str,
    caster: Callable[[str], float],
) -> float | None:
    """Read the optional environment variable ``name`` and convert it with
    ``caster``, returning None when absent or raising ConfigurationError on a
    non-numeric value."""
    raw = env.get(name)
    if raw is None:
        return None
    try:
        return caster(raw)
    except (TypeError, ValueError):
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from None


def load_env_file(path: Path) -> None:
    """Populate ``os.environ`` from a simple KEY=VALUE ``.env`` file.

    A dependency-free stand-in for python-dotenv, shared by every entry point
    (CLI, HTTP API, gunicorn config). Blank lines and lines starting with
    ``#`` are skipped; an optional leading ``export `` is stripped; whitespace
    around the key and value is trimmed; a value wrapped in matching single or
    double quotes has them removed. A variable already present in the real
    environment is left untouched — the file only fills in what is missing.
    Does nothing if ``path`` does not exist. Never logs variable values.
    """
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def _read_limits(env: Mapping[str, str]) -> ResourceLimits:
    """Build the resource limits, overriding only what the environment sets.

    Absent variables keep the calibrated defaults from ``anonymizer.limits``
    rather than becoming zero, which would disable the very bound they name.
    """
    defaults = DEFAULT_LIMITS
    overrides: dict[str, object] = {}
    for field_name, variable, caster in (
        ("max_upload_bytes", "ANON_MAX_UPLOAD_BYTES", int),
        ("max_zip_members", "ANON_MAX_ZIP_MEMBERS", int),
        ("max_zip_member_bytes", "ANON_MAX_ZIP_MEMBER_BYTES", int),
        ("max_zip_total_bytes", "ANON_MAX_ZIP_TOTAL_BYTES", int),
        ("max_compression_ratio", "ANON_MAX_COMPRESSION_RATIO", float),
        ("compression_ratio_floor_bytes", "ANON_COMPRESSION_RATIO_FLOOR_BYTES", int),
        ("max_text_chars", "ANON_MAX_TEXT_CHARS", int),
        ("max_chunks", "ANON_MAX_CHUNKS", int),
    ):
        value = _optional_number(env, variable, caster)
        if value is not None:
            overrides[field_name] = caster(value)
    if not overrides:
        return defaults
    return ResourceLimits(**{**defaults.__dict__, **overrides})


def load_runtime_config(env: Mapping[str, str] | None = None) -> RuntimeConfig:
    """Build a :class:`RuntimeConfig` from ``env`` (defaulting to the process
    environment), validating the selected provider's required variables and
    applying optional tuning overrides."""
    if env is None:
        # Every entry point (CLI and HTTP API) runs from the project root, so
        # the root .env is loaded automatically before reading the environment.
        # Real environment variables always take precedence — the file only
        # fills in what is missing. An explicitly injected env mapping skips
        # this entirely (tests stay hermetic).
        load_env_file(Path.cwd() / ".env")
        env = os.environ

    provider = env.get("ANON_PROVIDER", "openai")
    if not is_provider(provider):
        raise ConfigurationError(
            f"ANON_PROVIDER must be 'openai' or 'azure', got {provider!r}"
        )

    openai_api_key: str | None = None
    openai_model: str | None = None
    azure_api_key: str | None = None
    azure_endpoint: str | None = None
    azure_deployment: str | None = None
    azure_api_version: str | None = None

    if provider == "openai":
        openai_api_key = _require(env, "OPENAI_API_KEY", provider)
        openai_model = _require(env, "ANON_MODEL", provider)
    else:
        azure_api_key = _require(env, "AZURE_OPENAI_API_KEY", provider)
        azure_endpoint = _require(env, "AZURE_OPENAI_ENDPOINT", provider)
        azure_deployment = _require(env, "ANON_AZURE_DEPLOYMENT", provider)
        azure_api_version = _require(env, "ANON_AZURE_API_VERSION", provider)
        parsed = urlsplit(azure_endpoint)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            # The value is NOT echoed: an endpoint can carry a tenant name.
            raise ConfigurationError(
                "AZURE_OPENAI_ENDPOINT must be an absolute http(s) URL"
            )
        if parsed.scheme == "http":
            logger.warning(
                "AZURE_OPENAI_ENDPOINT is not https; document text will cross "
                "the network in the clear"
            )

    # API bearer key. Read for every provider; only the HTTP transport enforces
    # it. An all-whitespace value counts as unset, so a blank line in .env can
    # never become a usable credential.
    api_key = (env.get("ANON_API_KEY") or "").strip() or None

    # Optional knobs: keep dataclass defaults when the variable is absent by
    # only supplying keys that were actually provided.
    overrides: _Tuning = {}
    timeout = _optional_number(env, "ANON_LLM_TIMEOUT_S", float)
    if timeout is not None:
        overrides["llm_timeout_s"] = _number(
            "ANON_LLM_TIMEOUT_S", timeout, maximum=3600
        )
    chunk_size = _optional_number(env, "ANON_CHUNK_SIZE_CHARS", int)
    if chunk_size is not None:
        overrides["chunk_size_chars"] = int(
            _number("ANON_CHUNK_SIZE_CHARS", chunk_size, maximum=200_000)
        )
    max_completion_tokens = _optional_number(env, "ANON_MAX_COMPLETION_TOKENS", int)
    if max_completion_tokens is not None:
        overrides["max_completion_tokens"] = int(
            _number("ANON_MAX_COMPLETION_TOKENS", max_completion_tokens, maximum=1_000_000)
        )
    llm_concurrency = _optional_number(env, "ANON_LLM_CONCURRENCY", int)
    if llm_concurrency is not None:
        overrides["llm_concurrency"] = int(
            _number("ANON_LLM_CONCURRENCY", llm_concurrency, maximum=64)
        )
    limits = _validate_limits(_read_limits(env))
    if limits != DEFAULT_LIMITS:
        overrides["limits"] = limits
    document_deadline_s = _optional_number(env, "ANON_DOCUMENT_DEADLINE_S", float)
    if document_deadline_s is not None:
        overrides["document_deadline_s"] = _number(
            "ANON_DOCUMENT_DEADLINE_S", document_deadline_s, maximum=86_400
        )
    log_level = env.get("ANON_LOG_LEVEL")
    if log_level is not None:
        level = log_level.strip().upper()
        if level not in _LOG_LEVELS:
            # Otherwise this reaches logging.basicConfig at startup and dies
            # with an untyped ValueError, after the config has loaded.
            raise ConfigurationError(
                f"ANON_LOG_LEVEL must be one of {', '.join(sorted(_LOG_LEVELS))}, "
                f"got {log_level!r}"
            )
        overrides["log_level"] = level

    return RuntimeConfig(
        provider=provider,
        openai_api_key=openai_api_key,
        openai_model=openai_model,
        azure_api_key=azure_api_key,
        azure_endpoint=azure_endpoint,
        azure_deployment=azure_deployment,
        azure_api_version=azure_api_version,
        anon_api_key=api_key,
        **overrides,
    )


# ---------------------------------------------------------------------------
# File config (config directory)
# ---------------------------------------------------------------------------

def _load_yaml_mapping(path: Path, missing_message: str) -> dict:
    """Parse the YAML file at ``path`` and return it as a dict (empty when the
    file is blank), raising ConfigurationError with ``missing_message`` if the
    file does not exist.

    A SYNTACTICALLY BROKEN FILE IS A CONFIGURATION ERROR, not a parser
    exception. Without this, a stray tab in policy.yaml leaves the server
    with a raw ``yaml.YAMLError`` and an operator with a traceback instead of
    a filename and a line number. Only the parser's own problem description
    and position are reported — never the offending source line, which for
    the allowlists and pattern files could carry material an operator would
    rather not see repeated in a log.
    """
    if not path.exists():
        raise ConfigurationError(missing_message)
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        where = (
            f" at line {mark.line + 1}, column {mark.column + 1}"
            if mark is not None
            else ""
        )
        raise ConfigurationError(
            f"{path.name} is not valid YAML: {exc.problem or 'parse error'}{where}"
        ) from None
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"{path.name} is not valid YAML ({type(exc).__name__})"
        ) from None
    except UnicodeDecodeError:
        # The files are declared UTF-8 and read as UTF-8; anything else is a
        # file saved in another encoding, which is an operator problem with a
        # one-line fix.
        raise ConfigurationError(f"{path.name} is not valid UTF-8") from None
    return data or {}


def _load_allowlist(path: Path) -> frozenset[str]:
    """Read a plain-text allowlist file at ``path`` into a frozenset of
    non-empty, non-comment lines, returning an empty set (with a warning) when
    the file is missing."""
    if not path.exists():
        logger.warning("Allowlist file not found: %s (using empty allowlist)", path)
        return frozenset()
    entries: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.add(stripped)
    return frozenset(entries)


def load_file_config(config_dir: Path) -> FileConfig:
    """Load policy thresholds, regex detector patterns, and Greek-domain
    allowlists (DOY tax offices, public services, legal references, preserved
    email domains) from ``config_dir`` and return them as a FileConfig."""
    config_dir = Path(config_dir)

    policy_data = _load_yaml_mapping(
        config_dir / "policy.yaml",
        f"policy.yaml not found in {config_dir}",
    )
    if not isinstance(policy_data, dict):
        raise ConfigurationError("policy.yaml must be a mapping")
    policy_map = policy_data.get("policy", {}) or {}
    if not isinstance(policy_map, dict):
        raise ConfigurationError("policy.yaml: 'policy:' must be a mapping")

    def _policy_threshold(key: str) -> float:
        """Read a required numeric threshold from the policy mapping, raising a
        typed ConfigurationError (never a raw KeyError) when it is absent."""
        if key not in policy_map:
            raise ConfigurationError(
                f"policy.yaml is missing required key {key!r} under 'policy:'"
            )
        try:
            value = float(policy_map[key])
        except (TypeError, ValueError):
            raise ConfigurationError(
                f"policy.yaml: {key!r} must be a number, got {policy_map[key]!r}"
            ) from None
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ConfigurationError(
                f"policy.yaml: {key!r} must be a confidence between 0 and 1, "
                f"got {value!r}"
            )
        return value

    policy = PolicySettings(
        preserve_high_confidence_threshold=_policy_threshold(
            "preserve_high_confidence_threshold"
        ),
        redact_high_confidence_threshold=_policy_threshold(
            "redact_high_confidence_threshold"
        ),
        redact_threshold=_policy_threshold("redact_threshold"),
        hard_preserve_categories=frozenset(
            str(c) for c in policy_map.get("hard_preserve_categories", [])
        ),
        hard_redact_categories=frozenset(
            str(c) for c in policy_map.get("hard_redact_categories", [])
        ),
    )

    # The one ordering the resolver's semantics actually require: the
    # structured-redact tier is gated on the high threshold and the ordinary
    # one on the low threshold, so inverting them makes the structured tier
    # unreachable. The preserve threshold is an independent band and no
    # relation between it and these is invented here.
    if policy.redact_threshold > policy.redact_high_confidence_threshold:
        raise ConfigurationError(
            "policy.yaml: redact_threshold must not exceed "
            "redact_high_confidence_threshold"
        )

    for field_name, categories in (
        ("hard_preserve_categories", policy.hard_preserve_categories),
        ("hard_redact_categories", policy.hard_redact_categories),
    ):
        unknown = sorted(categories - ALL_CATEGORIES)
        if unknown:
            # A category nothing produces is a policy line that does nothing,
            # and the operator believes it is protecting something.
            raise ConfigurationError(
                f"policy.yaml: {field_name} names categories that do not "
                f"exist: {', '.join(unknown)}"
            )
    both = sorted(policy.hard_preserve_categories & policy.hard_redact_categories)
    if both:
        raise ConfigurationError(
            f"policy.yaml: {', '.join(both)} is listed as both hard-preserve "
            f"and hard-redact"
        )

    preserve_email_domains = frozenset(
        str(domain).strip().casefold()
        for domain in policy_map.get("preserve_email_domains", [])
        if str(domain).strip()
    )

    patterns_data = _load_yaml_mapping(
        config_dir / "regex_patterns.yaml",
        f"regex_patterns.yaml not found in {config_dir}",
    )
    if not isinstance(patterns_data, dict):
        raise ConfigurationError("regex_patterns.yaml must be a mapping")
    patterns: dict[str, dict[str, str]] = {
        name: {str(k): str(v) for k, v in spec.items()}
        for name, spec in patterns_data.items()
        if isinstance(spec, dict)
    }
    _validate_patterns(patterns, config_dir / "regex_patterns.yaml")

    # Prompt-injection rules. REQUIRED, not optional: a security control that
    # silently disables itself when its file is missing is worse than one
    # that refuses to start, because nothing downstream can tell the
    # difference between 'no rules matched' and 'no rules were loaded'.
    injection_data = _load_yaml_mapping(
        config_dir / "prompt_injection.yaml",
        f"prompt_injection.yaml not found in {config_dir}",
    )
    injection_rules = compile_rules(
        injection_data, source=str(config_dir / "prompt_injection.yaml")
    )

    allowlist_dir = config_dir / "allowlists"
    rules = DetectorRules(
        patterns=patterns,
        dou_allowlist=_load_allowlist(allowlist_dir / "dou.txt"),
        public_services=_load_allowlist(allowlist_dir / "public_services.txt"),
        legal_refs=_load_allowlist(allowlist_dir / "legal_refs.txt"),
        preserve_email_domains=preserve_email_domains,
        regions=_load_allowlist(allowlist_dir / "regions.txt"),
    )

    # Provenance: one hash over every config file's raw bytes, in a fixed
    # order; a missing allowlist contributes nothing (matching the loader's
    # warn-and-continue behavior above).
    digest = hashlib.sha256()
    for name in (
        "policy.yaml",
        "regex_patterns.yaml",
        "prompt_injection.yaml",
        "allowlists/dou.txt",
        "allowlists/public_services.txt",
        "allowlists/legal_refs.txt",
        "allowlists/regions.txt",
    ):
        path = config_dir / name
        digest.update(name.encode("utf-8"))
        if path.exists():
            digest.update(path.read_bytes())

    return FileConfig(
        policy=policy,
        rules=rules,
        injection_rules=injection_rules,
        config_sha256=digest.hexdigest(),
    )


__all__ = [
    "RuntimeConfig",
    "PolicySettings",
    "DetectorRules",
    "FileConfig",
    "load_env_file",
    "load_runtime_config",
    "load_file_config",
]
