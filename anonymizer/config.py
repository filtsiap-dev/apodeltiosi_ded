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
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Mapping

import yaml

from anonymizer.errors import ConfigurationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuntimeConfig:
    provider: Literal["openai", "azure"]
    openai_api_key: str | None
    openai_model: str | None
    azure_api_key: str | None
    azure_endpoint: str | None
    azure_deployment: str | None
    azure_api_version: str | None
    llm_timeout_s: float = 60.0
    chunk_size_chars: int = 3000
    max_completion_tokens: int = 2000
    llm_concurrency: int = 8
    log_level: str = "INFO"
    max_upload_mb: int = 20

    @property
    def model_handle(self) -> str:
        """The provider-appropriate model identifier used by the LLM client.

        For ``openai`` this is the OpenAI model name; for ``azure`` it is the
        deployment name. ``load_runtime_config`` guarantees the relevant field
        is populated for the selected provider.
        """
        if self.provider == "openai":
            return self.openai_model  # type: ignore[return-value]
        return self.azure_deployment  # type: ignore[return-value]


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


@dataclass(frozen=True)
class FileConfig:
    policy: PolicySettings
    rules: DetectorRules
    # sha256 over the raw bytes of every config file loaded (policy.yaml,
    # regex_patterns.yaml, allowlists) — the "which rules produced this
    # output?" half of the result's provenance stamp.
    config_sha256: str = ""


# ---------------------------------------------------------------------------
# Runtime config (process environment)
# ---------------------------------------------------------------------------

def _require(env: Mapping[str, str], name: str, provider: str) -> str:
    """Return the value of environment variable ``name`` from ``env``, raising
    :class:`ConfigurationError` if it is missing or empty for ``provider``."""
    value = env.get(name)
    if not value:
        raise ConfigurationError(f"{name} is required when ANON_PROVIDER={provider}")
    return value


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
    if provider not in ("openai", "azure"):
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

    # Optional knobs: keep dataclass defaults when the variable is absent by
    # only supplying keys that were actually provided.
    overrides: dict[str, object] = {}
    timeout = _optional_number(env, "ANON_LLM_TIMEOUT_S", float)
    if timeout is not None:
        overrides["llm_timeout_s"] = timeout
    chunk_size = _optional_number(env, "ANON_CHUNK_SIZE_CHARS", int)
    if chunk_size is not None:
        overrides["chunk_size_chars"] = chunk_size
    max_completion_tokens = _optional_number(env, "ANON_MAX_COMPLETION_TOKENS", int)
    if max_completion_tokens is not None:
        overrides["max_completion_tokens"] = max_completion_tokens
    llm_concurrency = _optional_number(env, "ANON_LLM_CONCURRENCY", int)
    if llm_concurrency is not None:
        overrides["llm_concurrency"] = llm_concurrency
    max_upload_mb = _optional_number(env, "ANON_MAX_UPLOAD_MB", int)
    if max_upload_mb is not None:
        overrides["max_upload_mb"] = max_upload_mb
    log_level = env.get("ANON_LOG_LEVEL")
    if log_level is not None:
        overrides["log_level"] = log_level

    return RuntimeConfig(
        provider=provider,  # type: ignore[arg-type]
        openai_api_key=openai_api_key,
        openai_model=openai_model,
        azure_api_key=azure_api_key,
        azure_endpoint=azure_endpoint,
        azure_deployment=azure_deployment,
        azure_api_version=azure_api_version,
        **overrides,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# File config (config directory)
# ---------------------------------------------------------------------------

def _load_yaml_mapping(path: Path, missing_message: str) -> dict:
    """Parse the YAML file at ``path`` and return it as a dict (empty when the
    file is blank), raising ConfigurationError with ``missing_message`` if the
    file does not exist."""
    if not path.exists():
        raise ConfigurationError(missing_message)
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


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
    policy_map = policy_data.get("policy", {}) or {}

    def _policy_threshold(key: str) -> float:
        """Read a required numeric threshold from the policy mapping, raising a
        typed ConfigurationError (never a raw KeyError) when it is absent."""
        if key not in policy_map:
            raise ConfigurationError(
                f"policy.yaml is missing required key {key!r} under 'policy:'"
            )
        return float(policy_map[key])

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

    preserve_email_domains = frozenset(
        str(domain).strip().casefold()
        for domain in policy_map.get("preserve_email_domains", [])
        if str(domain).strip()
    )

    patterns_data = _load_yaml_mapping(
        config_dir / "regex_patterns.yaml",
        f"regex_patterns.yaml not found in {config_dir}",
    )
    patterns: dict[str, dict[str, str]] = {
        name: {str(k): str(v) for k, v in spec.items()}
        for name, spec in patterns_data.items()
        if isinstance(spec, dict)
    }

    allowlist_dir = config_dir / "allowlists"
    rules = DetectorRules(
        patterns=patterns,
        dou_allowlist=_load_allowlist(allowlist_dir / "dou.txt"),
        public_services=_load_allowlist(allowlist_dir / "public_services.txt"),
        legal_refs=_load_allowlist(allowlist_dir / "legal_refs.txt"),
        preserve_email_domains=preserve_email_domains,
    )

    # Provenance: one hash over every config file's raw bytes, in a fixed
    # order; a missing allowlist contributes nothing (matching the loader's
    # warn-and-continue behavior above).
    digest = hashlib.sha256()
    for name in (
        "policy.yaml",
        "regex_patterns.yaml",
        "allowlists/dou.txt",
        "allowlists/public_services.txt",
        "allowlists/legal_refs.txt",
    ):
        path = config_dir / name
        digest.update(name.encode("utf-8"))
        if path.exists():
            digest.update(path.read_bytes())

    return FileConfig(policy=policy, rules=rules, config_sha256=digest.hexdigest())


__all__ = [
    "RuntimeConfig",
    "PolicySettings",
    "DetectorRules",
    "FileConfig",
    "load_env_file",
    "load_runtime_config",
    "load_file_config",
]
