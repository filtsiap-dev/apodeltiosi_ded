"""Provider client construction.

One decision worth stating: THE SDK DOES NOT RETRY. Both clients are built with
``max_retries=0``, because ``anonymizer.llm.detector`` owns the retry policy and
two retry layers would multiply rather than cooperate — the SDK's default of two
silent retries inside each of our four attempts would be up to twelve calls for
one chunk, at twelve times the cost, with the delays and the failure count in
the logs describing none of it. Ours are the only retries, and every one of them
is logged.
"""

import openai

from anonymizer.config import RuntimeConfig
from anonymizer.errors import ConfigurationError

# Retries are the application's job (see anonymizer.llm.detector._call_with_retries).
_SDK_RETRIES = 0


def build_client(cfg: RuntimeConfig) -> "openai.OpenAI | openai.AzureOpenAI":
    """Build an LLM client from the runtime config, returning an OpenAI client when cfg.provider is "openai" and an AzureOpenAI client otherwise.

    Both are constructed with ``max_retries=0``: the SDK makes exactly the call
    it is asked for, and the application decides what happens when it fails.
    """
    if cfg.provider == "openai":
        if not cfg.openai_api_key or not cfg.openai_model:
            # Unreachable through the loader, which requires both. Named
            # rather than assumed, so a hand-built config fails with a
            # sentence instead of a None reaching the SDK.
            raise ConfigurationError(
                "ANON_PROVIDER=openai requires OPENAI_API_KEY and ANON_MODEL"
            )
        return openai.OpenAI(
            api_key=cfg.openai_api_key,
            timeout=cfg.llm_timeout_s,
            max_retries=_SDK_RETRIES,
        )
    if not (
        cfg.azure_api_key
        and cfg.azure_endpoint
        and cfg.azure_deployment
        and cfg.azure_api_version
    ):
        raise ConfigurationError(
            "ANON_PROVIDER=azure requires AZURE_OPENAI_API_KEY, "
            "AZURE_OPENAI_ENDPOINT, ANON_AZURE_DEPLOYMENT and "
            "ANON_AZURE_API_VERSION"
        )
    return openai.AzureOpenAI(
        api_key=cfg.azure_api_key,
        azure_endpoint=cfg.azure_endpoint,
        api_version=cfg.azure_api_version,
        timeout=cfg.llm_timeout_s,
        max_retries=_SDK_RETRIES,
    )
