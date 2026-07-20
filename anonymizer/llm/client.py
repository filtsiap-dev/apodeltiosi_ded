import openai

from anonymizer.config import RuntimeConfig


def build_client(cfg: RuntimeConfig) -> "openai.OpenAI | openai.AzureOpenAI":
    """Build an LLM client from the runtime config, returning an OpenAI client when cfg.provider is "openai" and an AzureOpenAI client otherwise."""
    if cfg.provider == "openai":
        return openai.OpenAI(api_key=cfg.openai_api_key, timeout=cfg.llm_timeout_s)
    return openai.AzureOpenAI(
        api_key=cfg.azure_api_key,
        azure_endpoint=cfg.azure_endpoint,
        api_version=cfg.azure_api_version,
        timeout=cfg.llm_timeout_s,
    )
