"""Build providers from Settings. The only place that knows which backends exist."""

from __future__ import annotations

from archthreat.config import Settings
from archthreat.llm.base import Embedder, LLMError, LLMProvider
from archthreat.llm.fake import FakeLLM, HashEmbedder, Responder

DEFAULT_MODELS = {
    "ollama": "qwen2.5:7b",
    "anthropic": "claude-haiku-4-5",
    "bedrock": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "fake": "fake-offline",
}

DEFAULT_EMBED_MODELS = {
    "ollama": "nomic-embed-text",
    "bedrock": "amazon.titan-embed-text-v2:0",
}


def get_llm(settings: Settings, offline_responder: Responder | None = None) -> LLMProvider:
    provider = settings.llm_provider.lower()
    model = settings.llm_model or DEFAULT_MODELS.get(provider, "")
    if provider == "fake":
        if offline_responder is None:
            raise LLMError("LLM_PROVIDER=fake needs an offline responder")
        return FakeLLM(offline_responder, model=model)
    if provider == "ollama":
        from archthreat.llm.ollama import OllamaLLM

        return OllamaLLM(model=model, host=settings.ollama_host)
    if provider == "anthropic":
        from archthreat.llm.anthropic_provider import AnthropicLLM

        return AnthropicLLM(api_key=settings.anthropic_api_key, model=model)
    if provider == "bedrock":
        from archthreat.llm.bedrock import BedrockLLM

        return BedrockLLM(model=model, region=settings.aws_region)
    raise LLMError(f"Unknown LLM_PROVIDER '{settings.llm_provider}'")


def get_embedder(settings: Settings) -> Embedder:
    provider = settings.embed_provider.lower()
    model = settings.embed_model or DEFAULT_EMBED_MODELS.get(provider, "")
    if provider == "hash":
        return HashEmbedder()
    if provider == "ollama":
        from archthreat.llm.ollama import OllamaEmbedder

        return OllamaEmbedder(model=model, host=settings.ollama_host)
    if provider == "bedrock":
        from archthreat.llm.bedrock import BedrockEmbedder

        return BedrockEmbedder(model=model, region=settings.aws_region)
    raise LLMError(f"Unknown EMBED_PROVIDER '{settings.embed_provider}'")
