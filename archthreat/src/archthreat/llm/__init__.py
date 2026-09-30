"""Pluggable LLM layer: one interface, four backends (fake, ollama, anthropic, bedrock)."""

from archthreat.llm.base import Embedder, LLMError, LLMProvider, LLMResponse, Message
from archthreat.llm.factory import get_embedder, get_llm
from archthreat.llm.fake import FakeLLM, HashEmbedder
from archthreat.llm.structured import StructuredOutputError, generate_structured

__all__ = [
    "Embedder",
    "FakeLLM",
    "HashEmbedder",
    "LLMError",
    "LLMProvider",
    "LLMResponse",
    "Message",
    "StructuredOutputError",
    "generate_structured",
    "get_embedder",
    "get_llm",
]
