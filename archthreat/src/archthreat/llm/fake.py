"""Test doubles: a scriptable fake LLM and a deterministic hashing embedder.

These make the whole system runnable with no model, no network and no cost. That is what
lets CI run the full pipeline and the eval suite on every pull request.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import numpy as np

from archthreat.llm.base import LLMResponse, Message
from archthreat.rag.bm25 import tokenize

Responder = Callable[[list[Message], str | None], str]


class FakeLLM:
    """Returns scripted replies. Pass a list (consumed in order) or a function."""

    name = "fake"

    def __init__(self, responses: list[str] | Responder, model: str = "fake-model") -> None:
        self.model = model
        self._responses = responses
        self.calls: list[tuple[list[Message], str | None]] = []

    def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> LLMResponse:
        self.calls.append((list(messages), system))
        if callable(self._responses):
            text = self._responses(messages, system)
        else:
            if not self._responses:
                raise AssertionError("FakeLLM ran out of scripted responses")
            text = self._responses.pop(0)
        prompt_chars = sum(len(m.content) for m in messages) + len(system or "")
        return LLMResponse(
            text=text,
            model=self.model,
            input_tokens=prompt_chars // 4,  # ~4 chars per token rule of thumb
            output_tokens=len(text) // 4,
            latency_ms=1,
            stop_reason="end_turn",
        )


class HashEmbedder:
    """Feature-hashing embedder: deterministic, dependency-free, NOT semantic.

    Each token (and adjacent token pair) is hashed into one of `dims` buckets with a +/- sign.
    Texts sharing words end up with similar vectors, which is enough for tests and offline
    demos. For real semantic search use EMBED_PROVIDER=ollama or bedrock.
    """

    name = "hash"

    def __init__(self, dims: int = 384) -> None:
        self.dims = dims
        self.model = f"hash-{dims}"

    def _vector(self, text: str) -> list[float]:
        vec = np.zeros(self.dims, dtype=np.float32)
        tokens = tokenize(text)
        features = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:], strict=False)]
        for feat in features:
            digest = hashlib.md5(feat.encode(), usedforsecurity=False).digest()
            bucket = int.from_bytes(digest[:4], "little") % self.dims
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vec[bucket] += sign
        norm = np.linalg.norm(vec)
        return (vec / norm if norm else vec).tolist()

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(t) for t in texts]
