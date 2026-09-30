"""Ollama provider: free, local models on your laptop.

Setup:  brew install ollama && ollama serve
        ollama pull qwen2.5:7b          # good at following JSON schemas
        ollama pull nomic-embed-text    # embeddings
API docs: https://github.com/ollama/ollama/blob/main/docs/api.md
"""

from __future__ import annotations

import httpx

from archthreat.llm.base import LLMError, LLMResponse, Message, RetryableError, Timer, with_retries


class OllamaLLM:
    name = "ollama"

    def __init__(
        self,
        model: str = "qwen2.5:7b",
        host: str = "http://localhost:11434",
        client: httpx.Client | None = None,
    ) -> None:
        self.model = model
        self._client = client or httpx.Client(base_url=host, timeout=180)

    def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> LLMResponse:
        payload: dict = {
            "model": self.model,
            "messages": ([{"role": "system", "content": system}] if system else [])
            + [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if json_mode:
            payload["format"] = "json"

        def call() -> dict:
            try:
                resp = self._client.post("/api/chat", json=payload)
            except httpx.TransportError as exc:
                raise RetryableError(
                    f"Ollama unreachable at {self._client.base_url}: {exc}"
                ) from exc
            if resp.status_code >= 500:
                raise RetryableError(f"Ollama {resp.status_code}: {resp.text[:200]}")
            if resp.status_code >= 400:
                raise LLMError(f"Ollama {resp.status_code}: {resp.text[:200]}")
            return resp.json()

        with Timer() as t:
            data = with_retries(call, attempts=2)
        return LLMResponse(
            text=data["message"]["content"],
            model=self.model,
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            latency_ms=t.ms,
            stop_reason=data.get("done_reason"),
        )


class OllamaEmbedder:
    name = "ollama"

    def __init__(
        self,
        model: str = "nomic-embed-text",
        host: str = "http://localhost:11434",
        client: httpx.Client | None = None,
    ) -> None:
        self.model = model
        self._client = client or httpx.Client(base_url=host, timeout=120)

    def embed(self, texts: list[str]) -> list[list[float]]:
        resp = self._client.post("/api/embed", json={"model": self.model, "input": texts})
        if resp.status_code != 200:
            raise LLMError(f"Ollama embed {resp.status_code}: {resp.text[:200]}")
        return resp.json()["embeddings"]
