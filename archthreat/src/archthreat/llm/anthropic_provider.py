"""Anthropic Messages API over raw HTTP (no SDK), so every header and field is visible.

Docs: https://docs.claude.com/en/api/messages
"""

from __future__ import annotations

import httpx

from archthreat.llm.base import LLMError, LLMResponse, Message, RetryableError, Timer, with_retries

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"


class AnthropicLLM:
    name = "anthropic"

    def __init__(
        self, api_key: str, model: str = "claude-haiku-4-5", client: httpx.Client | None = None
    ) -> None:
        if not api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")
        self.model = model
        self._headers = {
            "x-api-key": api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        self._client = client or httpx.Client(timeout=120)

    def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        json_mode: bool = False,  # prompting + validation handles JSON; see llm/structured.py
    ) -> LLMResponse:
        body: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        if system:
            body["system"] = system

        def call() -> dict:
            try:
                resp = self._client.post(API_URL, json=body, headers=self._headers)
            except httpx.TransportError as exc:
                raise RetryableError(str(exc)) from exc
            # 429 = rate limited, 529 = overloaded, 5xx = server error: all worth retrying.
            if resp.status_code == 429 or resp.status_code >= 500:
                raise RetryableError(f"Anthropic {resp.status_code}: {resp.text[:200]}")
            if resp.status_code >= 400:
                raise LLMError(f"Anthropic {resp.status_code}: {resp.text[:300]}")
            return resp.json()

        with Timer() as t:
            data = with_retries(call)
        text = "".join(block.get("text", "") for block in data.get("content", []))
        usage = data.get("usage", {})
        return LLMResponse(
            text=text,
            model=data.get("model", self.model),
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=t.ms,
            stop_reason=data.get("stop_reason"),
        )
