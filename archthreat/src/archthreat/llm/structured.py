"""Structured output: make an LLM return JSON that validates against a Pydantic schema.

Loop:  prompt + schema  ->  parse  ->  validate  ->  on failure, show the model its own
answer and the validation error, and ask again (bounded retries).

This "validate and repair" loop works with every provider, including small local models,
which is why we use it instead of any one vendor's JSON mode.
"""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from archthreat.llm.base import LLMProvider, LLMResponse, Message

T = TypeVar("T", bound=BaseModel)

FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class StructuredOutputError(RuntimeError):
    def __init__(self, message: str, responses: list[LLMResponse]) -> None:
        super().__init__(message)
        self.responses = responses


def extract_json(text: str) -> str:
    """Pull the JSON object out of a reply that may include prose or ``` fences."""
    fenced = FENCE_RE.search(text)
    if fenced:
        text = fenced.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end < start:
        raise ValueError("no JSON object found in model output")
    return text[start : end + 1]


def schema_instructions(schema: type[BaseModel]) -> str:
    return (
        "Respond with ONLY a JSON object (no prose, no code fences) that validates against "
        f"this JSON Schema:\n{json.dumps(schema.model_json_schema(), indent=None)}"
    )


def _short_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}"
            for e in exc.errors()[:5]
        )
    return str(exc)


def generate_structured(
    llm: LLMProvider,
    *,
    prompt: str,
    schema: type[T],
    system: str | None = None,
    max_retries: int = 2,
    max_tokens: int = 1500,
) -> tuple[T, list[LLMResponse]]:
    messages = [Message("user", f"{prompt}\n\n{schema_instructions(schema)}")]
    responses: list[LLMResponse] = []
    for _ in range(max_retries + 1):
        resp = llm.complete(
            messages, system=system, max_tokens=max_tokens, temperature=0.0, json_mode=True
        )
        responses.append(resp)
        try:
            return schema.model_validate_json(extract_json(resp.text)), responses
        except (ValidationError, ValueError) as exc:
            messages = [
                *messages,
                Message("assistant", resp.text),
                Message(
                    "user",
                    f"That reply was invalid: {_short_error(exc)}. "
                    "Reply again with ONLY the corrected JSON object.",
                ),
            ]
    raise StructuredOutputError(
        f"model did not return valid {schema.__name__} after {max_retries + 1} attempts",
        responses,
    )
