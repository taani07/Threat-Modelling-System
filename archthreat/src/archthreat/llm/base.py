"""Provider-neutral LLM interfaces.

`typing.Protocol` is structural typing: any class with a matching `complete()` method *is* an
LLMProvider, no inheritance needed. Closest Java analogy: an interface, except the class never
has to say `implements`.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, TypeVar, runtime_checkable

Role = Literal["user", "assistant"]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    stop_reason: str | None = None


class LLMError(RuntimeError):
    """Raised for provider failures after retries are exhausted."""


class RetryableError(LLMError):
    """Transient failure (rate limit, 5xx, timeout) worth retrying."""


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str

    def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> LLMResponse: ...


@runtime_checkable
class Embedder(Protocol):
    name: str
    model: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


T = TypeVar("T")


def with_retries(
    fn: Callable[[], T],
    *,
    attempts: int = 4,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Retry `fn` on RetryableError with exponential backoff and full jitter.

    delay = random(0, min(max_delay, base_delay * 2**attempt))
    Jitter stops many clients retrying in lock-step after a shared outage.
    """
    for attempt in range(attempts):
        try:
            return fn()
        except RetryableError:
            if attempt == attempts - 1:
                raise
            sleep(random.uniform(0, min(max_delay, base_delay * 2**attempt)))  # noqa: S311
    raise AssertionError("unreachable")


class Timer:
    """Context manager that measures elapsed milliseconds."""

    def __enter__(self) -> Timer:
        self.start = time.perf_counter()
        self.ms = 0
        return self

    def __exit__(self, *exc: object) -> None:
        self.ms = int((time.perf_counter() - self.start) * 1000)
