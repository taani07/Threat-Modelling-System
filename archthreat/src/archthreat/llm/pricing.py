"""Rough cost tracking. Prices change: check the provider's pricing page and update this table.

Values are USD per million tokens (input, output). Treat estimates as approximate.
"""

from __future__ import annotations

PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-4-5": (3.00, 15.00),
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    for key, (inp, out) in PRICES_PER_MTOK.items():
        if key in model:  # also matches Bedrock IDs like us.anthropic.claude-haiku-4-5-2025...
            return round((input_tokens * inp + output_tokens * out) / 1_000_000, 6)
    return 0.0  # local / fake / unknown models
