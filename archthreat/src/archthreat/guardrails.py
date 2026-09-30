"""Fence untrusted text before it goes into a prompt (see VulnLens for the full rationale)."""

from __future__ import annotations

import re


def fence_untrusted(text: str, tag: str = "untrusted_model", max_chars: int = 6000) -> str:
    text = (text or "")[:max_chars]
    text = re.sub(r"<\s*/?\s*" + re.escape(tag) + r"\s*>", "[tag removed]", text, flags=re.I)
    return f"<{tag}>\n{text}\n</{tag}>"
