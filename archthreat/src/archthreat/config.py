"""Settings from environment variables. See .env.example."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    home: Path = field(default_factory=lambda: Path(_env("ARCHTHREAT_HOME", ".archthreat")))
    knowledge_dir: Path = field(
        default_factory=lambda: Path(_env("ARCHTHREAT_KNOWLEDGE_DIR", "data/knowledge"))
    )
    llm_provider: str = field(default_factory=lambda: _env("LLM_PROVIDER", "fake"))
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL", ""))
    embed_provider: str = field(default_factory=lambda: _env("EMBED_PROVIDER", "hash"))
    embed_model: str = field(default_factory=lambda: _env("EMBED_MODEL", ""))
    ollama_host: str = field(default_factory=lambda: _env("OLLAMA_HOST", "http://localhost:11434"))
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    aws_region: str = field(default_factory=lambda: _env("AWS_REGION", "us-east-1"))
    api_key: str = field(default_factory=lambda: _env("ARCHTHREAT_API_KEY"))
    max_llm_threats_per_element: int = field(
        default_factory=lambda: int(_env("ARCHTHREAT_MAX_LLM_THREATS", "3"))
    )

    @property
    def index_dir(self) -> Path:
        return self.home / "index"
