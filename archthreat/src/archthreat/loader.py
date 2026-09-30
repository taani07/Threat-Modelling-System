"""Load and validate system models from YAML."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from archthreat.models import SystemModel

MAX_MODEL_BYTES = 256_000


class ModelError(ValueError):
    """A model file that cannot be parsed or fails validation, with a readable message."""


def parse_model(text: str) -> SystemModel:
    if len(text.encode()) > MAX_MODEL_BYTES:
        raise ModelError(f"model is larger than {MAX_MODEL_BYTES} bytes")
    try:
        # safe_load, never load(): yaml.load on untrusted input is code execution (CWE-502).
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ModelError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelError("model must be a YAML mapping")
    try:
        return SystemModel.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'model'}: {e['msg']}" for e in exc.errors()
        )
        raise ModelError(problems) from exc


def load_model(path: str | Path) -> SystemModel:
    return parse_model(Path(path).read_text(encoding="utf-8"))
