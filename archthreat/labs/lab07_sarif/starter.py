"""Lab 07 starter."""

from __future__ import annotations

import re  # noqa: F401

from archthreat import __version__  # noqa: F401
from archthreat.models import Severity, SystemModel, Threat, sort_threats  # noqa: F401

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def rule_id_for(t: Threat) -> str:
    return t.rule_id or f"LLM-{t.stride.value}"


def element_line(yaml_text: str, element_id: str) -> int:
    # TODO
    raise NotImplementedError


def to_sarif(model: SystemModel, threats: list[Threat], model_path: str, yaml_text: str) -> dict:
    # TODO
    raise NotImplementedError
