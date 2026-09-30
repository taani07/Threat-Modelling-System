"""Lab 04 starter."""

from __future__ import annotations

from archthreat.graph import crosses_boundary  # noqa: F401
from archthreat.models import AuthN, Component, ComponentType, SystemModel  # noqa: F401


def _escape(text: str) -> str:
    return text.replace('"', "'").replace("\n", " ")


def node(c: Component) -> str:
    # TODO
    raise NotImplementedError


def to_mermaid(model: SystemModel) -> str:
    lines = ["flowchart LR"]
    # TODO: subgraphs, nodes, edges, classDef
    raise NotImplementedError
    return "\n".join(lines)
