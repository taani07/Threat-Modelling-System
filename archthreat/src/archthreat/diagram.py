"""Render the system model as a Mermaid data-flow diagram.

Conventions: external entities are rectangles, processes are rounded, data stores are
cylinders. Trust boundaries are subgraphs (untrusted ones are labelled). Unencrypted flows are
dotted, and a flow that crosses a boundary without authentication is marked with a warning.
Mermaid renders natively on GitHub, in Claude artifacts, and in most docs tools.
"""

from __future__ import annotations

from archthreat.graph import crosses_boundary
from archthreat.models import AuthN, Component, ComponentType, SystemModel


def _escape(text: str) -> str:
    return text.replace('"', "'").replace("\n", " ")


def node(c: Component) -> str:
    label = _escape(c.label) + (f"<br/>{_escape(c.tech)}" if c.tech else "")
    if c.type == ComponentType.EXTERNAL_ENTITY:
        return f'{c.id}["{label}"]'
    if c.type == ComponentType.DATA_STORE:
        return f'{c.id}[("{label}")]'
    return f'{c.id}("{label}")'


def to_mermaid(model: SystemModel) -> str:
    lines = ["flowchart LR"]
    for b in model.trust_boundaries:
        members = [c for c in model.components if c.boundary == b.id]
        if not members:
            continue
        title = _escape(b.name + (" (untrusted)" if b.untrusted else ""))
        lines.append(f'  subgraph {b.id}["{title}"]')
        lines += [f"    {node(c)}" for c in members]
        lines.append("  end")
    for f in model.flows:
        label = f"{f.protocol} / {f.authn.value}" + (" (pull)" if f.pull else "")
        if f.authn == AuthN.NONE and not f.pull and crosses_boundary(model, f):
            label = "⚠ " + label
        arrow = "-->" if f.encrypted else "-.->"
        lines.append(f'  {f.source} {arrow}|"{_escape(label)}"| {f.target}')
    untrusted = [b.id for b in model.trust_boundaries if b.untrusted]
    if untrusted:
        lines.append("  classDef untrusted stroke:#d9534f,stroke-width:2px,stroke-dasharray:4 3")
        lines.append(f"  class {','.join(untrusted)} untrusted")
    return "\n".join(lines)
