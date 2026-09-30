"""Markdown threat model report."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from archthreat.diagram import to_mermaid
from archthreat.models import Severity, Stride, SystemModel, Threat, sort_threats

STRIDE_LABEL = {
    Stride.SPOOFING: "Spoofing",
    Stride.TAMPERING: "Tampering",
    Stride.REPUDIATION: "Repudiation",
    Stride.INFORMATION_DISCLOSURE: "Information disclosure",
    Stride.DENIAL_OF_SERVICE: "Denial of service",
    Stride.ELEVATION_OF_PRIVILEGE: "Elevation of privilege",
}


def summary_table(threats: list[Threat]) -> list[str]:
    counts = Counter((t.stride, t.severity) for t in threats)
    sev = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    rows = [
        "| STRIDE | " + " | ".join(s.value.title() for s in sev) + " |",
        "| --- |" + " --- |" * len(sev),
    ]
    for stride in Stride:
        cells = [str(counts.get((stride, s), 0) or "") for s in sev]
        rows.append(f"| {STRIDE_LABEL[stride]} | " + " | ".join(cells) + " |")
    return rows


def render_report(model: SystemModel, threats: list[Threat]) -> str:
    threats = sort_threats(threats)
    n_llm = sum(1 for t in threats if t.source == "llm")
    lines = [
        f"# Threat model: {model.system}",
        "",
        f"Generated {datetime.now(UTC):%Y-%m-%d} by ArchThreat. {len(threats)} threats "
        f"({len(threats) - n_llm} from rules, {n_llm} model-generated and marked as such).",
        "",
    ]
    if model.description:
        lines += [model.description, ""]
    lines += [
        "## Data-flow diagram",
        "",
        "```mermaid",
        to_mermaid(model),
        "```",
        "",
        "## Summary",
        "",
        *summary_table(threats),
        "",
        "## Threats",
        "",
        "| ID | Severity | STRIDE | Element | Threat | Source |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for t in threats:
        source = t.rule_id or "LLM (review)"
        lines.append(
            f"| {t.id} | {t.severity.value} | {STRIDE_LABEL[t.stride]} | `{t.element_id}` | {t.title} | {source} |"
        )
    lines += ["", "## Details"]
    for t in threats:
        refs = ", ".join(t.references)
        lines += [
            "",
            f"### {t.id} {t.title}",
            "",
            f"**{t.severity.value.title()}** (likelihood {t.likelihood}/3, impact {t.impact}/3) · "
            f"{STRIDE_LABEL[t.stride]} · element `{t.element_id}`"
            + (f" · {refs}" if refs else "")
            + (" · *model-generated, verify before accepting*" if t.source == "llm" else ""),
            "",
            t.description,
            "",
            "Mitigations:",
            *[f"- [ ] {m}" for m in t.mitigations],
        ]
    return "\n".join(lines) + "\n"
