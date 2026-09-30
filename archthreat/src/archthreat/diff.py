"""Compare two versions of a system model and their threats (for pull request comments)."""

from __future__ import annotations

from dataclasses import dataclass, field

from archthreat.models import SEVERITY_RANK, Severity, SystemModel, Threat, sort_threats

WATCHED_COMPONENT_FIELDS = (
    "type",
    "boundary",
    "tech",
    "data_classification",
    "encrypted_at_rest",
    "audit_logging",
    "rate_limiting",
    "input_validation",
    "runs_as_root",
    "admin_interface",
    "llm",
)
WATCHED_FLOW_FIELDS = ("source", "target", "pull", "protocol", "authn", "encrypted", "data")


@dataclass
class ModelDiff:
    added_components: list[str] = field(default_factory=list)
    removed_components: list[str] = field(default_factory=list)
    changed_components: dict[str, list[str]] = field(default_factory=dict)
    added_flows: list[str] = field(default_factory=list)
    removed_flows: list[str] = field(default_factory=list)
    changed_flows: dict[str, list[str]] = field(default_factory=dict)
    new_threats: list[Threat] = field(default_factory=list)
    resolved_threats: list[Threat] = field(default_factory=list)

    @property
    def architecture_changed(self) -> bool:
        return any(
            [
                self.added_components,
                self.removed_components,
                self.changed_components,
                self.added_flows,
                self.removed_flows,
                self.changed_flows,
            ]
        )

    def worst_new_severity(self) -> Severity | None:
        if not self.new_threats:
            return None
        return max((t.severity for t in self.new_threats), key=SEVERITY_RANK.__getitem__)


def _changes(old: object, new: object, fields: tuple[str, ...]) -> list[str]:
    out = []
    for name in fields:
        before, after = getattr(old, name), getattr(new, name)
        if before != after:
            out.append(f"{name}: {_fmt(before)} -> {_fmt(after)}")
    return out


def _fmt(value: object) -> str:
    if hasattr(value, "value"):
        return str(value.value)
    if hasattr(value, "model_dump"):
        return str(value.model_dump())
    return str(value)


def diff_models(
    old: SystemModel, new: SystemModel, old_threats: list[Threat], new_threats: list[Threat]
) -> ModelDiff:
    d = ModelDiff()
    old_c = {c.id: c for c in old.components}
    new_c = {c.id: c for c in new.components}
    d.added_components = sorted(new_c.keys() - old_c.keys())
    d.removed_components = sorted(old_c.keys() - new_c.keys())
    for cid in sorted(old_c.keys() & new_c.keys()):
        if changes := _changes(old_c[cid], new_c[cid], WATCHED_COMPONENT_FIELDS):
            d.changed_components[cid] = changes

    old_f = {f.id: f for f in old.flows}
    new_f = {f.id: f for f in new.flows}
    d.added_flows = sorted(new_f.keys() - old_f.keys())
    d.removed_flows = sorted(old_f.keys() - new_f.keys())
    for fid in sorted(old_f.keys() & new_f.keys()):
        if changes := _changes(old_f[fid], new_f[fid], WATCHED_FLOW_FIELDS):
            d.changed_flows[fid] = changes

    old_keys = {t.key for t in old_threats}
    new_keys = {t.key for t in new_threats}
    d.new_threats = sort_threats([t for t in new_threats if t.key not in old_keys])
    d.resolved_threats = sort_threats([t for t in old_threats if t.key not in new_keys])
    return d


def diff_markdown(d: ModelDiff, system: str) -> str:
    """A compact PR comment: what changed in the architecture and what that did to risk."""
    if not d.architecture_changed and not d.new_threats and not d.resolved_threats:
        return f"### ArchThreat: {system}\n\nNo architecture or threat changes.\n"
    lines = [f"### ArchThreat: {system}", ""]
    worst = d.worst_new_severity()
    if worst in (Severity.CRITICAL, Severity.HIGH):
        lines += [
            f"**This change introduces {worst.value} threats. Security review requested.**",
            "",
        ]
    lines += [f"{len(d.new_threats)} new threats, {len(d.resolved_threats)} resolved.", ""]

    arch = []
    arch += [f"- added component `{c}`" for c in d.added_components]
    arch += [f"- removed component `{c}`" for c in d.removed_components]
    arch += [f"- changed `{c}`: {'; '.join(ch)}" for c, ch in d.changed_components.items()]
    arch += [f"- added flow `{f}`" for f in d.added_flows]
    arch += [f"- removed flow `{f}`" for f in d.removed_flows]
    arch += [f"- changed flow `{f}`: {'; '.join(ch)}" for f, ch in d.changed_flows.items()]
    if arch:
        lines += ["**Architecture changes**", "", *arch, ""]
    if d.new_threats:
        lines += [
            "**New threats**",
            "",
            "| Severity | Element | Threat | Rule |",
            "| --- | --- | --- | --- |",
        ]
        lines += [
            f"| {t.severity.value} | `{t.element_id}` | {t.title} | {t.rule_id or 'LLM'} |"
            for t in d.new_threats
        ]
        lines.append("")
    if d.resolved_threats:
        lines += ["**Resolved threats**", ""]
        lines += [f"- ~~{t.title}~~ (`{t.element_id}`)" for t in d.resolved_threats]
        lines.append("")
    return "\n".join(lines)
