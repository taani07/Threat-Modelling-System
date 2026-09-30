# Lab 06: Diff two versions of an architecture

## Goal

Implement `diff_models(old, new, old_threats, new_threats)` returning a `ModelDiff` (the
dataclass is given): added, removed and changed components and flows, plus new and resolved
threats matched by `Threat.key`. Changed items list `"<field>: <before> -> <after>"` for each
watched field that differs (use the given `_changes` helper).

## Why it matters

Threat models die when they are a one-off document. Diffing makes them part of the normal
change process: when a pull request adds a component or weakens a flow, the reviewer sees the
exact security consequence ("5 new threats, 1 resolved"), and a policy can require security
review only when high or critical threats appear. That's how you scale a security architecture
function without becoming a bottleneck, which is a strong story for staff and architect interviews.

## Python you will learn

- Dict comprehensions to index by id: `{c.id: c for c in model.components}`.
- Set algebra on dict keys: `new.keys() - old.keys()`, `old.keys() & new.keys()`.
- The walrus operator: `if changes := _changes(a, b, fields):`.
- `getattr(obj, name)` for generic field access (Java reflection, minus the ceremony).
