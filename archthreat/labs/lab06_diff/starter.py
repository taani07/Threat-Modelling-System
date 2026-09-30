"""Lab 06 starter. ModelDiff, the field lists and _changes are given."""

from __future__ import annotations

from archthreat.diff import (  # noqa: F401
    WATCHED_COMPONENT_FIELDS,
    WATCHED_FLOW_FIELDS,
    ModelDiff,
    _changes,
)
from archthreat.models import SystemModel, Threat, sort_threats  # noqa: F401


def diff_models(
    old: SystemModel, new: SystemModel, old_threats: list[Threat], new_threats: list[Threat]
) -> ModelDiff:
    d = ModelDiff()
    # TODO: components (added/removed sorted; changed as dict id -> list of changes)
    # TODO: flows (same)
    # TODO: new_threats / resolved_threats by key, each passed through sort_threats
    raise NotImplementedError
    return d
