"""Lab 01 starter."""

from __future__ import annotations

from archthreat.models import SystemModel


def reference_errors(model: SystemModel) -> list[str]:
    errors: list[str] = []
    # TODO 1: duplicate ids across components and flows (one message, sorted ids)
    # TODO 2: components whose boundary is not a declared trust boundary
    # TODO 3: flows whose source or target is not a component
    raise NotImplementedError
    return errors
