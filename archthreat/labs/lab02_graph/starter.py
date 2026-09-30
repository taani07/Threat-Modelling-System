"""Lab 02 starter."""

from __future__ import annotations

from collections import deque  # noqa: F401

from archthreat.models import Flow, SystemModel


def from_untrusted(model: SystemModel, flow: Flow) -> bool:
    """Given: does the flow start in an untrusted boundary?"""
    return model.boundary(model.component(flow.source).boundary).untrusted


def crosses_boundary(model: SystemModel, flow: Flow) -> bool:
    # TODO
    raise NotImplementedError


def is_internet_facing(model: SystemModel, component_id: str) -> bool:
    # TODO: pushed (not pull) inbound flows from untrusted zones only
    raise NotImplementedError


def receives_untrusted_data(model: SystemModel, component_id: str) -> bool:
    # TODO
    raise NotImplementedError


def reachable_from_untrusted(model: SystemModel) -> set[str]:
    # TODO: BFS from every component in an untrusted boundary, following model.outbound(id)
    raise NotImplementedError
