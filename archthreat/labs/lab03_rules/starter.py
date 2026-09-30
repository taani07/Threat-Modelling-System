"""Lab 03 starter. impact_for and the helpers are given."""

from __future__ import annotations

from collections.abc import Iterator

from archthreat.graph import (  # noqa: F401
    crosses_boundary,
    from_untrusted,
    is_sensitive,
    max_classification,
)
from archthreat.models import (  # noqa: F401
    AuthN,
    ComponentType,
    DataClassification,
    Stride,
    SystemModel,
    Threat,
)


def impact_for(classification: DataClassification | None, criticality: int = 3) -> int:
    if classification == DataClassification.RESTRICTED or criticality >= 5:
        return 3
    if classification in (None, DataClassification.PUBLIC) and criticality <= 2:
        return 1
    return 2


def unauthenticated_crossing(model: SystemModel) -> Iterator[Threat]:
    # TODO: for f in model.flows: if <conditions>: yield Threat(rule_id="AUTH-001", ...)
    raise NotImplementedError
    yield  # (makes this a generator even before you write it)


def unencrypted_store(model: SystemModel) -> Iterator[Threat]:
    # TODO
    raise NotImplementedError
    yield


def excessive_agency(model: SystemModel) -> Iterator[Threat]:
    # TODO
    raise NotImplementedError
    yield
