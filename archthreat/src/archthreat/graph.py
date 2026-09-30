"""Graph questions about a system model: boundary crossings, exposure, data sensitivity."""

from __future__ import annotations

from collections import deque

from archthreat.models import (
    CLASSIFICATION_RANK,
    ComponentType,
    DataClassification,
    Flow,
    SystemModel,
)


def crosses_boundary(model: SystemModel, flow: Flow) -> bool:
    return model.component(flow.source).boundary != model.component(flow.target).boundary


def from_untrusted(model: SystemModel, flow: Flow) -> bool:
    return model.boundary(model.component(flow.source).boundary).untrusted


def is_internet_facing(model: SystemModel, component_id: str) -> bool:
    """True if the component ACCEPTS connections from an untrusted zone (pushed inbound flows).

    A job that pulls web pages receives untrusted data but is not internet-facing: nobody can
    connect to it. Mixing those two up is a classic source of threat-model false positives.
    """
    return any(from_untrusted(model, f) and not f.pull for f in model.inbound(component_id))


def receives_untrusted_data(model: SystemModel, component_id: str) -> bool:
    """True if any inbound flow, pushed or pulled, carries data from an untrusted zone."""
    return any(from_untrusted(model, f) for f in model.inbound(component_id))


def reachable_from_untrusted(model: SystemModel) -> set[str]:
    """Components that untrusted data can reach, following flows transitively (BFS).

    This is how indirect prompt injection is found: a web page (untrusted) -> an ingest job ->
    a vector store -> the LLM. The LLM never talks to the internet, yet it reads internet text.
    """
    start = [c.id for c in model.components if model.boundary(c.boundary).untrusted]
    seen: set[str] = set(start)
    queue = deque(start)
    while queue:
        current = queue.popleft()
        for flow in model.outbound(current):
            if flow.target not in seen:
                seen.add(flow.target)
                queue.append(flow.target)
    untrusted_components = set(start)
    return seen - untrusted_components


def max_classification(model: SystemModel, component_id: str) -> DataClassification | None:
    """Highest classification of any data store the component reads from or writes to,
    including its own classification."""
    candidates: list[DataClassification] = []
    own = model.component(component_id).data_classification
    if own:
        candidates.append(own)
    for flow in model.inbound(component_id) + model.outbound(component_id):
        other_id = flow.source if flow.target == component_id else flow.target
        other = model.component(other_id)
        if other.type == ComponentType.DATA_STORE and other.data_classification:
            candidates.append(other.data_classification)
    return max(candidates, key=CLASSIFICATION_RANK.__getitem__) if candidates else None


def is_sensitive(classification: DataClassification | None) -> bool:
    return classification in (DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED)
