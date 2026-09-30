"""Export asset context for VulnLens (github.com/taani07/vulnlens).

The threat model already knows which services are internet-facing and what data they touch.
VulnLens needs exactly that to prioritise vulnerabilities. One source of truth, two tools.
"""

from __future__ import annotations

from archthreat.graph import is_internet_facing, max_classification
from archthreat.models import ComponentType, SystemModel


def to_vulnlens_assets(model: SystemModel) -> dict:
    assets = []
    for c in model.components:
        if c.type != ComponentType.PROCESS:
            continue
        classification = max_classification(model, c.id)
        assets.append(
            {
                "name": c.id,
                "internet_facing": is_internet_facing(model, c.id),
                "data_classification": classification.value if classification else "internal",
                "criticality": c.criticality,
            }
        )
    return {"assets": assets}
