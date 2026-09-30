"""Export threats as SARIF 2.1.0 so they appear in GitHub code scanning (and in VulnLens).

Each threat becomes a result located at the line in the model YAML where its element is
declared. `partialFingerprints` use the threat key, so GitHub tracks a threat across commits
and closes it when the architecture fixes it.
"""

from __future__ import annotations

import re

from archthreat import __version__
from archthreat.models import Severity, SystemModel, Threat, sort_threats

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def element_line(yaml_text: str, element_id: str) -> int:
    """1-based line where `id: <element_id>` appears, or 1 if not found."""
    pattern = re.compile(r"\bid:\s*['\"]?" + re.escape(element_id) + r"['\"]?(?![\w-])")
    for number, line in enumerate(yaml_text.splitlines(), start=1):
        if pattern.search(line):
            return number
    return 1


def rule_id_for(t: Threat) -> str:
    return t.rule_id or f"LLM-{t.stride.value}"


def to_sarif(model: SystemModel, threats: list[Threat], model_path: str, yaml_text: str) -> dict:
    threats = sort_threats(threats)
    rules: dict[str, dict] = {}
    for t in threats:
        rid = rule_id_for(t)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {
                    "text": t.title if t.rule_id else f"Model-generated {t.stride.value} threat"
                },
                "properties": {"tags": ["security", "threat-model", t.stride.value, *t.references]},
            }
    results = [
        {
            "ruleId": rule_id_for(t),
            "level": SARIF_LEVEL[t.severity],
            "message": {
                "text": f"{t.title}. {t.description} Mitigations: {'; '.join(t.mitigations)}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": model_path},
                        "region": {"startLine": element_line(yaml_text, t.element_id)},
                    }
                }
            ],
            "partialFingerprints": {"archthreatKey": t.key},
            "properties": {
                "security-severity": SECURITY_SEVERITY[t.severity],
                "tags": list(t.references),
                "source": t.source,
            },
        }
        for t in threats
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ArchThreat",
                        "version": __version__,
                        "informationUri": "https://github.com/taani07/archthreat",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
