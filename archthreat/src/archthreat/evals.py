"""Threat model evals.

Rules layer (deterministic, run on every PR):
  rule_recall          - share of must-find threats that were found
  negative_precision   - share of must-not-find threats that were correctly NOT raised

LLM layer (`--llm`, costs tokens):
  llm_failed_elements, llm_stride_violation_rate, llm_invalid_reference_rate,
  llm_duplicate_rate, llm_accepted
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from archthreat.loader import load_model
from archthreat.services import Services


@dataclass
class EvalResult:
    metrics: dict[str, float]
    misses: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)


def _key(item: dict) -> str:
    return f"{item['rule']}:{item['element']}"


def run_evals(golden_path: str | Path, svc: Services, with_llm: bool = False) -> EvalResult:
    golden = yaml.safe_load(Path(golden_path).read_text(encoding="utf-8"))
    base = Path(golden_path).parent.parent
    must, must_not, found_must, found_not = 0, 0, 0, 0
    misses, fps = [], []
    proposed = accepted = dupes = bad_stride = bad_refs = failed = 0

    for case in golden["cases"]:
        model = load_model(base / case["model"])
        analysis = svc.analyze(model, use_llm=with_llm)
        keys = {t.key for t in analysis.threats}
        for item in case.get("must_find", []):
            must += 1
            if _key(item) in keys:
                found_must += 1
            else:
                misses.append(f"{case['model']} {_key(item)}")
        for item in case.get("must_not_find", []):
            must_not += 1
            if _key(item) in keys:
                found_not += 1
                fps.append(f"{case['model']} {_key(item)}")
        if analysis.stats:
            s = analysis.stats
            proposed += s.proposed
            accepted += s.accepted
            dupes += s.duplicates
            bad_stride += s.rejected_stride
            bad_refs += s.invalid_references
            failed += len(s.failed_elements)

    metrics = {
        "rule_recall": round(found_must / must, 4) if must else 1.0,
        "negative_precision": round(1 - found_not / must_not, 4) if must_not else 1.0,
    }
    if with_llm:
        metrics |= {
            "llm_proposed": proposed,
            "llm_accepted": accepted,
            "llm_duplicate_rate": round(dupes / proposed, 4) if proposed else 0.0,
            "llm_stride_violation_rate": round(bad_stride / proposed, 4) if proposed else 0.0,
            "llm_invalid_references": bad_refs,
            "llm_failed_elements": failed,
        }
    thresholds = golden.get("thresholds", {})
    failures = [
        f"{name} = {metrics[name]} < {minimum}"
        for name, minimum in thresholds.items()
        if name in metrics and metrics[name] < minimum
    ]
    return EvalResult(metrics, misses, fps, failures)
