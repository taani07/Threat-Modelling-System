from pathlib import Path

from archthreat.diff import ModelDiff, diff_models
from archthreat.loader import load_model
from archthreat.rules import run_rules
from labs._harness import load

m = load("labs.lab08_pr_workflow.starter", "archthreat.diff")
SAMPLES = Path(__file__).parents[2] / "samples"
V1 = load_model(SAMPLES / "payments-platform.yaml")
V2 = load_model(SAMPLES / "payments-platform-v2.yaml")


def test_comment_for_risky_change():
    md = m.diff_markdown(diff_models(V1, V2, run_rules(V1), run_rules(V2)), "Payments platform")
    lines = md.splitlines()
    assert lines[0] == "### ArchThreat: Payments platform"
    assert "**This change introduces high threats. Security review requested.**" in lines
    assert "5 new threats, 1 resolved." in lines
    assert "- added component `merchant_portal`" in lines
    assert "- changed `reporting_db`: encrypted_at_rest: False -> True" in lines
    assert "| Severity | Element | Threat | Rule |" in lines
    assert (
        "| high | `merchant_portal` | Untrusted input to Merchant refund portal is not validated | INPUT-001 |"
        in lines
    )
    assert (
        "- ~~Reporting database holds confidential data without encryption at rest~~ (`reporting_db`)"
        in lines
    )


def test_comment_for_safe_change():
    md = m.diff_markdown(diff_models(V2, V1, run_rules(V2), run_rules(V1)), "P")
    assert "Security review requested" in md  # reverting re-introduces a high threat
    assert (
        m.diff_markdown(ModelDiff(), "P")
        == "### ArchThreat: P\n\nNo architecture or threat changes.\n"
    )
