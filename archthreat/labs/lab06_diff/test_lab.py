from pathlib import Path

from archthreat.loader import load_model
from archthreat.rules import run_rules
from labs._harness import load

m = load("labs.lab06_diff.starter", "archthreat.diff")
SAMPLES = Path(__file__).parents[2] / "samples"
V1 = load_model(SAMPLES / "payments-platform.yaml")
V2 = load_model(SAMPLES / "payments-platform-v2.yaml")


def test_diff_v1_v2():
    d = m.diff_models(V1, V2, run_rules(V1), run_rules(V2))
    assert d.added_components == ["merchant", "merchant_portal"]
    assert d.removed_components == []
    assert d.changed_components == {"reporting_db": ["encrypted_at_rest: False -> True"]}
    assert d.added_flows == ["f_merchant_upload", "f_portal_payments"]
    assert d.changed_flows == {}
    assert [t.key for t in d.resolved_threats] == ["DATA-001:reporting_db"]
    assert len(d.new_threats) == 5 and d.new_threats[0].severity.value == "high"


def test_reverse_diff_and_no_change():
    back = m.diff_models(V2, V1, run_rules(V2), run_rules(V1))
    assert back.removed_components == ["merchant", "merchant_portal"]
    assert [t.key for t in back.new_threats] == ["DATA-001:reporting_db"]
    same = m.diff_models(V1, V1, run_rules(V1), run_rules(V1))
    assert not same.architecture_changed and not same.new_threats
