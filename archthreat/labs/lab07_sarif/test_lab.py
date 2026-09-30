import json
from pathlib import Path

from archthreat.loader import load_model
from archthreat.rules import run_rules
from labs._harness import load

s = load("labs.lab07_sarif.starter", "archthreat.sarif")
PATH = Path(__file__).parents[2] / "samples/payments-platform.yaml"
TEXT = PATH.read_text()
MODEL = load_model(PATH)


def test_element_line():
    assert s.element_line("a: 1\n- {id: f_a}\n- {id: f_ab}\n", "f_ab") == 3
    assert s.element_line("a: 1\n- {id: f_a}\n- {id: f_ab}\n", "f_a") == 2
    assert s.element_line("  - id: reporting_db\n", "reporting_db") == 1
    assert s.element_line("nothing", "x") == 1


def test_sarif_document():
    doc = s.to_sarif(MODEL, run_rules(MODEL), "samples/payments-platform.yaml", TEXT)
    json.dumps(doc)
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "ArchThreat"
    assert len(run["results"]) == 11
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    by_key = {r["partialFingerprints"]["archthreatKey"]: r for r in run["results"]}
    vault = by_key["DATA-001:reporting_db"]
    assert vault["level"] == "error" and vault["properties"]["security-severity"] == "7.5"
    line = vault["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert "id: reporting_db" in TEXT.splitlines()[line - 1]
    assert (
        vault["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "samples/payments-platform.yaml"
    )
