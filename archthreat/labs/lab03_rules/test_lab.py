from pathlib import Path

from archthreat.loader import load_model
from labs._harness import load

r = load("labs.lab03_rules.starter", "archthreat.rules")
SAMPLES = Path(__file__).parents[2] / "samples"
PAY = load_model(SAMPLES / "payments-platform.yaml")
PAY2 = load_model(SAMPLES / "payments-platform-v2.yaml")
RAG = load_model(SAMPLES / "rag-assistant.yaml")
CLAIMS = load_model(SAMPLES / "claims-portal.yaml")


def test_auth_001():
    threats = list(r.unauthenticated_crossing(PAY2))
    by_el = {t.element_id: t for t in threats}
    assert set(by_el) == {"f_admin_reporting", "f_merchant_upload"}
    assert by_el["f_merchant_upload"].likelihood == 3 and by_el["f_admin_reporting"].likelihood == 2
    assert by_el["f_admin_reporting"].impact == 2
    assert all(
        t.rule_id == "AUTH-001" and t.stride.value == "spoofing" and t.references == ["CWE-306"]
        for t in threats
    )
    assert list(r.unauthenticated_crossing(RAG)) == []  # the only unauthenticated flow is a pull


def test_data_001():
    [t] = list(r.unencrypted_store(PAY))
    assert (t.element_id, t.rule_id, t.likelihood, t.impact) == ("reporting_db", "DATA-001", 2, 3)
    assert t.severity.value == "high"
    assert list(r.unencrypted_store(PAY2)) == []


def test_llm_002():
    [t] = list(r.excessive_agency(RAG))
    assert t.element_id == "orchestrator" and t.references == ["LLM06"]
    assert t.stride.value == "elevation_of_privilege"
    assert list(r.excessive_agency(CLAIMS)) == []  # read-only agency
