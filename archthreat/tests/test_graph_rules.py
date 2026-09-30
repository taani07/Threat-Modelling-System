from conftest import model

from archthreat.graph import (
    crosses_boundary,
    is_internet_facing,
    max_classification,
    reachable_from_untrusted,
    receives_untrusted_data,
)
from archthreat.rules import RULES, STRIDE_PER_ELEMENT, run_rules


def keys(m):
    return {t.key for t in run_rules(m)}


def test_boundary_crossing():
    m = model("payments-platform.yaml")
    flows = {f.id: f for f in m.flows}
    assert crosses_boundary(m, flows["f_customer_api"])
    assert not crosses_boundary(m, flows["f_payments_vault"])


def test_pull_flows_are_not_an_attack_surface():
    m = model("rag-assistant.yaml")
    assert receives_untrusted_data(m, "ingest_job")
    assert not is_internet_facing(m, "ingest_job")
    assert "AUTH-001:f_docs_ingest" not in keys(m)
    assert "INPUT-001:ingest_job" in keys(m)


def test_indirect_exposure_is_transitive():
    m = model("rag-assistant.yaml")
    exposed = reachable_from_untrusted(m)
    assert {"ingest_job", "vector_store", "orchestrator"} <= exposed
    assert "hr_db" not in exposed and "chat_api" not in exposed


def test_max_classification_follows_data_stores():
    m = model("rag-assistant.yaml")
    assert max_classification(m, "orchestrator").value == "restricted"
    assert max_classification(m, "chat_api") is None


def test_stride_per_element_table():
    assert STRIDE_PER_ELEMENT["external_entity"] == {"spoofing", "repudiation"}
    assert len(STRIDE_PER_ELEMENT["process"]) == 6
    assert "elevation_of_privilege" not in STRIDE_PER_ELEMENT["data_store"]


def test_rules_are_deterministic_and_unique():
    m = model("payments-platform.yaml")
    first, second = run_rules(m), run_rules(m)
    assert [t.key for t in first] == [t.key for t in second]
    assert len({t.key for t in first}) == len(first)
    assert len({r.id for r in RULES}) == len(RULES)


def test_llm_rules_follow_agency():
    rag, claims = model("rag-assistant.yaml"), model("claims-portal.yaml")
    injection = {t.element_id: t for t in run_rules(rag) if t.rule_id == "LLM-001"}
    assert injection["orchestrator"].severity.value == "critical"  # write agency
    claims_injection = [t for t in run_rules(claims) if t.rule_id == "LLM-001"][0]
    assert claims_injection.severity.value == "high"  # read-only agency
    assert "LLM-002:claim_summariser" not in keys(claims)


def test_every_threat_has_mitigations_and_references():
    for name in ["payments-platform.yaml", "rag-assistant.yaml", "claims-portal.yaml"]:
        for t in run_rules(model(name)):
            assert t.mitigations and t.references, t.key
