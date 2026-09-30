import json

from conftest import model

from archthreat.enrich import LLMThreatList, enrich, is_duplicate, jaccard
from archthreat.llm.fake import FakeLLM
from archthreat.models import Stride, Threat
from archthreat.rules import run_rules
from archthreat.services import build_services


def proposal(**kw):
    base = {
        "stride": "tampering",
        "title": "Mass assignment via Spring data binding",
        "description": "d",
        "likelihood": 2,
        "impact": 3,
        "mitigations": ["Use DTOs"],
        "references": ["CWE-915"],
    }
    return base | kw


def responder_for(proposals_by_element):
    def respond(messages, system):
        prompt = messages[0].content
        for element, proposals in proposals_by_element.items():
            if f"Element id: {element}\n" in prompt:
                return json.dumps({"threats": proposals})
        return LLMThreatList().model_dump_json()

    return respond


def test_jaccard_and_duplicates():
    assert jaccard("prompt injection steers the model", "prompt injection can steer model") > 0.4
    existing = [
        Threat(
            stride=Stride.TAMPERING,
            element_id="a",
            title="Prompt injection can steer the orchestrator",
            description="d",
            likelihood=3,
            impact=3,
            rule_id="LLM-001",
        )
    ]
    dup = existing[0].model_copy(
        update={"rule_id": None, "title": "Prompt injection steers the orchestrator"}
    )
    other = dup.model_copy(update={"element_id": "b"})
    assert is_duplicate(dup, existing) and not is_duplicate(other, existing)


def test_enrichment_validates_everything(settings):
    m = model("payments-platform.yaml")
    rules = run_rules(m)
    llm = FakeLLM(
        responder_for(
            {
                "payments_service": [
                    proposal(),  # accepted
                    proposal(
                        title="Webhook replay changes settlement state",
                        stride="spoofing",
                        references=["CWE-294", "OWASP-TOTALLY-REAL-123"],
                    ),  # accepted, one bad ref dropped
                    proposal(
                        title="Payments service can be overwhelmed by untrusted callers",
                        stride="denial_of_service",
                    ),  # duplicate of DOS-001
                ],
                "card_vault": [
                    proposal(stride="elevation_of_privilege", title="Vault admin escalation")
                ],  # EoP not allowed on a data store
            }
        )
    )
    svc = build_services(settings, llm=llm)
    extra, stats = enrich(m, rules, llm, svc.index, max_per_element=3)
    titles = {t.title for t in extra}
    assert titles == {
        "Mass assignment via Spring data binding",
        "Webhook replay changes settlement state",
    }
    assert all(t.source == "llm" and t.rule_id is None for t in extra)
    replay = next(t for t in extra if "replay" in t.title)
    assert replay.references == ["CWE-294"]
    assert (stats.duplicates, stats.rejected_stride, stats.invalid_references) == (1, 1, 1)
    assert stats.elements == 6  # processes + data stores, not external entities


def test_prompt_fences_model_text_and_lists_known_threats(settings):
    m = model("rag-assistant.yaml")
    seen = []

    def respond(messages, system):
        seen.append(messages[0].content)
        return LLMThreatList().model_dump_json()

    llm = FakeLLM(respond)
    enrich(m, run_rules(m), llm, build_services(settings, llm=llm).index)
    orch = next(p for p in seen if "Element id: orchestrator\n" in p)
    assert "<untrusted_model>" in orch and "</untrusted_model>" in orch
    assert "Prompt injection can steer LLM orchestrator" in orch  # rule threat listed as known
    assert "Allowed STRIDE categories" in orch and "<context>" in orch


def test_max_per_element(settings):
    m = model("claims-portal.yaml")
    many = [
        proposal(title=t)
        for t in [
            "Mass assignment through request binding",
            "Claim status forged by replayed events",
            "Adjuster notes altered without versioning",
            "Attachment metadata spoofs policy number",
            "Bulk export bypasses field-level masking",
        ]
    ]
    llm = FakeLLM(responder_for({"claims_api": many}))
    extra, _ = enrich(
        m, run_rules(m), llm, build_services(settings, llm=llm).index, max_per_element=2
    )
    assert len([t for t in extra if t.element_id == "claims_api"]) == 2


def test_offline_mode_adds_nothing(services):
    analysis = services.analyze(model("payments-platform.yaml"), use_llm=True)
    assert all(t.source == "rule" for t in analysis.threats)
    assert analysis.notes
