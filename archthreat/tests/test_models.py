import pytest
from conftest import model

from archthreat.loader import ModelError, parse_model
from archthreat.models import Severity, Stride, Threat, severity_for

MINIMAL = """
system: t
trust_boundaries: [{id: net, name: Net, untrusted: true}, {id: app, name: App}]
components:
  - {id: user, type: external_entity, boundary: net}
  - {id: api, type: process, boundary: app}
flows:
  - {id: f1, source: user, target: api}
"""


def test_samples_load():
    m = model("payments-platform.yaml")
    assert m.component("card_vault").encrypted_at_rest
    assert [f.id for f in m.inbound("payments_service")] == ["f_api_payments", "f_network_webhook"]


def test_undeclared_properties_default_to_absent():
    m = parse_model(MINIMAL)
    api = m.component("api")
    assert not (api.rate_limiting or api.input_validation or api.audit_logging)
    assert m.flows[0].authn.value == "none" and m.flows[0].encrypted


@pytest.mark.parametrize(
    "bad,message",
    [
        (MINIMAL.replace("target: api", "target: nope"), "unknown component 'nope'"),
        (MINIMAL.replace("boundary: app}", "boundary: mars}"), "unknown boundary 'mars'"),
        (MINIMAL.replace("id: f1", "id: api"), "duplicate ids: api"),
        (MINIMAL.replace("id: api,", "id: Api-1,"), "String should match pattern"),
        ("- just\n- a list", "must be a YAML mapping"),
        ("system: [unclosed", "invalid YAML"),
    ],
)
def test_validation_errors_are_readable(bad, message):
    with pytest.raises(ModelError, match=message.replace("(", r"\(")):
        parse_model(bad)


def test_yaml_is_loaded_safely():
    with pytest.raises(ModelError):
        parse_model("!!python/object/apply:os.system ['echo pwned']")


@pytest.mark.parametrize(
    "likelihood,impact,sev",
    [
        (3, 3, "critical"),
        (2, 3, "high"),
        (3, 2, "high"),
        (2, 2, "medium"),
        (3, 1, "medium"),
        (2, 1, "low"),
        (1, 1, "low"),
    ],
)
def test_risk_matrix(likelihood, impact, sev):
    assert severity_for(likelihood, impact) is Severity(sev)


def test_threat_identity_is_stable():
    a = Threat(
        stride=Stride.SPOOFING,
        element_id="f1",
        title="x",
        description="d",
        likelihood=1,
        impact=1,
        rule_id="AUTH-001",
    )
    b = a.model_copy(update={"title": "different wording"})
    assert a.key == b.key == "AUTH-001:f1" and a.id == b.id
    llm = a.model_copy(update={"rule_id": None, "source": "llm"})
    assert llm.key.startswith("LLM:f1:spoofing:")
