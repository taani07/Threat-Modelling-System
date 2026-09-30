from archthreat.models import Component, Flow, SystemModel, TrustBoundary
from labs._harness import load

m = load("labs.lab01_model.starter", "archthreat.models")


def build(components, flows):
    return SystemModel.model_construct(
        system="t",
        description="",
        trust_boundaries=[
            TrustBoundary(id="net", name="Net", untrusted=True),
            TrustBoundary(id="app", name="App"),
        ],
        components=components,
        flows=flows,
    )


USER = Component(id="user", type="external_entity", boundary="net")
API = Component(id="api", type="process", boundary="app")


def test_valid_model_has_no_errors():
    assert (
        m.reference_errors(build([USER, API], [Flow(id="f1", source="user", target="api")])) == []
    )


def test_all_problems_reported():
    errors = m.reference_errors(
        build(
            [
                USER,
                API,
                Component(id="db", type="data_store", boundary="mars"),
                Component(id="api", type="process", boundary="app"),
            ],
            [
                Flow(id="f1", source="user", target="ghost"),
                Flow(id="user", source="nobody", target="api"),
            ],
        )
    )
    assert errors == [
        "duplicate ids: api, user",
        "component 'db' is in unknown boundary 'mars'",
        "flow 'f1' references unknown component 'ghost'",
        "flow 'user' references unknown component 'nobody'",
    ]
