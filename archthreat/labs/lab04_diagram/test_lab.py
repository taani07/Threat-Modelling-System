from pathlib import Path

from archthreat.loader import load_model
from archthreat.models import Component
from labs._harness import load

d = load("labs.lab04_diagram.starter", "archthreat.diagram")
SAMPLES = Path(__file__).parents[2] / "samples"


def test_node_shapes_and_escaping():
    assert (
        d.node(Component(id="u", name='The "user"', type="external_entity", boundary="b"))
        == "u[\"The 'user'\"]"
    )
    assert (
        d.node(Component(id="p", name="API", tech="Java", type="process", boundary="b"))
        == 'p("API<br/>Java")'
    )
    assert d.node(Component(id="s", type="data_store", boundary="b")) == 's[("s")]'


def test_full_diagram():
    text = d.to_mermaid(load_model(SAMPLES / "payments-platform-v2.yaml"))
    lines = text.splitlines()
    assert lines[0] == "flowchart LR"
    assert '  subgraph internet["Internet (untrusted)"]' in lines
    assert '    card_vault[("Card vault<br/>PostgreSQL on RDS")]' in lines
    assert '  customer -->|"HTTPS / oauth2"| api_gateway' in lines
    assert '  merchant -.->|"⚠ HTTP / none"| merchant_portal' in lines
    assert lines[-1] == "  class internet,partner untrusted"
    assert text.count("  end") == 4


def test_pull_flow_label():
    text = d.to_mermaid(load_model(SAMPLES / "rag-assistant.yaml"))
    assert '  vendor_docs -->|"HTTPS / none (pull)"| ingest_job' in text.splitlines()
