from pathlib import Path

from archthreat.loader import load_model
from labs._harness import load

g = load("labs.lab02_graph.starter", "archthreat.graph")
SAMPLES = Path(__file__).parents[2] / "samples"
PAY = load_model(SAMPLES / "payments-platform.yaml")
RAG = load_model(SAMPLES / "rag-assistant.yaml")


def flow(model, fid):
    return next(f for f in model.flows if f.id == fid)


def test_crosses_boundary():
    assert g.crosses_boundary(PAY, flow(PAY, "f_customer_api"))
    assert g.crosses_boundary(PAY, flow(PAY, "f_admin_reporting"))
    assert not g.crosses_boundary(PAY, flow(PAY, "f_payments_vault"))


def test_facing_vs_receiving():
    assert g.is_internet_facing(PAY, "api_gateway")
    assert g.is_internet_facing(PAY, "payments_service")  # partner webhook
    assert not g.is_internet_facing(PAY, "card_vault")
    assert not g.is_internet_facing(RAG, "ingest_job")  # it pulls
    assert g.receives_untrusted_data(RAG, "ingest_job")
    assert not g.receives_untrusted_data(RAG, "chat_api")  # employees are in a trusted zone


def test_reachability_is_transitive():
    assert g.reachable_from_untrusted(RAG) == {
        "ingest_job",
        "vector_store",
        "orchestrator",
        "foundation_model",
    }
    exposed = g.reachable_from_untrusted(PAY)
    assert {
        "api_gateway",
        "payments_service",
        "card_vault",
        "admin_console",
        "reporting_db",
    } <= exposed
    assert "customer" not in exposed and "card_network" not in exposed
