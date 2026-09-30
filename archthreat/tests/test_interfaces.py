import asyncio
from dataclasses import replace

from conftest import ROOT, SAMPLES
from fastapi.testclient import TestClient
from fastmcp import Client
from typer.testing import CliRunner

from archthreat.api import create_app
from archthreat.cli import app
from archthreat.evals import run_evals
from archthreat.mcp_server import create_mcp
from archthreat.services import build_services

YAML = (SAMPLES / "payments-platform.yaml").read_text()


def test_api(settings):
    client = TestClient(create_app(settings, build_services(settings)))
    r = client.post("/analyze", json={"model_yaml": YAML})
    assert r.status_code == 200
    body = r.json()
    assert body["system"] == "Payments platform" and len(body["threats"]) == 11
    assert body["mermaid"].startswith("flowchart")
    assert client.post("/analyze", json={"model_yaml": "system: [x"}).status_code == 422
    d = client.post(
        "/diff",
        json={"old_yaml": YAML, "new_yaml": (SAMPLES / "payments-platform-v2.yaml").read_text()},
    )
    assert "5 new threats, 1 resolved" in d.json()["markdown"]


def test_api_key(settings):
    s = replace(settings, api_key="k-123")
    client = TestClient(create_app(s, build_services(s)))
    assert client.post("/analyze", json={"model_yaml": YAML}).status_code == 401
    assert (
        client.post(
            "/analyze", json={"model_yaml": YAML}, headers={"x-api-key": "k-123"}
        ).status_code
        == 200
    )


def test_mcp(services):
    async def run():
        async with Client(create_mcp(services)) as c:
            names = {t.name for t in await c.list_tools()}
            assert names == {"analyze_threat_model", "render_data_flow_diagram", "list_rules"}
            result = (await c.call_tool("analyze_threat_model", {"model_yaml": YAML})).data
            assert result["threat_count"] == 11
            err = (await c.call_tool("analyze_threat_model", {"model_yaml": "nope: ["})).data
            assert "error" in err

    asyncio.run(run())


def test_evals(services):
    result = run_evals(ROOT / "evals/golden.yaml", services)
    assert not result.failures and result.metrics["rule_recall"] == 1.0


def test_cli(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("ARCHTHREAT_HOME", str(tmp_path))
    monkeypatch.setenv("LLM_PROVIDER", "fake")
    runner = CliRunner()
    assert runner.invoke(app, ["validate", str(SAMPLES / "claims-portal.yaml")]).exit_code == 0
    r = runner.invoke(
        app, ["analyze", str(SAMPLES / "rag-assistant.yaml"), "--fail-on", "critical"]
    )
    assert r.exit_code == 1 and "LLM-001" in r.output
    out = tmp_path / "tm.md"
    assert (
        runner.invoke(
            app, ["report", str(SAMPLES / "claims-portal.yaml"), "--out", str(out)]
        ).exit_code
        == 0
    )
    assert "```mermaid" in out.read_text()
    assert runner.invoke(app, ["eval"]).exit_code == 0
    v1, v2 = str(SAMPLES / "payments-platform.yaml"), str(SAMPLES / "payments-platform-v2.yaml")
    assert runner.invoke(app, ["diff", v1, v2, "--fail-on-new", "high"]).exit_code == 1
    assert runner.invoke(app, ["diff", v1, v2, "--fail-on-new", "critical"]).exit_code == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "system: x\ntrust_boundaries: []\ncomponents: [{id: a, type: process, boundary: b}]\n"
    )
    assert runner.invoke(app, ["validate", str(bad)]).exit_code == 2
    assert runner.invoke(app, ["extract", str(bad)]).exit_code == 2  # needs a real model
