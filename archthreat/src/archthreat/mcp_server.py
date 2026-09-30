"""MCP server: threat modeling as tools for Claude Desktop, Claude Code or any MCP client.

Claude Desktop config:
    {"mcpServers": {"archthreat": {"command": "archthreat", "args": ["mcp"],
                                    "env": {"ARCHTHREAT_HOME": "/path/to/repo/.archthreat"}}}}

A nice workflow: ask Claude to draft a model YAML from your architecture notes, then call
`analyze_threat_model` on it and iterate.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from archthreat.diagram import to_mermaid
from archthreat.loader import ModelError, parse_model
from archthreat.rules import RULES
from archthreat.services import Services, build_services


def create_mcp(services: Services | None = None) -> FastMCP:
    svc = services or build_services()
    mcp = FastMCP("archthreat")

    @mcp.tool
    def analyze_threat_model(model_yaml: str, use_llm: bool = False) -> dict[str, Any]:
        """Run STRIDE threat analysis on a system model written in ArchThreat YAML.
        Returns threats sorted by severity. Set use_llm to add model-generated threats."""
        try:
            model = parse_model(model_yaml)
        except ModelError as exc:
            return {"error": str(exc)}
        analysis = svc.analyze(model, use_llm=use_llm)
        return {
            "system": model.system,
            "threat_count": len(analysis.threats),
            "threats": [
                {
                    "id": t.id,
                    "severity": t.severity.value,
                    "stride": t.stride.value,
                    "element": t.element_id,
                    "title": t.title,
                    "mitigations": t.mitigations,
                    "references": t.references,
                    "source": t.source,
                    "rule": t.rule_id,
                }
                for t in analysis.threats
            ],
        }

    @mcp.tool
    def render_data_flow_diagram(model_yaml: str) -> str:
        """Return a Mermaid data-flow diagram for an ArchThreat YAML model."""
        try:
            return to_mermaid(parse_model(model_yaml))
        except ModelError as exc:
            return f"error: {exc}"

    @mcp.tool
    def list_rules() -> list[dict[str, str]]:
        """List the deterministic threat rules ArchThreat applies."""
        return [{"id": r.id, "stride": r.stride.value, "title": r.title} for r in RULES]

    return mcp
