"""archthreat CLI. Try: `archthreat analyze samples/payments-platform.yaml`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
import yaml

from archthreat.diagram import to_mermaid
from archthreat.diff import diff_markdown, diff_models
from archthreat.export import to_vulnlens_assets
from archthreat.loader import ModelError, load_model
from archthreat.models import SEVERITY_RANK, Severity
from archthreat.report import render_report
from archthreat.rules import RULES
from archthreat.sarif import to_sarif
from archthreat.services import build_services

app = typer.Typer(help="Threat modeling as code.", no_args_is_help=True)
ModelPath = Annotated[Path, typer.Argument(exists=True, help="System model YAML")]


def _load(path: Path):
    try:
        return load_model(path)
    except ModelError as exc:
        typer.echo(f"{path}: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def validate(model: ModelPath) -> None:
    """Check a model file for schema and reference errors."""
    m = _load(model)
    typer.echo(f"OK: {m.system} ({len(m.components)} components, {len(m.flows)} flows)")


@app.command()
def analyze(
    model: ModelPath,
    llm: Annotated[bool, typer.Option("--llm", help="Add LLM-generated threats")] = False,
    fail_on: Annotated[
        str | None, typer.Option(help="Exit 1 if any threat is at least this severity")
    ] = None,
) -> None:
    """List threats, most severe first."""
    analysis = build_services().analyze(_load(model), use_llm=llm)
    for t in analysis.threats:
        src = t.rule_id or "LLM"
        typer.echo(
            f"{t.severity.value:<8} {t.stride.value:<22} {t.element_id:<24} {src:<10} {t.title}"
        )
    for note in analysis.notes:
        typer.echo(f"note: {note}")
    if analysis.stats:
        s = analysis.stats
        typer.echo(
            f"\nLLM: {s.accepted} accepted of {s.proposed} proposed; {s.duplicates} duplicates, "
            f"{s.rejected_stride} wrong STRIDE category, {s.invalid_references} invalid references dropped"
        )
    if fail_on:
        threshold = SEVERITY_RANK[Severity(fail_on)]
        if any(SEVERITY_RANK[t.severity] >= threshold for t in analysis.threats):
            raise typer.Exit(code=1)


@app.command()
def report(
    model: ModelPath,
    out: Annotated[Path, typer.Option()] = Path("threat-model.md"),
    llm: Annotated[bool, typer.Option("--llm")] = False,
) -> None:
    """Write a markdown report with a Mermaid data-flow diagram."""
    analysis = build_services().analyze(_load(model), use_llm=llm)
    out.write_text(render_report(analysis.model, analysis.threats), encoding="utf-8")
    typer.echo(f"Wrote {out} ({len(analysis.threats)} threats)")


@app.command()
def diagram(model: ModelPath) -> None:
    """Print the Mermaid data-flow diagram."""
    typer.echo(to_mermaid(_load(model)))


@app.command()
def diff(
    old: Annotated[Path, typer.Argument(exists=True)],
    new: Annotated[Path, typer.Argument(exists=True)],
    out: Annotated[Path | None, typer.Option(help="Write the markdown PR comment here")] = None,
    fail_on_new: Annotated[
        str | None, typer.Option(help="Exit 1 if a NEW threat is at least this severity")
    ] = None,
) -> None:
    """Architecture and threat changes between two model versions (rules only)."""
    svc = build_services()
    old_m, new_m = _load(old), _load(new)
    d = diff_models(old_m, new_m, svc.analyze(old_m).threats, svc.analyze(new_m).threats)
    text = diff_markdown(d, new_m.system)
    if out:
        out.write_text(text, encoding="utf-8")
    typer.echo(text)
    worst = d.worst_new_severity()
    if fail_on_new and worst and SEVERITY_RANK[worst] >= SEVERITY_RANK[Severity(fail_on_new)]:
        raise typer.Exit(code=1)


@app.command()
def sarif(
    model: ModelPath,
    out: Annotated[Path, typer.Option()] = Path("threats.sarif"),
    llm: Annotated[bool, typer.Option("--llm")] = False,
) -> None:
    """Export threats as SARIF for GitHub code scanning (or VulnLens)."""
    analysis = build_services().analyze(_load(model), use_llm=llm)
    doc = to_sarif(analysis.model, analysis.threats, str(model), model.read_text(encoding="utf-8"))
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    typer.echo(f"Wrote {out} ({len(analysis.threats)} results)")


@app.command("export-assets")
def export_assets(
    model: ModelPath, out: Annotated[Path, typer.Option()] = Path("assets.yaml")
) -> None:
    """Write VulnLens asset context (internet exposure, data classification) from the model."""
    out.write_text(
        yaml.safe_dump(to_vulnlens_assets(_load(model)), sort_keys=False), encoding="utf-8"
    )
    typer.echo(f"Wrote {out}")


@app.command()
def extract(
    description: Annotated[
        Path, typer.Argument(exists=True, help="Architecture description (text/markdown)")
    ],
    out: Annotated[Path, typer.Option()] = Path("draft-model.yaml"),
) -> None:
    """Draft a model from prose with the configured LLM. Always review the draft."""
    from archthreat.extract import extract_model

    svc = build_services()
    if svc.settings.llm_provider == "fake":
        typer.echo(
            "extract needs a real model: set LLM_PROVIDER to ollama, anthropic or bedrock", err=True
        )
        raise typer.Exit(code=2)
    model = extract_model(description.read_text(encoding="utf-8"), svc.llm)
    out.write_text(
        yaml.safe_dump(model.model_dump(mode="json", exclude_defaults=True), sort_keys=False),
        encoding="utf-8",
    )
    typer.echo(f"Wrote {out}. Review it before trusting it.")


@app.command()
def rules() -> None:
    """List the deterministic rules."""
    for r in RULES:
        typer.echo(f"{r.id:<10} {r.stride.value:<22} {r.title}")


@app.command("eval")
def eval_(
    golden: Annotated[Path, typer.Option(exists=True)] = Path("evals/golden.yaml"),
    llm: Annotated[bool, typer.Option("--llm")] = False,
) -> None:
    """Recall of must-find threats and absence of known false positives."""
    from archthreat.evals import run_evals

    result = run_evals(golden, build_services(), with_llm=llm)
    for name, value in result.metrics.items():
        typer.echo(f"{name:<28} {value}")
    for miss in result.misses:
        typer.echo(f"MISSED  {miss}")
    for fp in result.false_positives:
        typer.echo(f"FALSE+  {fp}")
    if result.failures:
        typer.echo("FAILED: " + "; ".join(result.failures), err=True)
        raise typer.Exit(code=1)
    typer.echo("All thresholds met.")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8001) -> None:
    """Start the REST API (docs at /docs)."""
    import uvicorn

    from archthreat.api import create_app

    uvicorn.run(create_app(), host=host, port=port)


@app.command()
def mcp() -> None:
    """Start the MCP server on stdio."""
    from archthreat.mcp_server import create_mcp

    create_mcp().run()


if __name__ == "__main__":
    app()
