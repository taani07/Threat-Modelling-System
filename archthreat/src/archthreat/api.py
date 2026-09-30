"""REST API. Run `archthreat serve`, then open http://127.0.0.1:8001/docs."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from archthreat import __version__
from archthreat.config import Settings
from archthreat.diagram import to_mermaid
from archthreat.diff import diff_markdown, diff_models
from archthreat.loader import MAX_MODEL_BYTES, ModelError, parse_model
from archthreat.models import Threat
from archthreat.report import render_report
from archthreat.services import Services, build_services


class AnalyzeRequest(BaseModel):
    model_yaml: str = Field(max_length=MAX_MODEL_BYTES)
    use_llm: bool = False


class AnalyzeResponse(BaseModel):
    system: str
    threats: list[Threat]
    mermaid: str
    report_markdown: str


class DiffRequest(BaseModel):
    old_yaml: str = Field(max_length=MAX_MODEL_BYTES)
    new_yaml: str = Field(max_length=MAX_MODEL_BYTES)


def require_key(request: Request, x_api_key: Annotated[str | None, Header()] = None) -> None:
    """If ARCHTHREAT_API_KEY is set, every call must present it (constant-time compare)."""
    expected = request.app.state.settings.api_key
    if expected and not (x_api_key and hmac.compare_digest(x_api_key, expected)):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


# Module level on purpose: with `from __future__ import annotations` FastAPI resolves
# annotations against module globals, not a function's locals.
Auth = Annotated[None, Depends(require_key)]


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    settings = settings or Settings()
    svc = services or build_services(settings)
    app = FastAPI(title="ArchThreat", version=__version__)
    app.state.settings = settings

    def parse(text: str):
        try:
            return parse_model(text)
        except ModelError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/analyze")
    def analyze(req: AnalyzeRequest, _: Auth) -> AnalyzeResponse:
        analysis = svc.analyze(parse(req.model_yaml), use_llm=req.use_llm)
        return AnalyzeResponse(
            system=analysis.model.system,
            threats=analysis.threats,
            mermaid=to_mermaid(analysis.model),
            report_markdown=render_report(analysis.model, analysis.threats),
        )

    @app.post("/diff")
    def diff(req: DiffRequest, _: Auth) -> dict[str, str]:
        old, new = parse(req.old_yaml), parse(req.new_yaml)
        d = diff_models(old, new, svc.analyze(old).threats, svc.analyze(new).threats)
        return {"markdown": diff_markdown(d, new.system)}

    return app
