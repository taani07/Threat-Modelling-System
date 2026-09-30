"""Composition root: settings -> index, LLM, analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property

from archthreat.config import Settings
from archthreat.enrich import EnrichStats, enrich, offline_responder
from archthreat.llm.base import LLMProvider
from archthreat.llm.factory import get_embedder, get_llm
from archthreat.models import SystemModel, Threat, sort_threats
from archthreat.rag.index import KnowledgeIndex
from archthreat.rules import run_rules


@dataclass
class Analysis:
    model: SystemModel
    threats: list[Threat]
    stats: EnrichStats | None = None
    notes: list[str] = field(default_factory=list)


class Services:
    def __init__(self, settings: Settings, llm: LLMProvider | None = None) -> None:
        self.settings = settings
        self._llm = llm

    @cached_property
    def index(self) -> KnowledgeIndex:
        return KnowledgeIndex.load_or_build(
            self.settings.knowledge_dir, self.settings.index_dir, get_embedder(self.settings)
        )

    @cached_property
    def llm(self) -> LLMProvider:
        return self._llm or get_llm(self.settings, offline_responder=offline_responder)

    def analyze(self, model: SystemModel, use_llm: bool = False) -> Analysis:
        threats = run_rules(model)
        analysis = Analysis(model, threats)
        if use_llm:
            extra, stats = enrich(
                model, threats, self.llm, self.index, self.settings.max_llm_threats_per_element
            )
            analysis.threats = threats + extra
            analysis.stats = stats
            if self.settings.llm_provider == "fake" and self._llm is None:
                analysis.notes.append(
                    "LLM_PROVIDER=fake: rules only; set a provider for enrichment"
                )
        analysis.threats = sort_threats(analysis.threats)
        return analysis


def build_services(settings: Settings | None = None, llm: LLMProvider | None = None) -> Services:
    return Services(settings or Settings(), llm)
