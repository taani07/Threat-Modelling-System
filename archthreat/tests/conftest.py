from dataclasses import replace
from pathlib import Path

import pytest

from archthreat.config import Settings
from archthreat.loader import load_model
from archthreat.services import build_services

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def model(name: str):
    return load_model(SAMPLES / name)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return replace(
        Settings(),
        home=tmp_path / "home",
        knowledge_dir=ROOT / "data/knowledge",
        llm_provider="fake",
        embed_provider="hash",
        api_key="",
    )


@pytest.fixture
def services(settings):
    return build_services(settings)
