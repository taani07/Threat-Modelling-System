"""Lab 05 starter."""

from __future__ import annotations

import re

from archthreat.models import Threat
from archthreat.rag.bm25 import tokenize  # noqa: F401

REFERENCE_RE = re.compile(r"^(CWE-\d{1,4}|CAPEC-\d{1,4}|LLM(0[1-9]|10))$")


def jaccard(a: str, b: str) -> float:
    # TODO
    raise NotImplementedError


def is_duplicate(candidate: Threat, existing: list[Threat], threshold: float = 0.5) -> bool:
    # TODO
    raise NotImplementedError


def clean_references(refs: list[str]) -> tuple[list[str], int]:
    # TODO
    raise NotImplementedError
