import pytest

from archthreat.models import Stride, Threat
from labs._harness import load

e = load("labs.lab05_enrich.starter", "archthreat.enrich")


def t(title, element="api", stride=Stride.TAMPERING):
    return Threat(
        stride=stride, element_id=element, title=title, description="d", likelihood=2, impact=2
    )


def test_jaccard():
    assert e.jaccard("SQL injection in login", "SQL injection in login") == 1.0
    assert e.jaccard("sql injection", "cross site scripting") == 0.0
    assert e.jaccard("sql injection login", "sql injection search") == pytest.approx(2 / 4)
    assert e.jaccard("", "anything") == 0.0


def test_is_duplicate_needs_same_element_and_category():
    existing = [t("Prompt injection can steer the orchestrator")]
    assert e.is_duplicate(t("Prompt injection steers the orchestrator"), existing)
    assert not e.is_duplicate(
        t("Prompt injection steers the orchestrator", element="other"), existing
    )
    assert not e.is_duplicate(
        t("Prompt injection steers the orchestrator", stride=Stride.SPOOFING), existing
    )
    assert not e.is_duplicate(t("Webhook replay alters settlement state"), existing)


def test_clean_references():
    kept, dropped = e.clean_references(
        [" cwe-89 ", "LLM01", "LLM11", "CAPEC-66", "OWASP-A03", "CWE-89"]
    )
    assert kept == ["CWE-89", "LLM01", "CAPEC-66"]
    assert dropped == 3
