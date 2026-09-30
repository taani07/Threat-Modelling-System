"""The system model (what you draw) and the threat model (what can go wrong).

The system model is a data-flow diagram as YAML: trust boundaries, components (external
entities, processes, data stores) and flows between them, plus the security properties that
matter for threats (authentication, encryption, logging, rate limiting...). A property that is
not declared is treated as absent. That is deliberate: in threat modeling, "unknown" should
look like a gap, not like a control.
"""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, computed_field, model_validator

ID_PATTERN = r"^[a-z][a-z0-9_]*$"


class ComponentType(StrEnum):
    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"


class AuthN(StrEnum):
    NONE = "none"
    APIKEY = "apikey"
    SESSION = "session"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    IAM = "iam"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


CLASSIFICATION_RANK = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}


class Stride(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class TrustBoundary(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    name: str
    untrusted: bool = False


class LLMProperties(BaseModel):
    """Extra properties for components that call or host an LLM."""

    agency: Literal["none", "read", "write"] = "none"
    tools: list[str] = Field(default_factory=list)


class Component(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    name: str = ""
    type: ComponentType
    boundary: str
    tech: str = ""
    tags: list[str] = Field(default_factory=list)
    data_classification: DataClassification | None = None
    criticality: int = Field(default=3, ge=1, le=5)
    # Security properties. Undeclared = absent.
    encrypted_at_rest: bool = False
    audit_logging: bool = False
    rate_limiting: bool = False
    input_validation: bool = False
    runs_as_root: bool = False
    admin_interface: bool = False
    llm: LLMProperties | None = None

    @property
    def label(self) -> str:
        return self.name or self.id

    @property
    def is_llm(self) -> bool:
        return self.llm is not None or "llm" in self.tags


class Flow(BaseModel):
    """Data moves from source to target. By default the source opens the connection (push).
    Set pull: true when the target opens it and fetches (a job downloading web pages, a
    service reading a queue): then the target is a client, not a server, for that flow."""

    id: str = Field(pattern=ID_PATTERN)
    source: str
    target: str
    pull: bool = False
    protocol: str = "HTTPS"
    authn: AuthN = AuthN.NONE
    encrypted: bool = True
    data: list[str] = Field(default_factory=list)


class SystemModel(BaseModel):
    system: str
    description: str = ""
    trust_boundaries: list[TrustBoundary]
    components: list[Component]
    flows: list[Flow] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_references(self) -> SystemModel:
        errors = reference_errors(self)
        if errors:
            raise ValueError("; ".join(errors))
        return self

    # Convenience lookups
    def component(self, component_id: str) -> Component:
        return next(c for c in self.components if c.id == component_id)

    def boundary(self, boundary_id: str) -> TrustBoundary:
        return next(b for b in self.trust_boundaries if b.id == boundary_id)

    def inbound(self, component_id: str) -> list[Flow]:
        return [f for f in self.flows if f.target == component_id]

    def outbound(self, component_id: str) -> list[Flow]:
        return [f for f in self.flows if f.source == component_id]

    def element_ids(self) -> set[str]:
        return {c.id for c in self.components} | {f.id for f in self.flows}


def reference_errors(model: SystemModel) -> list[str]:
    """Every referential-integrity problem in the model, as readable messages.

    - duplicate ids across components and flows
    - components in a boundary that does not exist
    - flows whose source or target is not a component
    """
    errors: list[str] = []
    ids = [c.id for c in model.components] + [f.id for f in model.flows]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        errors.append(f"duplicate ids: {', '.join(dupes)}")
    boundaries = {b.id for b in model.trust_boundaries}
    components = {c.id for c in model.components}
    for c in model.components:
        if c.boundary not in boundaries:
            errors.append(f"component '{c.id}' is in unknown boundary '{c.boundary}'")
    for f in model.flows:
        for end in (f.source, f.target):
            if end not in components:
                errors.append(f"flow '{f.id}' references unknown component '{end}'")
    return errors


def severity_for(likelihood: int, impact: int) -> Severity:
    """3x3 risk matrix: likelihood x impact."""
    score = likelihood * impact
    if score >= 9:
        return Severity.CRITICAL
    if score >= 6:
        return Severity.HIGH
    if score >= 3:
        return Severity.MEDIUM
    return Severity.LOW


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


class Threat(BaseModel):
    stride: Stride
    element_id: str
    title: str = Field(max_length=160)
    description: str = Field(max_length=1200)
    likelihood: int = Field(ge=1, le=3)
    impact: int = Field(ge=1, le=3)
    mitigations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source: Literal["rule", "llm"] = "rule"
    rule_id: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> Severity:
        return severity_for(self.likelihood, self.impact)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def key(self) -> str:
        """Stable identity used for diffs and SARIF fingerprints."""
        if self.rule_id:
            return f"{self.rule_id}:{self.element_id}"
        return f"LLM:{self.element_id}:{self.stride.value}:{_slug(self.title)}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        return "T-" + hashlib.sha256(self.key.encode()).hexdigest()[:8]


def sort_threats(threats: list[Threat]) -> list[Threat]:
    return sorted(threats, key=lambda t: (-SEVERITY_RANK[t.severity], t.element_id, t.key))
