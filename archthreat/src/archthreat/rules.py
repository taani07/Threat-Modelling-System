"""Deterministic threat rules.

Each rule is a plain function registered with the `@rule` decorator. A rule inspects the
model and yields Threats. Rules are the part of threat modeling that must be reliable: the
same architecture always produces the same threats, so they can gate a pull request.

Two layers:
  1. `STRIDE_PER_ELEMENT`: the classic Microsoft table of which STRIDE categories apply to
     which element type. Used for the report checklist and to constrain LLM output.
  2. Targeted rules: specific, explainable conditions (an unauthenticated flow across a trust
     boundary, an LLM reachable by untrusted content, ...).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from archthreat.graph import (
    crosses_boundary,
    from_untrusted,
    is_internet_facing,
    is_sensitive,
    max_classification,
    reachable_from_untrusted,
    receives_untrusted_data,
)
from archthreat.models import AuthN, ComponentType, DataClassification, Stride, SystemModel, Threat

S, T, R, I, D, E = (  # noqa: E741 - the STRIDE letters are the clearest names here
    Stride.SPOOFING,
    Stride.TAMPERING,
    Stride.REPUDIATION,
    Stride.INFORMATION_DISCLOSURE,
    Stride.DENIAL_OF_SERVICE,
    Stride.ELEVATION_OF_PRIVILEGE,
)

STRIDE_PER_ELEMENT: dict[str, set[Stride]] = {
    ComponentType.EXTERNAL_ENTITY: {S, R},
    ComponentType.PROCESS: {S, T, R, I, D, E},
    ComponentType.DATA_STORE: {T, R, I, D},
    "flow": {T, I, D},
}

RuleFn = Callable[[SystemModel], Iterator[Threat]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    stride: Stride
    fn: RuleFn


RULES: list[Rule] = []


def rule(rule_id: str, title: str, stride: Stride) -> Callable[[RuleFn], RuleFn]:
    """Register a rule. Decorators are just functions that receive your function."""

    def register(fn: RuleFn) -> RuleFn:
        RULES.append(Rule(rule_id, title, stride, fn))
        return fn

    return register


def impact_for(classification: DataClassification | None, criticality: int = 3) -> int:
    """Impact 1-3 from the most sensitive data involved and the component's criticality."""
    if classification == DataClassification.RESTRICTED or criticality >= 5:
        return 3
    if classification in (None, DataClassification.PUBLIC) and criticality <= 2:
        return 1
    return 2


# --------------------------------------------------------------------------------------
# Authentication and transport
# --------------------------------------------------------------------------------------


@rule("AUTH-001", "Unauthenticated flow across a trust boundary", S)
def unauthenticated_crossing(model: SystemModel) -> Iterator[Threat]:
    for f in model.flows:
        target = model.component(f.target)
        if (
            f.authn == AuthN.NONE
            and not f.pull
            and crosses_boundary(model, f)
            and target.type != ComponentType.EXTERNAL_ENTITY
        ):
            yield Threat(
                rule_id="AUTH-001",
                stride=S,
                element_id=f.id,
                title=f"Unauthenticated access to {target.label} across a trust boundary",
                description=(
                    f"Flow '{f.id}' from {model.component(f.source).label} to {target.label} "
                    "crosses a trust boundary with no authentication, so any caller that can "
                    "reach the endpoint can impersonate a legitimate client."
                ),
                likelihood=3 if from_untrusted(model, f) else 2,
                impact=impact_for(max_classification(model, target.id), target.criticality),
                mitigations=[
                    "Require OAuth 2.0 access tokens with audience restriction, or mTLS for service-to-service calls",
                    "Enforce authentication at the gateway and again in the service (defence in depth)",
                ],
                references=["CWE-306"],
            )


@rule("AUTH-002", "Static API key used from an untrusted zone", S)
def api_key_from_untrusted(model: SystemModel) -> Iterator[Threat]:
    for f in model.flows:
        if f.authn == AuthN.APIKEY and from_untrusted(model, f) and not f.pull:
            target = model.component(f.target)
            yield Threat(
                rule_id="AUTH-002",
                stride=S,
                element_id=f.id,
                title=f"Long-lived API key authenticates untrusted callers of {target.label}",
                description=(
                    f"Flow '{f.id}' authenticates with a static API key from an untrusted zone. "
                    "Keys leak through logs, repositories and partners' systems, carry no user "
                    "identity, and are rarely rotated."
                ),
                likelihood=2,
                impact=impact_for(max_classification(model, target.id), target.criticality),
                mitigations=[
                    "Replace with short-lived OAuth 2.0 client-credentials tokens or mTLS",
                    "If keys must stay: scope per partner, rotate automatically, verify request signatures (HMAC) and timestamps",
                ],
                references=["CWE-798", "CWE-522"],
            )


@rule("CRYPTO-001", "Unencrypted flow across a trust boundary", I)
def unencrypted_crossing(model: SystemModel) -> Iterator[Threat]:
    for f in model.flows:
        if not f.encrypted and crosses_boundary(model, f):
            data = ", ".join(f.data) or "its payload"
            classification = max_classification(model, f.target) or max_classification(
                model, f.source
            )
            likelihood = 3 if from_untrusted(model, f) else 2
            yield Threat(
                rule_id="CRYPTO-001",
                stride=I,
                element_id=f.id,
                title=f"Data in transit readable on unencrypted flow {f.id}",
                description=f"Flow '{f.id}' ({f.protocol}) carries {data} across a trust boundary without encryption.",
                likelihood=likelihood,
                impact=impact_for(classification),
                mitigations=[
                    "Use TLS 1.2+ (prefer 1.3) end to end",
                    "Reject plaintext listeners at the load balancer",
                ],
                references=["CWE-319"],
            )
            yield Threat(
                rule_id="CRYPTO-002",
                stride=T,
                element_id=f.id,
                title=f"Data in transit can be modified on unencrypted flow {f.id}",
                description=f"Without TLS, an attacker on the network path can alter {data} on flow '{f.id}'.",
                likelihood=likelihood,
                impact=impact_for(classification),
                mitigations=[
                    "Use TLS with certificate validation; add message signing for high-value payloads"
                ],
                references=["CWE-319", "CWE-345"],
            )


# --------------------------------------------------------------------------------------
# Data, logging, availability, privilege
# --------------------------------------------------------------------------------------


@rule("DATA-001", "Sensitive data store not encrypted at rest", I)
def unencrypted_store(model: SystemModel) -> Iterator[Threat]:
    for c in model.components:
        if (
            c.type == ComponentType.DATA_STORE
            and is_sensitive(c.data_classification)
            and not c.encrypted_at_rest
        ):
            yield Threat(
                rule_id="DATA-001",
                stride=I,
                element_id=c.id,
                title=f"{c.label} holds {c.data_classification.value} data without encryption at rest",
                description=(
                    f"{c.label} ({c.tech or 'data store'}) is not declared as encrypted at rest. "
                    "Snapshots, backups, or a stolen disk expose the data directly."
                ),
                likelihood=2,
                impact=3,
                mitigations=[
                    "Enable storage encryption with a customer-managed KMS key",
                    "Restrict key usage with a key policy; log key use in CloudTrail",
                ],
                references=["CWE-311"],
            )


@rule("AUDIT-001", "No audit logging on a process handling sensitive data", R)
def missing_audit_log(model: SystemModel) -> Iterator[Threat]:
    for c in model.components:
        if (
            c.type == ComponentType.PROCESS
            and not c.audit_logging
            and is_sensitive(max_classification(model, c.id))
        ):
            yield Threat(
                rule_id="AUDIT-001",
                stride=R,
                element_id=c.id,
                title=f"Actions in {c.label} on sensitive data cannot be attributed",
                description=(
                    f"{c.label} reads or writes sensitive data but has no audit logging, so a "
                    "user or operator can deny an action and incidents cannot be reconstructed."
                ),
                likelihood=2,
                impact=2,
                mitigations=[
                    "Log who did what, to which record, when and from where, to an append-only store",
                    "Protect logs from the service's own credentials; alert on gaps",
                ],
                references=["CWE-778"],
            )


@rule("DOS-001", "Internet-facing process without rate limiting", D)
def missing_rate_limit(model: SystemModel) -> Iterator[Threat]:
    for c in model.components:
        if (
            c.type == ComponentType.PROCESS
            and is_internet_facing(model, c.id)
            and not c.rate_limiting
        ):
            yield Threat(
                rule_id="DOS-001",
                stride=D,
                element_id=c.id,
                title=f"{c.label} can be overwhelmed by untrusted callers",
                description=f"{c.label} accepts traffic from an untrusted zone with no rate limiting or quotas.",
                likelihood=3,
                impact=2,
                mitigations=[
                    "Rate-limit and throttle per client at the gateway or WAF",
                    "Set request size limits and timeouts; autoscale with a cost ceiling",
                ],
                references=["CWE-770"],
            )


@rule("INPUT-001", "Entry point without input validation", T)
def missing_input_validation(model: SystemModel) -> Iterator[Threat]:
    for c in model.components:
        if (
            c.type == ComponentType.PROCESS
            and receives_untrusted_data(model, c.id)
            and not c.input_validation
        ):
            yield Threat(
                rule_id="INPUT-001",
                stride=T,
                element_id=c.id,
                title=f"Untrusted input to {c.label} is not validated",
                description=(
                    f"{c.label} receives data from an untrusted zone with no declared schema "
                    "validation, opening the door to injection and logic abuse."
                ),
                likelihood=3,
                impact=impact_for(max_classification(model, c.id), c.criticality),
                mitigations=[
                    "Validate every request against a strict schema (allow-list types, lengths, formats)",
                    "Use parameterised queries and context-aware output encoding downstream",
                ],
                references=["CWE-20"],
            )


@rule("EOP-001", "Process runs as root", E)
def runs_as_root(model: SystemModel) -> Iterator[Threat]:
    for c in model.components:
        if c.type == ComponentType.PROCESS and c.runs_as_root:
            yield Threat(
                rule_id="EOP-001",
                stride=E,
                element_id=c.id,
                title=f"Compromise of {c.label} yields root privileges",
                description=f"{c.label} runs as root, so any code execution bug becomes full control of its host or container.",
                likelihood=2,
                impact=3,
                mitigations=[
                    "Run as a non-root user; drop Linux capabilities; read-only root filesystem",
                    "Enforce with Kubernetes Pod Security Standards (restricted) or equivalent",
                ],
                references=["CWE-250"],
            )


@rule("EOP-002", "Administrative interface reachable from an untrusted zone", E)
def exposed_admin(model: SystemModel) -> Iterator[Threat]:
    exposed = reachable_from_untrusted(model)
    for c in model.components:
        if c.type == ComponentType.PROCESS and c.admin_interface and c.id in exposed:
            yield Threat(
                rule_id="EOP-002",
                stride=E,
                element_id=c.id,
                title=f"Administrative functions of {c.label} are reachable from untrusted networks",
                description=f"{c.label} exposes administrative functions on a path reachable from an untrusted zone.",
                likelihood=2,
                impact=3,
                mitigations=[
                    "Move admin interfaces to a private network behind SSO with MFA (zero-trust access proxy)",
                    "Separate admin and public endpoints; require step-up authentication for privileged actions",
                ],
                references=["CWE-284", "CWE-306"],
            )


# --------------------------------------------------------------------------------------
# LLM components (OWASP Top 10 for LLM Applications 2025)
# --------------------------------------------------------------------------------------

AGENCY_IMPACT = {"none": 2, "read": 2, "write": 3}


@rule("LLM-001", "LLM processes content an attacker can influence (prompt injection)", T)
def prompt_injection(model: SystemModel) -> Iterator[Threat]:
    exposed = reachable_from_untrusted(model)
    for c in model.components:
        if c.is_llm and c.id in exposed:
            agency = c.llm.agency if c.llm else "none"
            yield Threat(
                rule_id="LLM-001",
                stride=T,
                element_id=c.id,
                title=f"Prompt injection can steer {c.label}",
                description=(
                    f"Content that originates in an untrusted zone reaches {c.label} (directly or "
                    "through intermediate stores), so instructions hidden in that content can "
                    f"override the system prompt. The component's agency is '{agency}'."
                ),
                likelihood=3,
                impact=AGENCY_IMPACT[agency],
                mitigations=[
                    "Treat retrieved and user content as data: fence it and label it in the prompt",
                    "Keep high-impact decisions out of the model; validate outputs in code",
                    "Least-privilege tools and human approval for side effects",
                ],
                references=["LLM01", "CWE-77"],
            )


@rule("LLM-002", "LLM can take actions with side effects (excessive agency)", E)
def excessive_agency(model: SystemModel) -> Iterator[Threat]:
    for c in model.components:
        if c.llm and c.llm.agency == "write":
            tools = ", ".join(c.llm.tools) or "write-capable tools"
            yield Threat(
                rule_id="LLM-002",
                stride=E,
                element_id=c.id,
                title=f"{c.label} can act through {tools} without a human decision",
                description=(
                    f"{c.label} can invoke {tools}. A manipulated or mistaken model can take "
                    "actions with the component's full privileges."
                ),
                likelihood=2,
                impact=3,
                mitigations=[
                    "Scope each tool to the minimum permissions and to the calling user's identity",
                    "Require human approval for irreversible or external actions; rate-limit tool calls",
                ],
                references=["LLM06"],
            )


@rule("LLM-003", "LLM has access to sensitive data (disclosure risk)", I)
def llm_sensitive_data(model: SystemModel) -> Iterator[Threat]:
    for c in model.components:
        if c.is_llm and is_sensitive(max_classification(model, c.id)):
            classification = max_classification(model, c.id)
            yield Threat(
                rule_id="LLM-003",
                stride=I,
                element_id=c.id,
                title=f"{c.label} can disclose {classification.value} data to users who should not see it",
                description=(
                    f"{c.label} reads {classification.value} data. Without entitlement-aware "
                    "retrieval and output controls, a user can extract data they are not "
                    "authorised to see, and the data may be sent to the model provider."
                ),
                likelihood=2,
                impact=3,
                mitigations=[
                    "Filter retrieval by the requesting user's entitlements before generation",
                    "Redact or tokenise sensitive fields; keep processing in an approved region",
                ],
                references=["LLM02", "CWE-200"],
            )


@rule("LLM-004", "Untrusted callers can drive unbounded LLM consumption", D)
def unbounded_consumption(model: SystemModel) -> Iterator[Threat]:
    exposed = reachable_from_untrusted(model)
    for c in model.components:
        if c.is_llm and c.id in exposed and not c.rate_limiting:
            yield Threat(
                rule_id="LLM-004",
                stride=D,
                element_id=c.id,
                title=f"Cost and capacity of {c.label} can be exhausted",
                description=f"{c.label} can be triggered by untrusted input without rate limits or token budgets.",
                likelihood=2,
                impact=2,
                mitigations=[
                    "Per-user and per-tenant rate limits and token budgets",
                    "Cap input size and max_tokens; alert on spend anomalies",
                ],
                references=["LLM10", "CWE-770"],
            )


def run_rules(model: SystemModel) -> list[Threat]:
    threats: dict[str, Threat] = {}
    for r in RULES:
        for threat in r.fn(model):
            threats.setdefault(threat.key, threat)
    return list(threats.values())
