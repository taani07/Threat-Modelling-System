# ADR 0001: Rules first, LLM second

**Status:** accepted

## Context

Threat modeling needs two things that pull in opposite directions: **reliability** (the same
architecture must always raise the same must-fix threats, so the result can gate a pull
request) and **context** (threats specific to the technology, data and business, which fixed
rules can't enumerate).

## Decision

Deterministic rules run first and always. The LLM runs second, optionally, and only adds.
Its proposals are validated in code: STRIDE category allowed for the element type, references
well-formed, near-duplicates of existing threats dropped, a cap per element. LLM threats carry
`source: llm`, no rule id, and are marked "verify before accepting" in every output. CI gates use
rules only.

## Consequences

- PR gates are reproducible and cheap (no model call).
- The LLM can't remove or downgrade a rule finding, only add to them.
- LLM value is measured separately (`archthreat eval --llm`): acceptance rate, duplicate rate,
  category violations, invalid references.
