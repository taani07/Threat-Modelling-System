# ADR 0002: Distinguish data direction from connection direction

**Status:** accepted

## Context

A data-flow diagram arrow shows where data goes. It doesn't show who opens the connection. The
first version of the rules treated every inbound flow from an untrusted zone as an inbound
connection. On `samples/rag-assistant.yaml` that raised three false positives against a job
that *downloads* public web pages: "unauthenticated access", "can be overwhelmed by untrusted
callers" and so on. Nobody can call that job.

## Decision

Flows get `pull: bool` (default false). Two graph questions replace one:

- `is_internet_facing`: accepts pushed connections from an untrusted zone (exposure: AUTH, DOS).
- `receives_untrusted_data`: any inbound untrusted data, pushed or pulled (INPUT validation).

Reachability for prompt injection follows data regardless of direction.

## Consequences

- The false positives are gone, and they're encoded as `must_not_find` cases in
  `evals/golden.yaml` so they can't come back.
- The ingest job still gets "untrusted input is not validated", which is the real risk.
