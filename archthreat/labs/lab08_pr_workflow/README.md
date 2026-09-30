# Lab 08: Threat modeling on every pull request

## Goal

1. Implement `diff_markdown(d, system)`, the PR comment. Match the tests: a heading, a warning
   line when the worst new threat is high or critical, a count line, then "Architecture
   changes", "New threats" (a table) and "Resolved threats" (struck through) sections, each
   only when non-empty. When nothing changed, say so in one line.
2. Read `.github/workflows/threat-model-pr.yml`. It runs `archthreat diff` between the base
   branch and the PR for every model in `threatmodels/`, posts the result as a PR comment, and
   fails the check when new high or critical threats appear. Open a PR on your fork that
   edits `threatmodels/archthreat-service.yaml` (for example, remove `rate_limiting: true`) and
   watch it work.

## Why it matters

This is the "shift-left, developer enablement" story: security review becomes a comment on the
PR that introduced the risk, written in the developer's terms, with a clear list of fixes.
The gate only fails for high and critical threats, so it stays useful rather than noisy.

## Python you will learn

- Building markdown tables with f-strings.
- Walrus and truthiness checks for "only add the section if there is something to show".

## Interview questions

- *"How would you scale threat modeling across 50 teams?"* Templates and models as code,
  deterministic rules in CI, an LLM assist for drafting, diffs on PRs, security review only
  when the policy says so, and metrics on what gets found and fixed.
