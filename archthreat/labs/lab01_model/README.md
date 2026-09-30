# Lab 01: Validate the system model

## Goal

Implement `reference_errors(model)` in `starter.py`. It returns a list of readable problems:

- `duplicate ids: a, b` (one message listing every duplicated id across components and flows, sorted)
- `component '<id>' is in unknown boundary '<boundary>'`
- `flow '<id>' references unknown component '<end>'` (check source, then target)

`SystemModel` calls the real version in a `@model_validator(mode="after")`, so a broken model
never gets as far as the rules. Read `src/archthreat/models.py` first.

## Why it matters

"Architecture as code" only works if the code is checked like code. A model that refers to a
component that doesn't exist silently hides threats. Validation at load time turns that into
a clear error in CI. The same validator makes `archthreat extract` work: when the LLM drafts
a model that references a missing component, this error message goes back to the model and
it fixes its own draft.

## Python you will learn

- `SystemModel.model_construct(...)` builds a model **without** validation. The tests use it to
  create broken models, which normal construction would refuse.
- Set comprehensions for fast membership checks: `{b.id for b in model.trust_boundaries}`.
- `sorted({i for i in ids if ids.count(i) > 1})` finds duplicates (fine for small lists; for
  big ones use `collections.Counter`).

## Interview questions

- *"How do you keep architecture diagrams from going stale?"* Put them in the repo as code,
  generate the picture from the model, validate in CI, and review changes in pull requests.
