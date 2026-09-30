# Lab 03: Write STRIDE rules

## Goal

Implement three rules in `starter.py`. Each is a generator: it `yield`s zero or more `Threat`s.

1. `unauthenticated_crossing` (AUTH-001, spoofing): a flow with `authn == none`, that is **not**
   a pull flow, crosses a trust boundary, and whose target is not an external entity.
   Likelihood 3 if the flow starts in an untrusted zone, else 2. Impact from `impact_for(...)`
   using the target's most sensitive data and criticality. References `["CWE-306"]`.
2. `unencrypted_store` (DATA-001, information disclosure): a data store with confidential or
   restricted data and `encrypted_at_rest` false. Likelihood 2, impact 3, `["CWE-311"]`.
3. `excessive_agency` (LLM-002, elevation of privilege): a component whose `llm.agency` is
   `"write"`. Likelihood 2, impact 3, `["LLM06"]`.

Every threat needs `rule_id`, `stride`, `element_id`, a specific `title` that names the element,
a `description` and at least one mitigation. Then read the other ten rules in
`src/archthreat/rules.py` and the `@rule` decorator that registers them.

## Why it matters

STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation
of privilege) is the most common threat-modeling framework, and interviewers for security
architecture roles expect you to use it fluently. Encoding it as rules makes it repeatable:
every pull request gets the same scrutiny, and humans spend their time on the threats rules
can't find.

## Python you will learn

- Generators: a function with `yield` returns an iterator; callers loop over it. Memory-light
  and composable (`run_rules` loops over every rule's generator).
- Decorators with arguments: `@rule("AUTH-001", ...)` calls `rule(...)`, which returns the real
  decorator, which receives your function. Read it in `rules.py`.
- Type hints like `Iterator[Threat]`.

## Interview questions

- *"Walk me through STRIDE."* One sentence per letter, the property it violates (authentication,
  integrity, non-repudiation, confidentiality, availability, authorisation), and one control each.
- *"What's STRIDE-per-element?"* Which categories apply to which DFD element: external entities
  S and R; processes all six; data stores T, R, I, D; flows T, I, D.
