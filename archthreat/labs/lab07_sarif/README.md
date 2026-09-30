# Lab 07: Export threats as SARIF

## Goal

Implement `element_line(yaml_text, element_id)` and `to_sarif(model, threats, model_path, yaml_text)`.

- `element_line`: the 1-based line containing `id: <element_id>` as a whole id (`f_a` must not
  match `f_ab`), or 1.
- `to_sarif`: one SARIF 2.1.0 run, tool name `ArchThreat`, one rule per distinct
  `rule_id_for(threat)`, one result per threat (sorted with `sort_threats`) with `level` from
  `SARIF_LEVEL`, a location in the model file at `element_line`, `partialFingerprints`
  `{"archthreatKey": threat.key}`, and `properties.security-severity` from `SECURITY_SEVERITY`.

## Why it matters

SARIF is the lingua franca of security tooling. GitHub code scanning ingests it, so threat-model
findings show up in the Security tab next to CodeQL alerts, on the exact line of the model file.
The fingerprint lets GitHub close an alert automatically when a later commit fixes the
architecture. And because VulnLens reads SARIF, the two projects compose.

## Python you will learn

- Building nested dicts and lists that serialise straight to JSON.
- `re.escape` and negative look-ahead `(?![\w-])` for whole-word matching.
