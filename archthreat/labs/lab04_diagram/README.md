# Lab 04: Generate the data-flow diagram

## Goal

Implement `node(component)` and `to_mermaid(model)` so the diagram matches the tests:

- `flowchart LR` first.
- One `subgraph <boundary_id>["<name>"]` per boundary that has components, with ` (untrusted)`
  appended to the name when untrusted, closed by `end`.
- Nodes: external entity `id["label"]`, process `id("label")`, data store `id[("label")]`.
  The label is the name, plus `<br/>` and the tech when there is one. Replace `"` with `'`.
- Edges: `src -->|"PROTOCOL / authn"| dst`, dotted `-.->` when not encrypted, `" (pull)"`
  appended for pull flows, and `"⚠ "` prefixed when the flow is unauthenticated, not a pull,
  and crosses a boundary.
- Finally a `classDef untrusted ...` line and `class <ids> untrusted` for untrusted boundaries.

## Why it matters

A diagram generated from the model can never drift from the model. Reviewers read pictures
faster than YAML, and the warnings put the risky flows in front of them. Mermaid renders
natively in GitHub markdown, so the report and PR comments show the diagram inline.

## Python you will learn

- Building text with lists and `"\n".join(lines)` (Java `StringBuilder` / `String.join`).
- Conditional expressions: `"-->" if f.encrypted else "-.->"`.
- f-strings containing quotes and braces.
