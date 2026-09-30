# ArchThreat labs

Same format as the VulnLens labs: a `starter.py` with signatures and hints, a `test_lab.py`
that tells you when you're done, and the finished version in `src/archthreat/`.

```bash
pytest labs/lab01_model                 # your code
LAB_SOLUTION=1 pytest labs/lab01_model  # the reference solution
```

| Lab | You build | Python you learn | Security / AI concept | Time |
| --- | --- | --- | --- | --- |
| [01](lab01_model) | Referential-integrity checks for the model | Pydantic validators, `model_construct`, sets | Architecture as code | 1 h |
| [02](lab02_graph) | Boundary crossing, exposure, transitive reachability | BFS with `collections.deque`, generator expressions | Trust boundaries; indirect prompt injection paths | 1.5 h |
| [03](lab03_rules) | Three STRIDE rules | generators with `yield`, decorators (read) | STRIDE, CWE mapping, deterministic analysis | 2 h |
| [04](lab04_diagram) | Mermaid DFD renderer | string building, escaping | Data-flow diagrams | 1 h |
| [05](lab05_enrich) | Validation of LLM-proposed threats | regex, sets, Jaccard similarity | Grounding, dedupe, never trusting model output | 1.5 h |
| [06](lab06_diff) | Architecture and threat diff | set algebra on dict keys, `getattr` | Threat modeling per pull request | 1.5 h |
| [07](lab07_sarif) | SARIF export | nested dict/JSON construction | GitHub code scanning integration | 1 h |
| [08](lab08_pr_workflow) | PR comment + GitHub Action | f-strings, markdown; YAML workflow | Security review gates in CI | 1.5 h |
