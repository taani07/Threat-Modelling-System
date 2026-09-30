# Eval log

`archthreat eval` checks `evals/golden.yaml`: 19 must-find threats and 12 must-not-find false
positives across four models. Both metrics must be 1.0 for CI to pass.

## 2026-09-29: false positives on pull flows

The first run of the rules on the RAG assistant flagged the web ingestion job as
internet-facing. The fix and its rationale are in ADR 0002. The three false positives are now
must-not-find cases.

## LLM enrichment (fill in after running `archthreat eval --llm` with a real model)

| Model | proposed | accepted | duplicate rate | STRIDE violations | invalid refs | failed elements |
| --- | --- | --- | --- | --- | --- | --- |
| qwen2.5:7b via Ollama | | | | | | |
| claude-haiku-4-5 | | | | | | |

Questions to answer from the numbers: which model repeats rule threats most (duplicate rate)?
Which invents identifiers? Is the extra cost of a larger model visible in *accepted* threats
that a reviewer would actually keep?
