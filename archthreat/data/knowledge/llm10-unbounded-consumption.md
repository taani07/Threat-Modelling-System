---
id: llm10-unbounded-consumption
title: Unbounded consumption (OWASP LLM10)
tags: [llm, LLM10, denial_of_service, CWE-770]
source_url: https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
---
# What it is

Attackers or runaway loops make an LLM application consume excessive tokens, compute or money: very long inputs, requests that trigger long outputs, agent loops, or high-volume scraping of a paid model.

# Controls

- Per-user and per-tenant rate limits and token budgets; hard caps on input size and max output tokens.
- Loop and step limits for agents; timeouts on tool calls.
- Cache repeated requests; route simple tasks to smaller models.
- Budget alerts and anomaly detection on spend; the ability to disable the feature quickly.
