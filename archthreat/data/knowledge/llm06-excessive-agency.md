---
id: llm06-excessive-agency
title: Excessive agency (OWASP LLM06)
tags: [llm, LLM06, elevation_of_privilege, agents]
source_url: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
---
# What it is

An LLM-based system is given more functionality, permissions or autonomy than it needs, so a hallucination or a prompt injection becomes a real action: an email sent, a record deleted, a payment issued.

# Controls

- Minimise tools: expose only what the use case needs; prefer narrow tools (`create_ticket`) to general ones (`run_sql`, `http_request`).
- Minimise permissions: tools act with the end user's identity and scopes, not a shared service account with broad rights.
- Require human approval for irreversible, external or high-value actions; show the exact action to approve.
- Put hard limits in code (amounts, recipients, rate of calls), not in the prompt.
- Log every tool call with the triggering prompt for audit.
