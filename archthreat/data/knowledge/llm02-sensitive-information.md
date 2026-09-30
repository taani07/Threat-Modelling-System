---
id: llm02-sensitive-information
title: Sensitive information disclosure (OWASP LLM02)
tags: [llm, LLM02, information_disclosure, CWE-200]
source_url: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
---
# What it is

An LLM application reveals data to people who should not see it: other users' records surfaced by retrieval, secrets in prompts, regulated data sent to a provider or region that is not approved, or training data memorised by a fine-tuned model.

# Controls

- Enforce entitlements in retrieval: filter documents by the requesting user's permissions before they reach the prompt. Never rely on the model to withhold information.
- Minimise and redact: send the fields the task needs; tokenise identifiers; strip secrets.
- Choose a deployment that meets data-residency and retention requirements (for example Bedrock in the required region, or a model inside your network), and record it in the model inventory.
- Log prompts and outputs with access controls and retention limits, since logs now contain sensitive data too.
