---
id: llm01-prompt-injection
title: Prompt injection (OWASP LLM01)
tags: [llm, LLM01, tampering, CWE-77]
source_url: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
---
# What it is

Prompt injection is input that changes an LLM's behaviour in ways the developer did not intend. Direct injection comes from the user's own message. Indirect injection arrives inside content the system processes: retrieved documents, web pages, emails, tickets, scanner output. The model cannot reliably tell instructions from data, so any content an attacker can influence is a way in.

# Why it matters in RAG and agents

A retrieval pipeline that ingests public web pages or customer uploads gives attackers a path into the prompt without ever talking to the system. If the model can call tools, injected instructions can trigger actions: sending email, creating tickets, exfiltrating data through a URL.

# Controls

- Treat all retrieved and user content as untrusted data; fence and label it in the prompt.
- Privilege separation: the model proposes, deterministic code decides and executes.
- Least-privilege tools bound to the end user's identity; human approval for side effects.
- Output validation against a schema; block links and markdown images to untrusted domains in rendered output.
- Detection classifiers and canary tokens as signals, never as the only control. Red-team with indirect injection test cases.
