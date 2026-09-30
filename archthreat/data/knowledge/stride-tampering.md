---
id: stride-tampering
title: Tampering threats and integrity controls
tags: [tampering, CWE-20, CWE-345, CWE-319, integrity]
source_url: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
---
# What tampering means

Tampering is unauthorised modification of data in transit, at rest, or in processing. It violates integrity. It applies to processes, data stores and flows.

# Common patterns

- Injection: untrusted input changes a SQL query, a shell command, a template or an LLM prompt.
- Plaintext protocols across boundaries let an on-path attacker change requests.
- Mass assignment and data binding that let callers set fields they should not (Spring4Shell was a data-binding flaw).
- Unsigned messages on queues or event buses that any producer can write.

# Controls

- Strict schema validation at every entry point; parameterised queries; context-aware encoding.
- TLS everywhere, with certificate validation; message signing for high-value events.
- Allow-list bindable fields (DTOs), never bind requests directly to domain entities.
- Least-privilege write access to queues, buckets and databases; object versioning or WORM storage for evidence.
