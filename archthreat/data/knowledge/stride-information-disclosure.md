---
id: stride-information-disclosure
title: Information disclosure threats and confidentiality controls
tags: [information_disclosure, CWE-200, CWE-311, CWE-319, confidentiality]
source_url: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
---
# What information disclosure means

Information disclosure is exposing data to someone not authorised to see it. It applies to processes, data stores and flows.

# Common patterns

- Sensitive data stores without encryption at rest; snapshots and backups copied to other accounts.
- Plaintext flows across trust boundaries.
- Verbose errors and stack traces returned to clients.
- Broken object-level authorisation (IDOR): changing an id in the URL returns someone else's record.
- AI assistants retrieving documents the asking user is not entitled to.

# Controls

- Encrypt at rest with customer-managed KMS keys and restrictive key policies; TLS 1.2+ in transit.
- Object-level authorisation checks on every request, enforced server side.
- Data minimisation and tokenisation (keep card numbers in a vault, pass tokens elsewhere).
- Generic error messages to clients; details only in protected logs.
