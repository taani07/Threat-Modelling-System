---
id: stride-repudiation
title: Repudiation threats and audit logging
tags: [repudiation, CWE-778, CWE-117, logging]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
---
# What repudiation means

Repudiation is being able to deny having performed an action because the system cannot prove otherwise. It violates non-repudiation and accountability, and it makes incident response guesswork.

# Controls

- Log security-relevant events: authentication, authorisation failures, privileged actions, changes to sensitive records, with who, what, when, where and outcome.
- Send logs to an append-only or WORM store (S3 Object Lock, immutable Log Analytics) outside the reach of the service's own credentials.
- Neutralise log injection: encode user-supplied values, use structured (JSON) logging.
- Never log secrets, tokens or full card numbers; mask sensitive fields.
- Correlate with a request id across services; monitor for gaps in log delivery.
