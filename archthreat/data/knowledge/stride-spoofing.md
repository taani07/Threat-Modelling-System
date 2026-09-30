---
id: stride-spoofing
title: Spoofing threats and authentication controls
tags: [spoofing, CWE-306, CWE-287, authentication]
source_url: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
---
# What spoofing means

Spoofing is pretending to be someone or something else: a user, a service, a partner system. It violates authentication. It applies to external entities and processes, and to any flow whose receiver trusts who the sender claims to be.

# Common patterns

- Endpoints reachable across a trust boundary with no authentication.
- Static API keys shared with partners, never rotated, with no binding to a caller identity.
- Webhooks accepted without verifying a signature, so anyone who learns the URL can send events.
- Service-to-service calls that trust a network location ("it's inside the VPC") instead of an identity.

# Controls

- OAuth 2.0 access tokens validated for issuer, audience, expiry and scope at every service.
- Mutual TLS or workload identity (SPIFFE, IAM roles) for service-to-service calls.
- Signed webhooks (HMAC with a timestamp and replay window) and allow-listed source ranges as defence in depth.
- MFA and phishing-resistant authenticators (WebAuthn) for human administrators.
