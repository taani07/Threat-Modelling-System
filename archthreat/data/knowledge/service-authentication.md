---
id: service-authentication
title: Service-to-service and partner authentication
tags: [spoofing, authentication, CWE-306, CWE-798, CWE-522, mtls, oauth2]
source_url: https://datatracker.ietf.org/doc/html/rfc8705
---
# Options, strongest first

- **Workload identity and mTLS** (RFC 8705 certificate-bound tokens, service mesh identities, SPIFFE): both sides prove identity with short-lived certificates.
- **OAuth 2.0 client credentials** with short-lived, audience-restricted access tokens; rotate client secrets or use private-key JWT client authentication.
- **Cloud IAM** (AWS SigV4 with roles, Azure managed identities) for calls to cloud services.
- **Static API keys**: only with per-partner keys, automatic rotation, request signing with timestamps, and source IP allow-lists as extra defence.

# Webhooks from partners

Verify an HMAC signature over the raw body and a timestamp, reject stale or replayed messages, and treat webhook content as untrusted input.
