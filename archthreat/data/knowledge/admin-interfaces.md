---
id: admin-interfaces
title: Securing administrative interfaces
tags: [elevation_of_privilege, CWE-284, CWE-306, CWE-250, admin]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
---
# Controls

- Do not expose admin consoles to the internet. Put them behind a zero-trust access proxy (for example AWS Verified Access, Cloudflare Access, Entra Application Proxy) or a private network.
- SSO with phishing-resistant MFA; short sessions; step-up authentication for destructive actions.
- Separate admin and customer applications and credentials; separate IAM roles.
- Run the service as a non-root user and audit every privileged action to an append-only store.
