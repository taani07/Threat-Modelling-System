---
id: stride-denial-of-service
title: Denial of service threats and availability controls
tags: [denial_of_service, CWE-770, CWE-400, availability]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
---
# What denial of service means

Denial of service is making a system unavailable or too expensive to run. For cloud and AI systems, cost exhaustion ("denial of wallet") is as real as downtime.

# Controls

- Rate limits and quotas per client at the edge (API gateway, WAF), with burst limits.
- Request size limits, timeouts, and bounded queues; reject early.
- Autoscaling with a ceiling and budget alerts, so an attack cannot scale your bill without limit.
- Bulkheads and circuit breakers between dependencies.
- For LLM features: per-user token budgets, max input and output tokens, and caching.
