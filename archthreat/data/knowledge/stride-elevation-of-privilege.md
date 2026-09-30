---
id: stride-elevation-of-privilege
title: Elevation of privilege threats and authorisation controls
tags: [elevation_of_privilege, CWE-250, CWE-284, CWE-269, authorization]
source_url: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
---
# What elevation of privilege means

Elevation of privilege is gaining capabilities you should not have: a user becoming an admin, code execution in a container becoming root on the node, an AI agent using tools beyond its purpose.

# Common patterns

- Administrative interfaces reachable from the internet, protected by a password alone.
- Processes running as root with broad Linux capabilities.
- Overly broad IAM roles (`*` actions or resources) attached to workloads.
- Missing function-level authorisation checks on admin APIs.

# Controls

- Admin access through a private network or zero-trust access proxy, SSO with MFA, and step-up auth for privileged actions.
- Non-root containers, dropped capabilities, read-only root filesystems, Pod Security Standards (restricted).
- Least-privilege IAM with resource-level scoping; review with access analyzers.
- Role and scope checks enforced server side on every privileged function.
