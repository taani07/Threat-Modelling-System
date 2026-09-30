---
id: encryption
title: Encryption in transit and at rest
tags: [information_disclosure, tampering, CWE-311, CWE-319, CWE-345, kms]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
---
# In transit

Use TLS 1.2 or later (prefer 1.3) on every flow, including inside private networks, with certificate validation enabled. Database protocols (PostgreSQL, MySQL, SQL Server) support TLS; require it on the server so clients cannot fall back to plaintext.

# At rest

Enable storage encryption for databases, volumes, buckets and backups with KMS customer-managed keys. Restrict who can use the key with the key policy, separate key administrators from key users, and monitor key usage. Encryption at rest protects against lost media and copied snapshots; it does not protect against a compromised application that can read the data, which is why access control still matters.
