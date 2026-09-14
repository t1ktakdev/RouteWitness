# Security policy

Before a public repository exists, report security findings privately to the person who supplied this source release. After public GitHub setup, enable Private Vulnerability Reporting and use its security advisory interface. No invented contact mailbox is provided.

Do not publish raw incident evidence, credentials, home network identifiers or exploit payloads containing personal information in an issue. Include a minimal synthetic reproduction and version.

## Boundary

RouteWitness is an observer. It has no upload, account, remote-control, scanning, elevation or system-repair feature. Probes contact only the configured diagnostic hosts/ports and local gateways/resolvers. Subprocesses use argument arrays, fixed scripts, explicit time/output limits and cancellation cleanup. System DNS uses a bounded child rather than a lingering resolver thread. HTTPS validates certificates and sends HEAD without storing response bodies or following redirects.

Raw evidence is private local data, not an encrypted vault. POSIX files are created mode 0600 and new incident directories 0700. Windows relies on the user's directory ACLs. Do not choose a shared/untrusted data directory. Same-user malware or an administrator can alter evidence. Checksums are not signatures or a guarantee against malicious rewriting. Remote responses and imported metadata must always be treated as untrusted.

Reports default to an allowlisted sanitized projection and strict no-script CSP. Review retained timestamps/context before sharing. Data loaded from disk is schema-validated and size-bounded; unknown schema versions, malformed IDs and symlink incident paths are rejected. Retention is opt-in and avoids incomplete evidence and symlink trees.

v0.1 has no promised support lifetime. Security fixes should be applied before use; there is no background update checker or telemetry.
