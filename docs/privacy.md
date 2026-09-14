# Privacy and collection

No accounts, telemetry, cloud service, upload mechanism, remote administration or packet capture. No credentials, environment values, credential stores, browser history, process inventory, SSIDs/BSSIDs, MACs or unrelated filesystem content are collected. Environment variables are inherited by fixed OS subprocesses as normal process execution but are not inspected or recorded. Proxy environment configuration is not consumed for diagnostic HTTP.

Active probes transmit ordinary DNS, ICMP, TCP and HTTPS HEAD traffic to configured destinations. Those destinations/resolvers can observe a source IP, requested hostname and timing. This is not passive monitoring and is not zero network traffic. No system settings are modified.

## Raw local evidence

`incident.json` and `.pending-<id>.json` checkpoints include local interface name, IP addresses, gateways, route descriptions, configured DNS servers, explicitly probed hostnames, numeric path hops and UTC timestamps. They contain synthetic/generated explanations, not unbounded command stdout or HTTP bodies. `show --json` and `diagnose --json` expose raw evidence for technical automation. Config/status commands expose their local paths/PID as needed for local operation; these are not copied into shareable reports.

Files use atomic replace; new POSIX files are private and incident directories are user-only. Windows relies on standard per-user ACLs. Evidence is not encrypted. Choose a private local directory; shared directory permissions and same-user attackers are outside the protection boundary.

## Sanitized projection (default report)

A fresh copy replaces interface names, addresses, routes, resolver identifiers, queried/configured hostnames and path hops with per-report pseudonyms. Only known protocol/status fields and built-in operator labels survive; arbitrary probe/platform free text is replaced. Classifications are recomputed from this sanitized copy. A pseudonym preserves equality inside one report, not identity across reports. The demo uses synthetic data and remains explicitly marked.

Share `report.html`, `report.md`, `timeline.csv` or `shareable.json`. HTML escapes all dynamic values, has no JavaScript and contains no remote assets. CSP blocks remote connections, images, frames, scripts and forms. Only inline CSS is allowed. The report opens offline without a server. UTC timestamps, observed timings, failure patterns and software version remain; they can reveal when a person was online. Review before sharing.

`SHA256SUMS` covers raw and sanitized files. It provides accidental-corruption checking, not cryptographic provenance or adversarial tamper resistance. Do not share the whole directory by default because it contains raw incident.json.

## Retention

Healthy steady-state telemetry remains only in bounded memory. An incident keeps prehistory, affected samples and recovery. Active checkpoints are replaced every five seconds; power loss can lose this interval plus a current round. Completed incidents remain until the user removes them or explicitly configures `retention_days`. Retention removes only schema-valid old completed diagnosis/recovered bundles, not interrupted/continued evidence or arbitrary directories. Disk usage depends on incident volume; no silent deletion is enabled by default.
