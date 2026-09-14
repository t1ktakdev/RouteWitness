# RouteWitness incident 20260913T214324Z-00000018

**SIMULATED OFFLINE DEMO**

Evidence is most consistent with an upstream connectivity failure. Confidence: **high**.

Status: recovered. Duration: 14.0 seconds.

Start: 2026-09-13T21:43:22+00:00. Detection: 2026-09-13T21:43:24+00:00.

## Evidence for

- upstream-or-isp: 12/14 affected rounds; sample seq 24,25,26,27,28,29,30,31,32,33,34,35
- Gateway reachable in 14/14 examined rounds.
- Local interface reported up in 14/14 examined rounds.
- cloudflare: 12/14 failed reachability rounds (86% probe loss).
- google: 12/14 failed reachability rounds (86% probe loss).
- quad9: 12/14 failed reachability rounds (86% probe loss).

## Evidence against

- A responding gateway argues against a complete local-link outage.
- Independent IP successes argue against a continuous general Internet outage.

## Unknowns

- Single-host probes cannot prove ISP fault or exclude local filtering/VPN policy.

## Next checks

- Compare the same time window from another device; ask the ISP to check its uplink logs.

## Timeline

See report.html for the layered timeline and timeline.csv for every probe.

## Privacy

Local identifiers and hostnames are pseudonymized. Timestamps remain. No payload capture, uploads, JavaScript or remote report assets. Review before sharing. incident.json and checkpoints contain raw local evidence; share report.html or shareable.json.
