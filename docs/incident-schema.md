# Incident schema v1

Canonical schema: `incident.json`, validated by `routewitness.models.Incident`. The generated JSON Schema is `incident.schema.json`. Unknown versions/fields, malformed IDs, non-finite or negative durations, missing required records and oversized evidence are rejected. Import reads are capped at 32 MiB. Datetimes must carry timezone; the recorder emits UTC.

| Field | Meaning |
|---|---|
| schema_version | Integer 1; incompatible future versions require a migration |
| tool_version | Producer version |
| id | UTC detection timestamp plus eight lowercase hexadecimal characters |
| start / detected / end | First symptomatic time, debounce trigger, first final healthy sample (or last observation if interrupted/continued) |
| duration_s | Monotonic elapsed duration from start to end; excludes recovery hold |
| status | recording, recovered, interrupted, continued, diagnosis |
| previous_id | Previous long-outage segment, if present |
| simulated | Explicit demo evidence flag |
| samples | Strictly increasing seq/elapsed observations, bounded to 2,048 by schema and 1,800 in default recorder |
| paths | Bounded baseline/start/during/recovery numeric-hop observations |
| diagnosis | Domain, verdict, confidence, evidence_for, evidence_against, unknowns, recommended_next_checks |
| warnings / capability_gaps | Collection/interruption warnings and unavailable evidence |

A sample contains UTC `at`, `seq`, monotonic `elapsed` since watcher start, network snapshot, probes, transition events, detected symptoms and baseline/current aggregate latency. A probe contains layer, target, method, family (4/6/0), operator, tri-state result, optional latency_ms, bounded detail and failure stage. `unknown` never silently becomes a failed probe. Network type may be unknown; Wi-Fi signal is not invented.

The classifier evaluates affected rounds, while HTML summary statistics cover the full retained prehistory-to-recovery interval. Evidence cites sample sequence IDs, enabling direct inspection of raw JSON and per-probe CSV. The classification rules are in diagnosis-model.md. `insufficient-evidence` is also used for healthy one-shot observations, with an explicit no-failure verdict.

Each bundle contains raw incident.json, sanitized shareable.json, report.html, report.md, timeline.csv and SHA256SUMS. Network/path/probe evidence is nested in the canonical JSON instead of duplicated loose files. HTML is derived output, never the source of truth. Regeneration rewrites derived files and the manifest; canonical evidence remains unchanged. Per-file atomic replace is used during regeneration, while a new complete bundle is staged and renamed as a directory. A crash in regeneration may leave an outdated checksum manifest; regenerate again from canonical JSON.

Checkpoints are hidden `.pending-<id>.json` files. The next watcher holding the process lock finalizes recording checkpoints as interrupted bundles, rebuilds their diagnosis, and uses the last recorded observation as the end. Already finalized checkpoints retain their observed recovery or continuation status. Malformed checkpoints are retained and produce an explicit error rather than being silently deleted. A completed directory with the same ID is never overwritten by a new capture.
