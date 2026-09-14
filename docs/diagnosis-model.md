# Deterministic detection and explanation

All timestamps are UTC. Intervals/durations use elapsed monotonic time; wall/monotonic gaps over max(10 seconds, 5 times configured interval) create a sampling-gap event, reset learning and finish an open segment as interrupted. Nothing is inferred about connectivity while asleep.

Each probe result is `ok`, `fail`, or `unknown`; only observed failures count as failures. Individual endpoint results retain IP family and method. Internet operator health is successful if either enabled address family succeeds, failed only if tested usable families all fail, and otherwise unknown. At least two independent operators must fail to signal general Internet failure. One failed operator alone is tolerated. Family-specific majority failures with another family healthy are a separate degradation, not a total outage.

Default learning: retain up to 120 healthy aggregate latency samples (median of successful public TCP connections per round). After 10 healthy samples, latency is anomalous when the current five-round median exceeds both 150 ms and 3 times the prior healthy baseline median. Do not learn anomalous samples or incident samples. p95 is nearest-rank; jitter is mean absolute consecutive latency difference, not an RTP jitter estimate. Loss means probe failure fraction, not a claim of wire packet loss for TCP/DNS.

Default detector: three consecutive symptomatic rounds OR at least three bad rounds among the last ten, with a bad fraction >=30%, and the current round bad. Count only current fresh observations. Symptoms include interface-down, correlated gateway+Internet failures, general Internet failure, two DNS-name failures with IP reachability, configured service failure, sustained latency anomaly, and family degradation. Gateway failure with external success is recorded but does not by itself blame the LAN: routers may filter ICMP.

A meaningful route/interface/address/resolver change opens a timeline event and an incident immediately, and resets learning. Prehistory is 45 seconds (hard cap 240 rounds). Incident start is the first bad round of the triggering sequence/window, detection time is separate. A continuous healthy period of 6 seconds is required before finalization; any symptom in this hold merges back into the same incident. Recovery time is the first healthy round in the final uninterrupted recovery run. Unknown-only rounds cannot prove recovery. Finalized incidents do not get rewritten to merge later outages. At 1,800 rounds a long outage is segmented with a continuation link; no unbounded active list.

## Classification rules

Classify only affected rounds, excluding healthy prehistory/recovery. Evidence strings include round counts; raw samples explain every aggregate. A domain needs >=60% of affected rounds (or >=3 supporting rounds); competing independent domains produce `mixed`. Missing probes lower confidence. High confidence needs >=3 supporting rounds, known local interface and gateway evidence, and corroboration; it is confidence in pattern matching, never attribution of legal fault.

| Evidence pattern | Domain | Important alternative |
|---|---|---|
| Interface explicitly down | local-interface | OS reporting delay |
| Interface up, gateway and external probes fail | gateway-or-router | Wi-Fi, cable, router, VPN/local firewall indistinguishable |
| Interface up, gateway good, >=2 independent operators fail | upstream-or-isp | VPN, filtering, local policy, endpoint-specific routing |
| IP operators healthy, >=2 queried DNS names fail | dns | resolver policy, captive network, stale system resolver configuration |
| >=2 IP operators healthy, configured service DNS/TCP/TLS/HTTP fails | remote-service | target-specific route, TLS interception, rejection of HEAD |
| Route-only change | route-change | intentional VPN or routing switch |
| Adapter/address/resolver change | system-network-change | intentional network handover |
| Incompatible independently supported symptoms | mixed | incident may cover multiple failures |
| Insufficient corroboration, isolated latency/family anomaly | insufficient-evidence | an observed degradation can have uncertain source |

Reports include verdict, low/medium/high confidence, evidence for, evidence against, unknowns and next checks. One-shot healthy observations explicitly say no fault observed, while the classifier domain remains insufficient-evidence. Traceroute silence is never used to assign blame to a hop. Paths are supporting observations only; route change refers to the local route snapshot, not a guessed remote hop change.
