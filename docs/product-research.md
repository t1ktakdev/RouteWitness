# Product research and v0.1 scope

Research date: 2026-09-13. This is a review of primary project/product documentation, not a hands-on comparative benchmark. Features and names can change. No claim of invention, market exclusivity, or exhaustive search is made.

## Existing tools

| Tool | What its documentation establishes | Implication for RouteWitness |
|---|---|---|
| [PingPlotter](https://www.pingplotter.com/) and [alerts](https://www.pingplotter.com/wisdom/article/stay-on-top-with-alerts/) | Continuous monitoring, latency/jitter/loss, path visualization, history and intelligent alerts; cloud/remote options also exist. | Proactive monitoring and intermittent fault capture are NOT new. Do not compete by drawing another ping graph. |
| [mtr](https://github.com/traviscross/mtr) | Combines traceroute and ping with ongoing path statistics and report modes. | Retain path evidence but never equate intermediate-hop ICMP loss with forwarded traffic loss. |
| [WinMTR Redux](https://github.com/White-Tiger/WinMTR) | Windows MTR lineage with IPv6 enhancements. | Cross-platform or IPv6 alone is no differentiator. |
| [OpenMTR](https://github.com/x-rated/OpenMTR) | Qt6 real-time ping/traceroute view on Windows, macOS and Linux, with export. | A modern interface and shareable path tables are already covered. |
| [SmokePing](https://oss.oetiker.ch/smokeping/) | Long-term RRDtool storage and graphs of latency, distribution and loss. | Long-running low-volume measurements and historical trends are established strengths. |
| [Network Doctor](https://github.com/heymaikol/network-doctor) | Cross-platform layered interface/DNS/TCP/TLS/HTTP diagnosis, plain-English findings, watch mode, JSON, and no-root probes. | Layered diagnosis and watch mode are ALSO not novel. RouteWitness must earn usefulness through the complete automatic incident lifecycle, bounded prehistory and portable evidence. No assertion that Network Doctor cannot do these things without further feature-level inspection. |
| [Speedtest Tracker](https://docs.speedtest-tracker.dev/) | Scheduled throughput tests, performance/uptime history; self-hosted Laravel/Ookla stack. | Useful for contracted throughput and trends. Short low-traffic event capture answers a different question from bulk transfer performance. |
| [speedtest-cli](https://github.com/sivel/speedtest-cli) | Python CLI for Internet bandwidth testing. | Python packaging and automation alone are not differentiation. |
| [NetCheck](https://github.com/azeryusifzade/netcheck) | Python terminal diagnostics: status, ping, DNS and related checks. | A wrapper around existing diagnostic commands is insufficient product scope. |
| [Uptime Kuma](https://github.com/louislam/uptime-kuma) | Self-hosted monitoring with multiple protocols and notifications. | Monitoring a service's availability is already well served. A local laptop's changing access network and evidence bundle are the focus here. |
| [monitor-internet-connection](https://github.com/mfoc/monitor-internet-connection), [internet-monitor](https://github.com/mclarkk/internet-monitor) | Python Internet uptime/downtime recording; simple periodic reachability/CSV designs respectively. | Automatic outage timing is established. Add independent layer evidence, uncertainty and safe sharing. |

## Useful gap (product hypothesis, not a proven exclusive feature)

A small installable local CLI with one coherent workflow: retain recent normal telemetry; debounce failures; capture an incident and recovery; explain a likely domain using reproducible rules; hand someone an offline, sanitized report without operating a server or reading a path table. This combination and its ease of use are the proposition, not any single probe.

- Home users: distinguish a disappearing adapter from a reachable router and failing external endpoints; do not promise to separate radio interference from a router hang without evidence.
- Gamers: preserve short drops and sustained latency changes; TCP probe timing is not game UDP latency or FPS.
- Students: explain measured layers with an offline reproducible demo and inspectable JSON.
- Remote workers: retain evidence around a call disruption without recording call traffic.
- Developers: compare incidents and consume stable JSON; explicit service targets isolate service-specific symptoms.
- ISP escalation: provide timestamped endpoint and gateway observations, alternatives and gaps. Single-vantage-point evidence is not proof of contractual fault.

## Derived v0.1 scope

Ship a foreground watcher (no service installer), one-shot diagnosis, status, incident list/show/report/compare, config, doctor, and offline demo. Three independent endpoint operators; per-family observations; separate system DNS and controlled DNS, bounded TCP/TLS/HTTP HEAD, opportunistic ICMP gateway evidence. Time-based prehistory, debounced sustained failures and loss, frozen normal latency baseline during incidents, network-change events, recovery hold/merge, chunked long outages. Numeric path capture at baseline/start/long-incident/recovery only. Explicit partial capability and no automatic system changes.

Defer background service integration, packet capture, cloud, profiles, GUI, router control, game-specific UDP and multipoint verification. Avoid throughput tests entirely.

## Name check

Working distribution/repository name: `routewitness` / `RouteWitness`.
Exact-name web search on 2026-09-13 returned no obvious software conflict. Direct HTTPS checks completed: `https://pypi.org/pypi/routewitness/json` returned HTTP 404; `https://api.github.com/repos/t1ktakdev/RouteWitness` returned HTTP 404; `https://api.github.com/search/repositories?q=RouteWitness+in:name` returned HTTP 200 with `total_count: 0`, `incomplete_results: false`. The name appears available at check time; it is not reserved and this is not trademark clearance. Recheck before publication. No repository or package was published.
