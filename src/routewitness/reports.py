"""Sanitized evidence projection and fully offline, no-JavaScript reports."""

import csv
import html
import io
import re
from collections import defaultdict

from routewitness.engine import classify, statistics
from routewitness.models import Incident

DEFAULT_OPERATORS = {"cloudflare", "google", "quad9", "alpha", "beta", "gamma"}


def sanitize(source: Incident) -> Incident:
    """Allowlist diagnostics; replace local identifiers before deriving explanations.

    Arbitrary free text from platform/probes is never trusted as shareable metadata.
    Timestamps remain because incident correlation requires them.
    """
    result = source.model_copy(deep=True)
    identifiers: dict[str, str] = {}

    def alias(value: str, category: str) -> str:
        key = category + ":" + value
        if key not in identifiers:
            identifiers[key] = (
                f"{category}-{1 + sum(k.startswith(category + ':') for k in identifiers)}"
            )
        return identifiers[key]

    allowed_symptoms = {
        "interface-down",
        "internet-loss",
        "local-path-loss",
        "dns-failure",
        "service-failure",
        "ipv4-degradation",
        "ipv6-degradation",
        "latency-spike",
    }
    for sample in result.samples:
        sample.symptoms = [
            s if s in allowed_symptoms else "unrecognized-symptom" for s in sample.symptoms
        ]
        net = sample.network
        if net.interface:
            net.interface = alias(net.interface, "interface")
        net.kind = net.kind if net.kind in {"wifi", "ethernet", "unknown"} else "unknown"
        net.addresses = [alias(a, "local-address") for a in net.addresses]
        net.gateways = [alias(a, "gateway") for a in net.gateways]
        net.routes = [alias(a, "route") for a in net.routes]
        net.resolvers = [alias(a, "resolver") for a in net.resolvers]
        net.gaps = (
            ["Platform capability unavailable; inspect raw local evidence for details."]
            if net.gaps
            else []
        )
        for event in sample.events:
            event.detail = {
                "system-network-change": "Interface, address or resolver configuration changed.",
                "route-change": "Default or split route configuration changed.",
                "sampling-gap": "Sampling paused; connectivity during the gap is unknown.",
            }.get(event.kind, "Recorded network event.")
            if event.kind not in {"system-network-change", "route-change", "sampling-gap"}:
                event.kind = "network-event"
        for p in sample.probes:
            if p.operator and p.operator not in DEFAULT_OPERATORS:
                p.operator = alias(p.operator, "operator")
            if p.layer == "internet":
                p.target = f"{p.operator}-ipv{p.family}"
            elif p.layer == "gateway":
                p.target = alias(p.target, "gateway")
            else:
                p.target = alias(p.target, "hostname")
            if not re.fullmatch(
                r"(?:icmp|tcp/\d{1,5}|getaddrinfo|dns-A|dns-AAAA|https-head|resolve)", p.method
            ):
                p.method = "probe"
            p.stage = p.stage if p.stage in {"", "dns", "tcp", "tls", "http"} else "unknown"
            if not re.fullmatch(r"HTTP [0-9]{3}", p.detail):
                p.detail = "" if p.state == "ok" else "Probe failed or was unavailable."
    for path in result.paths:
        path.target = alias(path.target, "path-target")
        path.hops = ["unanswered" if h == "unanswered" else alias(h, "hop") for h in path.hops]
        path.detail = "Hop silence does not prove forwarded packet loss."
    result.warnings = (
        ["Recording was interrupted or bounded; inspect status and local raw evidence."]
        if source.warnings
        else []
    )
    result.capability_gaps = sorted({g for s in result.samples for g in s.network.gaps})
    result.tool_version = "0.1.0"
    if result.previous_id and not re.fullmatch(r"\d{8}T\d{6}Z-[a-f0-9]{8}", result.previous_id):
        result.previous_id = None
    result.diagnosis = classify(
        [
            s
            for s in result.samples
            if s.at >= result.start and (result.end is None or s.at <= result.end)
        ]
    )
    return result


def terminal(incident: Incident) -> str:
    d = incident.diagnosis
    lines = [
        f"Incident {incident.id}" + (" [SIMULATED]" if incident.simulated else ""),
        "",
        f"Likely source: {d.domain}",
        f"Confidence: {d.confidence}",
        d.verdict,
        "",
        "Evidence",
    ]
    lines += [f"  {x}" for x in d.evidence_for]
    lines += [
        "",
        f"Duration: {incident.duration_s:.1f} s · {incident.status}",
        f"Recovered/end: {incident.end.isoformat() if incident.end else 'not established'}",
    ]
    if d.unknowns:
        lines += ["", "Unknowns", *[f"  {x}" for x in d.unknowns]]
    return "\n".join(lines)


def markdown(incident: Incident) -> str:
    d = incident.diagnosis
    lines = [
        f"# RouteWitness incident {incident.id}",
        "",
        "**SIMULATED OFFLINE DEMO**" if incident.simulated else "Sanitized local evidence report.",
        "",
        f"{d.verdict} Confidence: **{d.confidence}**.",
        "",
        f"Status: {incident.status}. Duration: {incident.duration_s:.1f} seconds.",
        "",
        f"Start: {incident.start.isoformat()}. Detection: {incident.detected.isoformat()}.",
        "",
    ]
    for title, rows in [
        ("Evidence for", d.evidence_for),
        ("Evidence against", d.evidence_against),
        ("Unknowns", d.unknowns),
        ("Next checks", d.recommended_next_checks),
    ]:
        lines += [f"## {title}", "", *[f"- {html.escape(r)}" for r in rows], ""]
    lines += [
        "## Timeline",
        "",
        "See report.html for the layered timeline and timeline.csv for every probe.",
        "",
        "## Privacy",
        "",
        "Local identifiers and hostnames are pseudonymized. Timestamps remain. "
        "No payload capture, uploads, JavaScript or remote report assets. Review before sharing. "
        "incident.json and checkpoints contain raw local evidence; share report.html or shareable.json.",
    ]
    return "\n".join(lines) + "\n"


def timeline_csv(incident: Incident) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "seq",
            "utc",
            "elapsed_s",
            "symptoms",
            "layer",
            "target",
            "family",
            "method",
            "state",
            "latency_ms",
            "stage",
        ]
    )
    for s in incident.samples:
        for p in s.probes:
            writer.writerow(
                [
                    s.seq,
                    s.at.isoformat(),
                    s.elapsed,
                    ";".join(s.symptoms),
                    p.layer,
                    p.target,
                    p.family,
                    p.method,
                    p.state,
                    round(p.latency_ms, 3) if p.latency_ms is not None else "",
                    p.stage,
                ]
            )
    return buf.getvalue()


CSS = """
:root {color-scheme:light dark;--bg:#fafafa;--fg:#202124;--muted:#62656b;--line:#d2d5da;--ok:#367b56;--fail:#c24439;--unknown:#95979a;--accent:#84662a}
@media(prefers-color-scheme:dark){:root{--bg:#17191c;--fg:#e4e6e9;--muted:#a0a5ad;--line:#41464e;--ok:#72ba91;--fail:#f47d72;--unknown:#646a73;--accent:#d8b56d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,sans-serif}main{max-width:1150px;margin:auto;padding:28px}header{border-bottom:2px solid var(--fg);padding-bottom:16px}h1{font-size:22px;margin:0}h2{font-size:16px;margin:28px 0 10px}h3{font-size:14px}p{margin:8px 0}.muted,small{color:var(--muted)}code,pre,.mono,th{font-family:ui-monospace,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--muted)}.scroll{overflow-x:auto}svg{display:block;width:100%;height:180px}.timeline-layout{display:grid;grid-template-columns:120px minmax(0,1fr);gap:10px}.lane-labels{padding-top:25px;font:12px ui-monospace,monospace}.lane-labels span{display:block;height:29px;line-height:19px}.time-axis{display:flex;justify-content:space-between;font:11px ui-monospace,monospace;color:var(--muted);margin-right:4.762%}svg text{fill:var(--fg);font:12px ui-monospace,monospace}.ok{fill:var(--ok)}.fail{fill:var(--fail)}.unknown{fill:var(--unknown)}.anomaly{fill:var(--accent)}.rule{stroke:var(--fg);stroke-dasharray:4 3}.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}.tag{font:12px ui-monospace,monospace;border:1px solid var(--line);padding:3px 7px;display:inline-block}li{margin-bottom:5px}footer{margin-top:28px;border-top:1px solid var(--line);padding-top:12px}@media(max-width:650px){.timeline-layout{grid-template-columns:86px minmax(0,1fr);gap:6px}.lane-labels{font-size:11px}.time-axis{font-size:10px}main{padding:16px}.grid{grid-template-columns:1fr}}@media print{:root{--bg:white;--fg:black;--muted:#555;--line:#ccc}main{padding:0}details{display:block}svg{min-width:0}}
"""


def html_report(incident: Incident) -> str:
    """Accept only sanitized Incident from storage; nevertheless escape every string."""
    esc = html.escape
    d = incident.diagnosis
    samples = incident.samples
    first, last = samples[0].elapsed, samples[-1].elapsed
    span = max(1.0, last - first)

    def x(at: float) -> float:
        return 160 + 800 * (at - first) / span

    lanes = ["gateway", "internet", "dns-system", "dns-query", "service"]
    svg = [
        '<svg viewBox="160 0 840 180" preserveAspectRatio="none" role="img" aria-label="Layered incident timeline">',
        "<title>Layered timeline: green success, red failure, gray unknown, amber anomaly</title>",
    ]
    for row, name in enumerate(lanes):
        y = 25 + row * 29
        for i, s in enumerate(samples):
            probes = [p for p in s.probes if p.layer == name]
            states = [p.state for p in probes]
            state = "fail" if "fail" in states else "ok" if "ok" in states else "unknown"
            if name == "internet" and "latency-spike" in s.symptoms and state == "ok":
                state = "anomaly"
            end = (
                samples[i + 1].elapsed if i + 1 < len(samples) else s.elapsed + span / len(samples)
            )
            width = max(0.3, min(960 - x(s.elapsed), x(end) - x(s.elapsed)))
            title = f"seq {s.seq} · {s.at.isoformat()} · {name}: {state}"
            svg.append(
                f'<rect class="{state}" x="{x(s.elapsed):.2f}" y="{y}" width="{width:.2f}" height="19"><title>{esc(title)}</title></rect>'
            )
    for label, at in (
        ("start", incident.start),
        ("detected", incident.detected),
        ("end", incident.end),
    ):
        if at is None:
            continue
        match = min(samples, key=lambda s: abs((s.at - at).total_seconds()))
        px = x(match.elapsed)
        svg.append(
            f'<line class="rule" x1="{px:.2f}" x2="{px:.2f}" y1="15" y2="177"><title>{label}: {esc(at.isoformat())}</title></line>'
        )
    svg.append("</svg>")
    lane_labels = "".join(f"<span>{esc(name)}</span>" for name in lanes)
    time_axis = "".join(
        f"<span>{span * fraction:.1f}s</span>" for fraction in (0, 0.25, 0.5, 0.75, 1)
    )
    timeline = (
        '<div class="timeline-layout"><div class="lane-labels">'
        + lane_labels
        + "</div><div>"
        + "".join(svg)
        + '<div class="time-axis">'
        + time_axis
        + "</div></div></div>"
    )

    def items(values: list[str]) -> str:
        return (
            "<ul>" + "".join(f"<li>{esc(v)}</li>" for v in values) + "</ul>"
            if values
            else '<p class="muted">None recorded.</p>'
        )

    grouped: dict[str, list[tuple[str, float | None]]] = defaultdict(list)
    for s in samples:
        for p in s.probes:
            grouped[f"{p.layer} / {p.target} / IPv{p.family} / {p.method}"].append(
                (p.state, p.latency_ms)
            )
    rows = []
    for name, observations in sorted(grouped.items()):
        known = [state for state, _ in observations if state != "unknown"]
        latency = [v for state, v in observations if state == "ok" and v is not None]
        stats = statistics(latency)

        def fmt(value: float | None) -> str:
            return f"{value:.1f}" if value is not None else "—"

        loss = f"{100 * known.count('fail') / len(known):.0f}%" if known else "unknown"
        rows.append(
            f"<tr><td>{esc(name)}</td><td>{loss}</td><td>{len(observations) - len(known)}</td><td>{fmt(stats['median_ms'])}</td><td>{fmt(stats['p95_ms'])}</td><td>{fmt(stats['jitter_ms'])}</td></tr>"
        )
    changes = [
        f"seq {s.seq} · {s.at.isoformat()} · {e.kind}: {e.detail}"
        for s in samples
        for e in s.events
    ]
    paths = [
        f"{p.phase} · {p.at.isoformat()} · {p.state} · {p.target}\n"
        + " → ".join(p.hops)
        + "\n"
        + p.detail
        for p in incident.paths
    ]
    title = f"RouteWitness · {incident.id}"
    demo = (
        '<p class="tag">SIMULATED OFFLINE DEMO · no real outage measured</p>'
        if incident.simulated
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>{esc(title)}</title><style>{CSS}</style></head>
<body><main><header><p class="muted mono">ROUTEWITNESS / INCIDENT EVIDENCE / v{esc(incident.tool_version)}</p>
<h1>{esc(incident.id)}</h1>{demo}<p>{esc(d.verdict)}</p>
<span class="tag">{esc(d.domain)}</span> <span class="tag">confidence: {esc(d.confidence)}</span> <span class="tag">{esc(incident.status)} · {incident.duration_s:.1f}s</span></header>
<section><h2>Incident summary</h2><p>Start <code>{esc(incident.start.isoformat())}</code> · Detected <code>{esc(incident.detected.isoformat())}</code></p></section>
<section><h2>Timeline</h2><p class="muted">Normal → degradation → failure → recovery. Hover a segment for UTC time and sample number. A red lane can include partial endpoint/family failure.</p>{timeline}
<p class="muted">Green: successful · Red: failed · Gray: unknown/unconfigured · Amber: latency anomaly. Dashed markers: start, detection, end. Time axis begins at first retained sample.</p></section>
<section><h2>Likely failure domain</h2><p>{esc(d.verdict)} This is evidence-based inference, not proof of responsibility.</p>
<div class="grid"><div><h3>Evidence for</h3>{items(d.evidence_for)}</div><div><h3>Evidence against</h3>{items(d.evidence_against)}<h3>Unknowns</h3>{items(d.unknowns)}</div></div><h3>Recommended next checks</h3>{items(d.recommended_next_checks)}</section>
<section><h2>Gateway · Internet reachability · DNS · Service</h2><p class="muted">Statistics cover all retained samples, including prehistory/recovery. TCP loss is failed connection attempts, not measured wire packet loss. Jitter is mean consecutive latency difference.</p><div class="scroll"><table><thead><tr><th>Probe</th><th>Failure rate</th><th>Unknown</th><th>Median ms</th><th>p95 ms</th><th>Jitter ms</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>
<section><h2>Path observations</h2>{"".join("<pre>" + esc(p) + "</pre>" for p in paths) or '<p class="muted">Path evidence unavailable or disabled.</p>'}</section>
<section><h2>Network changes</h2>{items(changes)}</section>
<section><h2>Recovery</h2><p>Status: {esc(incident.status)}. End: {esc(incident.end.isoformat()) if incident.end else "not established"}. Healthy post-event samples remain in the timeline; interrupted recordings do not establish recovery.</p></section>
<section><h2>Technical details</h2><p>Schema {incident.schema_version}; {len(samples)} rounds. Sequence numbers map directly to canonical evidence. Previous segment: {esc(incident.previous_id or "none")}.</p>{items(incident.warnings + incident.capability_gaps)}</section>
<footer><h2>Privacy / collection notes</h2><p>This sanitized report contains pseudonyms in place of addresses, interfaces, hostnames and hops. UTC timestamps remain. No packet payloads, SSIDs, BSSIDs, MACs, browser history or credentials are collected. No telemetry or upload feature exists. Probes themselves contact configured endpoints and resolvers.</p><p>Fully offline: no scripts, remote fonts, assets or network requests. Share this HTML or shareable.json; keep incident.json and checkpoints local. Review timestamps and context before sharing.</p></footer></main></body></html>"""
