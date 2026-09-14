"""Pure deterministic health reduction, rolling baseline and evidence rules."""

import math
from collections import Counter, deque
from collections.abc import Iterable
from statistics import mean, median
from typing import Literal

from routewitness.config import Config
from routewitness.models import Diagnosis, Domain, Probe, Sample, State


def combine(probes: Iterable[Probe]) -> State:
    states = [p.state for p in probes]
    if "ok" in states:
        return "ok"
    if states and all(s == "fail" for s in states):
        return "fail"
    return "unknown"


def operators(sample: Sample) -> dict[str, State]:
    names = {p.operator for p in sample.probes if p.layer == "internet"}
    return {
        name: combine(p for p in sample.probes if p.layer == "internet" and p.operator == name)
        for name in names
    }


def layer(sample: Sample, name: str) -> State:
    return combine(p for p in sample.probes if p.layer == name)


def symptoms(sample: Sample) -> list[str]:
    states = list(operators(sample).values())
    good, bad = states.count("ok"), states.count("fail")
    found: list[str] = []
    if sample.network.is_up is False:
        found.append("interface-down")
    if bad >= 2:
        found.append("internet-loss")
        if layer(sample, "gateway") == "fail":
            found.append("local-path-loss")
    if good >= 2:
        for dns_layer in ("dns-system", "dns-query"):
            names = {p.target for p in sample.probes if p.layer == dns_layer}
            if (
                sum(
                    combine(p for p in sample.probes if p.layer == dns_layer and p.target == n)
                    == "fail"
                    for n in names
                )
                >= 2
            ):
                found.append("dns-failure")
                break
        if any(p.layer == "service" and p.state == "fail" for p in sample.probes):
            found.append("service-failure")
    for family in (4, 6):
        bad_ops = {
            p.operator
            for p in sample.probes
            if p.layer == "internet" and p.family == family and p.state == "fail"
        }
        good_other = {
            p.operator
            for p in sample.probes
            if p.layer == "internet" and p.family != family and p.state == "ok"
        }
        if len(bad_ops) >= 2 and len(good_other) >= 2:
            found.append(f"ipv{family}-degradation")
    return found


def recovery_observed(sample: Sample) -> bool:
    return (
        not sample.symptoms
        and sample.network.is_up is not False
        and list(operators(sample).values()).count("ok") >= 2
        and not any(
            p.state == "unknown"
            for p in sample.probes
            if p.layer in {"dns-system", "dns-query", "service"}
        )
    )


def statistics(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"median_ms": None, "p95_ms": None, "jitter_ms": None}
    return {
        "median_ms": median(values),
        "p95_ms": sorted(values)[math.ceil(0.95 * len(values)) - 1],
        "jitter_ms": mean(abs(b - a) for a, b in zip(values, values[1:], strict=False))
        if len(values) > 1
        else 0.0,
    }


class Detector:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.baseline: deque[float] = deque(maxlen=config.baseline_samples)
        self.recent_latency: deque[float] = deque(maxlen=5)
        self.window: deque[tuple[float, bool]] = deque(maxlen=config.loss_window)
        self.consecutive = 0

    def reset(self) -> None:
        self.baseline.clear()
        self.recent_latency.clear()
        self.window.clear()
        self.consecutive = 0

    def observe(self, sample: Sample, active: bool = False) -> tuple[bool, float]:
        changed = any(e.kind in {"route-change", "system-network-change"} for e in sample.events)
        if changed:
            self.reset()
        sample.symptoms = symptoms(sample)
        values = [
            p.latency_ms
            for p in sample.probes
            if p.layer == "internet" and p.state == "ok" and p.latency_ms is not None
        ]
        sample.latency_ms = median(values) if values else None
        sample.baseline_ms = median(self.baseline) if len(self.baseline) >= 10 else None
        if sample.latency_ms is not None:
            self.recent_latency.append(sample.latency_ms)
            if (
                sample.baseline_ms is not None
                and len(self.recent_latency) == 5
                and median(self.recent_latency)
                > max(
                    self.config.latency_absolute_ms,
                    sample.baseline_ms * self.config.latency_multiplier,
                )
            ):
                sample.symptoms.append("latency-spike")
        else:
            self.recent_latency.clear()
        bad = bool(sample.symptoms)
        self.consecutive = self.consecutive + 1 if bad else 0
        self.window.append((sample.elapsed, bad))
        count = sum(b for _, b in self.window)
        trigger = changed or (
            bad
            and (
                self.consecutive >= self.config.failure_rounds
                or (
                    len(self.window) == self.config.loss_window
                    and count >= self.config.failure_rounds
                    and count / len(self.window) >= self.config.loss_threshold
                )
            )
        )
        if not active and not bad and not changed and sample.latency_ms is not None:
            # Prevent the first high samples polluting the baseline before five-round confirmation.
            if sample.baseline_ms is None or sample.latency_ms <= max(
                self.config.latency_absolute_ms, sample.baseline_ms * self.config.latency_multiplier
            ):
                self.baseline.append(sample.latency_ms)
        onset = next((at for at, b in self.window if b), sample.elapsed)
        return trigger, sample.elapsed if changed else onset


def classify(samples: list[Sample]) -> Diagnosis:
    affected = [s for s in samples if s.symptoms or symptoms(s)]
    votes: Counter[Domain] = Counter()
    support: dict[Domain, list[int]] = {}
    for s in affected:
        public = list(operators(s).values())
        gateway = layer(s, "gateway")
        flags = symptoms(s)
        domain: Domain = "insufficient-evidence"
        if s.network.is_up is False:
            domain = "local-interface"
        elif s.network.is_up is True and "internet-loss" in flags:
            if gateway == "ok":
                domain = "upstream-or-isp"
            elif gateway == "fail":
                domain = "gateway-or-router"
        elif public.count("ok") >= 2:
            if "dns-failure" in flags:
                domain = "dns"
            elif "service-failure" in flags:
                domain = "remote-service"
        if domain != "insufficient-evidence":
            votes[domain] += 1
            support.setdefault(domain, []).append(s.seq)
    eligible = [d for d, n in votes.items() if n >= 3 or n >= max(1, len(affected) * 0.6)]
    events = {e.kind for s in samples for e in s.events}
    domain = "insufficient-evidence"
    if len(eligible) > 1:
        domain = "mixed"
    elif eligible:
        domain = eligible[0]
    elif "system-network-change" in events:
        domain = "system-network-change"
    elif "route-change" in events:
        domain = "route-change"
    for_lines = [
        f"{d}: {votes[d]}/{len(affected)} affected rounds; sample seq "
        + ",".join(map(str, support[d][:12]))
        + ("…" if len(support[d]) > 12 else "")
        for d in sorted(votes)
    ]
    examined = affected or samples
    n = len(examined)
    gateway_ok = sum(layer(s, "gateway") == "ok" for s in examined)
    up = sum(s.network.is_up is True for s in examined)
    for_lines += [
        f"Gateway reachable in {gateway_ok}/{n} examined rounds.",
        f"Local interface reported up in {up}/{n} examined rounds.",
    ]
    for name in sorted({p.operator for s in examined for p in s.probes if p.layer == "internet"}):
        measured = [operators(s).get(name, "unknown") for s in examined]
        known = [x for x in measured if x != "unknown"]
        if known:
            for_lines.append(
                f"{name}: {known.count('fail')}/{len(known)} failed reachability rounds "
                f"({100 * known.count('fail') / len(known):.0f}% probe loss)."
            )
    unknowns = sorted(
        {g for s in samples for g in s.network.gaps}
        | {
            f"{p.layer}/{p.method}: {p.detail or 'unavailable'}"
            for s in examined
            for p in s.probes
            if p.state == "unknown"
        }
    )[:30]
    if any(s.network.is_up is None for s in examined):
        unknowns.append("Active interface state not established for every affected round.")
    if any(layer(s, "gateway") == "unknown" for s in examined):
        unknowns.append("Gateway reachability is incomplete.")
    unknowns.append(
        "Single-host probes cannot prove ISP fault or exclude local filtering/VPN policy."
    )
    against: list[str] = []
    if gateway_ok:
        against.append("A responding gateway argues against a complete local-link outage.")
    if any(list(operators(s).values()).count("ok") >= 2 for s in examined):
        against.append(
            "Independent IP successes argue against a continuous general Internet outage."
        )
    if domain == "gateway-or-router":
        unknowns.append(
            "ICMP filtering can look like a silent gateway; Wi-Fi/cable/router cannot be separated."
        )
    if domain == "remote-service":
        unknowns.append(
            "HEAD rejection, TLS inspection or target-specific routing can mimic service failure."
        )
    confidence: Literal["low", "medium", "high"] = "low"
    if eligible and domain != "mixed":
        confidence = "medium"
        if (
            votes[domain] >= 3
            and up == n
            and gateway_ok == n
            and not any(p.state == "unknown" for s in examined for p in s.probes)
        ):
            confidence = "high"
    verdicts: dict[str, str] = {
        "upstream-or-isp": "Evidence is most consistent with an upstream connectivity failure.",
        "gateway-or-router": "Evidence is most consistent with a local path or router failure.",
        "local-interface": "The operating system reported the active interface down.",
        "dns": "IP connectivity worked while multiple independent DNS-name checks failed.",
        "remote-service": "General connectivity worked while the configured service check failed.",
        "mixed": "Different affected rounds support more than one failure domain.",
        "route-change": "The local routing configuration changed during observation.",
        "system-network-change": "The local network configuration changed during observation.",
        "insufficient-evidence": "Degradation was observed, but evidence cannot locate its source."
        if affected
        else "No connectivity failure was established in the observed samples.",
    }
    checks = {
        "upstream-or-isp": "Compare the same time window from another device; ask the ISP to check its uplink logs.",
        "gateway-or-router": "Compare wired and wireless access; inspect router uptime and local link events.",
        "local-interface": "Inspect adapter reconnect, power-management and cable events at the recorded time.",
        "dns": "Compare system and direct DNS results; check resolver/VPN policy without changing settings.",
        "remote-service": "Check the recorded failure stage and the service status from another connection.",
    }
    return Diagnosis(
        domain=domain,
        verdict=verdicts[domain],
        confidence=confidence,
        evidence_for=for_lines,
        evidence_against=against,
        unknowns=unknowns,
        recommended_next_checks=[
            checks.get(
                domain,
                "Compare another incident and collect corroborating evidence from a second device.",
            )
        ],
    )
