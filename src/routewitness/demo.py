"""Deterministic offline upstream outage; no sockets, commands or OS discovery."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from routewitness.config import Config
from routewitness.models import Network, PathObservation, Probe, Sample
from routewitness.recorder import Capture, Phase
from routewitness.storage import Store

ORIGIN = datetime(2026, 9, 13, 21, 43, tzinfo=UTC)


def demo_sample(seq: int, at: datetime, elapsed: float) -> Sample:
    outage = 24 <= elapsed < 36
    latency = 184.0 if 20 <= elapsed < 24 else 37.0
    probes = [
        Probe(
            layer="gateway",
            target="192.168.1.1",
            method="icmp",
            family=4,
            state="ok",
            latency_ms=1.4,
        )
    ]
    for operator, ip, port in (
        ("cloudflare", "1.1.1.1", 443),
        ("google", "8.8.8.8", 53),
        ("quad9", "9.9.9.9", 53),
    ):
        probes.append(
            Probe(
                layer="internet",
                target=ip,
                operator=operator,
                family=4,
                method=f"tcp/{port}",
                state="fail" if outage else "ok",
                latency_ms=None if outage else latency,
            )
        )
    for hostname in ("example.com", "iana.org"):
        for layer in ("dns-system", "dns-query"):
            probes.append(
                Probe(
                    layer=layer,
                    target=hostname,
                    method="resolve",
                    family=4,
                    state="fail" if outage else "ok",
                    latency_ms=1500 if outage else 12,
                )
            )
    probes.append(
        Probe(
            layer="service",
            target="example.com",
            method="https-head",
            stage="tcp" if outage else "http",
            state="fail" if outage else "ok",
            detail="TCP failed" if outage else "HTTP 200",
            latency_ms=None if outage else 48,
        )
    )
    return Sample(
        seq=seq,
        at=at,
        elapsed=elapsed,
        network=Network(
            interface="demo-wifi",
            is_up=True,
            kind="wifi",
            addresses=["192.168.1.20"],
            gateways=["192.168.1.1"],
            routes=["default via 192.168.1.1"],
            resolvers=["192.168.1.1"],
        ),
        probes=probes,
    )


class DemoProvider:
    async def sample(self, seq: int, at: datetime, elapsed: float) -> Sample:
        return demo_sample(seq, at, elapsed)

    async def path(self, phase: Phase) -> PathObservation:
        offset = {"baseline": 0, "start": 24, "during": 30, "recovery": 42}[phase]
        return PathObservation(
            phase=phase,
            at=ORIGIN + timedelta(seconds=offset),
            target="1.1.1.1",
            state="ok",
            hops=["192.168.1.1", "unanswered" if phase in {"start", "during"} else "198.51.100.1"],
            detail="Simulated numeric path.",
        )


def generate(store: Store) -> Path:
    capture = Capture(Config(), simulated=True)
    finished = []
    for seq in range(43):
        s = demo_sample(seq, ORIGIN + timedelta(seconds=seq), float(seq))
        _, completed = capture.push(s)
        finished.extend(completed)
    if len(finished) != 1 or finished[0].diagnosis.domain != "upstream-or-isp":
        raise RuntimeError("offline demo did not produce the expected incident")
    incident = finished[0]
    for phase, seq in (("baseline", 0), ("start", 24), ("recovery", 42)):
        incident.paths.append(
            PathObservation.model_validate(
                {
                    "phase": phase,
                    "at": ORIGIN + timedelta(seconds=seq),
                    "target": "1.1.1.1",
                    "state": "ok",
                    "hops": ["192.168.1.1", "unanswered" if phase == "start" else "198.51.100.1"],
                    "detail": "Simulated path; no real network probe.",
                }
            )
        )
    return store.save(incident)
