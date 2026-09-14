from datetime import UTC, datetime, timedelta

import pytest

from routewitness.config import Config
from routewitness.engine import Detector, classify, operators, statistics, symptoms
from routewitness.models import Network, Probe, Sample


def sample(t=0, mode="healthy", latency=30, family=4):
    probes = [
        Probe(
            layer="gateway",
            target="192.168.1.1",
            method="icmp",
            state="fail" if mode == "local" else "ok",
            latency_ms=1,
        )
    ]
    for name in ("alpha", "beta", "gamma"):
        probes.append(
            Probe(
                layer="internet",
                target="192.0.2.1",
                operator=name,
                method="tcp",
                family=family,
                latency_ms=latency,
                state="fail" if mode in {"upstream", "local"} else "ok",
            )
        )
    for name in ("example.com", "iana.org"):
        for layer in ("dns-system", "dns-query"):
            probes.append(
                Probe(
                    layer=layer,
                    target=name,
                    method="resolve",
                    state="fail" if mode == "dns" else "ok",
                )
            )
    probes.append(
        Probe(
            layer="service",
            target="example.net",
            method="https-head",
            state="fail" if mode == "service" else "ok",
        )
    )
    return Sample(
        seq=t,
        at=datetime(2026, 9, 13, tzinfo=UTC) + timedelta(seconds=t),
        elapsed=float(t),
        network=Network(interface="eth0", is_up=True),
        probes=probes,
    )


@pytest.mark.parametrize(
    "mode,domain",
    [
        ("upstream", "upstream-or-isp"),
        ("local", "gateway-or-router"),
        ("dns", "dns"),
        ("service", "remote-service"),
        ("healthy", "insufficient-evidence"),
    ],
)
def test_classification(mode, domain):
    assert classify([sample(t, mode) for t in range(5)]).domain == domain


def test_one_failure_and_single_endpoint_are_noise():
    d = Detector(Config())
    for t in range(30):
        s = sample(t, "upstream" if t == 15 else "healthy")
        assert not d.observe(s)[0]
    s = sample()
    s.probes[1].state = "fail"
    assert symptoms(s) == []


def test_sustained_latency():
    d = Detector(Config())
    events = []
    for t in range(40):
        s = sample(t, latency=30 if t < 20 else 200)
        events.append(d.observe(s)[0])
    assert not any(events[:22])
    assert any(events[22:])
    assert s.baseline_ms == 30


def test_unknown_not_failure_or_success():
    s = sample()
    for p in s.probes:
        p.state = "unknown"
    s.network.is_up = None
    assert symptoms(s) == []
    assert classify([s]).confidence == "low"


def test_ipv6_partial_is_not_total_outage():
    s = sample(family=6)
    for name in ("alpha", "beta", "gamma"):
        s.probes.append(
            Probe(
                layer="internet",
                target="192.0.2.2",
                operator=name,
                method="tcp",
                family=4,
                state="fail",
            )
        )
    assert set(operators(s).values()) == {"ok"}
    assert symptoms(s) == ["ipv4-degradation"]
    assert classify([s]).domain == "insufficient-evidence"


def test_stats_exact():
    assert statistics([10, 20, 30, 40]) == {"median_ms": 25, "p95_ms": 40, "jitter_ms": 10}
    assert statistics([])["median_ms"] is None


def test_interface_down_and_mixed():
    down = sample(0)
    down.network.is_up = False
    assert classify([down]).domain == "local-interface"
    records = [sample(t, "upstream" if t < 5 else "dns") for t in range(10)]
    assert classify(records).domain == "mixed"


def test_route_event_only():
    from routewitness.models import Event

    s = sample()
    s.events = [Event(kind="route-change", detail="Default changed")]
    assert classify([s]).domain == "route-change"
    s.events = [Event(kind="system-network-change", detail="Interface changed")]
    assert classify([s]).domain == "system-network-change"
