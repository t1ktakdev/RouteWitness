import tracemalloc

from test_engine import sample

from routewitness.config import Config
from routewitness.recorder import Capture


def collect(modes, config=None):
    recorder = Capture(config or Config())
    completed = []
    for t, mode in enumerate(modes):
        _, incidents = recorder.push(sample(t, mode))
        completed += incidents
    return recorder, completed


def test_before_during_after_and_onset():
    recorder, incidents = collect(["healthy"] * 20 + ["upstream"] * 12 + ["healthy"] * 10)
    assert len(incidents) == 1
    i = incidents[0]
    assert i.status == "recovered"
    assert i.samples[0].seq == 0
    assert i.start.second == 20 and i.detected.second == 22
    assert i.end.second == 32
    assert i.duration_s == 12
    assert i.samples[-1].seq >= 38
    assert i.diagnosis.domain == "upstream-or-isp"
    assert recorder.active is None


def test_close_drops_merge():
    _, incidents = collect(
        ["healthy"] * 20 + ["upstream"] * 4 + ["healthy"] * 3 + ["upstream"] * 4 + ["healthy"] * 10
    )
    assert len(incidents) == 1


def test_short_repeated_drops_trigger_window():
    _, incidents = collect(["healthy"] * 20 + ["upstream", "healthy"] * 5 + ["healthy"] * 10)
    assert len(incidents) == 1


def test_shutdown_preserves_outage():
    r, _ = collect(["healthy"] * 10 + ["upstream"] * 5)
    i = r.stop()
    assert i.status == "interrupted"
    assert i.end is not None
    assert i.warnings


def test_handover_resets_baseline():
    r, _ = collect(["healthy"] * 20)
    s = sample(20)
    s.network.interface = "wlan0"
    started, _ = r.push(s)
    assert started is not None
    assert s.events[0].kind == "system-network-change"
    assert not r.detector.baseline


def test_resume_does_not_count_sleep_as_outage():
    r, _ = collect(["healthy"] * 20 + ["upstream"] * 5)
    s = sample(300)
    _, completed = r.push(s)
    assert completed[0].duration_s == 4
    assert completed[0].status == "interrupted"
    assert s.events[0].kind == "sampling-gap"
    assert len(r.pre) == 1


def test_unknown_cannot_prove_recovery():
    r, _ = collect(["upstream"] * 5)
    for t in range(5, 30):
        s = sample(t)
        for p in s.probes:
            p.state = "unknown"
        r.push(s)
    assert r.active is not None


def test_long_outage_has_bounded_linked_segments():
    r, incidents = collect(["upstream"] * 100, Config(segment_samples=30))
    assert len(incidents) >= 3
    assert all(len(i.samples) <= 30 for i in incidents)
    assert incidents[1].previous_id == incidents[0].id
    assert r.active is not None


def test_long_running_memory_bound():
    r = Capture(Config())
    tracemalloc.start()
    for t in range(5000):
        r.push(sample(t))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(r.pre) <= 46
    assert len(r.detector.baseline) <= 120
    assert peak < 5_000_000


def test_previous_incident_does_not_contaminate_next_verdict():
    _, incidents = collect(
        ["healthy"] * 15 + ["upstream"] * 5 + ["healthy"] * 8 + ["dns"] * 5 + ["healthy"] * 10
    )
    assert len(incidents) == 2
    assert incidents[0].diagnosis.domain == "upstream-or-isp"
    assert incidents[1].diagnosis.domain == "dns"
    from routewitness.reports import sanitize

    assert sanitize(incidents[1]).diagnosis.domain == "dns"


def test_wall_clock_backwards_is_a_gap():
    from datetime import timedelta

    r, _ = collect(["healthy"] * 20)
    s = sample(20)
    s.at -= timedelta(seconds=3)
    r.push(s)
    assert s.events[0].kind == "sampling-gap"
