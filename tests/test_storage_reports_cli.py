import asyncio
import hashlib
import json
import os

import pytest

from routewitness.cli import main
from routewitness.config import Config, hostname, load
from routewitness.demo import DemoProvider, generate
from routewitness.models import Incident
from routewitness.recorder import FakeClock, watch
from routewitness.reports import html_report, sanitize
from routewitness.storage import Store, WatchLock, atomic_text, status


def test_demo_reproducible_bundle_and_manifest(tmp_path):
    first = generate(Store(tmp_path / "a"))
    second = generate(Store(tmp_path / "b"))
    assert first.name == second.name
    for file in first.iterdir():
        assert file.read_bytes() == (second / file.name).read_bytes()
    for line in (first / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ")
        assert hashlib.sha256((first / name).read_bytes()).hexdigest() == expected
    assert Store(tmp_path / "a").load(first.name).diagnosis.domain == "upstream-or-isp"
    with pytest.raises(FileExistsError):
        generate(Store(tmp_path / "a"))


def test_hostile_metadata_escaped_and_not_shared(tmp_path):
    store = Store(tmp_path)
    folder = generate(store)
    raw = store.load(folder.name)
    payload = '<script>alert("secret-user")</script>'
    raw.samples[0].network.interface = payload
    raw.samples[0].network.addresses = ["2001:db8::secret-user"]
    raw.samples[0].probes[0].target = payload
    raw.samples[0].probes[0].detail = payload
    raw.samples[0].probes[1].operator = payload
    raw.paths[0].hops = [payload]
    raw.paths[0].detail = payload
    raw.diagnosis.verdict = payload
    rendered_raw = html_report(raw)
    assert "<script>" not in rendered_raw
    assert "&lt;script&gt;" in rendered_raw
    safe = sanitize(raw)
    rendered = html_report(safe)
    assert "secret-user" not in rendered
    assert "secret-user" not in safe.model_dump_json()
    assert "192.168.1.1" not in rendered
    assert "<script" not in rendered and "src=" not in rendered
    assert "default-src 'none'" in rendered


def test_schema_rejects_corruption_and_incomplete(tmp_path):
    store = Store(tmp_path)
    folder = generate(store)
    source = json.loads((folder / "incident.json").read_text())
    for field, value in [
        ("schema_version", 999),
        ("duration_s", -1),
        ("samples", []),
        ("status", "invented"),
        ("start", "no-date"),
    ]:
        with pytest.raises(ValueError):
            Incident.model_validate({**source, field: value})
    atomic_text(folder / "incident.json", "{broken")
    items, warnings = store.listing()
    assert items == [] and warnings
    with pytest.raises(ValueError):
        store.load("../../etc/passwd")


def test_checkpoint_recovery_and_retention(tmp_path):
    source = Store(tmp_path / "source")
    folder = generate(source)
    incident = source.load(folder.name)
    incident.status = "recording"
    incident.end = None
    target = Store(tmp_path / "target")
    target.checkpoint(incident)
    with WatchLock(target.root):
        recovered = target.recover_checkpoints()
    assert target.load(recovered[0].name).status == "interrupted"
    assert target.retain(None) == 0
    assert target.retain(1) == 0  # interrupted evidence is retained
    assert not list(target.incidents.glob(".pending-*"))


def test_lock_status_and_atomic_replace(tmp_path):
    assert status(tmp_path)["active"] is False
    with WatchLock(tmp_path) as lock:
        lock.heartbeat("healthy", None, 4)
        assert status(tmp_path)["active"] is True
        with pytest.raises(RuntimeError):
            with WatchLock(tmp_path):
                pass
    assert status(tmp_path)["active"] is False
    atomic_text(tmp_path / "file", "old")
    atomic_text(tmp_path / "file", "new")
    assert (tmp_path / "file").read_text() == "new"
    if os.name != "nt":
        assert (tmp_path / "file").stat().st_mode & 0o077 == 0


def test_symlink_incident_rejected(tmp_path):
    folder = generate(Store(tmp_path / "a"))
    store = Store(tmp_path / "b")
    store.incidents.mkdir(parents=True)
    try:
        (store.incidents / folder.name).symlink_to(folder, target_is_directory=True)
    except OSError:
        pytest.skip("OS denies unprivileged symlink creation")
    with pytest.raises(ValueError):
        store.load(folder.name)


def test_cli_json_is_clean_and_errors_on_stderr(tmp_path, capsys):
    args = ["--data-dir", str(tmp_path)]
    assert main([*args, "demo", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["simulated"]
    for command in [
        ["show", data["id"]],
        ["incidents"],
        ["status"],
        ["config"],
        ["compare", data["id"], data["id"]],
        ["report", data["id"]],
    ]:
        assert main([*args, *command, "--json"]) == 0
        assert isinstance(json.loads(capsys.readouterr().out), dict)
    assert main([*args, "show", "../../oops", "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and json.loads(captured.err)["error"]


@pytest.mark.parametrize(
    "name",
    [
        "https://example.com",
        "x; rm -rf",
        "-flag",
        "a\nheader",
        "user:password@site.test",
        "example.com:443",
    ],
)
def test_host_validation(name):
    with pytest.raises(ValueError):
        hostname(name)


def test_config_strict_limits(tmp_path):
    for data in [
        {"interval": 0},
        {"segment_samples": 999999},
        {"surprise": True},
        {"targets": ["x"] * 5},
        {"timeout": float("nan")},
        {"dns_names": ["same", "same"]},
    ]:
        with pytest.raises(ValueError):
            Config.model_validate(data)
    path = tmp_path / "config.toml"
    path.write_text("interval=2\npaths=false\n", encoding="utf-8")
    assert load(path).interval == 2


def test_full_watch_story_with_fake_clock_and_probes(tmp_path):
    store = Store(tmp_path)
    messages = []
    paths = asyncio.run(
        watch(
            Config(),
            DemoProvider(),
            store,
            clock=FakeClock(),
            rounds=70,
            simulated=True,
            emit=messages.append,
        )
    )
    assert len(paths) == 1
    incident = store.load(paths[0].name)
    assert incident.status == "recovered"
    assert incident.diagnosis.domain == "upstream-or-isp"
    assert incident.samples[0].elapsed == 0
    assert incident.samples[-1].elapsed >= 42
    assert {"start", "recovery"} <= {p.phase for p in incident.paths}
    assert (paths[0] / "report.html").exists()
    assert not status(tmp_path)["active"]
    assert any("incident started" in m for m in messages)


def test_watch_cancellation_flushes_active_evidence(tmp_path):
    class FailingProvider(DemoProvider):
        async def sample(self, seq, at, elapsed):
            if seq == 32:
                raise asyncio.CancelledError()
            return await super().sample(seq, at, elapsed)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            watch(
                Config(),
                FailingProvider(),
                Store(tmp_path),
                clock=FakeClock(),
                simulated=True,
                emit=lambda _: None,
            )
        )
    records, _ = Store(tmp_path).listing()
    assert records[0].status == "interrupted"
    assert not status(tmp_path)["active"]


def test_actual_retention_deletes_only_old_complete_bundles(tmp_path, monkeypatch):
    store = Store(tmp_path)
    folder = generate(store)
    incident = store.load(folder.name)
    monkeypatch.setattr(
        "routewitness.storage.time.time", lambda: incident.end.timestamp() + 3 * 86400
    )
    (store.incidents / "unrelated").mkdir()
    assert store.retain(1) == 1
    assert (store.incidents / "unrelated").is_dir()


def test_disk_write_failure_keeps_checkpoint(tmp_path, monkeypatch):
    store = Store(tmp_path / "source")
    directory = generate(store)
    incident = store.load(directory.name)
    target = Store(tmp_path / "target")
    target.checkpoint(incident)

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(target, "render", fail)
    with pytest.raises(OSError):
        target.save(incident)
    assert list(target.incidents.glob(".pending-*"))
    assert not target.location(incident.id).exists()
    assert not list(target.incidents.glob(".bundle-*"))


def test_schema_rejects_naive_and_nonmonotonic_samples(tmp_path):
    store = Store(tmp_path)
    folder = generate(store)
    source = store.load(folder.name).model_dump()
    source["samples"][0]["at"] = source["samples"][0]["at"].replace(tzinfo=None)
    with pytest.raises(ValueError):
        Incident.model_validate(source)
    source = store.load(folder.name).model_dump()
    source["samples"][1]["seq"] = source["samples"][0]["seq"]
    with pytest.raises(ValueError):
        Incident.model_validate(source)


def test_cli_help_version_and_human_commands(tmp_path, capsys, monkeypatch):
    from unittest.mock import AsyncMock

    from routewitness import cli
    from routewitness.demo import demo_sample
    from routewitness.models import Network

    for flag in ["--help", "--version"]:
        with pytest.raises(SystemExit) as e:
            main([flag])
        assert e.value.code == 0
    capsys.readouterr()
    assert main(["demo", "--data-dir", str(tmp_path)]) == 0
    assert "[SIMULATED]" in capsys.readouterr().out
    incident = Store(tmp_path).listing()[0][0]
    for command in [["show", incident.id], ["incidents"], ["compare", incident.id, incident.id]]:
        assert main([*command, "--data-dir", str(tmp_path)]) == 0
        assert capsys.readouterr().out
    discovery = type("Discovery", (), {"snapshot": AsyncMock(return_value=Network())})()
    monkeypatch.setattr(cli, "platform_provider", lambda: discovery)
    assert main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == "0.1.0"

    class Provider:
        def __init__(self, config):
            pass

        async def sample(self, seq, at, elapsed):
            return demo_sample(seq, at, elapsed)

    monkeypatch.setattr(cli, "RealProvider", Provider)
    assert main(["diagnose", "--json", "--family", "4", "--target", "github.com"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "diagnosis"
    monkeypatch.setattr(cli, "watch", AsyncMock(return_value=[]))
    assert main(["watch", "--interval", "2", "--no-paths", "--data-dir", str(tmp_path)]) == 0
    monkeypatch.setattr(cli.webbrowser, "open", lambda _: False)
    assert main(["report", incident.id, "--data-dir", str(tmp_path), "--open"]) == 0
    assert "Could not launch" in capsys.readouterr().err


def test_checkpoint_recovery_rebuilds_canonical_diagnosis(tmp_path):
    from test_engine import sample

    from routewitness.recorder import Capture

    capture = Capture(Config())
    for t in range(25):
        capture.push(sample(t, "upstream" if t >= 20 else "healthy"))
    assert capture.active is not None
    assert capture.active.diagnosis.domain == "insufficient-evidence"
    store = Store(tmp_path)
    store.checkpoint(capture.active)
    with WatchLock(tmp_path):
        paths = store.recover_checkpoints()
    recovered = store.load(paths[0].name)
    assert recovered.status == "interrupted"
    assert recovered.end == recovered.samples[-1].at
    assert recovered.duration_s == 4
    assert recovered.diagnosis.domain == "upstream-or-isp"
    assert sanitize(recovered).diagnosis.domain == recovered.diagnosis.domain


def test_checkpoint_keeps_already_observed_recovery(tmp_path):
    source = Store(tmp_path / "source")
    incident = source.load(generate(source).name)
    target = Store(tmp_path / "target")
    target.checkpoint(incident)
    with WatchLock(target.root):
        paths = target.recover_checkpoints()
    restored = target.load(paths[0].name)
    assert restored.status == "recovered"
    assert restored.end == incident.end
    assert restored.duration_s == incident.duration_s
    assert restored.diagnosis == incident.diagnosis


def test_unavailable_process_metadata_does_not_stop_watcher(tmp_path, monkeypatch):
    import psutil

    import routewitness.storage as storage

    def unavailable(*args, **kwargs):
        raise psutil.AccessDenied()

    monkeypatch.setattr(storage.psutil, "Process", unavailable)
    with WatchLock(tmp_path) as lock:
        lock.heartbeat("healthy", None, 2)
        current = status(tmp_path)
        assert current["active"] is True
        assert current["process_verified"] is False
        assert current["capability_gaps"]
    assert status(tmp_path)["active"] is False


def test_unlocked_stale_heartbeat_is_not_an_active_watcher(tmp_path):
    with WatchLock(tmp_path) as lock:
        lock.heartbeat("healthy", None, 2)
        saved = (tmp_path / "status.json").read_text()
    atomic_text(tmp_path / "status.json", saved)
    assert status(tmp_path)["active"] is False


def test_path_baseline_waits_for_network_discovery(tmp_path):
    class DiscoveryAwareProvider(DemoProvider):
        discovered = False
        phases = []

        async def sample(self, seq, at, elapsed):
            await asyncio.sleep(0)
            self.discovered = True
            return await super().sample(seq, at, elapsed)

        async def path(self, phase):
            assert self.discovered, "baseline must know the active address family"
            self.phases.append(phase)
            return await super().path(phase)

    provider = DiscoveryAwareProvider()
    asyncio.run(
        watch(
            Config(),
            provider,
            Store(tmp_path),
            clock=FakeClock(),
            rounds=70,
            simulated=True,
            emit=lambda _: None,
        )
    )
    assert provider.phases[0] == "baseline"


def test_cancelled_path_is_an_explicit_capability_gap(tmp_path):
    class SlowPathProvider(DemoProvider):
        async def path(self, phase):
            await asyncio.Event().wait()

    store = Store(tmp_path)
    asyncio.run(
        watch(
            Config(),
            SlowPathProvider(),
            store,
            clock=FakeClock(),
            rounds=30,
            simulated=True,
            emit=lambda _: None,
        )
    )
    incident = store.listing()[0][0]
    assert incident.status == "interrupted"
    assert any("Path" in warning and "cancel" in warning for warning in incident.warnings)
