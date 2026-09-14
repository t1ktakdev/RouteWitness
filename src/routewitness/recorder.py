"""Bounded flight recorder; pure capture lifecycle with injected time/probes."""

import asyncio
import time
import uuid
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol

from routewitness.config import Config
from routewitness.engine import Detector, classify, recovery_observed
from routewitness.models import Event, Incident, PathObservation, Sample
from routewitness.storage import Store, WatchLock

Phase = Literal["baseline", "start", "during", "recovery"]


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def utcnow(self) -> datetime: ...
    async def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def utcnow(self) -> datetime:
        return datetime.now(UTC)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class FakeClock:
    def __init__(self) -> None:
        self.elapsed = 0.0
        self.origin = datetime(2026, 9, 13, 21, 43, tzinfo=UTC)

    def monotonic(self) -> float:
        return self.elapsed

    def utcnow(self) -> datetime:
        return self.origin + timedelta(seconds=self.elapsed)

    async def sleep(self, seconds: float) -> None:
        self.elapsed += seconds
        await asyncio.sleep(0)


class ProbeProvider(Protocol):
    async def sample(self, seq: int, at: datetime, elapsed: float) -> Sample: ...
    async def path(self, phase: Phase) -> PathObservation: ...


class Capture:
    def __init__(self, config: Config, simulated: bool = False) -> None:
        self.config = config
        self.simulated = simulated
        self.detector = Detector(config)
        self.pre: deque[Sample] = deque(maxlen=config.pre_limit)
        self.active: Incident | None = None
        self.previous: Sample | None = None
        self.recovery: Sample | None = None
        self.onset_elapsed = 0.0
        self.continuation: str | None = None

    def begin(self, sample: Sample, onset: float) -> Incident:
        first = next((s for s in self.pre if s.elapsed >= onset), sample)
        incident = Incident(
            id=sample.at.strftime("%Y%m%dT%H%M%SZ-")
            + (f"{sample.seq:08x}" if self.simulated else uuid.uuid4().hex[:8]),
            start=first.at,
            detected=sample.at,
            status="recording",
            samples=list(self.pre)[-min(self.config.pre_limit, self.config.segment_samples // 2) :],
            previous_id=self.continuation,
            simulated=self.simulated,
        )
        self.onset_elapsed = first.elapsed
        self.active = incident
        self.continuation = None
        self.recovery = None
        return incident

    def finish(
        self, state: Literal["recovered", "interrupted", "continued"], end: Sample | None = None
    ) -> Incident:
        assert self.active is not None
        result = self.active
        last = end or result.samples[-1]
        result.end = max(result.start, last.at)
        result.duration_s = max(0, last.elapsed - self.onset_elapsed)
        result.status = state
        if state != "recovered":
            result.warnings.append(
                "Recovery not established; recording interrupted or segment limit reached."
            )
        result.diagnosis = classify(
            [s for s in result.samples if self.onset_elapsed <= s.elapsed <= last.elapsed]
        )
        result.capability_gaps = sorted({g for s in result.samples for g in s.network.gaps})[:64]
        self.active = None
        self.recovery = None
        if state == "continued":
            self.continuation = result.id
        else:
            self.detector.window.clear()
            self.detector.consecutive = 0
        return result

    def push(self, sample: Sample) -> tuple[Incident | None, list[Incident]]:
        finished: list[Incident] = []
        started = None
        old = self.previous
        if old:
            elapsed_gap = sample.elapsed - old.elapsed
            wall_gap = (sample.at - old.at).total_seconds()
            if elapsed_gap <= 0:
                raise ValueError("monotonic clock did not advance")
            if (
                wall_gap < 0
                or elapsed_gap > max(10, 5 * self.config.interval)
                or abs(wall_gap - elapsed_gap) > max(10, 5 * self.config.interval)
            ):
                if self.active:
                    finished.append(self.finish("interrupted"))
                self.detector.reset()
                self.pre.clear()
                self.continuation = None
                sample.events.append(
                    Event(
                        kind="sampling-gap",
                        detail="Clock/resume gap; no evidence for the missing interval.",
                    )
                )
                old = None
            if old and old.network.identity() != sample.network.identity():
                a, b = old.network, sample.network
                kind = (
                    "system-network-change"
                    if (a.interface, a.is_up, a.addresses, a.resolvers)
                    != (b.interface, b.is_up, b.addresses, b.resolvers)
                    else "route-change"
                )
                sample.events.append(
                    Event(kind=kind, detail="Observed local network configuration transition.")
                )
        self.previous = sample
        self.pre.append(sample)
        while self.pre and sample.elapsed - self.pre[0].elapsed > self.config.pre_seconds:
            self.pre.popleft()
        trigger, onset = self.detector.observe(sample, self.active is not None)
        if self.active is None and (trigger or self.continuation):
            started = self.begin(sample, sample.elapsed if self.continuation else onset)
        elif self.active:
            self.active.samples.append(sample)
        if self.active:
            self.active.duration_s = max(0, sample.elapsed - self.onset_elapsed)
            if recovery_observed(sample):
                self.recovery = self.recovery or sample
                if sample.elapsed - self.recovery.elapsed >= self.config.recovery_seconds:
                    finished.append(self.finish("recovered", self.recovery))
            else:
                self.recovery = None
            if self.active and len(self.active.samples) >= self.config.segment_samples:
                finished.append(self.finish("continued"))
        return started, finished

    def stop(self) -> Incident | None:
        return self.finish("interrupted") if self.active else None


async def watch(
    config: Config,
    provider: ProbeProvider,
    store: Store,
    *,
    clock: Clock | None = None,
    live: bool = False,
    rounds: int | None = None,
    simulated: bool = False,
    emit: Callable[[str], None] = print,
) -> list[Path]:
    """Foreground loop. Returns only a bounded list of the most recent saved paths."""
    clock = clock or SystemClock()
    capture = Capture(config, simulated)
    origin = clock.monotonic()
    saved: deque[Path] = deque(maxlen=32)
    jobs: list[tuple[asyncio.Task[PathObservation], Incident | None]] = []
    pending: list[Incident] = []
    baseline: PathObservation | None = None
    last_path = float("-inf")
    last_checkpoint = float("-inf")
    seq = 0

    def request_path(phase: Phase, owner: Incident | None) -> None:
        if config.paths and len(jobs) < 3:
            jobs.append((asyncio.create_task(provider.path(phase)), owner))
        elif owner and config.paths:
            owner.warnings.append("Path request skipped: bounded diagnostic concurrency reached.")

    def save_ready(force: bool = False) -> None:
        nonlocal baseline
        remaining = []
        for job, owner in jobs:
            if job.done():
                if job.cancelled() and owner:
                    owner.warnings = [
                        *owner.warnings,
                        "Path collection cancelled; path evidence is incomplete.",
                    ][-64:]
                if not job.cancelled():
                    try:
                        path = job.result()
                        if owner and len(owner.paths) < 32:
                            owner.paths.append(path)
                        elif owner is None:
                            baseline = path
                    except (OSError, ValueError):
                        if owner:
                            owner.warnings.append("Path probe unavailable.")
            else:
                remaining.append((job, owner))
        jobs[:] = remaining
        for incident in list(pending):
            if force or not any(owner is incident for _, owner in jobs):
                bundle_path = store.save(incident)
                saved.append(bundle_path)
                pending.remove(incident)
                emit(
                    f"{incident.end.strftime('%H:%M:%S') if incident.end else '--:--:--'}  "
                    f"{incident.status} · {incident.duration_s:.1f}s · {incident.diagnosis.domain}\n"
                    f"           report: {bundle_path / 'report.html'}"
                )

    with WatchLock(store.root) as lock:
        lock.heartbeat("starting", None, 0)
        store.recover_checkpoints()
        store.retain(config.retention_days)
        emit(
            "RouteWitness 0.1.0\nWatching network health.\n"
            f"Interval: {config.interval:g}s (incident: {config.incident_interval:g}s)\nPress Ctrl+C to stop."
        )
        try:
            while rounds is None or seq < rounds:
                elapsed = clock.monotonic() - origin
                at = clock.utcnow()
                sample = await provider.sample(seq, at, elapsed)
                if seq == 0:
                    request_path("baseline", None)
                    emit(
                        f"Gateway: {', '.join(sample.network.gateways) or 'unknown (partial evidence)'}"
                    )
                started, finished = capture.push(sample)
                if started:
                    if baseline:
                        started.paths.append(baseline)
                    request_path("start", started)
                    last_path = elapsed
                    emit(f"{at.strftime('%H:%M:%S')}  incident started · {started.id}")
                if capture.active and elapsed - last_path >= config.path_interval:
                    request_path("during", capture.active)
                    last_path = elapsed
                for incident in finished:
                    store.checkpoint(incident)
                    if incident.status == "recovered":
                        request_path("recovery", incident)
                    pending.append(incident)
                save_ready()
                # Path timeout bounds pending work; cap additionally for deliberately tiny test intervals.
                if len(pending) > 4:
                    oldest = pending[0]
                    for task, owner in jobs:
                        if owner is oldest:
                            task.cancel()
                    await asyncio.gather(
                        *(task for task, owner in jobs if owner is oldest), return_exceptions=True
                    )
                    oldest.warnings.append("Path collection ended at pending bundle limit.")
                    save_ready()
                if capture.active and elapsed - last_checkpoint >= 5:
                    store.checkpoint(capture.active)
                    last_checkpoint = elapsed
                health = (
                    "degraded"
                    if sample.symptoms
                    else "healthy"
                    if recovery_observed(sample)
                    else "unknown"
                )
                lock.heartbeat(health, capture.active.id if capture.active else None, seq)
                if live:
                    emit(
                        f"{at.strftime('%H:%M:%S')}  {health} · "
                        + (", ".join(sample.symptoms) or "no corroborated failure")
                    )
                seq += 1
                interval = config.incident_interval if capture.active else config.interval
                await clock.sleep(max(0.01, interval - (clock.monotonic() - origin - elapsed)))
        finally:
            interrupted = capture.stop()
            if interrupted:
                store.checkpoint(interrupted)
                pending.append(interrupted)
            # Cancellation never leaves orphaned diagnostic processes.
            for job, _ in jobs:
                if not job.done():
                    job.cancel()
            if jobs:
                await asyncio.gather(*(job for job, _ in jobs), return_exceptions=True)
            save_ready(force=True)
    return list(saved)
