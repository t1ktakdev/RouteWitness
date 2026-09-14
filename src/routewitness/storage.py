"""Atomic bundles, checkpoints, validation, retention, and process-held lock."""

import errno
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO

import psutil

from routewitness.engine import classify
from routewitness.models import Incident
from routewitness.reports import html_report, markdown, sanitize, timeline_csv

ID = re.compile(r"\d{8}T\d{6}Z-[a-f0-9]{8}")
MAX_BYTES = 32 * 1024 * 1024


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("storage directory must not be a symbolic link")


def atomic_text(path: Path, text: str) -> None:
    private_dir(path.parent)
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Store:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.incidents = root / "incidents"

    def location(self, incident_id: str) -> Path:
        if not ID.fullmatch(incident_id):
            raise ValueError("invalid incident ID")
        path = self.incidents / incident_id
        if self.incidents.is_symlink() or path.is_symlink():
            raise ValueError("incident path must not be a symbolic link")
        return path

    def load(self, incident_id: str) -> Incident:
        path = self.location(incident_id) / "incident.json"
        return self.read(path, incident_id)

    @staticmethod
    def read(path: Path, expected: str | None = None) -> Incident:
        if path.is_symlink() or path.stat().st_size > MAX_BYTES:
            raise ValueError("unsafe or oversized evidence file")
        result = Incident.model_validate_json(path.read_bytes())
        if expected and result.id != expected:
            raise ValueError("incident ID does not match its directory")
        return result

    def listing(self) -> tuple[list[Incident], list[str]]:
        result: list[Incident] = []
        errors: list[str] = []
        if not self.incidents.exists():
            return result, errors
        for path in sorted(self.incidents.iterdir(), reverse=True):
            if ID.fullmatch(path.name):
                try:
                    result.append(self.load(path.name))
                except (ValueError, OSError):
                    errors.append(f"Skipped corrupt/incomplete incident {path.name}")
        return result, errors

    def checkpoint(self, incident: Incident) -> None:
        atomic_text(self.incidents / f".pending-{incident.id}.json", incident.model_dump_json())

    def save(self, incident: Incident) -> Path:
        target = self.location(incident.id)
        private_dir(self.incidents)
        if target.exists():
            raise FileExistsError("incident already exists; refusing overwrite")
        temporary = Path(tempfile.mkdtemp(prefix=".bundle-", dir=self.incidents))
        try:
            atomic_text(temporary / "incident.json", incident.model_dump_json(indent=2))
            self.render(incident, temporary)
            os.rename(temporary, target)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        (self.incidents / f".pending-{incident.id}.json").unlink(missing_ok=True)
        return target

    @staticmethod
    def render(incident: Incident, directory: Path) -> None:
        safe = sanitize(incident)
        atomic_text(directory / "shareable.json", safe.model_dump_json(indent=2))
        atomic_text(directory / "timeline.csv", timeline_csv(safe))
        atomic_text(directory / "report.md", markdown(safe))
        atomic_text(directory / "report.html", html_report(safe))
        names = ["incident.json", "shareable.json", "timeline.csv", "report.md", "report.html"]
        manifest = "".join(
            f"{hashlib.sha256((directory / n).read_bytes()).hexdigest()}  {n}\n" for n in names
        )
        atomic_text(directory / "SHA256SUMS", manifest)

    def recover_checkpoints(self) -> list[Path]:
        """Call only while holding WatchLock; never pretend a crash was recovery."""
        recovered: list[Path] = []
        if not self.incidents.exists():
            return recovered
        for path in sorted(self.incidents.glob(".pending-*.json")):
            incident_id = path.name.removeprefix(".pending-").removesuffix(".json")
            if not ID.fullmatch(incident_id):
                continue
            incident = self.read(path, incident_id)
            if self.location(incident_id).exists():
                path.unlink()
                continue
            if incident.status == "recording":
                incident.end = max(incident.start, incident.samples[-1].at)
                incident.status = "interrupted"
                incident.diagnosis = classify(
                    [
                        sample
                        for sample in incident.samples
                        if incident.start <= sample.at <= incident.end
                    ]
                )
                incident.capability_gaps = sorted(
                    {gap for sample in incident.samples for gap in sample.network.gaps}
                )[:64]
                incident.warnings = [
                    *incident.warnings,
                    "Recovered incomplete checkpoint; end is last observation, not recovery.",
                ][-64:]
            # A finalized checkpoint can await a path task when the process exits.
            # Its observed recovery/continuation must not be relabeled as a crash.
            recovered.append(self.save(incident))
        return recovered

    def retain(self, days: int | None) -> int:
        if days is None or not self.incidents.exists():
            return 0
        cutoff = time.time() - days * 86400
        removed = 0
        for path in self.incidents.iterdir():
            if not ID.fullmatch(path.name) or path.is_symlink():
                continue
            try:
                incident = self.load(path.name)
                if (
                    incident.end
                    and incident.end.timestamp() < cutoff
                    and incident.status in {"recovered", "diagnosis"}
                ):
                    # Never traverse a user-added symlink when cleaning a managed bundle.
                    if any(p.is_symlink() for p in path.rglob("*")):
                        continue
                    shutil.rmtree(path)
                    removed += 1
            except (ValueError, OSError):
                continue
        return removed


class WatchLock:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.stream: BinaryIO | None = None
        self.process_created: float | None = None

    def __enter__(self) -> "WatchLock":
        private_dir(self.root)
        path = self.root / "watch.lock"
        if path.is_symlink():
            raise ValueError("watch lock must not be a symbolic link")
        self.stream = path.open("a+b")
        self.stream.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt

                if path.stat().st_size == 0:
                    self.stream.write(b"0")
                    self.stream.flush()
                    self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            self.stream = None
            raise RuntimeError("a watcher already holds this data directory") from exc
        try:
            self.process_created = psutil.Process().create_time()
        except (OSError, psutil.Error):
            # Process metadata can be hidden even from the current process.
            # The held OS lock still establishes a single watcher.
            self.process_created = None
        return self

    def heartbeat(self, health: str, incident_id: str | None, sequence: int) -> None:
        atomic_text(
            self.root / "status.json",
            json.dumps(
                {
                    "pid": os.getpid(),
                    "process_created": self.process_created,
                    "capability_gaps": []
                    if self.process_created is not None
                    else ["Process creation time unavailable; status uses the held watcher lock."],
                    "heartbeat": time.time(),
                    "health": health,
                    "incident_id": incident_id,
                    "sequence": sequence,
                }
            ),
        )

    def __exit__(self, *_args: object) -> None:
        if self.stream:
            try:
                (self.root / "status.json").unlink(missing_ok=True)
            finally:
                self.stream.close()
                self.stream = None


def lock_held(root: Path) -> bool | None:
    """Inspect an existing lock without creating a watcher or deleting its status."""
    path = root / "watch.lock"
    if path.is_symlink():
        return None
    try:
        with path.open("r+b") as stream:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(stream, fcntl.LOCK_UN)
                return False
            except OSError as exc:
                return True if exc.errno in {errno.EACCES, errno.EAGAIN} else None
    except FileNotFoundError:
        return False
    except OSError:
        return None


def status(root: Path) -> dict[str, Any]:
    path = root / "status.json"
    if not path.exists():
        return {"active": False, "health": "not watching"}
    try:
        if path.is_symlink() or path.stat().st_size > 8192:
            raise ValueError("invalid status")
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        active = lock_held(root)
        verified = False
        if data.get("process_created") is not None:
            try:
                proc = psutil.Process(int(data["pid"]))
                verified = abs(proc.create_time() - float(data["process_created"])) < 0.01
            except (OSError, psutil.Error):
                pass
        age = time.time() - float(data["heartbeat"])
        return {
            **data,
            "active": active,
            "process_verified": verified,
            "stale": age > 30 or age < 0,
            "health": data["health"] if active and 0 <= age <= 30 else "unknown/stale",
        }
    except (ValueError, OSError, KeyError, TypeError):
        return {"active": None, "health": "unreadable status; watcher state unknown"}
