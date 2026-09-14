"""CLI-first interface. JSON is stdout-only data; failures go to stderr."""

import argparse
import asyncio
import json
import shutil
import sys
import uuid
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from routewitness import __version__
from routewitness.config import Config, config_file, data_dir, load
from routewitness.demo import generate
from routewitness.engine import classify, symptoms
from routewitness.models import Incident
from routewitness.platform import provider as platform_provider
from routewitness.probes import RealProvider
from routewitness.recorder import watch
from routewitness.reports import sanitize, terminal
from routewitness.storage import Store, status


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--data-dir", type=Path, default=argparse.SUPPRESS, help="local evidence directory"
    )
    common.add_argument(
        "--config-file",
        type=Path,
        default=argparse.SUPPRESS,
        help="explicit TOML configuration file",
    )
    root = argparse.ArgumentParser(
        prog="routewitness",
        parents=[common],
        description="Your Internet connection's black box. Local evidence; no upload.",
    )
    root.add_argument("--version", action="version", version=f"RouteWitness {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in [
        ("diagnose", "One-shot layered network diagnosis"),
        ("watch", "Record intermittent incidents"),
        ("status", "Show watcher state"),
        ("incidents", "List recorded incidents"),
        ("show", "Explain one incident"),
        ("report", "Regenerate the sanitized offline HTML report"),
        ("compare", "Compare repeated evidence patterns"),
        ("config", "Display effective configuration"),
        ("doctor", "Check RouteWitness capabilities without network probes"),
        ("demo", "Generate a deterministic offline incident (no network access)"),
    ]:
        cmd = commands.add_parser(name, help=help_text, description=help_text, parents=[common])
        if name != "watch":
            cmd.add_argument("--json", action="store_true", help="emit machine-readable JSON")
        if name in {"diagnose", "watch"}:
            cmd.add_argument(
                "--target", action="append", help="HTTPS hostname (repeat up to four times)"
            )
            cmd.add_argument("--family", choices=["auto", "4", "6", "both"])
        if name == "watch":
            cmd.add_argument("--live", action="store_true", help="print per-round health")
            cmd.add_argument("--interval", type=float, help="quiet sampling interval in seconds")
            cmd.add_argument(
                "--no-paths", action="store_true", help="disable event-driven traceroute"
            )
        if name in {"show", "report"}:
            cmd.add_argument("incident_id")
        if name == "report":
            cmd.add_argument(
                "--open", action="store_true", help="open the local report in your browser"
            )
        if name == "compare":
            cmd.add_argument("incident_a")
            cmd.add_argument("incident_b")
    return root


def output(value: object, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=True, indent=2, default=str, allow_nan=False))
    elif isinstance(value, str):
        # Neutralize terminal control sequences from captured/hostile metadata.
        print("".join(c if c in "\n\t" or c.isprintable() else "?" for c in value))
    else:
        print(json.dumps(value, ensure_ascii=True, indent=2, default=str))


async def diagnose(cfg: Config) -> Incident:
    at = datetime.now(UTC)
    s = await RealProvider(cfg).sample(0, at, 0)
    s.symptoms = symptoms(s)
    return Incident(
        id=at.strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8],
        start=at,
        detected=at,
        end=at,
        status="diagnosis",
        samples=[s],
        diagnosis=classify([s]),
        capability_gaps=s.network.gaps,
        warnings=["One-shot observation: no prehistory or sustained incident detection."],
    )


async def doctor(cfg: Config) -> dict[str, Any]:
    snapshot = await platform_provider().snapshot()
    tools = ["powershell.exe", "tracert.exe"] if sys.platform == "win32" else ["ping", "traceroute"]
    return {
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "commands": {tool: shutil.which(tool) is not None for tool in tools},
        "gateway_discovered": bool(snapshot.gateways),
        "interface_discovered": snapshot.interface is not None,
        "resolver_count": len(snapshot.resolvers),
        "capability_gaps": snapshot.gaps,
        "paths_enabled": cfg.paths,
        "notes": [
            "No network probes run by doctor. Command presence does not prove permission.",
            "TCP/DNS/service checks can work without ICMP. Normal use never requests elevation.",
        ],
    }


def execute(args: argparse.Namespace) -> int:
    store = Store(getattr(args, "data_dir", data_dir()))
    cfg = load(getattr(args, "config_file", None))
    updates: dict[str, Any] = {}
    for flag, key in (("target", "targets"), ("family", "family"), ("interval", "interval")):
        if getattr(args, flag, None) is not None:
            updates[key] = getattr(args, flag)
    if getattr(args, "no_paths", False):
        updates["paths"] = False
    cfg = Config.model_validate({**cfg.model_dump(), **updates})
    as_json = getattr(args, "json", False)
    command = args.command
    if command == "config":
        output(
            {
                "config_file": str(getattr(args, "config_file", config_file())),
                "data_dir": str(store.root),
                **cfg.model_dump(mode="json"),
            },
            as_json,
        )
    elif command == "doctor":
        output(asyncio.run(doctor(cfg)), as_json)
    elif command == "status":
        output(status(store.root), as_json)
    elif command == "diagnose":
        incident = asyncio.run(diagnose(cfg))
        output(
            incident.model_dump(mode="json") if as_json else terminal(sanitize(incident)), as_json
        )
    elif command == "watch":
        asyncio.run(
            watch(
                cfg,
                RealProvider(cfg),
                store,
                live=args.live,
                emit=lambda message: output(message, False),
            )
        )
    elif command == "incidents":
        incidents, warnings = store.listing()
        rows = [
            {
                "id": i.id,
                "start": i.start.isoformat(),
                "duration_s": i.duration_s,
                "status": i.status,
                "domain": i.diagnosis.domain,
                "simulated": i.simulated,
            }
            for i in incidents
        ]
        output(
            {"incidents": rows, "warnings": warnings}
            if as_json
            else "\n".join(
                f"{r['id']}  {r['duration_s']:.1f}s  {r['status']}  {r['domain']}"
                + ("  [SIMULATED]" if r["simulated"] else "")
                for r in rows
            )
            or "No recorded incidents.",
            as_json,
        )
        if not as_json:
            for warning in warnings:
                print(warning, file=sys.stderr)
    elif command == "show":
        incident = store.load(args.incident_id)
        output(
            incident.model_dump(mode="json") if as_json else terminal(sanitize(incident)), as_json
        )
    elif command == "report":
        incident = store.load(args.incident_id)
        directory = store.location(incident.id)
        Store.render(incident, directory)
        report = (directory / "report.html").resolve()
        output({"report": str(report), "sanitized": True} if as_json else str(report), as_json)
        if args.open:
            if not webbrowser.open(report.as_uri()):
                print("Could not launch a browser; open the printed local path.", file=sys.stderr)
    elif command == "compare":
        a, b = store.load(args.incident_a), store.load(args.incident_b)
        flags_a = {f for s in a.samples for f in s.symptoms}
        flags_b = {f for s in b.samples for f in s.symptoms}
        data = {
            "a": a.id,
            "b": b.id,
            "same_domain": a.diagnosis.domain == b.diagnosis.domain,
            "domains": [a.diagnosis.domain, b.diagnosis.domain],
            "duration_delta_s": round(b.duration_s - a.duration_s, 3),
            "repeated_symptoms": sorted(flags_a & flags_b),
            "only_a": sorted(flags_a - flags_b),
            "only_b": sorted(flags_b - flags_a),
            "note": "Similar symptoms do not establish the same physical cause.",
        }
        output(data, as_json)
    elif command == "demo":
        bundle = generate(store)
        incident = store.load(bundle.name)
        output(
            {
                "id": incident.id,
                "report": str(bundle / "report.html"),
                "simulated": True,
                "domain": incident.diagnosis.domain,
            }
            if as_json
            else terminal(sanitize(incident)) + f"\n\nReport: {bundle / 'report.html'}",
            as_json,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return execute(args)
    except KeyboardInterrupt:
        print("Watcher stopped; active evidence flushed.", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, ValidationError) as exc:
        # Pydantic errors may contain supplied secrets; do not echo input values.
        message = (
            "Invalid configuration or evidence schema."
            if isinstance(exc, ValidationError)
            else str(exc)
        )
        if getattr(args, "json", False):
            print(json.dumps({"error": message}), file=sys.stderr)
        else:
            print(f"routewitness: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
