"""iproute2 JSON routes; no translated terminal tables."""

import asyncio
import ipaddress
import json
from pathlib import Path
from typing import Any

from routewitness.models import Network
from routewitness.platform.base import link, resolver_addresses, run


def parse_routes(text: str) -> tuple[str | None, list[str], list[str]]:
    data: list[dict[str, Any]] = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("route JSON must be an array")
    defaults = [
        r
        for r in data
        if r.get("dst") in {"default", "0.0.0.0/0", "::/0"}
        and r.get("type", "unicast") == "unicast"
    ]
    defaults.sort(key=lambda r: int(r.get("metric", 0)))
    gateways, routes = [], []
    for r in data:
        destination = str(r.get("dst", "default"))
        device = str(r.get("dev", ""))
        via = str(r.get("gateway", ""))
        if via:
            ipaddress.ip_address(via.split("%")[0])
        # Include /1 split VPN routes, but no LAN inventory or neighbour table.
        if destination in {
            "default",
            "0.0.0.0/0",
            "::/0",
            "0.0.0.0/1",
            "128.0.0.0/1",
            "::/1",
            "8000::/1",
        }:
            routes.append(f"{destination} via {via} dev {device} metric {r.get('metric', 0)}")
            if via and via not in gateways:
                scoped = (
                    f"{via}%{device}"
                    if ":" in via and ipaddress.ip_address(via).is_link_local
                    else via
                )
                gateways.append(scoped)
    return (
        str(defaults[0].get("dev")) if defaults and defaults[0].get("dev") else None,
        gateways,
        routes,
    )


class Platform:
    async def snapshot(self) -> Network:
        results = await asyncio.gather(
            run(["ip", "-j", "-4", "route", "show"]), run(["ip", "-j", "-6", "route", "show"])
        )
        interface = None
        gateways: list[str] = []
        routes: list[str] = []
        gaps = ["Wi-Fi signal not collected; no reliable unprivileged provider configured."]
        for result in results:
            if result.code != 0:
                gaps.append("Route discovery unavailable: iproute2 JSON required.")
                continue
            try:
                dev, via, entries = parse_routes(result.output)
                interface = interface or dev
                gateways.extend(via)
                routes.extend(entries)
            except (ValueError, TypeError, KeyError, AttributeError):
                gaps.append("Invalid route response; default gateway is unknown.")
        snapshot = link(interface, gateways, routes, resolver_addresses(), sorted(set(gaps)))
        if interface and Path("/sys/class/net", interface, "wireless").is_dir():
            snapshot.kind = "wifi"
        return snapshot
