"""BSD route fallback with numeric addresses and forced C locale.

No human interface descriptions, SSIDs or MACs are parsed. The BSD route command
is a bounded fallback; a failed/missing field is an explicit capability gap.
"""

import asyncio
import ipaddress

from routewitness.models import Network
from routewitness.platform.base import link, resolver_addresses, run


def parse_route(text: str) -> tuple[str | None, str | None]:
    fields = dict(line.strip().split(":", 1) for line in text.splitlines() if ":" in line)
    interface = fields.get("interface", "").strip() or None
    gateway = fields.get("gateway", "").strip() or None
    if gateway:
        try:
            ipaddress.ip_address(gateway.split("%")[0])
        except ValueError:
            gateway = None
    return interface, gateway


class Platform:
    async def snapshot(self) -> Network:
        results = await asyncio.gather(
            run(["/sbin/route", "-n", "get", "default"]),
            run(["/sbin/route", "-n", "get", "-inet6", "default"]),
        )
        interface = None
        gateways, routes = [], []
        gaps = [
            "macOS split-VPN routes and scoped DNS policies are not fully enumerated.",
            "Wi-Fi signal not collected; no reliable unprivileged provider configured.",
        ]
        for family, result in zip((4, 6), results, strict=True):
            if result.code != 0:
                continue
            dev, gateway = parse_route(result.output)
            interface = interface or dev
            if gateway:
                gateways.append(gateway)
            if dev:
                routes.append(f"IPv{family} default via {gateway or 'unknown'} dev {dev}")
        if not interface:
            gaps.append("Default route unavailable from BSD route fallback.")
        return link(interface, gateways, routes, resolver_addresses(), gaps)
