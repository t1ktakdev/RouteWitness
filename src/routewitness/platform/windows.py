"""Read stable PowerShell objects as JSON, not localized ipconfig/ping text."""

import ipaddress
import json
from typing import Any

from routewitness.models import Network
from routewitness.platform.base import link, run

SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$r = @(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') } | Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric)
$d = @(Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses)
[pscustomobject]@{routes=$r;dns=$d} | ConvertTo-Json -Depth 5 -Compress
"""


def parse_snapshot(text: str) -> tuple[str | None, list[str], list[str], list[str]]:
    data: dict[str, Any] = json.loads(text)
    rows = data["routes"]
    defaults = [r for r in rows if r["DestinationPrefix"] in {"0.0.0.0/0", "::/0"}]
    defaults.sort(key=lambda r: int(r.get("RouteMetric") or 0) + int(r.get("InterfaceMetric") or 0))
    interface = str(defaults[0]["InterfaceAlias"]) if defaults else None
    gateways, routes = [], []
    for row in rows:
        ip = str(row["NextHop"])
        address = ipaddress.ip_address(ip)
        if not address.is_unspecified:
            gateways.append(
                f"{ip}%{row['InterfaceIndex']}"
                if address.version == 6 and address.is_link_local
                else ip
            )
        routes.append(
            f"{row['DestinationPrefix']} via {ip} dev {row['InterfaceAlias']} "
            f"metric {row.get('RouteMetric', 0)}"
        )
    resolvers = [
        str(a)
        for d in data["dns"]
        if d["InterfaceAlias"] == interface
        for a in d["ServerAddresses"]
    ]
    return interface, list(dict.fromkeys(gateways)), routes, resolvers


class Platform:
    async def snapshot(self) -> Network:
        result = await run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", SCRIPT], 5
        )
        gaps = ["Wi-Fi type/signal not collected; SSID/BSSID deliberately omitted."]
        try:
            if result.code != 0:
                raise ValueError("unavailable")
            interface, gateways, routes, resolvers = parse_snapshot(result.output)
        except (ValueError, TypeError, KeyError):
            interface, gateways, routes, resolvers = None, [], [], []
            gaps.append("Windows route/resolver objects unavailable; PowerShell NetTCPIP required.")
        return link(interface, gateways, routes, resolvers, gaps)
