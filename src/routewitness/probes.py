"""Low-volume, timeout-bounded probes. Never capture application bodies."""

import asyncio
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from datetime import UTC, datetime
from typing import Literal

import dns.asyncresolver
import dns.exception
import dns.resolver

from routewitness.config import Config
from routewitness.models import Network, PathObservation, Probe, Sample
from routewitness.platform import Discovery, provider
from routewitness.platform.base import run

SYSTEM_DNS = """
import json,socket,sys
try:
 r=socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)
 print(json.dumps({'addresses':sorted(set(x[4][0] for x in r))[:16]}))
except socket.gaierror:
 print(json.dumps({'error':'resolution-failed'}))
"""


async def system_dns(host: str, timeout: float) -> tuple[Probe, list[str]]:
    start = time.monotonic()
    result = await run([sys.executable, "-I", "-c", SYSTEM_DNS, host], timeout, 8192)
    addresses: list[str] = []
    state: Literal["ok", "fail", "unknown"] = "unknown"
    detail = result.gap
    if result.code == 0:
        try:
            data = json.loads(result.output)
            addresses = [str(ipaddress.ip_address(a)) for a in data.get("addresses", [])][:16]
            state = "ok" if addresses else "fail"
            detail = "" if addresses else "system-resolution-failed"
        except (ValueError, TypeError):
            detail = "invalid system resolver response"
    elif result.gap == "command timeout":
        state, detail = "fail", "system-resolution-timeout"
    return Probe(
        layer="dns-system",
        target=host,
        method="getaddrinfo",
        state=state,
        latency_ms=(time.monotonic() - start) * 1000,
        detail=detail,
    ), addresses


async def direct_dns(host: str, family: Literal[4, 6], timeout: float) -> Probe:
    start = time.monotonic()
    state: Literal["ok", "fail", "unknown"] = "unknown"
    detail = ""
    try:
        resolver = dns.asyncresolver.Resolver()
        answer = await resolver.resolve(
            host, "A" if family == 4 else "AAAA", lifetime=timeout, search=False
        )
        state = "ok" if answer.rrset else "fail"
    except (dns.resolver.NoResolverConfiguration, PermissionError):
        detail = "configured DNS resolver unavailable"
    except (dns.exception.DNSException, OSError):
        state, detail = "fail", "DNS query failed or timed out"
    return Probe(
        layer="dns-query",
        target=host,
        method="dns-A" if family == 4 else "dns-AAAA",
        family=family,
        state=state,
        latency_ms=(time.monotonic() - start) * 1000,
        detail=detail,
    )


async def tcp(ip: str, port: int, operator: str, timeout: float) -> Probe:
    family: Literal[4, 6] = 6 if ":" in ip else 4
    start = time.monotonic()
    state: Literal["ok", "fail", "unknown"] = "fail"
    detail = ""
    sock = socket.socket(socket.AF_INET6 if family == 6 else socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, (ip, port)), timeout)
        state = "ok"
    except PermissionError:
        state, detail = "unknown", "socket access denied"
    except (OSError, TimeoutError):
        detail = "TCP connect failed or timed out"
    finally:
        sock.close()
    return Probe(
        layer="internet",
        target=ip,
        operator=operator,
        family=family,
        method=f"tcp/{port}",
        state=state,
        latency_ms=(time.monotonic() - start) * 1000 if state == "ok" else None,
        detail=detail,
    )


async def gateway(ip: str, timeout: float) -> Probe:
    address = ipaddress.ip_address(ip.split("%")[0])
    family: Literal[4, 6] = 6 if address.version == 6 else 4
    start = time.monotonic()
    if sys.platform == "win32":
        # Only a validated numeric address is included in this fixed script.
        if "%" in ip and not ip.split("%", 1)[1].isdigit():
            return Probe(
                layer="gateway",
                target=ip,
                method="icmp",
                state="unknown",
                detail="invalid Windows IPv6 scope",
            )
        script = (
            "$ErrorActionPreference='Stop'; $p=[System.Net.NetworkInformation.Ping]::new();"
            f"try {{$r=$p.Send('{ip}',{int(timeout * 1000)});"
            "@{status=[int]$r.Status;ms=$r.RoundtripTime}|ConvertTo-Json -Compress}"
            "finally {$p.Dispose()}"
        )
        result = await run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            timeout + 2,
            2048,
        )
        try:
            data = json.loads(result.output)
            return Probe(
                layer="gateway",
                target=ip,
                method="icmp",
                family=family,
                state="ok" if data["status"] == 0 else "fail",
                latency_ms=float(data["ms"]) if data["status"] == 0 else None,
            )
        except (ValueError, KeyError, TypeError):
            return Probe(
                layer="gateway",
                target=ip,
                method="icmp",
                state="unknown",
                family=family,
                detail="Windows ICMP API unavailable",
            )
    argv = (
        ["ping6" if family == 6 else "ping", "-n", "-c", "1", "-W", str(int(timeout * 1000)), ip]
        if sys.platform == "darwin"
        else ["ping", f"-{family}", "-n", "-c", "1", "-W", str(timeout), ip]
    )
    result = await run(argv, timeout + 0.3, 4096)
    state: Literal["ok", "fail", "unknown"] = "unknown"
    latency = None
    if result.code == 0:
        state = "ok"
        match = re.search(r"time[=<]([\d.]+)\s*ms", result.output)
        latency = float(match[1]) if match else None
    elif result.code == 1 or result.gap == "command timeout":
        state = "fail"
    # No elapsed subprocess launch time is misrepresented as ICMP RTT.
    _ = start
    return Probe(
        layer="gateway",
        target=ip,
        method="icmp",
        family=family,
        state=state,
        latency_ms=latency,
        detail=""
        if state == "ok"
        else "ICMP unanswered"
        if state == "fail"
        else "ICMP unavailable or not permitted",
    )


async def https(host: str, addresses: list[str], timeout: float) -> Probe:
    if not addresses:
        return Probe(
            layer="service",
            target=host,
            method="https-head",
            state="fail",
            stage="dns",
            detail="No system-resolved address available",
        )
    start = time.monotonic()
    # One address from each family: partial family failure must not hide a usable service.
    selected: list[str] = []
    for version in (6, 4):
        selected += next(([a] for a in addresses if ipaddress.ip_address(a).version == version), [])

    async def attempt(ip: str) -> Probe:
        stage = "tcp"
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(timeout):
                reader, writer = await asyncio.open_connection(ip, 443, limit=8192)
                stage = "tls"
                await writer.start_tls(
                    ssl.create_default_context(),
                    server_hostname=host,
                    ssl_handshake_timeout=timeout,
                )
                stage = "http"
                writer.write(
                    f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: RouteWitness/0.1.0\r\nConnection: close\r\n\r\n".encode(
                        "ascii"
                    )
                )
                await writer.drain()
                line = await reader.readline()
                match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})[^\r\n]*\r?\n", line)
                if not match:
                    raise ValueError("invalid HTTP status")
                code = int(match[1])
                return Probe(
                    layer="service",
                    target=host,
                    method="https-head",
                    stage=stage,
                    family=6 if ":" in ip else 4,
                    state="ok" if 200 <= code < 400 else "fail",
                    detail=f"HTTP {code}",
                    latency_ms=(time.monotonic() - start) * 1000,
                )
        except (OSError, TimeoutError, ValueError):
            return Probe(
                layer="service",
                target=host,
                method="https-head",
                stage=stage,
                family=6 if ":" in ip else 4,
                state="fail",
                detail=f"{stage} failed or timed out",
            )
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 0.2)
                except (OSError, TimeoutError):
                    pass

    results = await asyncio.gather(*(attempt(ip) for ip in selected))
    return next((r for r in results if r.state == "ok"), results[0])


def path_hops(text: str) -> list[str]:
    hops: list[str] = []
    for line in text.splitlines():
        if not re.match(r"^\s*\d+\s", line):
            continue
        found = []
        for token in line.split()[1:]:
            try:
                found.append(str(ipaddress.ip_address(token.strip("()[]"))))
            except ValueError:
                pass
        hops.append(", ".join(dict.fromkeys(found)) or "unanswered")
    return hops[:32]


async def trace(
    target: str, phase: Literal["baseline", "start", "during", "recovery"]
) -> PathObservation:
    ipaddress.ip_address(target)
    if sys.platform == "win32":
        argv = ["tracert.exe", "-d", "-h", "12", "-w", "500", target]
    else:
        argv = ["traceroute", "-n", "-m", "12", "-q", "1", "-w", "0.5", target]
        if ":" in target:
            argv = (
                ["traceroute6", *argv[1:]]
                if sys.platform == "darwin"
                else [*argv[:1], "-6", *argv[1:]]
            )
    result = await run(argv, 20, 16384)
    hops = path_hops(result.output)
    return PathObservation(
        phase=phase,
        at=datetime.now(UTC),
        target=target,
        state="ok" if hops else "unknown",
        hops=hops,
        detail="Hop silence does not prove forwarded packet loss."
        if hops
        else result.gap or "Numeric path unavailable or unsupported",
    )


class RealProvider:
    def __init__(self, config: Config, discovery: Discovery | None = None) -> None:
        self.config = config
        self.discovery = discovery or provider()
        self.network: Network | None = None
        self.next_discovery = 0.0

    async def sample(self, seq: int, at: datetime, elapsed: float) -> Sample:
        if self.network is None or elapsed >= self.next_discovery:
            self.network = await self.discovery.snapshot()
            self.next_discovery = elapsed + 5
        network = self.network.model_copy(deep=True)
        cfg = self.config
        families: list[Literal[4, 6]] = []
        for version in (4, 6):
            if cfg.family in {str(version), "both"} or (
                cfg.family == "auto"
                and any(
                    ipaddress.ip_address(a.split("%")[0]).version == version
                    and not ipaddress.ip_address(a.split("%")[0]).is_link_local
                    and not ipaddress.ip_address(a.split("%")[0]).is_loopback
                    for a in network.addresses
                )
            ):
                families.append(version)
        if not families:
            # Missing discovery must not suppress all connectivity evidence.
            families = [4, 6] if not network.addresses else [4]
            network.gaps.append("Usable address families not established; fallback probes enabled.")
        jobs = [
            tcp(e.ipv4 if f == 4 else e.ipv6, e.port, e.operator, cfg.timeout)
            for e in cfg.endpoints
            for f in families
        ]

        async def name_probes() -> list[Probe]:
            names = list(dict.fromkeys([*cfg.dns_names, *cfg.targets]))
            resolved, direct = await asyncio.gather(
                asyncio.gather(*(system_dns(n, cfg.timeout) for n in names)),
                asyncio.gather(*(direct_dns(n, families[0], cfg.timeout) for n in cfg.dns_names)),
            )

            async def service(host: str) -> Probe:
                resolution, addresses = resolved[names.index(host)]
                if resolution.state == "unknown":
                    return Probe(
                        layer="service",
                        target=host,
                        method="https-head",
                        state="unknown",
                        stage="dns",
                        detail="System resolver capability unavailable",
                    )
                return await https(host, addresses, cfg.timeout)

            services = await asyncio.gather(*(service(n) for n in cfg.targets))
            return [*(p for p, _ in resolved), *direct, *services]

        async def gateways() -> list[Probe]:
            if not network.gateways:
                return [
                    Probe(
                        layer="gateway",
                        target="unknown",
                        method="icmp",
                        state="unknown",
                        detail="No default gateway discovered",
                    )
                ]
            return list(
                await asyncio.gather(*(gateway(ip, cfg.timeout) for ip in network.gateways[:2]))
            )

        public, dns_service, local = await asyncio.gather(
            asyncio.gather(*jobs), name_probes(), gateways()
        )
        return Sample(
            seq=seq, at=at, elapsed=elapsed, network=network, probes=[*local, *public, *dns_service]
        )

    async def path(
        self, phase: Literal["baseline", "start", "during", "recovery"]
    ) -> PathObservation:
        endpoint = self.config.endpoints[0]
        v6_only = self.config.family == "6" or (
            self.network is not None
            and self.network.addresses
            and all(":" in a for a in self.network.addresses)
        )
        return await trace(endpoint.ipv6 if v6_only else endpoint.ipv4, phase)
