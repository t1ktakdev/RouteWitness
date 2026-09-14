"""Bounded process execution and portable link/address inventory."""

import asyncio
import os
import socket
from dataclasses import dataclass

import psutil

from routewitness.models import Network


@dataclass(frozen=True)
class Command:
    code: int | None
    output: str
    gap: str = ""


async def run(argv: list[str], timeout: float = 3, limit: int = 65536) -> Command:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            limit=limit + 1,
        )
    except (OSError, NotImplementedError):
        return Command(None, "", "command unavailable or not permitted")
    assert proc.stdout is not None
    stdout = proc.stdout

    async def collect() -> bytes:
        # read(n) can return early, so accumulate explicitly, with a strict cap.
        output = bytearray()
        while chunk := await stdout.read(min(4096, limit + 1 - len(output))):
            output.extend(chunk)
            if len(output) > limit:
                raise ValueError("output limit")
        await proc.wait()
        return bytes(output)

    try:
        raw = await asyncio.wait_for(collect(), timeout)
        return Command(proc.returncode, raw.decode("utf-8-sig", errors="replace"))
    except TimeoutError:
        return Command(None, "", "command timeout")
    except ValueError:
        return Command(None, "", "command output exceeded limit")
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            # Drain the killed child pipe: wait() alone can deadlock at StreamReader high-water.
            while await stdout.read(4096):
                pass
            await proc.wait()


def link(
    interface: str | None,
    gateways: list[str],
    routes: list[str],
    resolvers: list[str],
    gaps: list[str],
) -> Network:
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except (OSError, psutil.Error):
        return Network(
            gateways=gateways,
            routes=routes,
            resolvers=resolvers,
            gaps=[*gaps, "Interface API unavailable."],
        )
    ips = [
        a.address
        for a in addresses.get(interface or "", [])
        if a.family in {socket.AF_INET, socket.AF_INET6}
    ]
    return Network(
        interface=interface,
        is_up=stats[interface].isup if interface in stats else None,
        addresses=ips[:64],
        gateways=gateways[:16],
        routes=routes[:64],
        resolvers=resolvers[:32],
        gaps=gaps,
    )


def resolver_addresses() -> list[str]:
    # dnspython reads only OS resolver configuration; no environment/filesystem scan.
    import dns.resolver

    try:
        return [str(n) for n in dns.resolver.Resolver().nameservers][:32]
    except (OSError, dns.resolver.NoResolverConfiguration):
        return []
