import asyncio
import json
import socket
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import dns.resolver
import pytest

from routewitness import probes
from routewitness.config import Config
from routewitness.models import Network, Probe
from routewitness.platform import base, linux, macos, windows
from routewitness.platform.base import Command


def test_system_dns_outcomes(monkeypatch):
    for response, expected in [
        (Command(0, '{"addresses":["192.0.2.1","2001:db8::1"]}'), "ok"),
        (Command(0, '{"error":"failed"}'), "fail"),
        (Command(None, "", "command timeout"), "fail"),
        (Command(None, "", "missing"), "unknown"),
        (Command(0, "oops"), "unknown"),
    ]:
        monkeypatch.setattr(probes, "run", AsyncMock(return_value=response))
        result, addresses = asyncio.run(probes.system_dns("example.com", 1))
        assert result.state == expected
        assert bool(addresses) == (expected == "ok")


def test_direct_dns_outcomes(monkeypatch):
    class Resolver:
        async def resolve(self, *args, **kwargs):
            return SimpleNamespace(rrset=["address"])

    monkeypatch.setattr(probes.dns.asyncresolver, "Resolver", Resolver)
    assert asyncio.run(probes.direct_dns("example.com", 6, 1)).state == "ok"

    class BrokenResolver:
        async def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout()

    monkeypatch.setattr(probes.dns.asyncresolver, "Resolver", BrokenResolver)
    assert asyncio.run(probes.direct_dns("example.com", 4, 1)).state == "fail"

    def unavailable():
        raise dns.resolver.NoResolverConfiguration()

    monkeypatch.setattr(probes.dns.asyncresolver, "Resolver", unavailable)
    assert asyncio.run(probes.direct_dns("example.com", 4, 1)).state == "unknown"


@pytest.mark.parametrize(
    "platform,response,expected",
    [
        ("linux", Command(0, "64 bytes time=1.25 ms"), "ok"),
        ("linux", Command(1, ""), "fail"),
        ("linux", Command(2, ""), "unknown"),
        ("darwin", Command(0, "64 bytes time<1 ms"), "ok"),
        ("win32", Command(0, '{"status":0,"ms":2}'), "ok"),
        ("win32", Command(0, '{"status":11010,"ms":0}'), "fail"),
        ("win32", Command(1, ""), "unknown"),
    ],
)
def test_gateway_uses_os_success_semantics(monkeypatch, platform, response, expected):
    monkeypatch.setattr(probes.sys, "platform", platform)
    runner = AsyncMock(return_value=response)
    monkeypatch.setattr(probes, "run", runner)
    result = asyncio.run(probes.gateway("192.168.1.1", 1))
    assert result.state == expected
    assert isinstance(runner.call_args.args[0], list)


def test_tcp_socket_lifecycle_and_failures(monkeypatch):
    async def go(exception):
        loop = asyncio.get_running_loop()
        fn = AsyncMock(side_effect=exception)
        monkeypatch.setattr(loop, "sock_connect", fn)
        return await probes.tcp("192.0.2.1", 443, "test", 1)

    for exception, expected in [
        (None, "ok"),
        (OSError(), "fail"),
        (TimeoutError(), "fail"),
        (PermissionError(), "unknown"),
    ]:
        assert asyncio.run(go(exception)).state == expected


def test_https_success_and_stages(monkeypatch):
    class Writer:
        def __init__(self, tls_error=False):
            self.tls_error = tls_error
            self.closed = False
            self.request = b""

        async def start_tls(self, *args, **kwargs):
            if self.tls_error:
                raise OSError("certificate failed")

        def write(self, value):
            self.request = value

        async def drain(self):
            pass

        def close(self):
            self.closed = True

        async def wait_closed(self):
            pass

    async def run_case(line=b"HTTP/1.1 200 OK\r\n", tls_error=False, connection_error=False):
        writer = Writer(tls_error)
        reader = SimpleNamespace(readline=AsyncMock(return_value=line))
        connection = AsyncMock(
            side_effect=OSError() if connection_error else None, return_value=(reader, writer)
        )
        monkeypatch.setattr(asyncio, "open_connection", connection)
        result = await probes.https("example.com", ["192.0.2.1"], 1)
        if not connection_error:
            assert writer.closed
        if result.state == "ok":
            assert writer.request.startswith(b"HEAD / HTTP/1.1")
        return result

    assert asyncio.run(run_case()).state == "ok"
    assert asyncio.run(run_case(line=b"HTTP/1.1 503 Error\r\n")).state == "fail"
    assert asyncio.run(run_case(line=b"bad")).stage == "http"
    assert asyncio.run(run_case(tls_error=True)).stage == "tls"
    assert asyncio.run(run_case(connection_error=True)).stage == "tcp"
    assert asyncio.run(probes.https("example.com", [], 1)).stage == "dns"


def test_https_ipv6_fallback_and_cancellation(monkeypatch):
    writers = []

    class Writer:
        async def start_tls(self, *args, **kwargs):
            pass

        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            self.closed = True

        async def wait_closed(self):
            pass

    async def connect(ip, *args, **kwargs):
        if ":" in ip:
            raise OSError()
        writer = Writer()
        writers.append(writer)
        return SimpleNamespace(readline=AsyncMock(return_value=b"HTTP/1.1 204 OK\r\n")), writer

    monkeypatch.setattr(asyncio, "open_connection", connect)
    result = asyncio.run(probes.https("example.com", ["2001:db8::1", "192.0.2.1"], 1))
    assert result.state == "ok" and result.family == 4
    assert writers[0].closed


def test_numeric_path_and_missing_capability(monkeypatch):
    monkeypatch.setattr(
        probes, "run", AsyncMock(return_value=Command(0, " 1 192.168.1.1 1 ms\n 2 * * *"))
    )
    assert asyncio.run(probes.trace("1.1.1.1", "start")).hops == ["192.168.1.1", "unanswered"]
    monkeypatch.setattr(
        probes, "run", AsyncMock(return_value=Command(None, "", "command unavailable"))
    )
    assert asyncio.run(probes.trace("1.1.1.1", "recovery")).state == "unknown"


def test_real_provider_with_fake_io_and_discovery(monkeypatch):
    class Discovery:
        async def snapshot(self):
            return Network(
                interface="eth0",
                is_up=True,
                addresses=["192.0.2.2", "2001:db8::2"],
                gateways=["192.0.2.1"],
            )

    async def fake_tcp(ip, port, operator, timeout):
        return Probe(
            layer="internet",
            target=ip,
            operator=operator,
            method="tcp",
            state="ok",
            family=6 if ":" in ip else 4,
        )

    async def fake_system(host, timeout):
        return Probe(layer="dns-system", target=host, method="resolve", state="ok"), ["192.0.2.3"]

    async def fake_direct(host, family, timeout):
        return Probe(layer="dns-query", target=host, method="resolve", state="ok")

    monkeypatch.setattr(probes, "tcp", fake_tcp)
    monkeypatch.setattr(probes, "system_dns", fake_system)
    monkeypatch.setattr(probes, "direct_dns", fake_direct)
    monkeypatch.setattr(
        probes,
        "gateway",
        AsyncMock(
            return_value=Probe(layer="gateway", target="192.0.2.1", method="icmp", state="ok")
        ),
    )
    monkeypatch.setattr(
        probes,
        "https",
        AsyncMock(
            return_value=Probe(
                layer="service", target="example.com", method="https-head", state="ok"
            )
        ),
    )
    p = probes.RealProvider(Config(), Discovery())
    s = asyncio.run(p.sample(0, datetime.now(UTC), 0))
    assert len([x for x in s.probes if x.layer == "internet"]) == 6
    assert len([x for x in s.probes if x.layer == "service"]) == 1
    monkeypatch.setattr(probes, "trace", AsyncMock())
    asyncio.run(p.path("baseline"))
    probes.trace.assert_awaited_once_with("1.1.1.1", "baseline")


def test_platform_snapshot_adapters_and_gaps(monkeypatch):
    def fake_link(interface, gateways, routes, resolvers, gaps):
        return Network(
            interface=interface, gateways=gateways, routes=routes, resolvers=resolvers, gaps=gaps
        )

    for module in (linux, windows, macos):
        monkeypatch.setattr(module, "link", fake_link)
    monkeypatch.setattr(linux, "resolver_addresses", lambda: [])
    monkeypatch.setattr(macos, "resolver_addresses", lambda: [])
    monkeypatch.setattr(
        linux,
        "run",
        AsyncMock(
            return_value=Command(0, '[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]')
        ),
    )
    assert asyncio.run(linux.Platform().snapshot()).interface == "eth0"
    monkeypatch.setattr(linux, "run", AsyncMock(return_value=Command(0, "bad")))
    assert asyncio.run(linux.Platform().snapshot()).interface is None
    monkeypatch.setattr(linux, "run", AsyncMock(return_value=Command(None, "")))
    assert asyncio.run(linux.Platform().snapshot()).gaps
    monkeypatch.setattr(
        windows, "run", AsyncMock(return_value=Command(0, json.dumps({"routes": [], "dns": []})))
    )
    assert asyncio.run(windows.Platform().snapshot()).interface is None
    monkeypatch.setattr(windows, "run", AsyncMock(return_value=Command(None, "")))
    assert len(asyncio.run(windows.Platform().snapshot()).gaps) == 2
    monkeypatch.setattr(
        macos, "run", AsyncMock(return_value=Command(0, "gateway: 192.0.2.1\ninterface: en0"))
    )
    assert asyncio.run(macos.Platform().snapshot()).interface == "en0"
    monkeypatch.setattr(macos, "run", AsyncMock(return_value=Command(None, "")))
    assert len(asyncio.run(macos.Platform().snapshot()).gaps) == 3


def test_psutil_portable_inventory_excludes_mac(monkeypatch):
    monkeypatch.setattr(
        base.psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [
                SimpleNamespace(address="192.0.2.2", family=socket.AF_INET),
                SimpleNamespace(address="aa:bb:cc:dd:ee:ff", family=999),
            ]
        },
    )
    monkeypatch.setattr(base.psutil, "net_if_stats", lambda: {"eth0": SimpleNamespace(isup=True)})
    assert base.link("eth0", [], [], [], []).addresses == ["192.0.2.2"]

    def error():
        raise OSError()

    monkeypatch.setattr(base.psutil, "net_if_addrs", error)
    assert base.link("eth0", [], [], [], []).is_up is None


def test_unknown_resolver_does_not_fabricate_service_failure(monkeypatch):
    class Discovery:
        async def snapshot(self):
            return Network(interface="eth0", is_up=True, addresses=["192.0.2.2"])

    async def fake_tcp(ip, port, operator, timeout):
        return Probe(
            layer="internet", target=ip, operator=operator, method="tcp", state="ok", family=4
        )

    async def missing(host, timeout):
        return Probe(layer="dns-system", target=host, method="getaddrinfo", state="unknown"), []

    async def direct(host, family, timeout):
        return Probe(layer="dns-query", target=host, method="resolve", state="ok")

    monkeypatch.setattr(probes, "tcp", fake_tcp)
    monkeypatch.setattr(probes, "system_dns", missing)
    monkeypatch.setattr(probes, "direct_dns", direct)
    p = probes.RealProvider(Config(), Discovery())
    s = asyncio.run(p.sample(0, datetime.now(UTC), 0))
    assert next(r for r in s.probes if r.layer == "service").state == "unknown"
    from routewitness.engine import symptoms

    assert symptoms(s) == []
