import asyncio
import sys

import pytest

from routewitness.platform.base import run
from routewitness.platform.linux import parse_routes
from routewitness.platform.macos import parse_route
from routewitness.platform.windows import parse_snapshot
from routewitness.probes import path_hops


def test_linux_json_routes():
    text = '[{"dst":"default","gateway":"192.168.1.1","dev":"wlan0","metric":600},{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100}]'
    dev, gateways, routes = parse_routes(text)
    assert dev == "eth0"
    assert len(gateways) == len(routes) == 2


def test_linux_ipv6_scope_and_vpn():
    dev, gateways, routes = parse_routes(
        '[{"dst":"default","gateway":"fe80::1","dev":"eth0"},{"dst":"0.0.0.0/1","dev":"tun0"}]'
    )
    assert gateways == ["fe80::1%eth0"]
    assert len(routes) == 2


def test_windows_non_english_alias_and_metrics():
    text = '{"routes":[{"InterfaceAlias":"Беспроводная сеть","InterfaceIndex":5,"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1","RouteMetric":0,"InterfaceMetric":50}],"dns":[{"InterfaceAlias":"Беспроводная сеть","ServerAddresses":["192.168.1.1"]}]}'
    dev, gateways, routes, resolvers = parse_snapshot(text)
    assert dev == "Беспроводная сеть"
    assert resolvers == gateways == ["192.168.1.1"]


def test_macos_numeric_route():
    assert parse_route(" route to: default\n gateway: fe80::1%en0\n interface: en0\n") == (
        "en0",
        "fe80::1%en0",
    )
    assert parse_route("gateway: link#12\ninterface: utun1") == ("utun1", None)


@pytest.mark.parametrize("text", ["{", "{}", '[{"gateway":"not-an-IP"}]'])
def test_invalid_linux(text):
    with pytest.raises((ValueError, TypeError)):
        parse_routes(text)


def test_path_only_numeric_no_hostnames():
    assert path_hops(
        "traceroute to private-host\n 1 192.168.1.1 2.0 ms\n 2 * * *\n 3 2001:db8::1 20 ms"
    ) == ["192.168.1.1", "unanswered", "2001:db8::1"]


def test_command_missing_timeout_and_output_limit():
    assert asyncio.run(run(["routewitness-no-such-command"])).code is None
    assert (
        asyncio.run(run([sys.executable, "-c", "import time;time.sleep(10)"], 0.05)).gap
        == "command timeout"
    )
    assert (
        asyncio.run(run([sys.executable, "-c", 'print("x"*10000)'], 2, 20)).gap
        == "command output exceeded limit"
    )


def test_command_cancellation():
    async def go():
        task = asyncio.create_task(run([sys.executable, "-c", "import time;time.sleep(10)"], 20))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())
