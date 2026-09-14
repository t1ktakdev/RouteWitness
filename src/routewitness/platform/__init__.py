"""Read-only OS discovery. No adapter changes or privilege escalation."""

import importlib
import sys
from typing import Protocol

from routewitness.models import Network


class Discovery(Protocol):
    async def snapshot(self) -> Network: ...


def provider() -> Discovery:
    name = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
    module = importlib.import_module(f"routewitness.platform.{name}")
    result: Discovery = module.Platform()
    return result
