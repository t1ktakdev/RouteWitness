"""Strict, small TOML configuration. Never changes OS settings."""

import ipaddress
import re
import tomllib
from pathlib import Path
from typing import Literal

from platformdirs import user_config_path, user_data_path
from pydantic import Field, field_validator, model_validator

from routewitness.models import Model


def hostname(value: str) -> str:
    value = value.rstrip(".").lower()
    if (
        len(value) > 253
        or not value
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        )
    ):
        raise ValueError("target must be a hostname, without URL, port, path or credentials")
    return value


class Endpoint(Model):
    operator: str = Field(min_length=1, max_length=64)
    ipv4: str
    ipv6: str
    port: int = Field(default=443, ge=1, le=65535)

    @model_validator(mode="after")
    def addresses_valid(self) -> "Endpoint":
        if ipaddress.ip_address(self.ipv4).version != 4:
            raise ValueError("ipv4 must be a numeric IPv4 address")
        if ipaddress.ip_address(self.ipv6).version != 6:
            raise ValueError("ipv6 must be a numeric IPv6 address")
        return self


class Config(Model):
    interval: float = Field(default=1, ge=0.5, le=60)
    incident_interval: float = Field(default=0.5, ge=0.5, le=60)
    timeout: float = Field(default=1.5, ge=0.1, le=5)
    pre_seconds: float = Field(default=45, ge=5, le=120)
    pre_limit: int = Field(default=240, ge=10, le=240)
    failure_rounds: int = Field(default=3, ge=2, le=10)
    loss_window: int = Field(default=10, ge=5, le=60)
    loss_threshold: float = Field(default=0.3, gt=0, le=1)
    recovery_seconds: float = Field(default=6, ge=2, le=120)
    baseline_samples: int = Field(default=120, ge=10, le=600)
    latency_absolute_ms: float = Field(default=150, ge=10, le=5000)
    latency_multiplier: float = Field(default=3, ge=1.5, le=20)
    segment_samples: int = Field(default=1800, ge=30, le=1800)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    family: Literal["auto", "4", "6", "both"] = "auto"
    paths: bool = True
    path_interval: float = Field(default=300, ge=60, le=3600)
    targets: list[str] = Field(default_factory=lambda: ["example.com"], max_length=4)
    dns_names: list[str] = Field(
        default_factory=lambda: ["example.com", "iana.org"], min_length=2, max_length=4
    )
    endpoints: list[Endpoint] = Field(
        default_factory=lambda: [
            Endpoint(operator="cloudflare", ipv4="1.1.1.1", ipv6="2606:4700:4700::1111"),
            Endpoint(operator="google", ipv4="8.8.8.8", ipv6="2001:4860:4860::8888", port=53),
            Endpoint(operator="quad9", ipv4="9.9.9.9", ipv6="2620:fe::fe", port=53),
        ],
        min_length=3,
        max_length=6,
    )

    @field_validator("targets", "dns_names")
    @classmethod
    def names(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(hostname(v) for v in values))

    @model_validator(mode="after")
    def independent(self) -> "Config":
        if len({e.operator for e in self.endpoints}) != len(self.endpoints):
            raise ValueError("endpoints must have distinct operator labels")
        if len({e.ipv4 for e in self.endpoints}) != len(self.endpoints):
            raise ValueError("endpoints must have distinct addresses")
        if len(self.dns_names) < 2:
            raise ValueError("at least two distinct DNS names required")
        return self


def data_dir() -> Path:
    return user_data_path("routewitness", appauthor=False)


def config_file() -> Path:
    return user_config_path("routewitness", appauthor=False) / "config.toml"


def load(path: Path | None = None) -> Config:
    selected = path or config_file()
    if not selected.exists() and path is None:
        return Config()
    with selected.open("rb") as stream:
        return Config.model_validate(tomllib.load(stream))
