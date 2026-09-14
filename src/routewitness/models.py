"""Versioned evidence, validated at collection and at disk boundaries."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

State = Literal["ok", "fail", "unknown"]
Domain = Literal[
    "local-interface",
    "local-link",
    "gateway-or-router",
    "dns",
    "upstream-or-isp",
    "remote-service",
    "route-change",
    "system-network-change",
    "mixed",
    "insufficient-evidence",
]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, validate_assignment=True)


class Probe(Model):
    layer: Literal["gateway", "internet", "dns-system", "dns-query", "service"]
    target: str = Field(max_length=253)
    state: State
    method: str = Field(max_length=32)
    family: Literal[4, 6, 0] = 0
    operator: str = Field(default="", max_length=64)
    latency_ms: float | None = Field(default=None, ge=0)
    detail: str = Field(default="", max_length=256)
    stage: str = Field(default="", max_length=32)


class Network(Model):
    interface: str | None = Field(default=None, max_length=256)
    is_up: bool | None = None
    kind: str = "unknown"
    addresses: list[str] = Field(default_factory=list, max_length=64)
    gateways: list[str] = Field(default_factory=list, max_length=16)
    routes: list[str] = Field(default_factory=list, max_length=64)
    resolvers: list[str] = Field(default_factory=list, max_length=32)
    gaps: list[str] = Field(default_factory=list, max_length=32)

    def identity(self) -> tuple[object, ...]:
        # Raw routes are evidence, not stable network identity. Route tables can
        # contain volatile metrics/entries, especially on Windows. Gateway or
        # interface changes still produce a meaningful route/network change.
        return (
            self.interface,
            self.is_up,
            tuple(sorted(self.addresses)),
            tuple(sorted(self.gateways)),
            tuple(sorted(self.resolvers)),
        )


class Event(Model):
    kind: str = Field(max_length=64)
    detail: str = Field(max_length=512)


class Sample(Model):
    seq: int = Field(ge=0)
    at: datetime
    elapsed: float = Field(ge=0)
    network: Network
    probes: list[Probe] = Field(default_factory=list, max_length=64)
    events: list[Event] = Field(default_factory=list, max_length=16)
    symptoms: list[str] = Field(default_factory=list, max_length=16)
    baseline_ms: float | None = None
    latency_ms: float | None = None

    @field_validator("at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("sample timestamp must include timezone")
        return value


class Diagnosis(Model):
    domain: Domain = "insufficient-evidence"
    verdict: str = "Evidence is insufficient to locate the failure."
    confidence: Literal["low", "medium", "high"] = "low"
    evidence_for: list[str] = Field(default_factory=list)
    evidence_against: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    recommended_next_checks: list[str] = Field(default_factory=list)


class PathObservation(Model):
    phase: Literal["baseline", "start", "during", "recovery"]
    at: datetime
    target: str
    state: State
    hops: list[str] = Field(default_factory=list, max_length=64)
    detail: str = Field(default="", max_length=256)

    @field_validator("at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("path timestamp must include timezone")
        return value


class Incident(Model):
    schema_version: Literal[1] = 1
    tool_version: str = "0.1.0"
    id: str = Field(pattern=r"^\d{8}T\d{6}Z-[a-f0-9]{8}$")
    start: datetime
    detected: datetime
    end: datetime | None = None
    duration_s: float = Field(default=0, ge=0)
    status: Literal["recording", "recovered", "interrupted", "continued", "diagnosis"]
    previous_id: str | None = None
    simulated: bool = False
    samples: list[Sample] = Field(min_length=1, max_length=2048)
    paths: list[PathObservation] = Field(default_factory=list, max_length=32)
    diagnosis: Diagnosis = Field(default_factory=Diagnosis)
    warnings: list[str] = Field(default_factory=list, max_length=64)
    capability_gaps: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def consistent(self) -> "Incident":
        times = [self.start, self.detected, *([self.end] if self.end else [])]
        if any(t.tzinfo is None for t in times):
            raise ValueError("timestamps must include timezone")
        if self.detected < self.start or (self.end and self.end < self.start):
            raise ValueError("incident times are out of order")
        if self.status == "recovered" and self.end is None:
            raise ValueError("recovered incident requires end")
        if any(
            b.seq <= a.seq or b.elapsed <= a.elapsed
            for a, b in zip(self.samples, self.samples[1:], strict=False)
        ):
            raise ValueError("samples must have increasing sequence and elapsed time")
        return self
