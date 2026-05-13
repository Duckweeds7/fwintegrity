"""Dataclasses for normalized firewall changes (endpoints, services, kinds)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

Confidence = Literal["high", "medium", "low"]


class ChangeKind(str, Enum):
    ADD = "add"
    MODIFY = "modify"
    REMOVE = "remove"
    DISABLED = "disabled"


@dataclass(frozen=True)
class PortInterval:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start > self.end or self.start < 0 or self.end > 65535:
            raise ValueError("invalid port interval")


@dataclass(frozen=True)
class ServiceLiteral:
    proto: str
    intervals: tuple[PortInterval, ...]


@dataclass(frozen=True)
class ServiceRef:
    name: str


@dataclass(frozen=True)
class ServiceBundle:
    parts: tuple[ServiceLiteral, ...]


@dataclass(frozen=True)
class ServiceCompound:
    literals: tuple[ServiceLiteral, ...]
    objects: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.literals and not self.objects:
            raise ValueError("service compound must have literals and/or objects")


ServiceSpec = ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound


@dataclass(frozen=True)
class AddrLiteral:
    networks: tuple[str, ...]


@dataclass(frozen=True)
class AddrRef:
    name: str


@dataclass(frozen=True)
class AddrCompound:
    networks: tuple[str, ...]
    objects: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.networks and not self.objects:
            raise ValueError("addr compound must have networks and/or objects")


EndpointSpec = AddrLiteral | AddrRef | AddrCompound


@dataclass(frozen=True)
class NormalizedChange:
    change: ChangeKind
    source: EndpointSpec
    destination: EndpointSpec
    service: ServiceSpec
    meta: tuple[tuple[str, str], ...] = ()


@dataclass
class ParseIssue:
    message: str


@dataclass
class ParsedField:
    raw: str
    normalized: str | None
    confidence: Confidence
    issues: list[ParseIssue] = field(default_factory=list)
