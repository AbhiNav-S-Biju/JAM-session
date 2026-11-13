"""Shared data types. Owner: Person 1. Everyone imports from here.

Changing a field here is a contract change: edit docs/TEAM_PLAN.md first,
then tell the other two people.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Zone:
    name: str
    x: int
    y: int
    w: int
    h: int


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    zone: str
    x: int
    y: int
    type: str = ""
    critical: bool = False


@dataclass(frozen=True)
class Host:
    id: str
    name: str
    known: bool
    x: int
    y: int


@dataclass(frozen=True)
class Flow:
    src: str
    dst: str
    bytes: int
    t: int  # seconds from the start of the case


@dataclass(frozen=True)
class Case:
    id: str
    name: str
    flows: tuple[Flow, ...]
    expect: dict


@dataclass(frozen=True)
class Scenario:
    zones: tuple[Zone, ...]
    devices: tuple[Device, ...]
    hosts: tuple[Host, ...]
    foothold: str
    baseline: frozenset[tuple[str, str]]
    cases: tuple[Case, ...]
    # Flows of the case currently being run. Empty until model.with_case() is called.
    flows: tuple[Flow, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Alert:
    kind: str      # outbound_unlisted | outbound_over_limit | unlisted_flow | beaconing
    src: str
    dst: str
    message: str


@dataclass(frozen=True)
class ReachResult:
    reachable: frozenset[str]  # device ids, foothold not included
    count: int
    total: int                 # number of devices other than the foothold
