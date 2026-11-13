"""Load and validate scenario files. Owner: Person 1."""
from __future__ import annotations

import dataclasses

import yaml

from .contracts import Case, Device, Flow, Host, Scenario, Zone


def _load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return data


def _build(kind: str, cls, entries, **extra):
    """Build dataclass instances from a list of dicts, naming the bad entry on error."""
    out = []
    for i, e in enumerate(entries or []):
        if not isinstance(e, dict):
            raise ValueError(f"{kind}[{i}]: expected a mapping, got {e!r}")
        try:
            out.append(cls(**e, **extra))
        except TypeError as err:
            raise ValueError(f"{kind}[{i}] ({e.get('id', e.get('name', '?'))}): {err}") from None
    return out


def _unique(kind: str, ids: list[str]) -> None:
    seen = set()
    for i in ids:
        if i in seen:
            raise ValueError(f"{kind}: duplicate id {i!r}")
        seen.add(i)


def _flow(where: str, e, nodes: set[str], devices: set[str]) -> Flow:
    if not isinstance(e, dict):
        raise ValueError(f"{where}: expected a mapping, got {e!r}")
    try:
        f = Flow(**e)
    except TypeError as err:
        raise ValueError(f"{where}: {err}") from None
    if isinstance(f.bytes, bool) or not isinstance(f.bytes, int) or f.bytes < 0:
        raise ValueError(f"{where}: bytes must be a non-negative integer, got {f.bytes!r}")
    if isinstance(f.t, bool) or not isinstance(f.t, int) or f.t < 0:
        raise ValueError(f"{where}: t must be a non-negative integer, got {f.t!r}")
    if f.src not in devices:
        raise ValueError(f"{where}: src {f.src!r} is not a device")
    if f.dst not in nodes:
        raise ValueError(f"{where}: dst {f.dst!r} is not a device or host")
    return f


def load_scenario(path: str) -> Scenario:
    """Read a scenario YAML file into a Scenario.

    Validates every reference: each flow and baseline entry names an existing
    device or host, foothold is a device, every device zone exists. A bad reference
    raises ValueError that names the offending entry.
    """
    raw = _load_yaml(path)
    for key in ("zones", "devices", "hosts", "foothold", "baseline", "scenarios"):
        if key not in raw:
            raise ValueError(f"{path}: missing required key {key!r}")

    zones = _build("zones", Zone, raw["zones"])
    devices = _build("devices", Device, raw["devices"])
    hosts = _build("hosts", Host, raw["hosts"])

    _unique("zones", [z.name for z in zones])
    _unique("devices", [d.id for d in devices])
    _unique("hosts", [h.id for h in hosts])

    zone_names = {z.name for z in zones}
    device_ids = {d.id for d in devices}
    host_ids = {h.id for h in hosts}
    clash = device_ids & host_ids
    if clash:
        raise ValueError(f"devices/hosts: id used for both a device and a host: {sorted(clash)}")
    nodes = device_ids | host_ids

    for d in devices:
        if d.zone not in zone_names:
            raise ValueError(f"devices[{d.id}]: zone {d.zone!r} does not exist")

    foothold = raw["foothold"]
    if foothold not in device_ids:
        raise ValueError(f"foothold: {foothold!r} is not a device")

    baseline = set()
    for i, pair in enumerate(raw["baseline"] or []):
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError(f"baseline[{i}]: expected [src, dst], got {pair!r}")
        src, dst = pair
        if src not in device_ids:
            raise ValueError(f"baseline[{i}]: src {src!r} is not a device")
        if dst not in nodes:
            raise ValueError(f"baseline[{i}]: dst {dst!r} is not a device or host")
        baseline.add((src, dst))

    cases = []
    for i, c in enumerate(raw["scenarios"] or []):
        if not isinstance(c, dict) or "id" not in c:
            raise ValueError(f"scenarios[{i}]: expected a mapping with an id, got {c!r}")
        cid = c["id"]
        flows = tuple(
            _flow(f"scenarios[{cid}].flows[{j}]", fl, nodes, device_ids)
            for j, fl in enumerate(c.get("flows") or [])
        )
        cases.append(Case(id=cid, name=c.get("name", cid), flows=flows,
                          expect=c.get("expect") or {}))
    _unique("scenarios", [c.id for c in cases])

    return Scenario(
        zones=tuple(zones),
        devices=tuple(devices),
        hosts=tuple(hosts),
        foothold=foothold,
        baseline=frozenset(baseline),
        cases=tuple(cases),
    )


def load_thresholds(path: str = "config/thresholds.yaml") -> dict:
    """Read config/thresholds.yaml into a dict."""
    data = _load_yaml(path)
    for key in ("outbound_mb_limit", "beacon_min_count", "beacon_window_s"):
        if key not in data:
            raise ValueError(f"{path}: missing required key {key!r}")
    return data


def with_case(scenario: Scenario, case_id: str) -> Scenario:
    """Return a copy of scenario whose .flows are the flows of the named case."""
    for c in scenario.cases:
        if c.id == case_id:
            return dataclasses.replace(scenario, flows=c.flows)
    known = [c.id for c in scenario.cases]
    raise ValueError(f"unknown case {case_id!r}; known cases: {known}")
