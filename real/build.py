"""Merge the real inputs into the simulator's model, then reuse the simulator engine unchanged.

Reuses: src.policies (apply_policy via src.main.run_policy), src.reach.blast_radius,
src.outbound / src.alerts. Nothing in src/ is modified.
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from pathlib import Path

from src.contracts import Case, Device, Flow, Host, Scenario, Zone
from src.main import run_policy
from src.model import load_thresholds, with_case
from src.policies import load_policies

from . import attack, ingest
from .ingest import InputError, mask_mac
from .layout import layout

UNASSIGNED = "unassigned"


@dataclass
class RealDevice:
    id: str
    name: str
    ip: str
    mac: str
    sources: list[str]
    status: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def flags(self) -> list[str]:
        return [] if "router" in self.sources else ["not in router_devices.csv"]


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def load_inputs(input_dir: str | Path, live_rows: list[dict] | None = None,
                quick: bool = False, foothold: str | None = None) -> dict:
    """quick=True (live discovery) lets router_devices.csv and zones.yaml be absent."""
    d = Path(input_dir)
    router = ([] if quick and not (d / "router_devices.csv").is_file()
              else ingest.parse_router_devices(d / "router_devices.csv"))
    arp = ingest.parse_arp_file(d / "arp.txt") if (d / "arp.txt").is_file() else []
    traffic = (ingest.parse_traffic(d / "router_traffic.csv")
               if (d / "router_traffic.csv").is_file() else None)
    if quick and not (d / "zones.yaml").is_file():
        zones = {"foothold": foothold, "zones": [], "devices": {}, "allowed": [], "known_hosts": [], "hosts": {}}
    else:
        zones = ingest.parse_zones(d / "zones.yaml")
        if foothold:
            zones["foothold"] = foothold
    return {"dir": str(d).replace("\\", "/"), "router": router, "arp": arp,
            "live": live_rows or [], "traffic": traffic, "zones": zones,
            "names": ingest.parse_names(d / "names.csv") if (d / "names.csv").is_file() else {}}


def merge_devices(router: list[dict], arp: list[dict], live: list[dict] = (),
                  names: dict[str, str] | None = None) -> list[RealDevice]:
    """Merge by MAC address. Records which source(s) saw each device."""
    by_mac: dict[str, RealDevice] = {}
    for r in router:
        by_mac[r["mac"]] = RealDevice(id="", name=r["name"] or r["ip"], ip=r["ip"], mac=r["mac"],
                                      sources=["router"], status=r["status"], extra=r["extra"])
    for label, rows in (("arp", arp), ("live", live)):
        for r in rows:
            dev = by_mac.get(r["mac"])
            if dev:
                if label not in dev.sources:
                    dev.sources.append(label)
                dev.ip = dev.ip or r["ip"]
            else:
                tail = mask_mac(r["mac"])[9:].replace(":", "-")
                by_mac[r["mac"]] = RealDevice(id="", name=f"unknown-{tail}", ip=r["ip"],
                                              mac=r["mac"], sources=[label])
    devices = list(by_mac.values())
    for dev in devices:                     # names.csv (ip,name) overrides any discovered name
        if names and dev.ip in names:
            dev.name = names[dev.ip]
    used: set[str] = set()
    for dev in devices:
        base, i, cand = _slug(dev.name), 2, _slug(dev.name)
        while cand in used:
            cand, i = f"{base}-{i}", i + 1
        dev.id = cand
        used.add(cand)
    return devices


def assemble(inputs: dict, devices: list[RealDevice], thresholds: dict, policies_path: str,
             attack_demo: bool = False, test_upload: dict | None = None) -> tuple[dict, dict]:
    """Build the simulator's `results` dict (shape documented in src/report.py) from real data.

    Returns (results, extras). extras carries notes, connections and the device table for the writers.
    """
    zcfg = inputs["zones"]
    notes: list[str] = []
    by_name = {d.name.casefold(): d for d in devices}
    by_ip = {d.ip: d for d in devices if d.ip}

    # --- zones and device attributes (from zones.yaml only; nothing assumed) ---
    zdev = {k.casefold(): v for k, v in zcfg["devices"].items()}
    for k in zcfg["devices"]:
        if k.casefold() not in by_name:
            notes.append(f"zones.yaml lists '{k}' but no such device was seen in the exports.")
    zone_of = {d.id: (zdev.get(d.name.casefold()) or {}).get("zone", UNASSIGNED) for d in devices}
    zone_names = [z["name"] for z in zcfg["zones"]]
    for z in zone_of.values():
        if z not in zone_names:
            zone_names.append(z)
    if UNASSIGNED in zone_names:   # list "unassigned" last
        zone_names.remove(UNASSIGNED)
        zone_names.append(UNASSIGNED)
    n_unassigned = sum(1 for z in zone_of.values() if z == UNASSIGNED)
    if n_unassigned:
        notes.append(f"{n_unassigned} device(s) have no zone in zones.yaml and are listed under '{UNASSIGNED}'.")
    arp_only = [d for d in devices if d.flags]
    if arp_only:
        notes.append(f"{len(arp_only)} device(s) were seen only in arp/live discovery, not in "
                     f"router_devices.csv: " + ", ".join(d.name for d in arp_only) + ".")

    if not zcfg["foothold"]:
        if not devices:
            raise InputError(f"{inputs['dir']}: no devices found, nothing to show")
        # Prefer a device that is not the router/gateway (an address ending .1 or .254).
        fh = next((d for d in devices if not d.ip.endswith((".1", ".254"))), devices[0])
        notes.append(f"No foothold was named, so '{fh.name}' was used. Pass --foothold NAME or set "
                     f"'foothold:' in zones.yaml.")
    else:
        fh = by_name.get(zcfg["foothold"].casefold())
    if fh is None:
        raise InputError(f"{inputs['dir']}/zones.yaml: foothold '{zcfg['foothold']}' is not a device "
                         f"seen in the exports")

    # --- destinations: device or outside host ---
    allowed_dst = {dst.casefold() for _, dst in zcfg["allowed"]}
    known = {h.casefold() for h in zcfg["known_hosts"]} | allowed_dst
    hosts: dict[str, Host] = {}

    def resolve(name: str) -> str:
        dev = by_name.get(name.casefold()) or by_ip.get(name)
        if dev:
            return dev.id
        hid = "h-" + _slug(name)
        hosts.setdefault(hid, Host(id=hid, name=name, known=name.casefold() in known, x=0, y=0))
        return hid

    baseline = set()
    for i, (src, dst) in enumerate(zcfg["allowed"]):
        sdev = by_name.get(src.casefold())
        if sdev is None:
            raise InputError(f"{inputs['dir']}/zones.yaml: allowed[{i}] source '{src}' is not a device "
                             f"seen in the exports")
        baseline.add((sdev.id, resolve(dst)))

    # --- observed flows from router_traffic.csv ---
    flows, skipped, d2d, traffic_note = [], [], 0, None
    if inputs["traffic"] is None:
        traffic_note = "No router_traffic.csv was provided, so there are no observed connections."
    else:
        rows = []
        for r in inputs["traffic"]:
            sdev = by_name.get(r["src"].casefold()) or by_ip.get(r["src"])
            if sdev is None:
                skipped.append(f"unknown source '{r['src']}'")
                continue
            rows.append((sdev.id, resolve(r["dst"]), r["bytes"], r["ts"]))
        t0 = min((r[3] for r in rows), default=0)
        dev_ids = {d.id for d in devices}
        for s, dst, nbytes, ts in sorted(rows, key=lambda r: (r[3], r[0], r[1])):
            flows.append(Flow(src=s, dst=dst, bytes=nbytes, t=int(round(ts - t0))))
            d2d += dst in dev_ids
        if skipped:
            notes.append(f"{len(skipped)} traffic row(s) skipped (source not in the device list): "
                         + "; ".join(sorted(set(skipped))) + ".")
        if not d2d:
            traffic_note = ("router_traffic.csv has NO device-to-device rows, so no links between "
                            "devices are shown. Only device-to-outside traffic is observed.")
    if traffic_note:
        notes.append(traffic_note)

    dev_contract_ids = [d.id for d in devices]
    cases = [Case(id="observed",
                  name="Observed traffic" if inputs["traffic"] is not None else "Blast radius only (no traffic file)",
                  flows=tuple(flows), expect={})]

    # --- optional attack demo overlay and real test upload ---
    contract_devices = [Device(id=d.id, name=d.name, zone=zone_of[d.id],
                               type=str((zdev.get(d.name.casefold()) or {}).get("type", "")),
                               critical=bool((zdev.get(d.name.casefold()) or {}).get("critical", False)),
                               x=0, y=0) for d in devices]
    if attack_demo:
        sim_cases, sim_host, sim_notes = attack.sim_cases(contract_devices, fh.id, thresholds)
        cases += sim_cases
        notes += sim_notes
        if sim_cases:
            hosts[sim_host.id] = sim_host
    if test_upload:
        lap = attack.pick_laptop(contract_devices)
        hid = resolve(test_upload["host"])
        cases.append(Case(id="live_test", name="REAL test upload from the laptop (harmless dummy data)",
                          flows=(Flow(src=lap.id, dst=hid, bytes=test_upload["bytes"], t=0),), expect={}))
        notes.append(f"Real test upload: {test_upload['bytes']} bytes of dummy data sent from "
                     f"{lap.name} to {test_upload['host']}. The 'monitor' here is this tool's own send "
                     f"record, not an independent capture.")

    # --- layout (positions come from zones.yaml when given) ---
    zspecs = {z["name"]: z for z in zcfg["zones"]}
    dev_in = [{"id": d.id, "zone": zone_of[d.id], **{k: v for k, v in (zdev.get(d.name.casefold()) or {}).items()
                                                      if k in ("x", "y")}} for d in devices]
    zones, dpos, hpos = layout(zone_names, dev_in, zspecs, list(hosts), {
        "h-" + _slug(k): v for k, v in zcfg["hosts"].items() if isinstance(v, dict)})
    contract_devices = [dataclasses.replace(d, x=int(dpos[d.id][0]), y=int(dpos[d.id][1])) for d in contract_devices]
    contract_hosts = [dataclasses.replace(h, x=int(hpos[h.id][0]), y=int(hpos[h.id][1])) for h in hosts.values()]

    scenario = Scenario(zones=tuple(Zone(**z) for z in zones), devices=tuple(contract_devices),
                        hosts=tuple(contract_hosts), foothold=fh.id, baseline=frozenset(baseline),
                        cases=tuple(cases))

    policies = load_policies(policies_path)
    pids = list(policies)
    out_cases = []
    for c in scenario.cases:
        s = with_case(scenario, c.id)
        out_cases.append({"id": c.id, "name": c.name, "flows": [dataclasses.asdict(f) for f in c.flows],
                          "results": {p: run_policy(s, p, thresholds, policies_path) for p in pids},
                          "checks": []})
    results = {"scenario_file": inputs["dir"], "foothold": fh.id, "thresholds": thresholds,
               "policies": [{"id": p, "description": (policies[p] or {}).get("description", "")} for p in pids],
               "before_policy": pids[0], "after_policy": pids[-1],
               "zones": [dataclasses.asdict(z) for z in scenario.zones],
               "devices": [dataclasses.asdict(d) for d in scenario.devices],
               "hosts": [dataclasses.asdict(h) for h in scenario.hosts],
               "baseline": sorted([list(p) for p in scenario.baseline]), "cases": out_cases}

    names = {d.id: d.name for d in devices} | {h.id: h.name for h in contract_hosts}
    extras = {
        "notes": notes, "devices": devices, "zone_of": zone_of, "names": names,
        "device_to_device_rows": d2d, "skipped": skipped, "dev_ids": dev_contract_ids,
        "declared_allowed": [[names[a], names[b]] for a, b in sorted(baseline)],
        "observed": [{"src": names[f.src], "dst": names[f.dst], "bytes": f.bytes, "t": f.t,
                      "dst_kind": "device" if f.dst in dev_contract_ids else "host"} for f in flows],
    }
    return results, extras


def load_thresholds_default(path: str = "config/thresholds.yaml") -> dict:
    return load_thresholds(path)
