"""Read the files you export yourself. Local files only: no network access in this module.

Every problem raises InputError with a message that names the file. Nothing is guessed.
"""
from __future__ import annotations

import csv
import ipaddress
import re
from datetime import datetime
from pathlib import Path

import yaml


class InputError(Exception):
    """A file is missing, has an unrecognised format, or has a bad value."""


# ---------- MAC helpers ----------

def norm_mac(text: str) -> str:
    """'AA-BB-CC-0-0-3' -> 'aa:bb:cc:00:00:03'. Raises ValueError if it is not a MAC."""
    parts = re.split(r"[:-]", text.strip().lower())
    if len(parts) != 6 or any(not re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        raise ValueError(f"not a MAC address: {text!r}")
    return ":".join(p.zfill(2) for p in parts)


def mask_mac(mac: str) -> str:
    """Show only the last 3 octets: 'aa:bb:cc:00:00:03' -> 'xx:xx:xx:00:00:03'."""
    return "xx:xx:xx:" + ":".join(mac.split(":")[3:])


# ---------- CSV ----------

def _key(header: str) -> str:
    return re.sub(r"[\s_\-]+", "", header.lower())


def _read_csv(path: Path) -> tuple[list[str], list[dict]]:
    if not path.is_file():
        raise InputError(f"{path}: file not found")
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise InputError(f"{path}: file is empty (no header row)")
        headers = [h.strip() for h in reader.fieldnames]
        rows = []
        for raw in reader:
            rows.append({(k or "").strip(): (v or "").strip()
                         for k, v in raw.items() if k is not None})
    return headers, rows


def _columns(path: Path, headers: list[str], spec: dict[str, tuple[str, ...]],
             required: tuple[str, ...]) -> dict[str, str | None]:
    """Map canonical column -> actual header, by header NAME (never by position)."""
    by_key = {_key(h): h for h in headers}
    found: dict[str, str | None] = {}
    for canon, aliases in spec.items():
        found[canon] = next((by_key[a] for a in aliases if a in by_key), None)
    missing = [c for c in required if found[c] is None]
    if missing:
        raise InputError(f"{path}: missing column(s) {missing}; found headers {headers}. "
                         f"Accepted names: " + "; ".join(f"{c} = {list(spec[c])}" for c in missing))
    return found


ROUTER_SPEC = {
    "name": ("name", "hostname", "devicename", "device", "host"),
    "ip": ("ip", "ipaddress", "ipv4", "ipv4address"),
    "mac": ("mac", "macaddress", "macaddr", "physicaladdress"),
    "status": ("status", "connection", "connectionstatus", "state", "connected", "online"),
}


def parse_router_devices(path: str | Path) -> list[dict]:
    path = Path(path)
    headers, rows = _read_csv(path)
    cols = _columns(path, headers, ROUTER_SPEC, required=("name", "ip", "mac"))
    used = {h for h in cols.values() if h}
    out = []
    for n, row in enumerate(rows, start=2):  # row 1 is the header
        try:
            mac = norm_mac(row[cols["mac"]])
        except ValueError as e:
            raise InputError(f"{path}: row {n}: {e}") from None
        out.append({
            "name": row[cols["name"]], "ip": row[cols["ip"]], "mac": mac,
            "status": row[cols["status"]] if cols["status"] else "",
            "extra": {k: v for k, v in row.items() if k not in used},   # unknown columns kept as-is
        })
    return out


def parse_names(path: str | Path) -> dict[str, str]:
    """names.csv with columns ip,name (matched by header name). Returns {ip: name}."""
    path = Path(path)
    headers, rows = _read_csv(path)
    cols = _columns(path, headers, {"ip": ROUTER_SPEC["ip"], "name": ROUTER_SPEC["name"]},
                    required=("ip", "name"))
    return {r[cols["ip"]]: r[cols["name"]] for r in rows if r[cols["ip"]] and r[cols["name"]]}


TRAFFIC_SPEC = {
    "src": ("source", "src", "sourcedevice", "device", "client", "from"),
    "dst": ("destination", "dst", "dest", "destinationhost", "host", "remote", "to"),
    "bytes": ("bytes", "totalbytes", "size", "traffic"),
    "time": ("time", "timestamp", "ts", "date", "datetime"),
}


def parse_time(text: str) -> float:
    """Epoch seconds, or an ISO date-time. Returns seconds. Raises ValueError."""
    t = text.strip()
    try:
        return float(t)
    except ValueError:
        pass
    return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()


def parse_traffic(path: str | Path) -> list[dict]:
    path = Path(path)
    headers, rows = _read_csv(path)
    cols = _columns(path, headers, TRAFFIC_SPEC, required=("src", "dst", "bytes", "time"))
    out = []
    for n, row in enumerate(rows, start=2):
        try:
            nbytes = int(float(row[cols["bytes"]]))
            if nbytes < 0:
                raise ValueError("negative")
        except ValueError:
            raise InputError(f"{path}: row {n}: bytes must be a non-negative number, "
                             f"got {row[cols['bytes']]!r}") from None
        try:
            ts = parse_time(row[cols["time"]])
        except ValueError:
            raise InputError(f"{path}: row {n}: cannot read the time {row[cols['time']]!r} "
                             f"(use an ISO date-time or epoch seconds)") from None
        out.append({"src": row[cols["src"]], "dst": row[cols["dst"]], "bytes": nbytes, "ts": ts})
    return out


# ---------- arp -a ----------

_WIN = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+")
_UNIX = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(\S+)")
_IGNORE = re.compile(r"^\s*(interface:|internet address|address\s+hwtype|$)", re.I)


def parse_arp(text: str, source: str = "arp.txt") -> list[dict]:
    """Parse `arp -a` output (Windows, or macOS/Linux). Returns [{'ip','mac'}], no duplicates.

    Skips incomplete entries, broadcast and multicast. A file with no recognisable
    line at all raises InputError instead of returning an empty list.
    """
    entries: dict[str, dict] = {}
    recognised = 0
    for line in text.splitlines():
        if _IGNORE.match(line):
            continue
        m = _WIN.match(line)
        if m:
            ip, raw = m.group(1), m.group(2)
        else:
            m = _UNIX.search(line)
            if not m:
                continue
            ip, raw = m.group(1), m.group(2)
        recognised += 1
        if "incomplete" in raw.lower():
            continue
        try:
            mac = norm_mac(raw)
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_multicast or int(mac[:2], 16) & 1:   # multicast / broadcast MACs have this bit set
            continue
        entries.setdefault(mac, {"ip": ip, "mac": mac})
    if not recognised:
        raise InputError(f"{source}: unrecognised format. Expected the output of `arp -a` "
                         f"(Windows: '192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic', "
                         f"macOS/Linux: '? (192.168.1.1) at aa:bb:cc:dd:ee:ff ...')")
    return list(entries.values())


def parse_arp_file(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.is_file():
        raise InputError(f"{path}: file not found")
    return parse_arp(path.read_text(encoding="utf-8", errors="replace"), str(path))


# ---------- zones.yaml ----------

def parse_zones(path: str | Path) -> dict:
    """Your hand-written map. Returns a dict with foothold, zones, devices, allowed, known_hosts, hosts."""
    path = Path(path)
    if not path.is_file():
        raise InputError(f"{path}: file not found (needed to name the foothold device and the zones)")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise InputError(f"{path}: not valid YAML: {e}") from None
    if not isinstance(data, dict):
        raise InputError(f"{path}: expected a mapping at the top level")
    if not isinstance(data.get("foothold"), str) or not data["foothold"].strip():
        raise InputError(f"{path}: 'foothold' (a device name) is required")

    devices = {}
    for name, spec in (data.get("devices") or {}).items():
        if isinstance(spec, str):
            spec = {"zone": spec}
        if not isinstance(spec, dict) or not isinstance(spec.get("zone"), str):
            raise InputError(f"{path}: devices[{name!r}] needs a zone, e.g. {{zone: Trusted}}")
        devices[str(name)] = spec

    zones = data.get("zones") or []
    if not isinstance(zones, list) or any(not isinstance(z, dict) or "name" not in z for z in zones):
        raise InputError(f"{path}: 'zones' must be a list of mappings with a name")

    allowed = []
    for i, pair in enumerate(data.get("allowed") or []):
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise InputError(f"{path}: allowed[{i}] must be [source, destination], got {pair!r}")
        allowed.append((str(pair[0]), str(pair[1])))

    return {"foothold": data["foothold"].strip(), "zones": zones, "devices": devices,
            "allowed": allowed, "known_hosts": [str(h) for h in data.get("known_hosts") or []],
            "hosts": data.get("hosts") or {}}
