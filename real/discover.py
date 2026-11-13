"""OPT-IN live discovery of YOUR OWN home network.

Only runs when the user passes --live-discover with --subnet and --i-own-this-network.

What it does: sends ONE ordinary ping to each address in the subnet you name (so your OS
fills its ARP table), then reads that table with `arp -a`. What it does NOT do: scan ports,
probe services, try passwords, or touch anything outside the private ranges below.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .ingest import InputError, norm_mac, parse_arp

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
MAX_HOSTS = 1024   # /22


def validate_subnet(text: str) -> ipaddress.IPv4Network:
    """Accept only private (RFC 1918) IPv4 subnets of at most 1024 addresses."""
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        raise InputError(f"--subnet {text!r} is not a valid network, e.g. 192.168.1.0/24") from None
    if net.version != 4 or not any(net.subnet_of(p) for p in PRIVATE):
        raise InputError(f"--subnet {text!r} is not a private home range "
                         f"(allowed: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Refusing.")
    if net.num_addresses > MAX_HOSTS:
        raise InputError(f"--subnet {text!r} is larger than {MAX_HOSTS} addresses (/22). Refusing.")
    return net


def ping_command(ip: str, windows: bool | None = None) -> list[str]:
    windows = platform.system() == "Windows" if windows is None else windows
    return ["ping", "-n", "1", "-w", "700", ip] if windows else ["ping", "-c", "1", "-W", "1", ip]


def sweep(net: ipaddress.IPv4Network, runner=subprocess.run, workers: int = 32) -> int:
    """One ping per host address. Returns how many answered. Arguments are a list, never a shell string."""
    def one(ip) -> bool:
        try:
            r = runner(ping_command(str(ip)), capture_output=True, timeout=5)
            return r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return sum(pool.map(one, net.hosts()))


def read_arp_table(runner=subprocess.run) -> list[dict]:
    """Run `arp -a` on this computer and parse it. Local only."""
    try:
        r = runner(["arp", "-a"], capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise InputError(f"could not run `arp -a`: {e}") from None
    return parse_arp(r.stdout or "", "live `arp -a`")


_MAC = re.compile(r"Physical Address[ .]*:\s*([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})")
_IP4 = re.compile(r"IPv4 Address[ .]*:\s*(\d{1,3}(?:\.\d{1,3}){3})")


def own_entry(net: ipaddress.IPv4Network, runner=subprocess.run, system: str | None = None) -> dict | None:
    """This computer's own address on the subnet, from `ipconfig /all` (Windows only, local, no network).

    A computer never lists itself in its own ARP table, so the scan would otherwise miss it.
    """
    if (system or platform.system()) != "Windows":
        return None
    try:
        out = runner(["ipconfig", "/all"], capture_output=True, text=True, timeout=15).stdout or ""
    except (subprocess.TimeoutExpired, OSError):
        return None
    mac = None
    for line in out.splitlines():
        if line and not line[0].isspace():       # a new adapter section starts
            mac = None
        m = _MAC.search(line)
        if m:
            mac = m.group(1)
        i = _IP4.search(line)
        if i and mac and ipaddress.ip_address(i.group(1)) in net:
            return {"ip": i.group(1), "mac": norm_mac(mac)}
    return None


def discover(subnet: str, runner=subprocess.run) -> list[dict]:
    """Ping the subnet once, read the ARP table, and add this computer. Only addresses inside the subnet."""
    net = validate_subnet(subnet)
    sweep(net, runner)
    rows = [e for e in read_arp_table(runner) if ipaddress.ip_address(e["ip"]) in net]
    me = own_entry(net, runner)
    if me and me["mac"] not in {r["mac"] for r in rows}:
        rows.append(me)
    return rows
