"""OPT-IN live discovery of YOUR OWN home network.

Only runs when the user passes --live-discover with --subnet and --i-own-this-network.

What it does: sends ONE ordinary ping to each address in the subnet you name (so your OS
fills its ARP table), then reads that table with `arp -a`. What it does NOT do: scan ports,
probe services, try passwords, or touch anything outside the private ranges below.
"""
from __future__ import annotations

import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .ingest import InputError, parse_arp

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


def discover(subnet: str, runner=subprocess.run) -> list[dict]:
    """Ping the subnet once, then read the ARP table, keeping only addresses inside the subnet."""
    net = validate_subnet(subnet)
    sweep(net, runner)
    return [e for e in read_arp_table(runner) if ipaddress.ip_address(e["ip"]) in net]
