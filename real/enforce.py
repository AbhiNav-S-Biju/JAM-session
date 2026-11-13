"""Router control, safely.

Today this only PLANS: it writes the rules that would enforce the default-deny policy, and a
quarantine step for the compromised device. Nothing is sent to any router.

`--enforce apply` is refused until a router adapter exists for YOUR router (which model?).
When one is added: credentials come from environment variables only, are never written to a
file, log or report, and a rollback plan is produced first.
"""
from __future__ import annotations

from .ingest import InputError


class RouterAdapter:
    """Interface a real router/Firewalla adapter must implement."""

    def apply(self, plan: dict) -> None:
        raise NotImplementedError

    def rollback(self, plan: dict) -> None:
        raise NotImplementedError


ARCHER_C6_STEPS = [
    "Open http://tplinkwifi.net (or the router's address, e.g. 192.168.0.1) and sign in yourself.",
    "Go to Advanced > Security > Access Control (menu names vary by firmware; Parental Controls can also block a device).",
    "Switch Access Control on, choose Blacklist, and add {device} ({ip}). Save.",
    "Check: the device loses its connection, and the next run shows it gone from the live list.",
    "Optional: Advanced > Guest Network, put IoT devices there and keep 'Allow guests to see each other' off.",
    "Undo: remove the device from the Blacklist and save.",
]


def make_plan(results: dict, devices, show_mac: bool, mask, router: str | None = None) -> dict:
    """Rules that turn the 'after' policy into router rules, plus quarantine of the foothold.

    router='archer-c6' adds manual steps for a router that has no VLANs and no per-pair rules.
    """
    names = {d["id"]: d["name"] for d in results["devices"]} | {h["id"]: h["name"] for h in results["hosts"]}
    mac = {d.id: (d.mac if show_mac else mask(d.mac)) for d in devices}
    foot = results["foothold"]
    ip = {d.id: d.ip for d in devices}
    before = results["cases"][0]["results"][results["before_policy"]]
    after = results["cases"][0]["results"][results["after_policy"]]
    plan = {
        "mode": "dry-run (nothing was sent to any router)",
        "policy": results["after_policy"],
        "allow": [{"src": names[a], "dst": names[b], "src_mac": mac.get(a)} for a, b in results["baseline"]],
        "then": "deny everything else between devices (default-deny)",
        "quarantine": {"device": names[foot], "mac": mac.get(foot),
                       "reason": "compromised foothold",
                       "devices_reachable_before": before["blast_radius"],
                       "devices_reachable_after": after["blast_radius"]},
        "rollback": "remove the rules above; the router returns to its previous behaviour",
    }
    plan["quarantine"]["ip"] = ip.get(foot)
    if router == "archer-c6":
        plan["router"] = "TP-Link Archer C6 (US)"
        plan["can_enforce"] = ["block one device from the network", "guest network separation"]
        plan["cannot_enforce"] = (f"the {len(plan['allow'])} per-pair allow rules and default-deny between devices: "
                                  f"this router has no VLANs or per-pair rules")
        plan["manual_steps"] = [t.format(device=plan["quarantine"]["device"], ip=ip.get(foot) or "?")
                                for t in ARCHER_C6_STEPS]
    return plan


def apply_plan(plan: dict, adapter: RouterAdapter | None = None) -> None:
    if adapter is None:
        raise InputError("--enforce apply: no router adapter is configured. Only the dry-run plan is "
                         "available until we add one for your router model.")
    adapter.apply(plan)
