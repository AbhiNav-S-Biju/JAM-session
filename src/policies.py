"""Policy engine. Owner: Person 1."""
from __future__ import annotations

import yaml

from .contracts import Scenario


def _all_pairs(s: Scenario) -> set[tuple[str, str]]:
    ids = [d.id for d in s.devices] + [h.id for h in s.hosts]
    return {(d.id, n) for d in s.devices for n in ids if n != d.id}


def _same_zone(s: Scenario) -> set[tuple[str, str]]:
    return {(a.id, b.id) for a in s.devices for b in s.devices
            if a.id != b.id and a.zone == b.zone}


def _device_to_known_host(s: Scenario) -> set[tuple[str, str]]:
    return {(d.id, h.id) for d in s.devices for h in s.hosts if h.known}


def _baseline_only(s: Scenario) -> set[tuple[str, str]]:
    return set(s.baseline)


# The rule vocabulary used in config/policies.yaml. Policies themselves are NOT here.
RULES = {
    "all_pairs": _all_pairs,
    "same_zone": _same_zone,
    "device_to_known_host": _device_to_known_host,
    "baseline_only": _baseline_only,
}


def load_policies(config_path: str = "config/policies.yaml") -> dict:
    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or not isinstance(data.get("policies"), dict):
        raise ValueError(f"{config_path}: expected a top-level 'policies' mapping")
    return data["policies"]


def apply_policy(name: str, scenario: Scenario,
                 config_path: str = "config/policies.yaml") -> set[tuple[str, str]]:
    """Return the set of allowed (src, dst) edges for policy `name`.

    The rules come from config/policies.yaml (rule names: all_pairs, same_zone,
    device_to_known_host, baseline_only). The union of a policy's rules is returned.
    """
    policies = load_policies(config_path)
    if name not in policies:
        raise ValueError(f"unknown policy {name!r}; known policies: {sorted(policies)}")
    edges: set[tuple[str, str]] = set()
    for rule in policies[name].get("rules") or []:
        if rule not in RULES:
            raise ValueError(f"policy {name!r}: unknown rule {rule!r}; known rules: {sorted(RULES)}")
        edges |= RULES[rule](scenario)
    return edges
