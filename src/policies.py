"""Policy engine. Owner: Person 1."""
from __future__ import annotations

from .contracts import Scenario


def apply_policy(name: str, scenario: Scenario,
                 config_path: str = "config/policies.yaml") -> set[tuple[str, str]]:
    """Return the set of allowed (src, dst) edges for policy `name`.

    name is one of flat, vlan_only, vlan_deny. The rules come from
    config/policies.yaml (rule names: all_pairs, same_zone, device_to_known_host,
    baseline_only). Do not hardcode policy behaviour per name in Python.
    """
    raise NotImplementedError
