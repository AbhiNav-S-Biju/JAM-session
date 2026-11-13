"""Load and validate scenario files. Owner: Person 1."""
from __future__ import annotations

from .contracts import Scenario


def load_scenario(path: str) -> Scenario:
    """Read a scenario YAML file into a Scenario.

    Must validate every reference: each flow and baseline entry names an existing
    device or host, foothold is a device, every device zone exists. A bad reference
    raises ValueError that names the offending entry.
    """
    raise NotImplementedError


def load_thresholds(path: str = "config/thresholds.yaml") -> dict:
    """Read config/thresholds.yaml into a dict."""
    raise NotImplementedError


def with_case(scenario: Scenario, case_id: str) -> Scenario:
    """Return a copy of scenario whose .flows are the flows of the named case."""
    raise NotImplementedError
