"""Baseline alerts. Owner: Person 2."""
from __future__ import annotations

from .contracts import Alert, Scenario


def check_baseline(scenario: Scenario, thresholds: dict) -> list[Alert]:
    """Runs on every flow in scenario.flows, whatever the policy (the monitor is always on).

    - unlisted_flow: a flow whose (src, dst) is not in scenario.baseline AND whose dst
      is a host with known == False.
    - beaconing: at least thresholds["beacon_min_count"] flows from one src to one dst
      inside thresholds["beacon_window_s"] seconds.
    """
    raise NotImplementedError
