"""Laptop outbound checks. Owner: Person 2."""
from __future__ import annotations

from .contracts import Alert, Scenario


def check_laptop(scenario: Scenario, edges: set[tuple[str, str]],
                 thresholds: dict) -> list[Alert]:
    """Check the laptop's flows in scenario.flows.

    - outbound_unlisted: any laptop flow to a host with known == False, even if the
      policy blocks it (the alert still fires).
    - outbound_over_limit: DELIVERED bytes (flows whose (src, dst) is in edges)
      exceed thresholds["outbound_mb_limit"] megabytes.
    """
    raise NotImplementedError


def delivered_mb(scenario: Scenario, edges: set[tuple[str, str]]) -> float:
    """Megabytes the laptop actually got out under these edges (1 MB = 1_000_000 bytes).
    Used by the report and by the laptop_outbound_mb expect check."""
    raise NotImplementedError
