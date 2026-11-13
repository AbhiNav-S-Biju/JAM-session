"""Laptop outbound checks. Owner: Person 2."""
from __future__ import annotations

from collections import defaultdict

from .contracts import Alert, Scenario

BYTES_PER_MB = 1_000_000  # 1 MB = 1,000,000 bytes, so 48_000_000 bytes = 48.0 MB


def _laptops(scenario: Scenario) -> set[str]:
    """Ids of devices whose type is 'laptop'. Found from the data, never by a hardcoded id."""
    return {d.id for d in scenario.devices if d.type == "laptop"}


def _limit_mb(thresholds: dict) -> float:
    if "outbound_mb_limit" not in thresholds:
        raise ValueError("thresholds: missing required key 'outbound_mb_limit'")
    limit = thresholds["outbound_mb_limit"]
    if isinstance(limit, bool) or not isinstance(limit, (int, float)) or limit < 0:
        raise ValueError(f"thresholds: outbound_mb_limit must be a number >= 0, got {limit!r}")
    return limit


def _outbound_flows(scenario: Scenario):
    """Laptop flows that leave the home (the destination is a host, not another device)."""
    laptops = _laptops(scenario)
    host_ids = {h.id for h in scenario.hosts}
    return [f for f in sorted(scenario.flows, key=lambda f: (f.t, f.src, f.dst))
            if f.src in laptops and f.dst in host_ids]


def delivered_mb(scenario: Scenario, edges: set[tuple[str, str]]) -> float:
    """Megabytes the laptop actually got out under these edges (1 MB = 1_000_000 bytes).

    Counts only flows to outside hosts whose (src, dst) is in edges. A blocked flow
    delivered nothing. Used by the report and by the laptop_outbound_mb expect check.
    """
    total = sum(f.bytes for f in _outbound_flows(scenario) if (f.src, f.dst) in edges)
    return total / BYTES_PER_MB


def check_laptop(scenario: Scenario, edges: set[tuple[str, str]],
                 thresholds: dict) -> list[Alert]:
    """Check the laptop's flows in scenario.flows.

    - outbound_unlisted: any laptop flow to a host with known == False, even if the
      policy blocks it (the attempt itself is the signal). One alert per flow.
    - outbound_over_limit: DELIVERED bytes (flows whose (src, dst) is in edges)
      exceed thresholds["outbound_mb_limit"] megabytes. One alert per laptop, counting
      every outside host; blocked bytes never count. Strictly greater than the limit.

    The limit comes from the thresholds argument, never from a number in this file.
    """
    limit = _limit_mb(thresholds)
    unlisted_hosts = {h.id for h in scenario.hosts if not h.known}
    flows = _outbound_flows(scenario)
    alerts: list[Alert] = []

    for f in flows:
        if f.dst in unlisted_hosts:
            outcome = "delivered" if (f.src, f.dst) in edges else "blocked by policy"
            alerts.append(Alert(
                kind="outbound_unlisted", src=f.src, dst=f.dst,
                message=f"{f.src} sent {f.bytes} bytes to unlisted host {f.dst} at t={f.t}s ({outcome})"))

    delivered: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in flows:
        if (f.src, f.dst) in edges:
            delivered[f.src][f.dst] += f.bytes
    for src in sorted(delivered):
        total_mb = sum(delivered[src].values()) / BYTES_PER_MB
        if total_mb > limit:
            # dst = the host that received the most (ties: lowest id); the message gives the total.
            top = min(delivered[src], key=lambda d: (-delivered[src][d], d))
            alerts.append(Alert(
                kind="outbound_over_limit", src=src, dst=top,
                message=f"{src} delivered {total_mb:.1f} MB to outside hosts, over the "
                        f"{limit} MB limit (most to {top})"))
    return alerts
