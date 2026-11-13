"""Baseline alerts. Owner: Person 2."""
from __future__ import annotations

from collections import defaultdict

from .contracts import Alert, Scenario


def _require(thresholds: dict, key: str) -> int | float:
    if key not in thresholds:
        raise ValueError(f"thresholds: missing required key {key!r}")
    return thresholds[key]


def check_baseline(scenario: Scenario, thresholds: dict) -> list[Alert]:
    """Runs on every flow in scenario.flows, whatever the policy (the monitor is always on).

    - unlisted_flow: a flow whose (src, dst) is not in scenario.baseline AND whose dst
      is a host with known == False. One alert per flow.
    - beaconing: at least thresholds["beacon_min_count"] flows from one src to one dst
      inside thresholds["beacon_window_s"] seconds (first flow to last flow, inclusive).
      One alert per (src, dst) pair.

    Thresholds are read from the argument, never hardcoded. Alerts come back in a stable
    order (flows by time, then beaconing by src and dst), so the same input gives the
    same output.
    """
    min_count = _require(thresholds, "beacon_min_count")
    window_s = _require(thresholds, "beacon_window_s")
    if min_count < 1:
        raise ValueError(f"thresholds: beacon_min_count must be >= 1, got {min_count!r}")
    if window_s < 0:
        raise ValueError(f"thresholds: beacon_window_s must be >= 0, got {window_s!r}")

    unlisted_hosts = {h.id for h in scenario.hosts if not h.known}
    flows = sorted(scenario.flows, key=lambda f: (f.t, f.src, f.dst))
    alerts: list[Alert] = []

    # unlisted_flow: outside the baseline AND going to an unlisted host.
    for f in flows:
        if f.dst in unlisted_hosts and (f.src, f.dst) not in scenario.baseline:
            alerts.append(Alert(
                kind="unlisted_flow", src=f.src, dst=f.dst,
                message=f"{f.src} sent {f.bytes} bytes to unlisted host {f.dst} at t={f.t}s "
                        f"(not in the baseline)"))

    # beaconing: min_count flows to one destination within the window (sliding window).
    times: dict[tuple[str, str], list[int]] = defaultdict(list)
    for f in flows:
        times[(f.src, f.dst)].append(f.t)
    for (src, dst) in sorted(times):
        ts = times[(src, dst)]  # already sorted by t
        for i in range(len(ts) - min_count + 1):
            if ts[i + min_count - 1] - ts[i] <= window_s:
                alerts.append(Alert(
                    kind="beaconing", src=src, dst=dst,
                    message=f"{src} contacted {dst} {min_count} or more times within "
                            f"{window_s}s (first at t={ts[i]}s)"))
                break  # one beaconing alert per (src, dst)
    return alerts
