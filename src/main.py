"""CLI entry point. Owner: Person 3.

    python -m src.main scenarios/home.yaml --out out/

Runs every case under every policy, collects blast radius, laptop outbound MB and
alerts, calls report.write_all, and prints the before-and-after table.
"""
from __future__ import annotations

import argparse
import dataclasses
from collections import deque

from .alerts import check_baseline
from .contracts import Scenario
from .model import load_scenario, load_thresholds, with_case
from .outbound import check_laptop, delivered_mb
from .policies import apply_policy, load_policies
from .reach import blast_radius
from .report import summary_table, write_all


def reach_tree(edges: set[tuple[str, str]], foothold: str, reachable: frozenset[str]) -> list[list[str]]:
    """One shortest path tree from the foothold over the reachable devices, for drawing only.
    The blast-radius numbers come from reach.blast_radius, not from this."""
    nodes = reachable | {foothold}
    out: dict[str, list[str]] = {}
    for s, d in sorted(edges):
        if s in nodes and d in nodes:
            out.setdefault(s, []).append(d)
    seen, queue, tree = {foothold}, deque([foothold]), []
    while queue:
        cur = queue.popleft()
        for nxt in out.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
                tree.append([cur, nxt])
    return tree


def run_policy(s: Scenario, policy: str, thresholds: dict, policies_path: str) -> dict:
    """All measures for one case (already selected with with_case) under one policy."""
    edges = apply_policy(policy, s, policies_path)
    r = blast_radius(edges, s.foothold, [d.id for d in s.devices])
    alerts = check_laptop(s, edges, thresholds) + check_baseline(s, thresholds)
    return {"blast_radius": r.count, "total": r.total, "reachable": sorted(r.reachable),
            "reach_edges": reach_tree(edges, s.foothold, r.reachable),
            "laptop_outbound_mb": round(delivered_mb(s, edges), 3),
            "delivered": [(f.src, f.dst) in edges for f in s.flows],
            "alerts": [dataclasses.asdict(a) for a in alerts]}


def check(key: str, expected, got: dict):
    """Compare one expect: value with the measured result. Returns (got_value, passed)."""
    if key == "blast_radius":
        return got["blast_radius"], got["blast_radius"] == expected
    if key == "laptop_outbound_mb":
        return got["laptop_outbound_mb"], abs(got["laptop_outbound_mb"] - float(expected)) < 1e-9
    if key == "alerts":   # "these kinds must be present", not "exactly these"
        kinds = sorted({a["kind"] for a in got["alerts"]})
        return kinds, set(expected) <= set(kinds)
    return f"unknown check {key!r}", False


def build_results(scenario_path: str, policies_path: str = "config/policies.yaml",
                  thresholds_path: str = "config/thresholds.yaml") -> dict:
    """Run every case under every policy and return the `results` dict (shape: see report.py)."""
    scenario = load_scenario(scenario_path)
    thresholds = load_thresholds(thresholds_path)
    policies = load_policies(policies_path)
    pids = list(policies)
    cases = []
    for case in scenario.cases:
        s = with_case(scenario, case.id)
        res = {p: run_policy(s, p, thresholds, policies_path) for p in pids}
        checks = []
        for key, per_policy in case.expect.items():
            for p, expected in (per_policy or {}).items():
                got, ok = check(key, expected, res[p]) if p in res else (f"unknown policy {p!r}", False)
                checks.append({"policy": p, "key": key, "expected": expected, "got": got, "pass": ok})
        cases.append({"id": case.id, "name": case.name,
                      "flows": [dataclasses.asdict(f) for f in case.flows],
                      "results": res, "checks": checks})
    return {"scenario_file": scenario_path.replace("\\", "/"), "foothold": scenario.foothold,
            "thresholds": thresholds,
            "policies": [{"id": p, "description": (policies[p] or {}).get("description", "")} for p in pids],
            "before_policy": pids[0], "after_policy": pids[-1],
            "zones": [dataclasses.asdict(z) for z in scenario.zones],
            "devices": [dataclasses.asdict(d) for d in scenario.devices],
            "hosts": [dataclasses.asdict(h) for h in scenario.hosts],
            "baseline": sorted([list(p) for p in scenario.baseline]),
            "cases": cases}


def format_table(rows: list[list[str]]) -> str:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    line = lambda r: "  ".join(v.ljust(w) for v, w in zip(r, widths)).rstrip()
    return "\n".join([line(rows[0]), "  ".join("-" * w for w in widths)] + [line(r) for r in rows[1:]])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Home network segmentation simulator (simulated data only).")
    ap.add_argument("scenario", help="scenario YAML, e.g. scenarios/home.yaml")
    ap.add_argument("--out", default="out/", help="output folder (default out/)")
    ap.add_argument("--policies", default="config/policies.yaml")
    ap.add_argument("--thresholds", default="config/thresholds.yaml")
    ap.add_argument("--demo", default=None, help="folder for results.js (default demo/)")
    a = ap.parse_args(argv)
    results = build_results(a.scenario, a.policies, a.thresholds)
    paths = write_all(results, a.out, a.demo)
    print(f"Foothold: {results['foothold']}   before = {results['before_policy']}, "
          f"after = {results['after_policy']}\n")
    print(format_table(summary_table(results)))
    checks = [ch for c in results["cases"] for ch in c["checks"]]
    failed = [ch for ch in checks if not ch["pass"]]
    print(f"\nExpected results: {len(checks) - len(failed)} of {len(checks)} pass")
    for ch in failed:
        print(f"  FAIL {ch['policy']} {ch['key']}: expected {ch['expected']}, got {ch['got']}")
    print("\nWrote: " + ", ".join(str(p) for p in paths))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
