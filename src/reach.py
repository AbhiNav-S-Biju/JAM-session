"""Blast radius. Owner: Person 1."""
from __future__ import annotations

from collections import deque

from .contracts import ReachResult


def blast_radius(edges: set[tuple[str, str]], foothold: str,
                 device_ids: list[str]) -> ReachResult:
    """Breadth-first search over the directed device-to-device edges.

    Counts devices only (not hosts, not the foothold). total = len(device_ids) - 1.
    """
    devices = set(device_ids)
    if foothold not in devices:
        raise ValueError(f"foothold {foothold!r} is not in device_ids")

    out: dict[str, list[str]] = {}
    for src, dst in edges:
        if src in devices and dst in devices:
            out.setdefault(src, []).append(dst)

    seen = {foothold}
    queue = deque([foothold])
    while queue:
        cur = queue.popleft()
        for nxt in out.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)

    reachable = frozenset(seen - {foothold})
    return ReachResult(reachable=reachable, count=len(reachable), total=len(devices) - 1)
