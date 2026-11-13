"""Blast radius. Owner: Person 1."""
from __future__ import annotations

from .contracts import ReachResult


def blast_radius(edges: set[tuple[str, str]], foothold: str,
                 device_ids: list[str]) -> ReachResult:
    """Breadth-first search over the directed device-to-device edges.

    Counts devices only (not hosts, not the foothold). total = len(device_ids) - 1.
    """
    raise NotImplementedError
