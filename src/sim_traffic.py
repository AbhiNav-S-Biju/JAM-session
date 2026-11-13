"""Seeded traffic generator. Owner: Person 1."""
from __future__ import annotations

from .contracts import Flow, Scenario


def make_traffic(scenario: Scenario, seed: int) -> list[Flow]:
    """Expand scenario.flows into timed events, sorted by t.

    The seed controls any jitter. Same scenario + same seed = identical output.
    Use random.Random(seed), never the global random module.
    """
    raise NotImplementedError
