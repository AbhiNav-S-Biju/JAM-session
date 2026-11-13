"""Seeded traffic generator. Owner: Person 1."""
from __future__ import annotations

import dataclasses
import random

from .contracts import Flow, Scenario


def make_traffic(scenario: Scenario, seed: int, jitter_s: int = 0) -> list[Flow]:
    """Expand scenario.flows into timed events, sorted by t.

    The seed controls the jitter: each flow's t is shifted by a random whole number of
    seconds in [-jitter_s, +jitter_s] (never below 0). With the default jitter_s=0 the
    flows come back exactly as written, so the hand-written expected results hold.
    Same scenario + same seed + same jitter_s = identical output (uses random.Random(seed),
    never the global random module).
    """
    if jitter_s < 0:
        raise ValueError("jitter_s must be >= 0")
    rng = random.Random(seed)
    out = []
    for f in scenario.flows:
        shift = rng.randint(-jitter_s, jitter_s) if jitter_s else 0
        out.append(dataclasses.replace(f, t=max(0, f.t + shift)))
    return sorted(out, key=lambda f: (f.t, f.src, f.dst))
