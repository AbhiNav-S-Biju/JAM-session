"""Computed map layout. Positions come from zones.yaml when given, otherwise from this grid.

Nothing here is a hardcoded list of devices; it only turns counts into coordinates.
"""
from __future__ import annotations

import math

CELL_W, CELL_H = 90, 60
COLS = 2
PAD_TOP = 34
ZONES_PER_ROW = 3
ZONE_GAP = 30
X0, Y0 = 40, 70
HOST_Y = 30
HOST_STEP = 120


def layout(zone_names: list[str], devices: list[dict], zone_specs: dict[str, dict],
           host_ids: list[str], host_pos: dict[str, dict]) -> tuple[list[dict], dict, dict]:
    """Return (zones, device_positions, host_positions).

    devices: [{'id', 'zone', 'x'?, 'y'?}]. zone_specs: {zone name: {'x','y','w','h'}} (all four to be used).
    """
    members: dict[str, list[dict]] = {z: [] for z in zone_names}
    for d in devices:
        members[d["zone"]].append(d)

    zones, placed = [], {}
    cursor_x, cursor_y, row_h, col = X0, Y0, 0, 0
    for name in zone_names:
        spec = zone_specs.get(name) or {}
        n = max(len(members[name]), 1)
        if all(isinstance(spec.get(k), (int, float)) for k in ("x", "y", "w", "h")):
            z = {"name": name, "x": spec["x"], "y": spec["y"], "w": spec["w"], "h": spec["h"]}
        else:
            w = COLS * CELL_W + 20
            h = PAD_TOP + math.ceil(n / COLS) * CELL_H
            if col == ZONES_PER_ROW:
                cursor_x, cursor_y, row_h, col = X0, cursor_y + row_h + ZONE_GAP, 0, 0
            z = {"name": name, "x": cursor_x, "y": cursor_y, "w": w, "h": h}
            cursor_x += w + ZONE_GAP
            row_h = max(row_h, h)
            col += 1
        zones.append(z)
        for i, d in enumerate(members[name]):
            if isinstance(d.get("x"), (int, float)) and isinstance(d.get("y"), (int, float)):
                placed[d["id"]] = (d["x"], d["y"])
            else:
                placed[d["id"]] = (z["x"] + 10 + CELL_W * (i % COLS) + CELL_W // 2,
                                   z["y"] + PAD_TOP + CELL_H * (i // COLS) + 16)

    hosts = {}
    for i, hid in enumerate(host_ids):
        p = host_pos.get(hid) or {}
        if isinstance(p.get("x"), (int, float)) and isinstance(p.get("y"), (int, float)):
            hosts[hid] = (p["x"], p["y"])
        else:
            hosts[hid] = (60 + HOST_STEP * i, HOST_Y)
    return zones, placed, hosts
