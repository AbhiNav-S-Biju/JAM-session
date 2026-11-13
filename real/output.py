"""Write devices.json, connections.json, report.md, map.html (and enforcement_plan.json). Local files only."""
from __future__ import annotations

import json
from pathlib import Path

from src.main import format_table
from src.report import summary_table

from .ingest import mask_mac

DEMO_HTML = Path(__file__).resolve().parents[1] / "demo" / "index.html"
SCRIPT_TAG = '<script src="results.js"></script>'


def _mac(mac: str, show: bool) -> str:
    return mac if show else mask_mac(mac)


def write_devices(path: Path, extras: dict, show_mac: bool) -> None:
    rows = [{"id": d.id, "name": d.name, "ip": d.ip, "mac": _mac(d.mac, show_mac),
             "zone": extras["zone_of"][d.id], "sources": d.sources, "flags": d.flags,
             "status": d.status, "extra": d.extra} for d in extras["devices"]]
    path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


def write_connections(path: Path, results: dict, extras: dict, traffic_provided: bool) -> None:
    data = {"observed": extras["observed"], "declared_allowed": extras["declared_allowed"],
            "traffic_file_provided": traffic_provided,
            "device_to_device_rows": extras["device_to_device_rows"],
            "skipped_rows": extras["skipped"], "notes": extras["notes"]}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def markdown(results: dict, extras: dict, show_mac: bool) -> str:
    names = extras["names"]
    t = summary_table(results)
    out = ["# Real home network: blast radius and alerts", "",
           f"Input folder `{results['scenario_file']}`. Compromised device (foothold): "
           f"**{names[results['foothold']]}**. MAC addresses are "
           f"{'shown in full' if show_mac else 'masked (last 3 octets only)'}.", "",
           "## Devices", "", "| Name | IP | MAC | Zone | Seen by | Flags |", "|---|---|---|---|---|---|"]
    for d in extras["devices"]:
        out.append(f"| {d.name} | {d.ip} | {_mac(d.mac, show_mac)} | {extras['zone_of'][d.id]} | "
                   f"{', '.join(d.sources)} | {'; '.join(d.flags) or '-'} |")
    out += ["", "## Results (before = " + results["before_policy"] + ", after = " + results["after_policy"] + ")", "",
            "| " + " | ".join(t[0]) + " |", "|" + "---|" * len(t[0])]
    out += ["| " + " | ".join(r) + " |" for r in t[1:]]
    out += ["", "## What the data does and does not show", ""]
    out += [f"- {n}" for n in extras["notes"]] or ["- Nothing unusual about the inputs."]
    out += [f"- Observed traffic rows: {len(extras['observed'])}, of which device-to-device: "
            f"{extras['device_to_device_rows']}.",
            "- Blast radius is computed from the zones and allowed pairs YOU declared in zones.yaml, "
            "not from reading your router's real firewall rules.",
            "- Cases marked [SIMULATED] use synthetic flows; no packet was sent to any device."]
    alerts = [f"- {c['id']} / {p['id']}: `{a['kind']}` {a['message']}"
              for c in results["cases"] for p in results["policies"] for a in c["results"][p["id"]]["alerts"]]
    out += ["", "## Alerts", ""] + (alerts or ["No alerts."])
    return "\n".join(out) + "\n"


def write_map(path: Path, results: dict) -> None:
    """Copy the existing demo page with the data inlined, so a double-click works (no results.js needed)."""
    html = DEMO_HTML.read_text(encoding="utf-8")
    if SCRIPT_TAG not in html:
        raise RuntimeError(f"{DEMO_HTML}: expected {SCRIPT_TAG!r}; the demo page changed, update real/output.py")
    data = json.dumps(results).replace("</", "<\\/")
    html = html.replace(SCRIPT_TAG, f"<script>window.RESULTS = {data};</script>")
    html = html.replace("Home Network Blast Radius", "My Home Network: Blast Radius")
    html = html.replace('". Simulated data from "', '". Data from "')
    banner = ('<p class="sub" id="sub"></p><p class="sub"><b style="color:#0a7a2f">REAL NETWORK</b>: your own '
              'devices. Cases marked [SIMULATED] are pretend attacks on the real map. '
              '<a href="../index.html">Back to the launcher</a></p>')
    html = html.replace('<p class="sub" id="sub"></p>', banner)
    path.write_text(html, encoding="utf-8")


def write_all(out_dir: str, results: dict, extras: dict, show_mac: bool, traffic_provided: bool,
              plan: dict | None = None) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = [out / "devices.json", out / "connections.json", out / "report.md", out / "map.html"]
    write_devices(paths[0], extras, show_mac)
    write_connections(paths[1], results, extras, traffic_provided)
    paths[2].write_text(markdown(results, extras, show_mac), encoding="utf-8")
    write_map(paths[3], results)
    from src.report import results_js   # also written so iot/index.html?data=real can load it
    (out / "results.js").write_text(results_js(results), encoding="utf-8")
    if plan is not None:
        p = out / "enforcement_plan.json"
        p.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        paths.append(p)
    return paths


def write_zones_template(input_dir: str, devices, foothold_name: str) -> Path:
    """A starting point for zones.yaml listing every discovered device. Never overwrites zones.yaml."""
    import yaml
    path = Path(input_dir) / "zones.template.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"foothold": foothold_name,
            "devices": {d.name: {"zone": "unassigned", "type": "", "critical": False} for d in devices},
            "allowed": [], "known_hosts": []}
    # Never overwrite a template that already exists: you may have edited it. Delete it to regenerate.
    if not path.exists():
        path.write_text("# Copy to zones.yaml, rename devices you recognise, set real zones.\n"
                        + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    import csv
    names_path = Path(input_dir) / "names.template.csv"
    if not names_path.exists():
        with names_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "name"])
            w.writerows([[d.ip, d.name] for d in devices])
    return path


def console_table(results: dict) -> str:
    return format_table(summary_table(results))
