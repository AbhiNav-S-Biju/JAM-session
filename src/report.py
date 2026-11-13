"""Reports. Owner: Person 3.

write_all(results, out_dir) writes, from one `results` dict and nothing else:
    out/results.json, out/results.csv, out/report.md, out/before_after.html
    demo/results.js   (one line: window.RESULTS = {...};  so demo/index.html works from a double click)

Shape of `results` (built by main.build_results; every value comes from the YAML files):

    {
      "scenario_file": "scenarios/home.yaml",
      "foothold": "camera",
      "thresholds": {"outbound_mb_limit": 10, "beacon_min_count": 5, "beacon_window_s": 300},
      "policies": [{"id": "flat", "description": "..."}, ...],      # config/policies.yaml order
      "before_policy": "flat",                                        # first policy in the config
      "after_policy": "vlan_deny",                                    # last policy in the config
      "zones":   [{"name", "x", "y", "w", "h"}],
      "devices": [{"id", "name", "zone", "type", "critical", "x", "y"}],
      "hosts":   [{"id", "name", "known", "x", "y"}],
      "baseline": [[src, dst], ...],                                  # sorted
      "cases": [{
        "id": "vendor", "name": "...",
        "flows": [{"src", "dst", "bytes", "t"}],
        "results": {                                                  # one entry per policy
          "flat": {
            "blast_radius": 7, "total": 7, "reachable": ["doorbell", ...],   # sorted device ids
            "reach_edges": [[src, dst], ...],   # one shortest path tree from the foothold (for drawing)
            "laptop_outbound_mb": 48.0,
            "delivered": [true, ...],           # per flow, same order as "flows": allowed by the policy?
            "alerts": [{"kind", "src", "dst", "message"}]
          }, ...
        },
        "checks": [{"policy", "key", "expected", "got", "pass"}]     # every expect: value in the YAML
      }]
    }
"""
from __future__ import annotations

import csv
import json
from html import escape
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parents[1] / "demo"


def _policy_ids(results: dict) -> list[str]:
    return [p["id"] for p in results["policies"]]


def _kinds(alerts: list[dict]) -> str:
    """Distinct alert kinds in first-seen order, e.g. 'outbound_unlisted, unlisted_flow'."""
    return ", ".join(dict.fromkeys(a["kind"] for a in alerts)) or "-"


def _mb(v: float) -> str:
    return f"{v:.1f} MB"


def _rows(results: dict) -> list[dict]:
    """One flat row per (case, policy) for the CSV."""
    rows = []
    for c in results["cases"]:
        for pid in _policy_ids(results):
            r = c["results"][pid]
            rows.append({"case": c["id"], "case_name": c["name"], "policy": pid,
                         "blast_radius": r["blast_radius"], "total": r["total"],
                         "reachable": " ".join(r["reachable"]),
                         "laptop_outbound_mb": r["laptop_outbound_mb"],
                         "alert_count": len(r["alerts"]), "alert_kinds": _kinds(r["alerts"])})
    return rows


def _val(v) -> str:
    return ", ".join(map(str, v)) if isinstance(v, list) else str(v)


def _checks(results: dict) -> list[dict]:
    """Every expect: check, with expected/got as display text."""
    return [dict(ch, case=c["id"], expected=_val(ch["expected"]), got=_val(ch["got"]))
            for c in results["cases"] for ch in c["checks"]]


def write_csv(results: dict, path: Path) -> None:
    rows = _rows(results)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["case"])
        w.writeheader()
        w.writerows(rows)


def summary_table(results: dict) -> list[list[str]]:
    """Before-and-after grid: header row, then per case a blast-radius, laptop-MB and alerts row."""
    pids = _policy_ids(results)
    table = [["Case", "Measure"] + pids]
    for c in results["cases"]:
        rs = [c["results"][p] for p in pids]
        table.append([c["id"], "Blast radius"] + [f"{r['blast_radius']} of {r['total']}" for r in rs])
        table.append([c["id"], "Laptop outbound"] + [_mb(r["laptop_outbound_mb"]) for r in rs])
        table.append([c["id"], "Alerts"] + [_kinds(r["alerts"]) for r in rs])
    return table


def markdown(results: dict) -> str:
    pids = _policy_ids(results)
    t = summary_table(results)
    out = ["# Home network segmentation: before and after", "",
           f"Scenario `{results['scenario_file']}`, compromised device (foothold): "
           f"**{results['foothold']}**. Before = `{results['before_policy']}`, "
           f"after = `{results['after_policy']}`. All traffic is simulated.", "",
           "## Policies", ""]
    out += [f"- `{p['id']}`: {p['description']}" for p in results["policies"]]
    out += ["", "## Results", "", "| " + " | ".join(t[0]) + " |", "|" + "---|" * len(t[0])]
    out += ["| " + " | ".join(row) + " |" for row in t[1:]]
    alerts = [f"- {c['id']} / {pid}: `{a['kind']}` {a['message']}"
              for c in results["cases"] for pid in pids for a in c["results"][pid]["alerts"]]
    out += ["", "## Alerts", ""] + (alerts or ["No alerts."])
    checks = _checks(results)
    passed = sum(ch["pass"] for ch in checks)
    out += ["", f"## Expected results (oracle in the scenario file): {passed} of {len(checks)} pass", "",
            "| Case | Policy | Check | Expected | Got | Result |", "|---|---|---|---|---|---|"]
    out += [f"| {ch['case']} | {ch['policy']} | {ch['key']} | {ch['expected']} | {ch['got']} | "
            f"{'PASS' if ch['pass'] else 'FAIL'} |" for ch in checks]
    th = results["thresholds"]
    out += ["", f"Thresholds: outbound limit {th['outbound_mb_limit']} MB; beaconing = "
                f"{th['beacon_min_count']} flows to one destination within {th['beacon_window_s']} s.", ""]
    return "\n".join(out)


def _svg(results: dict, case: dict, pid: str) -> str:
    """Small static map: foothold red, reachable devices orange, the rest grey."""
    r = case["results"][pid]
    pos = {n["id"]: (n["x"], n["y"]) for n in results["devices"] + results["hosts"]}
    xs = [z["x"] + z["w"] for z in results["zones"]] + [x for x, _ in pos.values()]
    ys = [z["y"] + z["h"] for z in results["zones"]] + [y for _, y in pos.values()]
    parts = [f'<svg viewBox="0 0 {max(xs) + 60} {max(ys) + 40}" role="img" '
             f'aria-label="{escape(case["id"])} under {escape(pid)}">']
    for z in results["zones"]:
        parts.append(f'<rect class="zone" x="{z["x"]}" y="{z["y"]}" width="{z["w"]}" height="{z["h"]}" rx="8"/>'
                     f'<text class="zl" x="{z["x"] + 6}" y="{z["y"] + 14}">{escape(z["name"])}</text>')
    for s, d in r["reach_edges"]:
        (x1, y1), (x2, y2) = pos[s], pos[d]
        parts.append(f'<line class="reach" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"/>')
    for f, ok in zip(case["flows"], r["delivered"]):
        (x1, y1), (x2, y2) = pos[f["src"]], pos[f["dst"]]
        parts.append(f'<line class="{"flow" if ok else "blocked"}" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"/>')
    reach = set(r["reachable"])
    for d in results["devices"]:
        cls = "foot" if d["id"] == results["foothold"] else "hit" if d["id"] in reach else "dev"
        parts.append(f'<circle class="{cls}" cx="{d["x"]}" cy="{d["y"]}" r="13"/>'
                     f'<text x="{d["x"]}" y="{d["y"] + 27}">{escape(d["name"])}</text>')
    for h in results["hosts"]:
        parts.append(f'<rect class="{"host" if h["known"] else "unk"}" x="{h["x"] - 11}" y="{h["y"] - 11}" '
                     f'width="22" height="22" rx="3"/><text x="{h["x"]}" y="{h["y"] + 25}">{escape(h["name"])}</text>')
    return "".join(parts) + "</svg>"


CSS = """
body{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#111;background:#fff}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border-bottom:1px solid #ddd;padding:5px 8px;text-align:left}
th{background:#f2f2f2}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
figure{margin:0;border:1px solid #ddd;border-radius:6px;padding:8px}figcaption{font-weight:600}
svg{width:100%;height:auto}svg text{font-size:10px;text-anchor:middle;fill:#333}svg .zl{text-anchor:start;fill:#666}
.zone{fill:#f6f7fb;stroke:#c9cde0}.dev{fill:#bbb}.hit{fill:#f39c12}.foot{fill:#d62828}.host{fill:#5b8def}.unk{fill:#222}
.reach{stroke:#f39c12;stroke-width:2}.flow{stroke:#d62828;stroke-width:2}.blocked{stroke:#999;stroke-width:2;stroke-dasharray:4 4}
.pass{color:#0a7a2f}.fail{color:#b00020;font-weight:700}
"""


def html(results: dict) -> str:
    t = summary_table(results)
    head = "".join(f"<th>{escape(h)}</th>" for h in t[0])
    body = "".join("<tr>" + "".join(f"<td>{escape(str(v))}</td>" for v in row) + "</tr>" for row in t[1:])
    figs = []
    for c in results["cases"]:
        figs.append(f"<h2>{escape(c['name'])} <small>({escape(c['id'])})</small></h2><div class='grid'>")
        for pid in (results["before_policy"], results["after_policy"]):
            r = c["results"][pid]
            figs.append(f"<figure><figcaption>{escape(pid)}: blast radius {r['blast_radius']} of {r['total']}, "
                        f"laptop out {escape(_mb(r['laptop_outbound_mb']))}, alerts {escape(_kinds(r['alerts']))}"
                        f"</figcaption>{_svg(results, c, pid)}</figure>")
        figs.append("</div>")
    checks = _checks(results)
    rows = "".join(f"<tr><td>{escape(ch['case'])}</td><td>{escape(ch['policy'])}</td><td>{escape(ch['key'])}</td>"
                   f"<td>{escape(str(ch['expected']))}</td><td>{escape(str(ch['got']))}</td>"
                   f"<td class='{'pass' if ch['pass'] else 'fail'}'>{'PASS' if ch['pass'] else 'FAIL'}</td></tr>"
                   for ch in checks)
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'><title>Before and after</title>"
            f"<style>{CSS}</style></head><body><h1>Before and after: {escape(results['before_policy'])} vs "
            f"{escape(results['after_policy'])}</h1><p>Foothold <b>{escape(results['foothold'])}</b>. Red = compromised "
            f"device, orange = devices it can reach, red line = delivered flow, dashed = blocked flow. Simulated data.</p>"
            f"<table><tr>{head}</tr>{body}</table>{''.join(figs)}"
            f"<h2>Expected results: {sum(ch['pass'] for ch in checks)} of {len(checks)} pass</h2>"
            f"<table><tr><th>Case</th><th>Policy</th><th>Check</th><th>Expected</th><th>Got</th><th>Result</th></tr>"
            f"{rows}</table></body></html>\n")


def results_js(results: dict) -> str:
    """One line. '</' is escaped so a name can never close the script tag."""
    return "window.RESULTS = " + json.dumps(results, separators=(",", ":")).replace("</", "<\\/") + ";\n"


def write_all(results: dict, out_dir: str, demo_dir: str | None = None) -> list[Path]:
    """Write the four out/ files and demo/results.js (demo_dir defaults to the repo's demo/).
    Returns the paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    demo = Path(demo_dir) if demo_dir else DEMO_DIR
    demo.mkdir(parents=True, exist_ok=True)
    paths = [out / "results.json", out / "results.csv", out / "report.md", out / "before_after.html",
             demo / "results.js"]
    paths[0].write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    write_csv(results, paths[1])
    paths[2].write_text(markdown(results), encoding="utf-8")
    paths[3].write_text(html(results), encoding="utf-8")
    paths[4].write_text(results_js(results), encoding="utf-8")
    return paths
