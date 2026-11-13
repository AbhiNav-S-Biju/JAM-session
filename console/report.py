"""Printable HTML incident report (Track B, B5). Everything comes from the incident, its evidence
snapshot and a fresh chain verification; nothing is hard-coded per incident."""
from datetime import datetime, timezone
from html import escape
from typing import Optional

# Recommendation text per rule family / chain step. Shown only when that rule or step occurred.
ADVICE = {
    "R-INJ": "Treat content from untrusted sources as data, not instructions: strip or quarantine "
             "instructions found in documents before the agent sees them, and require approval for "
             "sensitive actions that follow untrusted input.",
    "R-FILE": "Keep secrets out of the agent's reach: do not mount secret folders into agent "
              "containers, and give the agent a scoped, short-lived credential instead.",
    "R-NET": "Keep default-deny egress; allow-list only the destinations the task needs and keep "
             "the IoC list updated.",
    "R-TAMP": "Logs stayed outside the container, so tampering failed. Keep the monitor on the host "
              "and the agent filesystem read-only.",
    "manual_halt": "An analyst stopped the run by hand. Review the timeline for the behaviour that "
                   "prompted the halt and decide whether it should become a detection rule.",
}
ALWAYS = [
    "Keep the container hardening (non-root, all capabilities dropped, read-only root, "
    "no-new-privileges, no Docker socket) on every run.",
    "Verify the evidence chain before sharing this report; the chain head below anchors it.",
]

CSS = """
body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #111; background: #fff;
       max-width: 960px; margin: 24px auto; padding: 0 16px; }
h1 { font-size: 24px; margin: 0; } h2 { font-size: 17px; margin: 26px 0 8px; border-bottom: 2px solid #111; padding-bottom: 3px; }
.sub { color: #555; margin: 4px 0 16px; overflow-wrap: anywhere; }
.mono, code, td.mono { font-family: Consolas, "DejaVu Sans Mono", monospace; font-size: 12.5px; }
table { width: 100%; border-collapse: collapse; margin: 6px 0; }
th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid #ddd; vertical-align: top; }
th { background: #f2f2f2; font-weight: 600; }
tr { break-inside: avoid; }
.grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.card { border: 1px solid #ccc; border-radius: 6px; padding: 8px 10px; }
.card .n { font-size: 22px; font-weight: 700; } .card .l { font-size: 11px; color: #555; text-transform: uppercase; letter-spacing: 1px; }
.sev-critical, .sev-high, .bad { color: #b00020; } .sev-medium, .warn { color: #a05a00; } .good { color: #0a7a2f; }
.tag { font-size: 11px; font-weight: 700; padding: 0 5px; border: 1px solid currentColor; border-radius: 3px; }
.violation { background: #fdecee; } .suspicious { background: #fff6e0; }
.hash { word-break: break-all; }
.verdict { font-size: 18px; font-weight: 800; }
.toolbar { margin-bottom: 16px; } .toolbar button { font: inherit; padding: 6px 14px; cursor: pointer; }
@media (max-width: 640px) { .grid { grid-template-columns: 1fr 1fr; } }
@media print { .toolbar { display: none; } body { margin: 0; max-width: none; } h2 { break-after: avoid; } }
"""


def e(v) -> str:
    return escape("" if v is None else str(v))


def ms(v) -> str:
    return "-" if v is None else f"{v} ms"


def event_summary(ev: dict) -> str:
    d = ev.get("detail") or {}
    t = ev.get("type")
    if t == "step":
        target = "" if d.get("target") in (None, "-") else f" {d['target']}"
        return f"{d.get('action')}{target} — {d.get('reason', '')}" + (" [TAINTED]" if d.get("tainted") else "")
    if t == "step_result":
        return "ok" if d.get("ok") else f"BLOCKED: {d.get('error') or 'failed'}"
    if t == "net_connect":
        return f"{d.get('src_ip')}:{d.get('src_port')} -> {d.get('dst_ip')}:{d.get('dst_port')} {d.get('proto', '')}"
    if t == "disconnect":
        return f"{d.get('container')} disconnected from {d.get('network')}"
    return d.get("path") or d.get("container") or ""


def recommendations(inc: dict) -> list:
    seen, out = set(), []
    keys = [r.get("rule_id", "").rsplit("-", 1)[0] for r in inc.get("rules_triggered") or []]
    keys += [s for s in inc.get("chain") or [] if s in ADVICE]
    for k in keys:
        if k in ADVICE and k not in seen:
            seen.add(k)
            out.append(ADVICE[k])
    return out + ALWAYS


def section_summary(inc: dict, events: list) -> str:
    sev = inc.get("severity", "")
    reason = "automatic containment" if inc.get("containment_reason") == "auto" else "manual emergency halt"
    cards = [("Risk score", inc.get("risk_score")), ("Severity", sev.upper()),
             ("Time to detect", ms(inc.get("time_to_detect_ms"))), ("Time to contain", ms(inc.get("time_to_contain_ms")))]
    rows = [("Incident", inc.get("incident_id")), ("Run", inc.get("run_id")), ("Status", inc.get("status")),
            ("Containment", reason), ("First event", inc.get("first_event_ts")),
            ("Detected at", inc.get("detected_at")), ("Contained at", inc.get("contained_at")),
            ("Events in snapshot", len(events)), ("Attack chain", " → ".join(inc.get("chain") or []))]
    return ('<div class="grid">' + "".join(
        f'<div class="card"><div class="n {"sev-" + e(sev) if label == "Severity" else ""}">{e(v)}</div>'
        f'<div class="l">{e(label)}</div></div>' for label, v in cards) + "</div>"
        + "<table>" + "".join(f"<tr><th style='width:180px'>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows)
        + "</table>")


def section_rules(inc: dict) -> str:
    rules = inc.get("rules_triggered") or []
    table = ("<table><tr><th>Rule</th><th>Name</th><th>Steps</th><th>Events</th></tr>" + "".join(
        f"<tr><td class='mono bad'>{e(r.get('rule_id'))}</td><td>{e(r.get('name'))}</td>"
        f"<td class='mono'>{e(', '.join(r.get('step_ids') or []))}</td>"
        f"<td class='mono'>{e(', '.join(r.get('event_ids') or []))}</td></tr>" for r in rules)
        + "</table>") if rules else "<p>No detection rule fired.</p>"
    notes = inc.get("notes") or []
    return table + ("<p><b>Why each rule fired</b></p><ul>" + "".join(f"<li class='mono'>{e(n)}</li>" for n in notes)
                    + "</ul>" if notes else "")


def section_risk(inc: dict) -> str:
    f = inc.get("score_factors") or {}
    if f.get("severity") is None:
        return (f"<p>Risk score <b>{e(inc.get('risk_score'))}</b>. No rule score was computed: the agent was "
                f"contained by a manual emergency halt.</p>")
    return (f"<p class='mono'>risk = round(100 × (severity/5) × (asset_value/5) × confidence)<br>"
            f"= round(100 × ({e(f.get('severity'))}/5) × ({e(f.get('asset_value'))}/5) × {e(f.get('confidence'))}) "
            f"= <b>{e(inc.get('risk_score'))}</b></p>"
            + (f"<p>Highest-scoring rule: <code>{e(f.get('rule_id'))}</code></p>" if f.get("rule_id") else ""))


def section_actions(inc: dict) -> str:
    acts = inc.get("actions_taken") or []
    if not acts:
        return "<p>No containment actions recorded.</p>"
    return ("<table><tr><th>Action</th><th>Time</th><th>Result</th><th>Took</th></tr>" + "".join(
        f"<tr><td>{e(a.get('action'))}</td><td class='mono'>{e(a.get('ts'))}</td>"
        f"<td class='{'good' if a.get('ok') else 'bad'}'>{'OK' if a.get('ok') else 'FAILED ' + e(a.get('error'))}</td>"
        f"<td>{ms(a.get('took_ms'))}</td></tr>" for a in acts) + "</table>")


def section_timeline(events: list, inc: dict) -> str:
    if not events:
        return "<p>No event snapshot was found for this incident.</p>"
    flagged = {i for r in inc.get("rules_triggered") or [] for i in r.get("event_ids") or []}
    rule_tag = ' <span class="tag bad">RULE</span>'
    return ("<table><tr><th>Time (UTC)</th><th>Step</th><th>Source / type</th><th>What happened</th><th>Verdict</th></tr>"
            + "".join(
                f"<tr class='{e(ev.get('verdict')) if ev.get('verdict') != 'allow' else ''}'>"
                f"<td class='mono'>{e((ev.get('ts') or '')[11:23])}</td><td class='mono'>{e(ev.get('step_id') or '-')}</td>"
                f"<td class='mono'>{e(ev.get('source'))}/{e(ev.get('type'))}</td>"
                f"<td>{e(event_summary(ev))}{rule_tag if ev.get('id') in flagged else ''}</td>"
                f"<td>{e((ev.get('verdict') or '').upper())}</td></tr>" for ev in events)
            + "</table>")


def section_evidence(inc: dict, verify: Optional[dict]) -> str:
    ev = inc.get("evidence") or {}
    if verify is None:
        result = "<p class='warn'>Evidence chain file not found; not verified.</p>"
    elif verify.get("ok"):
        result = (f"<p class='verdict good'>✓ VALID</p><p>Re-verified at report time: {e(verify.get('length'))} records, "
                  f"recomputed head <span class='mono hash'>{e(verify.get('head'))}</span></p>")
    else:
        result = (f"<p class='verdict bad'>✗ BROKEN</p><p>First bad record seq {e(verify.get('first_bad_seq'))}: "
                  f"{e(verify.get('reason'))}</p>")
    return (f"<table><tr><th style='width:180px'>Chain head</th><td class='mono hash'>{e(ev.get('chain_head'))}</td></tr>"
            f"<tr><th>Chain length</th><td>{e(ev.get('chain_length'))}</td></tr>"
            f"<tr><th>Event log</th><td class='mono'>{e(ev.get('log'))}</td></tr>"
            f"<tr><th>Network capture</th><td class='mono'>{e(ev.get('pcap'))}</td></tr></table>" + result
            + "<p>Each record's hash is sha256(previous hash + canonical JSON of the record), starting from 64 zeros, "
              "so editing any record changes every hash after it.</p>")


def render_report(inc: dict, events: list, verify: Optional[dict], policy_sha: Optional[str]) -> str:
    """Full report page."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    recs = "".join(f"<li>{e(r)}</li>" for r in recommendations(inc))
    iid = e(inc.get("incident_id"))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident Report {iid}</title><style>{CSS}</style></head><body>
<div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
<h1>CageWatch Incident Report · {iid}</h1>
<p class="sub">Generated {e(now)} · policy <span class="mono">{e(policy_sha or 'unknown')}</span></p>
<h2>1. Summary</h2>{section_summary(inc, events)}
<h2>2. Rules triggered</h2>{section_rules(inc)}
<h2>3. Risk breakdown</h2>{section_risk(inc)}
<h2>4. Response actions</h2>{section_actions(inc)}
<h2>5. Timeline</h2>{section_timeline(events, inc)}
<h2>6. Evidence</h2>{section_evidence(inc, verify)}
<h2>7. Recommendations and lessons learned</h2><ul>{recs}</ul>
<p class="sub">Lab prototype: scripted agent, dummy secrets, controlled simulation. CageWatch detects and contains
attempted boundary violations; it does not claim to prevent every sandbox escape.</p>
</body></html>"""
