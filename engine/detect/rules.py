"""CageWatch detection engine (A5).

Plugs into the collector:  python3 engine/collector/collector.py --run-id X --rules engine.detect.rules:evaluate
Replay a saved run:        python3 engine/detect/rules.py shared/runtime/events.jsonl

evaluate(event) returns a verdict (allow|suspicious|violation) and keeps per-run state. Rule hits open or
extend one incident per run, written to shared/runtime/incidents.json (contract: CLAUDE.md section 6).

Two kinds of evidence:
  intent   - the agent ANNOUNCED a risky action (agent_step). Verdict "suspicious", lower confidence.
  observed - the host SAW it happen (file / network events). Verdict "violation", high confidence.

Risk = round(100 * (severity/5) * (asset_value/5) * confidence). The incident's score is its highest hit.
A responder (A6) can register with set_responder(fn); it is called once when risk reaches
policy.containment.auto_contain_min_risk.
"""
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
POLICY_PATH = os.path.join(ROOT, "shared", "policy.json")
RUNTIME = os.path.join(ROOT, "shared", "runtime")

RULES = {
    "R-FILE-001": "Restricted file read",
    "R-NET-001": "Blocked or unknown destination",
    "R-INJ-001": "Action following untrusted (tainted) content",
    "R-TAMPER-001": "Attempt to modify logs or agent code",
}
TAMPER_PREFIXES = ("/var/log/", "/agent/", "/proc/1/")  # covering tracks / rewriting own code
STAGE = {"R-FILE-001": "restricted_file_read", "R-NET-001": "blocked_destination",
         "R-INJ-001": "injection_followed", "R-TAMPER-001": "tamper_attempt"}

_policy = None
_state = {}
_responder = None
_replay = False  # replay mode: detection time = event time


def policy():
    global _policy
    if _policy is None:
        with open(POLICY_PATH) as f:
            _policy = json.load(f)
    return _policy


def set_responder(fn):
    global _responder
    _responder = fn


def reset():
    _state.clear()


# ---------------- helpers ----------------

def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def now_iso():
    t = time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(t * 1000) % 1000:03d}Z"


def under(path, prefixes):
    return any(path == p.rstrip("/") or path.startswith(p) for p in prefixes)


def asset_value(path_or_key):
    best, val = "", 1
    for k, v in policy()["asset_values"].items():
        if path_or_key.startswith(k) and len(k) > len(best):
            best, val = k, v
    return val


def ip_matches(ip, entries):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for e in entries:
        try:
            if addr in ipaddress.ip_network(e, strict=False):
                return True
        except ValueError:
            continue
    return False


def risk(sev, asset, conf):
    return round(100 * (sev / 5) * (asset / 5) * conf)


def label(score):
    return "critical" if score >= 70 else "high" if score >= 50 else "medium" if score >= 25 else "low"


# ---------------- rules ----------------

def match_rules(e):
    """Return a list of hits: (rule_id, severity, asset_value, confidence, verdict, note)."""
    pol, d, hits = policy(), e["detail"], []
    src, typ = e["source"], e["type"]

    if src == "file" and typ in ("file_read", "file_write", "file_delete"):
        path = d.get("path", "")
        if under(path, pol["restricted_paths"]):
            hits.append(("R-FILE-001", 5, asset_value(path), 0.95, "violation", f"host saw {typ} {path}"))

    elif src == "network" and typ == "net_connect":
        dst = d.get("dst_ip", "")
        if not ip_matches(dst, pol.get("allowed_destinations", [])) and pol.get("default_network_policy") == "deny":
            ioc = dst in pol["ioc"]["ips"] or ip_matches(dst, pol.get("blocked_destinations", []))
            hits.append(("R-NET-001", 5 if ioc else 4, pol["asset_values"].get("network_egress", 4),
                         0.99 if ioc else 0.9, "violation",
                         f"egress to {dst}:{d.get('dst_port')}" + (" (IoC / blocked list)" if ioc else " (not allow-listed)")))

    elif src == "agent_step" and typ == "step":
        action, target, tainted = d.get("action", ""), str(d.get("target", "")), d.get("tainted", False)
        sensitive_file = under(target, pol["restricted_paths"])
        egress = action == "net_connect"
        if action in ("write_file", "delete_file") and under(target, TAMPER_PREFIXES):
            hits.append(("R-TAMPER-001", 4, 4, 0.9, "violation", f"agent tried to {action} {target}: {d.get('reason')}"))
        if tainted and (sensitive_file or egress):
            hits.append(("R-INJ-001", 4, asset_value(target) if sensitive_file else
                         pol["asset_values"].get("network_egress", 4), 0.8, "suspicious",
                         f"tainted agent intends {action} {target}: {d.get('reason')}"))
        elif sensitive_file:
            hits.append(("R-FILE-001", 5, asset_value(target), 0.6, "suspicious", f"agent intends {action} {target}"))
        elif egress:
            hits.append(("R-NET-001", 4, pol["asset_values"].get("network_egress", 4), 0.6, "suspicious",
                         f"agent intends to connect to {target}"))
    return hits


# ---------------- incidents ----------------

def incidents_path():
    return os.path.join(RUNTIME, "incidents.json")


def load_incidents():
    try:
        with open(incidents_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_incidents(items):
    os.makedirs(RUNTIME, exist_ok=True)
    tmp = incidents_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(items, f, indent=2)
    os.replace(tmp, incidents_path())  # atomic: the dashboard never reads a half-written file


def upsert_incident(inc):
    items = [i for i in load_incidents() if i["incident_id"] != inc["incident_id"]]
    items.append(inc)
    save_incidents(items)


def new_incident_id(event_ts):
    day = event_ts[:10]
    n = sum(1 for i in load_incidents() if i["incident_id"].startswith(f"INC-{day}-")) + 1
    return f"INC-{day}-{n:03d}"


def record_hit(e, hit):
    rule_id, sev, asset, conf, _verdict, note = hit
    run = _state.setdefault(e["run_id"], {"incident": None, "contained_called": False})
    inc = run["incident"]
    detected_at = e["ts"] if _replay else now_iso()
    if inc is None:
        inc = {
            "incident_id": new_incident_id(e["ts"]), "run_id": e["run_id"], "status": "open",
            "severity": "low", "risk_score": 0, "score_factors": {},
            "rules_triggered": [], "chain": ["task_started"], "actions_taken": [],
            "first_event_ts": e["ts"], "detected_at": detected_at,
            "time_to_detect_ms": None, "time_to_contain_ms": None,
            "evidence": {"log": None, "pcap": None, "chain_head": None},
            "notes": [],
        }
        run["incident"] = inc

    rt = next((r for r in inc["rules_triggered"] if r["rule_id"] == rule_id), None)
    if rt is None:
        rt = {"rule_id": rule_id, "name": RULES[rule_id], "event_ids": [], "step_ids": []}
        inc["rules_triggered"].append(rt)
    rt["event_ids"].append(e["id"])
    if e.get("step_id") and e["step_id"] not in rt["step_ids"]:
        rt["step_ids"].append(e["step_id"])
    inc["notes"].append(f"{e['id']} {rule_id}: {note}")
    if STAGE[rule_id] not in inc["chain"]:
        inc["chain"].append(STAGE[rule_id])

    score = risk(sev, asset, conf)
    if score > inc["risk_score"]:
        inc["risk_score"] = score
        inc["score_factors"] = {"severity": sev, "asset_value": asset, "confidence": conf, "rule_id": rule_id}
        inc["severity"] = label(score)

    threshold = policy()["containment"]["auto_contain_min_risk"]
    if inc["risk_score"] >= threshold and inc["time_to_detect_ms"] is None:
        # time from the first observed malicious event to the moment we crossed the containment threshold
        inc["time_to_detect_ms"] = max(0, round((parse_ts(detected_at) - parse_ts(inc["first_event_ts"])) * 1000))
        inc["detected_at"] = detected_at
    upsert_incident(inc)

    if inc["risk_score"] >= threshold and _responder and not run["contained_called"]:
        run["contained_called"] = True
        _responder(inc)


def evaluate(event):
    """Collector hook. Returns the verdict for this event."""
    hits = match_rules(event)
    for h in hits:
        record_hit(event, h)
    if any(h[4] == "violation" for h in hits):
        return "violation"
    return "suspicious" if hits else "allow"


def current_incident(run_id):
    return (_state.get(run_id) or {}).get("incident")


# ---------------- replay CLI ----------------

def replay(path, write=True):
    global _replay
    _replay = True
    reset()
    events = [json.loads(l) for l in open(path) if l.strip()]
    for e in events:
        e["verdict"] = evaluate(e)
    if write:
        with open(path, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
    return events


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: rules.py <events.jsonl>")
        sys.exit(2)
    evs = replay(sys.argv[1])
    for e in evs:
        if e["verdict"] != "allow":
            print(e["id"], e["verdict"], e["source"], e["type"], e.get("step_id"))
    runs = {e["run_id"] for e in evs}
    for r in runs:
        inc = current_incident(r)
        print(r, "->", json.dumps({k: inc[k] for k in ("incident_id", "severity", "risk_score", "score_factors",
                                                         "chain", "time_to_detect_ms")}) if inc else "no incident")
