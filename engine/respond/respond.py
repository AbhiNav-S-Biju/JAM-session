"""CageWatch automatic response (A6).

on_incident(inc) is registered with the detection engine (rules.set_responder). It runs ONCE per run when
risk reaches policy.containment.auto_contain_min_risk, in a background thread so event writing never stalls.

Containment order (fastest freeze first):
  1. docker pause                - freezes every process in the cage instantly
  2. docker network disconnect   - cuts all network, even if the container is later unpaused
  3. revoke temp token           - the agent's short-lived credential is marked revoked
  4. preserve evidence           - snapshot of events + pcap (vault in A7 hashes it)

Every action is recorded in the incident's actions_taken with timestamp and success, then
time_to_contain_ms = last action done - first malicious event.

emergency_halt() is the manual "big red button" (dashboard -> control.json -> engine).
"""
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUNTIME = os.path.join(ROOT, "shared", "runtime")
CONTAINER = os.environ.get("CAGEWATCH_CONTAINER", "cagewatch-agent")
NETWORK = os.environ.get("CAGEWATCH_NETWORK", "cagewatch-net")
TOKENS = os.path.join(RUNTIME, "tokens.json")

_lock = threading.Lock()
_hooks = []  # extra callables run after containment, e.g. the evidence vault (A7)


def now():
    return time.time()


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(t * 1000) % 1000:03d}Z"


def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def add_hook(fn):
    _hooks.append(fn)


# ---------------- temp credentials ----------------

def _load_tokens():
    try:
        with open(TOKENS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_tokens(t):
    os.makedirs(RUNTIME, exist_ok=True)
    tmp = TOKENS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(t, f, indent=2)
    os.replace(tmp, TOKENS)


def issue_token(run_id, ttl_s=900):
    """Short-lived credential for the run. Only a fingerprint is stored; the value never hits disk."""
    value = secrets.token_hex(16)
    t = _load_tokens()
    t[run_id] = {"fingerprint": "tok_" + value[:6] + "...", "issued_at": iso(now()),
                 "expires_at": iso(now() + ttl_s), "revoked": False}
    _save_tokens(t)
    return value


def revoke_token(run_id):
    t = _load_tokens()
    if run_id not in t:
        return False, "no token issued for run"
    t[run_id]["revoked"] = True
    t[run_id]["revoked_at"] = iso(now())
    _save_tokens(t)
    return True, None


# ---------------- actions ----------------

def _docker(*args):
    r = subprocess.run(["docker", *args], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip() or None


def pause():
    return _docker("pause", CONTAINER)


def disconnect():
    return _docker("network", "disconnect", "--force", NETWORK, CONTAINER)


def preserve_evidence(inc):
    """Copy the raw run artefacts next to the incident. A7 builds the hash chain over them."""
    dest = os.path.join(RUNTIME, "evidence", inc["incident_id"])
    os.makedirs(dest, exist_ok=True)
    copied = []
    for name in ("events.jsonl", "capture.pcap"):
        src = os.path.join(RUNTIME, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(dest, name))
            copied.append(name)
    inc["evidence"]["log"] = f"evidence/{inc['incident_id']}/events.jsonl"
    inc["evidence"]["pcap"] = f"evidence/{inc['incident_id']}/capture.pcap" if "capture.pcap" in copied else None
    return True, None


def _record(inc, name, fn):
    t0 = now()
    ok, err = fn()
    inc["actions_taken"].append({"action": name, "ts": iso(now()), "ok": ok, "error": err,
                                 "took_ms": round((now() - t0) * 1000)})
    return ok


def contain(inc, reason="auto"):
    """Run the playbook against the agent container and update the incident in place."""
    from engine.detect import rules  # shared incident store + lock

    with rules.LOCK:
        inc.setdefault("actions_taken", [])
        inc["containment_reason"] = reason
    _record(inc, "docker pause", pause)
    _record(inc, "network disconnect", disconnect)
    _record(inc, "revoke temp token", lambda: revoke_token(inc["run_id"]))
    done = now()
    with rules.LOCK:
        if "contained" not in inc["chain"]:
            inc["chain"].append("contained")
        inc["status"] = "contained" if all(a["ok"] for a in inc["actions_taken"][:2]) else "open"
        inc["contained_at"] = iso(done)
        inc["time_to_contain_ms"] = max(0, round((done - parse_ts(inc["first_event_ts"])) * 1000))
        rules.upsert_incident(inc)
    # Evidence after the freeze so the snapshot includes the containment itself.
    time.sleep(0.6)  # let the collector flush the pause/disconnect events
    _record(inc, "preserve evidence", lambda: preserve_evidence(inc))
    for h in _hooks:
        try:
            h(inc)
        except Exception as e:  # a failing hook must not undo containment
            inc["actions_taken"].append({"action": getattr(h, "__name__", "hook"), "ts": iso(now()),
                                         "ok": False, "error": str(e), "took_ms": 0})
    with rules.LOCK:
        rules.upsert_incident(inc)
    return inc


_threads = []


def on_incident(inc):
    """Detection callback: contain in the background so the collector keeps writing events."""
    t = threading.Thread(target=contain, args=(inc, "auto"), daemon=True)
    _threads.append(t)
    t.start()


def wait_all(timeout=15):
    for t in _threads:
        t.join(timeout)


def emergency_halt(run_id=None):
    """Manual halt from the dashboard. Contains the current run's incident, or opens a manual one."""
    from engine.detect import rules

    inc = rules.current_incident(run_id) if run_id else None
    if inc is None:
        t = iso(now())
        with rules.LOCK:
            inc = {"incident_id": rules.new_incident_id(t), "run_id": run_id or "manual", "status": "open",
                   "severity": "high", "risk_score": 0, "score_factors": {}, "rules_triggered": [],
                   "chain": ["task_started", "manual_halt"], "actions_taken": [], "first_event_ts": t,
                   "detected_at": t, "time_to_detect_ms": 0, "time_to_contain_ms": None,
                   "evidence": {"log": None, "pcap": None, "chain_head": None},
                   "notes": ["Emergency halt pressed by analyst"]}
            rules.upsert_incident(inc)
    return contain(inc, reason="emergency_halt")
