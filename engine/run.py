"""CageWatch one-command runner (A8). Run inside WSL Ubuntu from the repo root.

  python3 engine/run.py benign | attack | benign_unusual   one run, live timeline in the terminal, summary at the end
  python3 engine/run.py serve-control                       wait for dashboard commands in shared/runtime/control.json
  python3 engine/run.py halt                                emergency halt the running agent
  python3 engine/run.py reset                               remove the agent container, clear live events
  python3 engine/run.py status                              print shared/runtime/engine_status.json

control.json (written by the dashboard, Track B):  {"cmd": "run_benign|run_attack|run_benign_unusual|emergency_halt|reset", "ts": "..."}
engine_status.json (written here, read by the dashboard):
  {"state": "idle|running|contained|finished|error", "mode", "run_id", "incident_id", "message", "updated_at", "last_cmd"}
"""
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
RUNTIME = os.path.join(ROOT, "shared", "runtime")
CONTROL = os.path.join(RUNTIME, "control.json")
STATUS = os.path.join(RUNTIME, "engine_status.json")
EVENTS = os.path.join(RUNTIME, "events.jsonl")
CONTAINER = "cagewatch-agent"
MODES = ("benign", "attack", "benign_unusual")
COMMANDS = {"run_benign", "run_attack", "run_benign_unusual", "emergency_halt", "reset"}

C = {"allow": "\033[32m", "suspicious": "\033[33m", "violation": "\033[31;1m", "dim": "\033[2m",
     "bold": "\033[1m", "red": "\033[41;97;1m", "green": "\033[42;30;1m", "end": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}

_run_lock = threading.Lock()
_current = {"run_id": None, "mode": None, "proc": None}


def iso():
    t = time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(t * 1000) % 1000:03d}Z"


def write_status(**kw):
    os.makedirs(RUNTIME, exist_ok=True)
    try:
        st = json.load(open(STATUS))
    except (OSError, ValueError):
        st = {}
    st.update(kw, updated_at=iso())
    tmp = STATUS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=2)
    os.replace(tmp, STATUS)


def incident_for(run_id):
    try:
        return next((i for i in json.load(open(os.path.join(RUNTIME, "incidents.json"))) if i["run_id"] == run_id), None)
    except (OSError, ValueError):
        return None


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


# ---------------- live view ----------------

def describe(e):
    d = e["detail"]
    if e["type"] == "step":
        taint = f" {C['violation']}[tainted]{C['end']}" if d.get("tainted") else ""
        return f"{d.get('action')} {d.get('target')}{taint}  {C['dim']}{d.get('reason')}{C['end']}"
    if e["type"] == "step_result":
        return f"{C['dim']}result: {'ok' if d.get('ok') else 'BLOCKED ' + str(d.get('error'))}{C['end']}"
    if e["source"] == "file":
        return f"{e['type']} {d.get('path')}"
    if e["source"] == "network":
        return f"connect {d.get('dst_ip')}:{d.get('dst_port')}/{d.get('proto')}"
    return f"{e['type']} {d.get('network') or ''}"


def tail_events(stop):
    """Print events.jsonl as the collector writes it."""
    pos = 0
    while not stop.is_set() or (os.path.exists(EVENTS) and os.path.getsize(EVENTS) > pos):
        if os.path.exists(EVENTS):
            with open(EVENTS) as f:
                f.seek(pos)
                for line in f:
                    if not line.endswith("\n"):
                        break
                    pos += len(line.encode())
                    e = json.loads(line)
                    if e["type"] == "step_result" and e["detail"].get("ok"):
                        continue
                    v = e["verdict"]
                    print(f"  {e['ts'][11:23]} {C[v]}{v.upper():<10}{C['end']} {e['source']:<10} "
                          f"{str(e['step_id'] or ''):<8} {describe(e)}", flush=True)
        time.sleep(0.15)


def summary(run_id):
    inc = incident_for(run_id)
    print()
    if not inc:
        print(f"{C['green']}  SAFE  {C['end']} {run_id}: no incident")
        return
    print(f"{C['red']}  {inc['status'].upper()}  {C['end']} {inc['incident_id']}  severity={inc['severity']}  risk={inc['risk_score']}")
    f = inc["score_factors"]
    print(f"  risk = 100 x ({f.get('severity')}/5) x ({f.get('asset_value')}/5) x {f.get('confidence')}   [{f.get('rule_id')}]")
    print(f"  chain: {' -> '.join(inc['chain'])}")
    for r in inc["rules_triggered"]:
        print(f"  {r['rule_id']:<13} {r['name']:<44} steps={','.join(r['step_ids'])}")
    print(f"  time to detect: {inc['time_to_detect_ms']} ms   time to contain: {inc['time_to_contain_ms']} ms")
    for a in inc["actions_taken"]:
        print(f"  {'OK ' if a['ok'] else 'ERR'} {a['action']:<20} {a['took_ms']} ms {a.get('error') or ''}")
    ev = inc["evidence"]
    print(f"  evidence: {ev.get('chain')} ({ev.get('chain_length')} records)")
    print(f"  chain head: {ev.get('chain_head')}")
    st = docker("inspect", "-f", "{{.State.Status}} networks=[{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}]", CONTAINER)
    print(f"  container: {st.stdout.strip() or st.stderr.strip()}")


# ---------------- actions ----------------

def run(mode, quiet=False):
    if mode not in MODES:
        raise SystemExit(f"mode must be one of {MODES}")
    if not _run_lock.acquire(blocking=False):
        return False, "a run is already in progress"
    try:
        run_id = f"run-{mode}-{time.strftime('%Y%m%d-%H%M%S')}"
        _current.update(run_id=run_id, mode=mode)
        write_status(state="running", mode=mode, run_id=run_id, incident_id=None, message="starting collector")
        docker("rm", "-f", CONTAINER)
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "engine", "collector", "collector.py"),
                                 "--run-id", run_id, "--until-exit", "--rules", "engine.detect.rules:evaluate",
                                 "--respond"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        _current["proc"] = proc
        log = []
        for line in proc.stdout:  # wait for readiness (first run may build the network-monitor image)
            log.append(line)
            if "collector: ready" in line:
                break
        else:
            write_status(state="error", message="collector failed to start")
            print("".join(log))
            return False, "collector failed to start"
        threading.Thread(target=lambda: [log.append(l) for l in proc.stdout], daemon=True).start()

        if not quiet:
            print(f"{C['bold']}CageWatch run {run_id}{C['end']}  (agent mode: {mode})\n")
        stop = threading.Event()
        tail = None if quiet else threading.Thread(target=tail_events, args=(stop,), daemon=True)
        if tail:
            tail.start()
        r = subprocess.run(["bash", os.path.join(ROOT, "engine", "sandbox", "run_agent.sh"), mode],
                           capture_output=True, text=True)
        if r.returncode != 0:
            proc.terminate()
            write_status(state="error", message=r.stderr.strip()[-300:])
            return False, r.stderr
        write_status(state="running", message="agent running")
        proc.wait(timeout=180)
        stop.set()
        if tail:
            tail.join(5)
        inc = incident_for(run_id)
        state = "contained" if inc and inc["status"] == "contained" else ("finished" if not inc else "incident_open")
        write_status(state=state, incident_id=inc["incident_id"] if inc else None,
                     message="agent contained" if state == "contained" else "run finished")
        if not quiet:
            summary(run_id)
        return True, run_id
    finally:
        _current["proc"] = None
        _run_lock.release()


def halt():
    """Manual emergency halt. If auto-containment already happened, say so."""
    run_id = _current["run_id"] or (json.load(open(STATUS)).get("run_id") if os.path.exists(STATUS) else None)
    inc = incident_for(run_id) if run_id else None
    if inc and inc["status"] == "contained":
        write_status(message=f"already contained ({inc['incident_id']})")
        return True, "already contained"
    if not docker("ps", "-q", "-f", f"name=^{CONTAINER}$").stdout.strip():
        write_status(message="emergency halt: no running agent")
        return False, "no running agent"
    from engine.respond import respond
    from engine.evidence import vault
    inc = respond.emergency_halt(run_id)
    for _ in range(100):  # let the collector see the pause, flush and exit before sealing
        if _current["proc"] is None:
            break
        time.sleep(0.1)
    vault.seal(inc)
    write_status(state="contained", incident_id=inc["incident_id"], message="emergency halt: agent contained")
    return True, inc["incident_id"]


def reset():
    p = _current.get("proc")
    if p:
        p.terminate()
    docker("rm", "-f", CONTAINER)
    docker("rm", "-f", "cagewatch-netmon")
    # Never delete control.json here: the dashboard may already have written the next command.
    for name in ("events.jsonl", "capture.pcap"):
        path = os.path.join(RUNTIME, name)
        if os.path.exists(path):
            os.remove(path)
    write_status(state="idle", mode=None, run_id=None, incident_id=None, message="reset")
    return True, "reset"


def serve_control():
    print("serve-control: watching", CONTROL, "(Ctrl+C to stop)", flush=True)
    write_status(state="idle", message="engine ready")
    last = None
    try:
        last = json.load(open(CONTROL)).get("ts")  # ignore a stale command from before we started
    except (OSError, ValueError):
        pass
    while True:
        try:
            cmd = json.load(open(CONTROL))
        except (OSError, ValueError):
            cmd = None
        if cmd and cmd.get("ts") != last:
            last = cmd.get("ts")
            name = cmd.get("cmd")
            write_status(last_cmd=name)
            print(f"[{iso()}] command: {name}", flush=True)
            if name not in COMMANDS:
                write_status(message=f"rejected unknown command {name!r}")
            elif name.startswith("run_"):
                if _run_lock.locked():
                    write_status(message="busy: a run is already in progress")
                else:
                    threading.Thread(target=run, args=(name[4:], True), daemon=True).start()
            elif name == "emergency_halt":
                threading.Thread(target=halt, daemon=True).start()
            elif name == "reset":
                reset()
        time.sleep(0.3)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd in MODES:
        ok, _ = run(cmd)
        return 0 if ok else 1
    if cmd == "serve-control":
        try:
            serve_control()
        except KeyboardInterrupt:
            write_status(state="idle", message="engine stopped")
        return 0
    if cmd == "halt":
        print(halt())
        return 0
    if cmd == "reset":
        print(reset())
        return 0
    if cmd == "status":
        print(open(STATUS).read() if os.path.exists(STATUS) else "{}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
