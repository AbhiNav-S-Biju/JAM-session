"""Build UI edge-case fixtures in shared/fixtures/mock/ (same format as shared/fixtures/real/).

Run from the repo root:  python shared/fixtures/mock/make_mock.py
Output is deterministic, so re-running gives the same files.
"""
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REAL = HERE.parent / "real"
T0 = datetime(2026, 11, 13, 9, 0, 0, tzinfo=timezone.utc)


def iso(t: datetime) -> str:
    """Engine timestamp format: millisecond precision, Z suffix."""
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def write_json(name: str, obj) -> None:
    (HERE / name).write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(name: str, rows: list) -> None:
    text = "".join(json.dumps(r) + "\n" for r in rows)
    (HERE / name).write_text(text, encoding="utf-8", newline="\n")


def status(state: str, mode, run_id, message: str, last_cmd) -> dict:
    return {"state": state, "mode": mode, "run_id": run_id, "incident_id": None,
            "message": message, "last_cmd": last_cmd, "updated_at": iso(T0)}


def long_benign_run(n_steps: int = 40) -> list:
    """A long benign run; some network events are written late (ts earlier than the line above)."""
    run_id = "run-benign-20261113-090000"
    rows, t = [], T0
    def ev(source, typ, detail, step_id, verdict="allow", ts=None):
        rows.append({"id": f"evt-{len(rows) + 1:04d}", "ts": iso(ts or t), "run_id": run_id,
                     "source": source, "type": typ, "detail": detail,
                     "step_id": step_id, "verdict": verdict})
    ev("container", "start", {"container": "cagewatch-agent"}, None)
    for i in range(1, n_steps + 1):
        sid = f"step-{i}"
        t += timedelta(milliseconds=700)
        path = f"/data/authorized/part_{i:02d}.txt"
        ev("agent_step", "step", {"action": "read_file", "target": path,
                                  "reason": f"read chunk {i} of the report", "tainted": False}, sid)
        ev("agent_step", "step_result", {"ok": True, "error": None}, sid)
        ev("file", "file_read", {"path": path, "inotify": "OPEN"}, sid,
           ts=t + timedelta(milliseconds=1))
        if i % 10 == 0:
            # Network capture lags: logged after the next step's line, but stamped earlier.
            lag_ts = t + timedelta(milliseconds=5)
            t += timedelta(milliseconds=700)
            nxt = f"step-{i}b"
            ev("agent_step", "step", {"action": "compute", "target": "subtotal",
                                      "reason": f"subtotal after chunk {i}", "tainted": False}, nxt)
            ev("network", "net_connect", {"src_ip": "172.18.0.2", "src_port": 40000 + i,
                                          "dst_ip": "10.0.0.5", "dst_port": 443, "proto": "tcp"},
               sid, ts=lag_ts)
    t += timedelta(seconds=1)
    ev("container", "exit", {"container": "cagewatch-agent", "exit_code": "0"}, f"step-{n_steps}")
    return rows


def tampered_chain() -> None:
    """Copy the real attack chain under a new id and edit one record, so verify reports BROKEN."""
    src = REAL / "evidence" / "INC-2026-11-12-006"
    dst = HERE / "evidence" / "INC-2026-11-12-099"
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    lines = (src / "chain.jsonl").read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        row = json.loads(line)
        ev = row["record"].get("event")
        if ev and ev.get("verdict") == "violation":
            ev["verdict"] = "allow"          # the edit an attacker would make
            lines[i] = json.dumps(row)
            break
    (dst / "chain.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    write_json("engine_status_idle.json", status("idle", None, None, "waiting for a command", None))
    write_json("engine_status_starting.json",
               status("running", "attack", "run-attack-20261113-090000", "starting sandbox", "run_attack"))
    write_json("engine_status_error.json",
               status("error", "attack", "run-attack-20261113-090000",
                      "docker: Cannot connect to the Docker daemon", "run_attack"))
    write_jsonl("events_empty.jsonl", [])
    write_jsonl("events_long.jsonl", long_benign_run())
    tampered_chain()


if __name__ == "__main__":
    main()
