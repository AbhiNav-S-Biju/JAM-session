"""CageWatch console API (Track B, B3).

Run from the repo root:
    $env:CAGEWATCH_DATA="shared/fixtures/real"; uvicorn console.api:app --reload --port 8000

Reads everything from CAGEWATCH_DATA (default shared/runtime). File names:
  engine_status.json, events.jsonl, incidents.json, evidence/<id>/chain.jsonl, control.json (written).
Fixture folders use suffixed names (engine_status_contained.json, events_attack.jsonl). When the exact
name is missing, the first suffixed file (alphabetical) is used; events prefer events_<mode>.jsonl.
"""
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from engine.evidence.vault import file_sha256, verify_chain  # noqa: E402

POLICY = REPO / "shared" / "policy.json"
STATIC = Path(__file__).resolve().parent / "static"
INCIDENT_ID = re.compile(r"^INC-\d{4}-\d{2}-\d{2}-\d{3}$")
RUN_NAME = re.compile(r"^[a-z_]{1,32}$")
COMMANDS = {"run_benign", "run_attack", "run_benign_unusual", "emergency_halt", "reset"}
HIDDEN_DETAIL_KEYS = {"host_path"}  # host file system paths never leave the API

app = FastAPI(title="CageWatch console")


# ---------- data access ----------

def data_dir() -> Path:
    """CAGEWATCH_DATA, relative paths resolved against the repo root."""
    p = Path(os.environ.get("CAGEWATCH_DATA", "shared/runtime"))
    return (p if p.is_absolute() else REPO / p).resolve()


def pick(stem: str, ext: str, prefer: Optional[str] = None) -> Optional[Path]:
    """Exact runtime file, else the fixture variant stem_<prefer>, else the first stem_*."""
    d = data_dir()
    exact = d / f"{stem}{ext}"
    if exact.is_file():
        return exact
    if prefer and (d / f"{stem}_{prefer}{ext}").is_file():
        return d / f"{stem}_{prefer}{ext}"
    found = sorted(d.glob(f"{stem}_*{ext}"))
    return found[0] if found else None


def read_json(path: Optional[Path], default):
    """Parse a JSON file; missing or half-written files give the default."""
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path else default
    except (OSError, ValueError):
        return default


def read_status() -> dict:
    return read_json(pick("engine_status", ".json"), {"state": "idle", "mode": None, "run_id": None,
                                                     "incident_id": None, "message": "no engine status",
                                                     "last_cmd": None, "updated_at": None})


def clean_event(ev: dict) -> dict:
    """Drop host-side paths from the event detail."""
    detail = ev.get("detail")
    if isinstance(detail, dict):
        ev = {**ev, "detail": {k: v for k, v in detail.items() if k not in HIDDEN_DETAIL_KEYS}}
    return ev


def read_events(run: Optional[str], status: dict, path: Optional[Path] = None) -> list:
    """Events of the engine's current run (or, with no run_id / with `run`, the file's last run), by ts."""
    path = path or pick("events", ".jsonl", prefer=run or status.get("mode"))
    rows = []
    if path:
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass  # skip a line the engine is still writing
        except OSError:
            pass
    if not rows:
        return []
    # The engine's run_id wins; a new run whose events haven't arrived yet shows nothing (not the old run).
    current = status.get("run_id") if not run and status.get("run_id") else rows[-1].get("run_id")
    rows = [clean_event(r) for r in rows if r.get("run_id") == current]
    return sorted(rows, key=lambda r: (r.get("ts") or "", r.get("id") or ""))


def event_num(event_id: Optional[str]) -> int:
    """evt-0012 -> 12 (0 when missing or malformed)."""
    m = re.search(r"(\d+)$", event_id or "")
    return int(m.group(1)) if m else 0


def read_incidents() -> list:
    data = read_json(pick("incidents", ".json"), [])
    return data if isinstance(data, list) else []


def get_incident(incident_id: str) -> dict:
    if not INCIDENT_ID.match(incident_id):
        raise HTTPException(400, "bad incident id")
    for inc in read_incidents():
        if inc.get("incident_id") == incident_id:
            return inc
    raise HTTPException(404, "incident not found")


def badge(status: dict, events: list) -> str:
    if status.get("state") == "contained":
        return "CONTAINED"
    if any(e.get("verdict") in ("suspicious", "violation") for e in events):
        return "SUSPICIOUS"
    return "SAFE"


def policy_hash() -> Optional[str]:
    """Same format as policy_sha256 in the evidence chain."""
    return "sha256:" + file_sha256(str(POLICY)) if POLICY.is_file() else None


# ---------- routes ----------

def check_run(run: Optional[str]) -> None:
    if run is not None and not RUN_NAME.match(run):
        raise HTTPException(400, "bad run name")


@app.get("/api/state")
def state(run: Optional[str] = Query(None)) -> dict:
    check_run(run)
    status = read_status()
    events = read_events(run, status)
    verdicts = [e.get("verdict") for e in events]
    incidents = read_incidents()
    return {
        "engine": status,
        "badge": badge(status, events),
        "starting": status.get("state") == "running" and not events,
        "run_id": events[0]["run_id"] if events else status.get("run_id"),
        "counts": {
            "events": len(events),
            "allowed": verdicts.count("allow"),
            "suspicious": verdicts.count("suspicious"),
            "violations": verdicts.count("violation"),
            "contained": sum(1 for i in incidents if i.get("status") == "contained"),
        },
        "policy_sha256": policy_hash(),
    }


@app.get("/api/events")
def events(since: Optional[str] = Query(None), run: Optional[str] = Query(None),
           incident: Optional[str] = Query(None)) -> list:
    """Current-run events sorted by ts; `since` returns only events with a higher id number.
    `incident` returns that incident's evidence snapshot instead of the live file."""
    check_run(run)
    if incident:
        get_incident(incident)  # validates the id and that it exists
        snap = data_dir() / "evidence" / incident / "events.jsonl"
        rows = read_events(None, {}, snap) if snap.is_file() else []
    else:
        rows = read_events(run, read_status())
    if since:
        floor = event_num(since)
        rows = [r for r in rows if event_num(r.get("id")) > floor]
    return rows


@app.get("/api/incidents")
def incidents() -> list:
    return read_incidents()


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str) -> dict:
    return get_incident(incident_id)


class Control(BaseModel):
    cmd: str


@app.post("/api/control")
def control(body: Control) -> dict:
    """Allow-listed command -> control.json with a fresh ts, written atomically."""
    if body.cmd not in COMMANDS:
        raise HTTPException(400, f"unknown command; allowed: {sorted(COMMANDS)}")
    now = datetime.now(timezone.utc)
    msg = {"cmd": body.cmd, "ts": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ") + f"-{time.perf_counter_ns()}"}
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".control-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(msg, f)
        os.replace(tmp, d / "control.json")
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return {"ok": True, "written": msg}


@app.get("/api/verify/{incident_id}")
def verify(incident_id: str) -> dict:
    if not INCIDENT_ID.match(incident_id):
        raise HTTPException(400, "bad incident id")
    chain = data_dir() / "evidence" / incident_id / "chain.jsonl"
    if not chain.is_file():
        raise HTTPException(404, "no evidence chain for this incident")
    ok, info = verify_chain(str(chain))
    return {"incident_id": incident_id, "ok": ok, "result": "VALID" if ok else "BROKEN", **info}


@app.get("/api/policy")
def policy() -> dict:
    return {"policy": read_json(POLICY, {}), "sha256": policy_hash()}


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "index.html")
