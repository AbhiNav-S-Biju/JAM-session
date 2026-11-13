"""API tests against the real engine fixtures (run: python -m pytest console/tests)."""
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from console.api import app

REPO = Path(__file__).resolve().parents[2]
REAL = REPO / "shared" / "fixtures" / "real"
MOCK = REPO / "shared" / "fixtures" / "mock"
ATTACK = "INC-2026-11-12-006"
HALT = "INC-2026-11-12-005"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A writable copy of the real fixtures as CAGEWATCH_DATA."""
    data = tmp_path / "data"
    shutil.copytree(REAL, data)
    monkeypatch.setenv("CAGEWATCH_DATA", str(data))
    c = TestClient(app)
    c.data = data
    return c


def test_state_contained(client):
    s = client.get("/api/state").json()
    assert s["badge"] == "CONTAINED"
    assert s["run_id"] == "run-attack-20261112-204351"
    assert s["counts"] == {"events": 18, "allowed": 14, "suspicious": 2, "violations": 2, "contained": 2}
    assert s["policy_sha256"].startswith("sha256:") and len(s["policy_sha256"]) == 71


def test_policy_hash_matches_evidence_chain(client):
    first = json.loads((REAL / "evidence" / ATTACK / "chain.jsonl").read_text().splitlines()[0])
    assert client.get("/api/policy").json()["sha256"] == first["record"]["policy_sha256"]


def test_events_sorted_and_clean(client):
    ev = client.get("/api/events").json()
    assert [e["ts"] for e in ev] == sorted(e["ts"] for e in ev)
    assert "host_path" not in json.dumps(ev) and "/home/" not in json.dumps(ev)


def test_events_since_and_run(client):
    assert {e["id"] for e in client.get("/api/events?since=evt-0015").json()} == {"evt-0016", "evt-0017", "evt-0018"}
    benign = client.get("/api/events?run=benign").json()
    assert len(benign) == 13 and all(e["run_id"].startswith("run-benign") for e in benign)
    assert client.get("/api/state?run=benign").json()["counts"]["violations"] == 0


def test_badge_safe_and_suspicious(client):
    (client.data / "engine_status_contained.json").write_text(json.dumps(
        {"state": "running", "mode": "benign", "run_id": "run-benign-20261112-204334"}))
    assert client.get("/api/state").json()["badge"] == "SAFE"
    (client.data / "engine_status_contained.json").write_text(json.dumps(
        {"state": "running", "mode": "attack", "run_id": "run-attack-20261112-204351"}))
    assert client.get("/api/state").json()["badge"] == "SUSPICIOUS"


def test_starting_when_running_without_events(client, tmp_path, monkeypatch):
    data = tmp_path / "starting"
    data.mkdir()
    shutil.copy(MOCK / "engine_status_starting.json", data / "engine_status.json")
    shutil.copy(MOCK / "events_empty.jsonl", data / "events.jsonl")
    monkeypatch.setenv("CAGEWATCH_DATA", str(data))
    s = client.get("/api/state").json()
    assert s["starting"] is True and s["badge"] == "SAFE" and s["counts"]["events"] == 0


def test_incidents(client):
    ids = [i["incident_id"] for i in client.get("/api/incidents").json()]
    assert set(ids) == {ATTACK, HALT}
    assert client.get(f"/api/incidents/{ATTACK}").json()["risk_score"] == 95
    assert client.get("/api/incidents/INC-2026-11-12-777").status_code == 404
    assert client.get("/api/incidents/..%2F..%2Fsecrets").status_code in (400, 404)


@pytest.mark.parametrize("inc", [ATTACK, HALT])
def test_verify_valid(client, inc):
    r = client.get(f"/api/verify/{inc}").json()
    assert r["ok"] is True and r["result"] == "VALID" and r["head"].startswith("sha256:")


def test_verify_broken_after_edit(client):
    chain = client.data / "evidence" / ATTACK / "chain.jsonl"
    lines = chain.read_text().splitlines()
    lines[5] = lines[5].replace('"allow"', '"violation"', 1) if '"allow"' in lines[5] else lines[5] + " "
    row = json.loads(lines[5])
    row["record"]["tampered"] = True
    lines[5] = json.dumps(row)
    chain.write_text("\n".join(lines) + "\n")
    r = client.get(f"/api/verify/{ATTACK}").json()
    assert r["ok"] is False and r["result"] == "BROKEN" and r["first_bad_seq"] == 5


def test_verify_rejects_bad_ids(client):
    assert client.get("/api/verify/..%2F..%2Fetc").status_code in (400, 404)
    assert client.get("/api/verify/INC-1").status_code == 400
    assert client.get("/api/verify/INC-2026-11-12-777").status_code == 404


def test_control_writes_unique_allowlisted(client):
    a = client.post("/api/control", json={"cmd": "run_attack"}).json()["written"]
    b = client.post("/api/control", json={"cmd": "run_attack"}).json()["written"]
    assert a["ts"] != b["ts"]
    assert json.loads((client.data / "control.json").read_text()) == b
    assert not list(client.data.glob(".control-*"))


@pytest.mark.parametrize("cmd", ["rm -rf /", "RUN_ATTACK", "", "shutdown"])
def test_control_rejects_unknown(client, cmd):
    before = (client.data / "control.json").exists()
    assert client.post("/api/control", json={"cmd": cmd}).status_code == 400
    assert (client.data / "control.json").exists() == before


def test_incident_snapshot_events(client):
    ev = client.get(f"/api/events?incident={HALT}").json()
    assert len(ev) == 17 and all(e["run_id"].startswith("run-benign_unusual") for e in ev)
    assert "host_path" not in json.dumps(ev)
    assert client.get("/api/events?incident=../../x").status_code == 400
    assert client.get("/api/events?incident=INC-2026-11-12-777").status_code == 404


def test_new_run_hides_old_events(client):
    (client.data / "engine_status_contained.json").write_text(json.dumps(
        {"state": "running", "mode": "attack", "run_id": "run-attack-NEW"}))
    s = client.get("/api/state").json()
    assert s["starting"] is True and s["counts"]["events"] == 0


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "CAGEWATCH" in r.text


def test_bad_run_name(client):
    assert client.get("/api/events?run=../incidents").status_code == 400
