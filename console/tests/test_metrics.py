"""Metrics tests on the real fixtures and small synthetic cases."""
import json
import shutil
from pathlib import Path

from console.metrics.compute import collect, compute, load_runs, main

REAL = Path(__file__).resolve().parents[2] / "shared" / "fixtures" / "real"
FIXTURE_EVENTS = [REAL / "events_attack.jsonl", REAL / "events_benign.jsonl",
                  REAL / "evidence" / "INC-2026-11-12-005" / "events.jsonl"]


def incidents():
    return json.loads((REAL / "incidents.json").read_text())


def test_fixtures_confusion_matrix():
    m = compute(load_runs(FIXTURE_EVENTS), incidents(), {})
    assert (m["n_runs"], m["tp"], m["fp"], m["tn"], m["fn"]) == (3, 1, 0, 2, 0)
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["false_positive_rate"] == 0.0
    assert m["avg_time_to_detect_ms"] == 408 and m["avg_time_to_contain_ms"] == 1302


def test_manual_halt_is_not_a_detection():
    m = compute(load_runs(FIXTURE_EVENTS), incidents(), {})
    halt = next(r for r in m["runs"] if r["mode"] == "benign_unusual")
    assert halt["detected"] is False and halt["truth"] == "benign"


def test_false_positive_and_miss_counted():
    runs = {"run-benign-20261113-100000": 5, "run-attack-20261113-100100": 5}
    incs = [{"incident_id": "INC-2026-11-13-001", "run_id": "run-benign-20261113-100000",
             "containment_reason": "auto", "time_to_detect_ms": 300, "time_to_contain_ms": 900}]
    m = compute(runs, incs, {})
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (0, 1, 0, 1)
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["false_positive_rate"] == 1.0
    assert m["avg_time_to_detect_ms"] is None   # timing averages only over true positives


def test_labels_override_and_unlabelled_skipped():
    runs = {"run-launder-20261113-100000": 3, "run-mystery-20261113-100000": 3}
    m = compute(runs, [], {"run-launder-20261113-100000": "malicious"})
    assert m["fn"] == 1 and m["skipped_unlabelled"] == ["run-mystery-20261113-100000"]
    assert m["precision"] is None   # no positives predicted: undefined, not 0


def test_collect_then_compute(tmp_path, capsys):
    data, runs = tmp_path / "runtime", tmp_path / "runs"
    data.mkdir()
    shutil.copy(REAL / "events_attack.jsonl", data / "events.jsonl")
    shutil.copy(REAL / "incidents.json", data / "incidents.json")
    assert collect(data, runs) == "run-attack-20261112-204351"
    shutil.copy(REAL / "events_benign.jsonl", data / "events.jsonl")
    collect(data, runs)
    assert len(json.loads((runs / "incidents.json").read_text())) == 2
    main(["--runs", str(runs), "--json", str(tmp_path / "m.json")])
    out = capsys.readouterr().out
    assert "| Precision | 1.0 |" in out and "not statistically meaningful" in out
    assert json.loads((tmp_path / "m.json").read_text())["n_runs"] == 2
