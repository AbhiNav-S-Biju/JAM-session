"""Detection metrics from saved runs (Track B, B6).

Save each run right after it finishes (the engine deletes events.jsonl on reset):
    python console/metrics/compute.py collect --data shared/runtime

Then compute metrics over everything saved:
    python console/metrics/compute.py
    python console/metrics/compute.py --events "shared/fixtures/real/events_*.jsonl" "shared/fixtures/real/evidence/*/events.jsonl" --incidents shared/fixtures/real/incidents.json

Ground truth: run mode from the run_id (attack -> malicious; benign, benign_unusual -> benign), or
labels.json {run_id: "malicious"|"benign"} in the runs folder. A run is "detected" when it has an
incident with containment_reason == "auto" (a manual emergency halt is not a detection).
"""
import argparse
import glob
import json
import re
import shutil
import sys
from pathlib import Path
from statistics import mean
from typing import Optional

REPO = Path(__file__).resolve().parents[2]
RUNS = Path(__file__).resolve().parent / "runs"
MODE_LABEL = {"attack": "malicious", "benign": "benign", "benign_unusual": "benign"}
RUN_ID = re.compile(r"^run-(?P<mode>[a-z_]+)-\d{8}-\d{6}$")


def run_mode(run_id: str) -> Optional[str]:
    m = RUN_ID.match(run_id or "")
    return m.group("mode") if m else None


def load_runs(event_files: list) -> dict:
    """{run_id: n_events} across all files (one file may hold several runs; duplicates merged)."""
    seen = {}
    for f in event_files:
        for line in Path(f).read_text(encoding="utf-8").splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            seen.setdefault(ev.get("run_id"), set()).add(ev.get("id"))
    return {r: len(ids) for r, ids in seen.items() if r}


def ground_truth(run_id: str, labels: dict) -> Optional[str]:
    return labels.get(run_id) or MODE_LABEL.get(run_mode(run_id) or "")


def ratio(a: int, b: int) -> Optional[float]:
    return round(a / b, 3) if b else None


def compute(runs: dict, incidents: list, labels: dict) -> dict:
    """Confusion matrix, precision/recall/FPR and timing over labelled runs."""
    auto = {i["run_id"]: i for i in incidents if i.get("containment_reason") == "auto"}
    rows, skipped = [], []
    for run_id in sorted(runs):
        truth = ground_truth(run_id, labels)
        if truth is None:
            skipped.append(run_id)
            continue
        inc = auto.get(run_id)
        rows.append({"run_id": run_id, "mode": run_mode(run_id), "truth": truth, "detected": inc is not None,
                     "incident_id": inc and inc["incident_id"], "events": runs[run_id],
                     "time_to_detect_ms": inc and inc.get("time_to_detect_ms"),
                     "time_to_contain_ms": inc and inc.get("time_to_contain_ms")})
    tp = sum(r["truth"] == "malicious" and r["detected"] for r in rows)
    fn = sum(r["truth"] == "malicious" and not r["detected"] for r in rows)
    fp = sum(r["truth"] == "benign" and r["detected"] for r in rows)
    tn = sum(r["truth"] == "benign" and not r["detected"] for r in rows)
    hits = [r for r in rows if r["truth"] == "malicious" and r["detected"]]
    avg = lambda k: round(mean(r[k] for r in hits if r[k] is not None), 1) if any(r[k] is not None for r in hits) else None
    return {"n_runs": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn), "false_positive_rate": ratio(fp, fp + tn),
            "avg_time_to_detect_ms": avg("time_to_detect_ms"), "avg_time_to_contain_ms": avg("time_to_contain_ms"),
            "runs": rows, "skipped_unlabelled": skipped}


def fmt(v) -> str:
    return "n/a" if v is None else str(v)


def markdown(m: dict) -> str:
    """Summary table + per-run table, ready for a slide or the README."""
    out = ["| Metric | Value |", "|---|---|"]
    for k, label in [("n_runs", "Runs (n)"), ("tp", "True positives"), ("fp", "False positives"),
                     ("tn", "True negatives"), ("fn", "False negatives"), ("precision", "Precision"),
                     ("recall", "Recall"), ("false_positive_rate", "False-positive rate"),
                     ("avg_time_to_detect_ms", "Avg time to detect (ms)"),
                     ("avg_time_to_contain_ms", "Avg time to contain (ms)")]:
        out.append(f"| {label} | {fmt(m[k])} |")
    out += ["", "| Run | Mode | Truth | Detected | Incident | TTD ms | TTC ms |", "|---|---|---|---|---|---|---|"]
    for r in m["runs"]:
        out.append(f"| {r['run_id']} | {r['mode']} | {r['truth']} | {'yes' if r['detected'] else 'no'} | "
                   f"{fmt(r['incident_id'])} | {fmt(r['time_to_detect_ms'])} | {fmt(r['time_to_contain_ms'])} |")
    if m["skipped_unlabelled"]:
        out += ["", "Skipped (no label): " + ", ".join(m["skipped_unlabelled"])]
    if m["n_runs"] < 20:
        out += ["", f"Note: only {m['n_runs']} runs; these rates are not statistically meaningful."]
    return "\n".join(out)


def expand(patterns: list) -> list:
    files = []
    for p in patterns:
        hits = glob.glob(str(p if Path(p).is_absolute() else REPO / p))
        files += sorted(hits)
    return files


def collect(data: Path, runs_dir: Path) -> str:
    """Save the live run's events and merge its incidents into the runs folder."""
    events = data / "events.jsonl"
    if not events.is_file():
        raise SystemExit(f"no {events}: run a scenario first (and collect before Reset)")
    run_ids = list(load_runs([events]))
    if not run_ids:
        raise SystemExit("events.jsonl has no events yet")
    runs_dir.mkdir(parents=True, exist_ok=True)
    run_id = run_ids[-1]
    shutil.copyfile(events, runs_dir / f"{run_id}.jsonl")
    merged = {i["incident_id"]: i for i in read_incidents(runs_dir / "incidents.json")}
    merged.update({i["incident_id"]: i for i in read_incidents(data / "incidents.json")})
    (runs_dir / "incidents.json").write_text(json.dumps(sorted(merged.values(), key=lambda i: i["incident_id"]),
                                                        indent=1) + "\n", encoding="utf-8", newline="\n")
    return run_id


def read_incidents(path: Path) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", nargs="?", default="compute", choices=["compute", "collect"])
    ap.add_argument("--runs", default=str(RUNS), help="folder with saved runs (default console/metrics/runs)")
    ap.add_argument("--data", default="shared/runtime", help="collect: live data folder")
    ap.add_argument("--events", nargs="+", help="event files or globs (instead of --runs)")
    ap.add_argument("--incidents", help="incidents.json (instead of --runs)")
    ap.add_argument("--json", help="also write the full result as JSON here")
    a = ap.parse_args(argv)
    runs_dir = Path(a.runs)
    if a.cmd == "collect":
        data = Path(a.data) if Path(a.data).is_absolute() else REPO / a.data
        print("saved", collect(data, runs_dir), "to", runs_dir)
        return
    event_files = expand(a.events) if a.events else sorted(str(p) for p in runs_dir.glob("run-*.jsonl"))
    if not event_files:
        sys.exit("no event files found; collect some runs first")
    incidents = read_incidents(Path(a.incidents) if a.incidents else runs_dir / "incidents.json")
    labels = json.loads((runs_dir / "labels.json").read_text()) if (runs_dir / "labels.json").is_file() else {}
    m = compute(load_runs(event_files), incidents, labels)
    print(markdown(m))
    if a.json:
        Path(a.json).write_text(json.dumps(m, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
