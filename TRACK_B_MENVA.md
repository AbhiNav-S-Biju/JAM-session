# Track B — Console (Menva)

Read `CLAUDE.md` first (shared contract in section 6, dashboard inspiration in section 5). You own everything the **judges see**: API, dashboard, incident report, evidence verification view, and the test/metrics write-up. You do **not** build the sandbox or detection.

> **Status (2026-11-13): Track A (engine) is finished and merged to `main`.** You build against **real engine output** in `shared/fixtures/real/`, so nothing on your side has to be guessed. You don't need Docker until integration; plain Python on Windows is enough to build the whole console.

**Branch:** create `track-b` from `main` (`git checkout main && git pull && git checkout -b track-b`). **Code lives in:** `console/`.
**Data directory:** read everything from `CAGEWATCH_DATA` (env var). Use `shared/fixtures/real` while building and `shared/runtime` at integration. Use the same file names in both (see the table below).

## What the engine gives you (already built)

| File (inside `CAGEWATCH_DATA`) | What it is | Fixture name in `shared/fixtures/real/` |
|---|---|---|
| `events.jsonl` | One event per line, live while a run is going | `events_attack.jsonl`, `events_benign.jsonl` (copy one to `events.jsonl` to test, or let the API pick via `?run=`) |
| `incidents.json` | List of incidents (auto-contained attack, manual emergency halt) | `incidents.json` |
| `evidence/<incident_id>/chain.jsonl` | Hash-chained evidence | `evidence/INC-2026-11-12-006/` (attack), `.../INC-2026-11-12-005/` (manual halt) |
| `evidence/<incident_id>/events.jsonl` | Snapshot of that run's events | same folders |
| `engine_status.json` | Engine state for the badge and buttons | `engine_status_contained.json` |
| `anchors.log` | One line per evidence seal (time, incident, chain head) | not in fixtures (runtime only) |
| `control.json` | **You write this** to send commands | n/a |
| `capture.pcap` | Network capture (gitignored, only at runtime) | n/a |

**Event fields you'll render** (full spec in CLAUDE.md section 6):
- `source`: `agent_step` | `file` | `network` | `container`. `type`: `step`, `step_result`, `file_read`, `dir_list`, `net_connect`, `start`, `pause`, `disconnect`, `exit`.
- `verdict`: `allow` (green), `suspicious` (amber, the agent *announced* a risky action), `violation` (red, the host *saw* it happen).
- `step_id`: groups each system event under the agent step that caused it. This drives the **intent-linked timeline**.
- `detail.tainted: true` on steps after the agent read untrusted content. Show a "TAINTED" tag (taint-tracking innovation).
- `step_result` with `ok:false` shows a blocked action (e.g. failed log tampering). Hide `ok:true` results or show them dimmed.
- **Sort events by `ts`**: network events can arrive up to about 0.5 s late.

**Incident fields you'll render:** `incident_id`, `status` (`contained`), `severity`, `risk_score`, `score_factors` `{severity, asset_value, confidence, rule_id}`, `rules_triggered[]` `{rule_id, name, event_ids, step_ids}`, `chain[]` (for the stepper; can include `injection_followed`, `restricted_file_read`, `blocked_destination`, `tamper_attempt`, `manual_halt`, `contained`), `actions_taken[]` `{action, ts, ok, error, took_ms}`, `time_to_detect_ms`, `time_to_contain_ms`, `containment_reason` (`auto` | `emergency_halt`), `notes[]` (human-readable reason for every rule hit, good for the alert popup), `evidence` `{log, pcap, chain, chain_head, chain_length}`.

**Engine status** (`engine_status.json`): `{"state":"idle|running|contained|finished|error", "mode", "run_id", "incident_id", "message", "last_cmd", "updated_at"}`.
- Badge: `running` with no violations = **SAFE**, any `suspicious`/`violation` event in the current run = **SUSPICIOUS**, `contained` = **CONTAINED** (red banner).
- A run takes about 16 s, about 8 s of which is start-up. While `state == running` and no events yet, show "Starting sandbox…".

**Commands** (`POST /api/control` writes `control.json`): `{"cmd": "run_benign|run_attack|run_benign_unusual|emergency_halt|reset", "ts": "<new unique value every time>"}`. The engine ignores a repeated `ts` and rejects unknown commands. Write the file atomically (write a temp file, then rename).

**Hash verification:** don't re-implement it. `from engine.evidence.vault import verify_chain` gives `verify_chain(path) -> (ok, {"length","head","first_bad_seq","reason"})`. Works on Windows and Linux, standard library only.

## Deliverables

### B1. Setup (15 min)
- `git clone`, then `git checkout -b track-b`. On Windows: `python -m venv .venv && .venv\Scripts\activate && pip install fastapi uvicorn`.
- Run with `set CAGEWATCH_DATA=shared/fixtures/real` (PowerShell: `$env:CAGEWATCH_DATA="shared/fixtures/real"`), then `uvicorn console.api:app --reload --port 8000`.
- Docker (CLAUDE.md section 8) is only needed on integration day.

### B2. Fixtures
**Done for you** by the engine. Optionally add `shared/fixtures/mock/` with extra edge cases (e.g. an `error` status or a long timeline) if you want to test the UI, keeping the exact same format.

### B3. FastAPI backend (`console/api.py`)
- `GET /api/state` returns engine status + counts (events, allowed, suspicious, violations, contained incidents) + current badge state + policy SHA-256 (of `shared/policy.json`).
- `GET /api/events?since=<id>` returns events of the current run, sorted by `ts`. Support `since` for cheap polling.
- `GET /api/incidents` and `GET /api/incidents/{id}`.
- `GET /api/incidents/{id}/report` returns printable HTML (B5).
- `POST /api/control` with body `{"cmd": ...}`: **allow-list check**, then the API adds `ts` and writes `control.json` atomically. Return 400 for anything else.
- `GET /api/verify/{id}` calls `verify_chain` and returns its result. `id` must match `^INC-\d{4}-\d{2}-\d{2}-\d{3}$` (blocks path traversal).
- `GET /api/policy` returns policy.json + its hash.
- Never return file paths outside `CAGEWATCH_DATA`, never return secrets (there are none in the data, but the dummy secret file content must never be served).

### B4. Dashboard (`console/static/index.html`, one dark page, vanilla JS, polls every 1 s)
Follow the three reference screenshots (CLAUDE.md section 5):
- **Header:** CageWatch name, run ID, policy SHA-256 (short), engine status dot "Connected", refresh selector.
- **4 stat tiles:** Events, Allowed, Violations, Contained.
- **State badge:** SAFE (green), SUSPICIOUS (amber), CONTAINED (full-width red banner with incident ID, severity and a live "contained for mm:ss" timer).
- **Intent-linked timeline (centre, the hero feature):** one row per agent step (`step-1`…), with the file/network/container events it caused nested underneath, colour-coded by verdict, plus the TAINTED tag.
- **Attack-chain stepper:** from `incident.chain`, for example Task started → Injection followed → Restricted file read → Blocked destination → Contained.
- **Node map (small SVG):** Agent container → sandbox network → host → external IP (`203.0.113.10`). Container ring turns red on violation; the link is drawn cut once a `disconnect` event appears.
- **Alert popup** on first critical incident: Source (agent step + reason) vs Target (path / IP), rules triggered, risk score with the formula `100 × (sev/5) × (asset/5) × confidence`.
- **Response playbook panel:** `actions_taken` with ✓/✗ and `took_ms`, plus time-to-detect and time-to-contain.
- **Evidence panel:** chain head, chain length, "Verify chain" button showing VALID/BROKEN (and the bad seq), report link.
- **Buttons:** Run benign, Run attack, Run benign-unusual, **Emergency Halt** (red), Reset. Disable run buttons while `state == running`.
- Filter chips ALLOW / SUSPICIOUS / VIOLATION, a search box, Export JSON/CSV of events.
- Big readable fonts: it will be projected.

### B5. Incident report (`/api/incidents/{id}/report`)
Printable HTML (print to PDF from the browser): summary, timeline, rules triggered with the `notes`, risk breakdown, actions taken, time-to-detect/contain, evidence chain head + length + verification result, recommendations / lessons learned.

### B6. Test scenarios + metrics (`console/metrics/`)
- Write `console/metrics/scenarios.md` **without reading `engine/detect/rules.py`**: about 10 malicious and about 10 benign/benign-unusual behaviours described in words. This keeps precision/recall honest.
- At integration, Abhinav turns any new scenarios into agent modes if time allows. Otherwise measure on the three existing modes run several times.
- `console/metrics/compute.py`: from runs (events + incidents) compute precision, recall, false-positive rate, average time-to-detect/contain. Output a small table (for the dashboard Trends tab or a slide). Report false positives honestly.

## Definition of done
- [ ] With `CAGEWATCH_DATA=shared/fixtures/real`, the full dashboard renders the attack incident and the manual-halt incident correctly.
- [ ] Timeline groups events by `step_id` and shows TAINTED + verdict colours.
- [ ] `/api/verify` returns VALID on the fixture chains, and BROKEN after editing one line of a copy.
- [ ] Control buttons write a valid `control.json` (allow-listed, unique `ts`).
- [ ] Report page prints cleanly.
- [ ] No hard-coded demo data in the UI: everything comes from the API.

## Hand-off
Push `track-b` and tell Abhinav: how to start the server and anything you need changed in the engine. Then follow `INTEGRATION.md` together.
