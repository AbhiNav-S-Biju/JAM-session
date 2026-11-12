# Track B — Console (Menva)

Read `CLAUDE.md` first (shared contract in section 6, dashboard inspiration in section 5). You own everything the **judges see**: API, dashboard, incident report, evidence verification view, and the test/metrics write-up. You do **not** build the sandbox or detection. Abhinav's engine produces the data; until it is ready you build against fixtures.

**Branch:** `track-b`. **Code lives in:** `console/`. **You read from:** `shared/runtime/` (live) or `shared/fixtures/` (default while developing).
**Independence:** run everything with `CAGEWATCH_DATA=shared/fixtures` and you never need Docker for your own work (still install it for integration day).

## Deliverables

### B1. Environment (hour 1)
- Follow CLAUDE.md section 8 (WSL2 + Docker), but you can start coding with just Python on Windows if Docker is slow.

### B2. Fixtures (do first so you are unblocked)
Create `shared/fixtures/`:
- `events_benign.jsonl` (about 10 events, all `allow`)
- `events_attack.jsonl` (about 20 events: steps, file reads, a blocked network connect, pause, disconnect, a failed log-tamper)
- `incidents.json` (one contained incident, severity critical, risk ~87, full `rules_triggered`, `actions_taken`, timings)
- `evidence/INC-.../chain.jsonl` (valid hash chain per contract)
Keep them **exactly** matching the contract; Abhinav's real output must be a drop-in replacement. Tell Abhinav if you think the contract needs a field.

### B3. FastAPI backend (`console/api.py`)
Endpoints (CLAUDE.md section 6): `GET /api/state`, `/api/events`, `/api/incidents`, `/api/incidents/{id}/report`, `POST /api/control`, `GET /api/verify/{id}`. Reads files from `CAGEWATCH_DATA` (default `shared/runtime`). `/api/verify` implements the hash-chain check itself or imports Abhinav's `engine.evidence.vault.verify_chain` once available. Validate inputs on `POST /api/control` (allow-list of commands only), no secrets in responses.

### B4. Dashboard (`console/static/index.html`, one dark page, vanilla JS)
Use the three reference screenshots (CLAUDE.md section 5):
- **Header**: CageWatch logo/name, run ID, policy SHA-256, uptime, "Connected" dot, auto-refresh selector.
- **4 stat tiles**: Events, Allowed, Violations, Contained.
- **State badge** SAFE (green) -> SUSPICIOUS (amber) -> CONTAINED (red banner with incident ID and an active timer).
- **Live event stream** with severity tags, filter chips (ALLOW / SUSPICIOUS / VIOLATION), search box.
- **Attack-chain stepper**: Task started -> Restricted file read -> Blocked destination -> Contained.
- **Intent-linked timeline**: each system event shown under the agent step that caused it, with the "tainted" marker.
- **Node map** (small SVG): Agent container -> sandbox net -> host -> external IP; container red when flagged, link cut when disconnected.
- **Alert popup** for the critical alert: Source vs Target, rules triggered, risk score with factors (`severity x asset value x confidence`).
- **Response playbook** panel listing actions taken with timestamps and status; **Emergency Halt** button; **Execute Containment**.
- **Evidence panel**: hashes, chain head, "Verify chain" button (calls `/api/verify`), PCAP link; **Export JSON/CSV**.
- Responsive enough to project on a screen; large readable fonts.

### B5. Incident report (`/api/incidents/{id}/report`)
Printable HTML: summary, timeline, rules triggered, risk-score breakdown, actions taken, time-to-detect/contain, evidence hashes + chain head, lessons learned/recommendations. Browser "Print to PDF" is the PDF export.

### B6. Control buttons
Dashboard buttons "Run benign", "Run attack", "Reset", "Emergency halt" write `shared/runtime/control.json` via `POST /api/control` (Abhinav's engine acts on it).

### B7. Test scenarios + metrics (`console/metrics/`)
- Write the **test scenarios independently from the detection rules** (do not peek at rule code): about 10 attack runs, about 10 benign runs, including benign-but-unusual ones. Describe each in `console/metrics/scenarios.md`.
- After integration run them, then compute precision, recall, false-positive rate, time-to-detect, time-to-contain. Output a small table the dashboard (or a slide) can show. Report honestly, including false positives.

## Definition of done
- [ ] With only fixtures, the whole dashboard works and looks like the reference screens.
- [ ] Report page prints cleanly.
- [ ] `/api/verify` passes on a valid chain and fails on an edited one.
- [ ] No hard-coded demo data in the UI; everything comes from the API.
- [ ] Scenarios file written before seeing rule code.

## Hand-off to Abhinav
Push to `track-b`, and tell Abhinav: how to start the server, the env var for the data directory, and any contract requests.
