# CageWatch — Project Instructions (read this first on every prompt)

> AI Agent Runtime Security & Containment Platform.
> Tagline: **Watch the agent. Detect the threat. Contain the breach.**
> Demo deadline: **2026-11-14** (3-minute live demo). Team: **Abhinav** and **Menva**.

Claude: this file is the source of truth. Before doing anything, find out which track the user is working on (A = Abhinav, B = Menva, or Integration), read that track file, and stay inside its scope. Do not change the shared contract (section 6) without telling the user, because the other teammate depends on it.

## 1. What CageWatch is

An AI agent runs inside a locked-down Docker container. A monitor running on the **host** (outside the agent's reach) records what the agent does: commands/steps, file access and network connections. When the agent breaks a rule (reads a restricted file, contacts a blocked IP), CageWatch scores the risk, **pauses the container, cuts its network, saves hash-chained evidence**, and generates an incident report. A dashboard shows the timeline, rules triggered, severity, hashes and report.

Pipeline: `Sandbox -> Collector -> Detection -> Risk score -> Auto response -> Evidence vault -> Dashboard/Report`

## 2. Honest scope (say this in the pitch)

- We **detect and contain attempted boundary violations** in a lab. We do NOT claim to prevent every sandbox escape.
- Prototype uses a **scripted agent**, **dummy secrets** and **controlled attack simulations** on our own machines only. Never attack or scan anything we don't own. No real exploit code.
- Falco/auditd/Isolation Forest/React/JWT are **stretch goals**, not required. Core = external monitoring + reliable detection + working auto-containment.

## 3. Innovations we can claim (pick 2-3 for the pitch)

1. **Intent-linked timeline**: each system event is tied to the agent step that caused it (read untrusted doc -> doc held an instruction -> agent ran curl to unknown IP -> contained). Generic runtime tools can't see agent intent.
2. **Taint tracking for prompt injection**: content from untrusted sources is marked; actions following it that touch sensitive things raise the risk score.
3. **Self-explaining risk score**: show `severity x asset_value x confidence` per alert.
4. **Time metrics**: time-to-detect and time-to-contain, plus precision/recall/false-positive rate.
5. **Tamper test**: agent tries to edit/delete logs and fails (proves external monitoring). Evidence hash chain with latest hash anchored in the report.

Do NOT claim: "novel external monitoring/egress control" (Falco, NVIDIA OpenShell, AgentShield exist), or high precision/recall unless attack scenarios were written separately from the rules and include benign-but-unusual actions.

## 4. Tech stack

| Part | Tech |
|---|---|
| Sandbox | Docker (inside WSL2 Ubuntu on Windows) |
| Backend | Python 3, FastAPI, SQLite or JSONL files |
| Monitoring | `docker events`/`docker logs`, `inotifywait` on mounted dummy-secrets dir, `tcpdump` on the docker bridge |
| Detection | Python rules + IoC list (Isolation Forest = stretch) |
| Evidence | SHA-256, hash-chained JSONL, PCAP |
| Dashboard | Single dark HTML page served by FastAPI (vanilla JS), no React needed |
| Report | HTML report, print to PDF from browser |

Container hardening (required, it is what makes "external monitoring" true): non-root user, `--cap-drop=ALL`, `--read-only` filesystem, `--security-opt no-new-privileges`, no Docker socket mounted, never `--privileged`, resource limits, dedicated network.

## 5. Dashboard design inspiration (3 reference screenshots)

1. **ROE Gate audit dashboard**: dark, monospace, neon green/red/amber on black. 4 stat tiles (Events / Allowed / Violations / Contained), By Category and By Tool bars, filter chips (ALLOW/DENY/HALT) + search, tabs (Decision Log, Policy, Trends, Alerts), **Emergency Halt** button, Export JSON/CSV, auto-refresh, "Connected" status, policy hash in header.
2. **SNAP Defense**: small node map (Agent container -> sandbox network -> host -> external IP), compromised node ringed red, critical alert popup with Source vs Target panels and buttons (Pause, Disconnect, Resolve, Suppress similar).
3. **Critical Incident Active view**: red banner (incident ID, active timer, severity), live event stream with severity tags (left), **attack-chain stepper** (center) + affected assets table, **response playbook** with step statuses and an "Execute Containment" button (right), evidence hashes and report link.

Demo states: **SAFE (green)** -> **SUSPICIOUS (amber)** -> **CONTAINED (red banner)** -> **REPORT GENERATED**.

## 6. SHARED CONTRACT (both tracks depend on this — change only by agreement)

All shared files live in `shared/`. Track A writes them, Track B reads them. Track B develops against `shared/fixtures/` until A is ready.

**Event** — one JSON object per line in `shared/runtime/events.jsonl`:
```json
{"id":"evt-0007","ts":"2026-11-14T10:02:11.412Z","run_id":"run-attack-01","source":"file|network|agent_step|container",
 "type":"file_read|net_connect|step|pause|disconnect",
 "detail":{"path":"/secrets/dummy.txt"},
 "step_id":"step-3","verdict":"allow|suspicious|violation"}
```
- `source: agent_step` events come from the agent's stdout (captured by `docker logs`, host-side), with `detail: {"action":"...","reason":"...","tainted":true|false}`.
- `step_id` links system events to the agent step that caused them (intent-linked timeline).
- Additive types (from A4): `agent_step/step_result` with `detail: {"ok":bool,"error":str|null}` (outcome of a step; failed tamper attempts show here), `file/dir_list`, `file/file_write`, `file/file_delete`, `container/start|exit|unpause`. `network/net_connect` detail is `{"src_ip","src_port","dst_ip","dst_port","proto"}`. Network capture is saved to `shared/runtime/capture.pcap`.

**Alert/Incident** — `shared/runtime/incidents.json` (list):
```json
{"incident_id":"INC-2026-11-14-001","run_id":"run-attack-01","status":"open|contained|resolved",
 "severity":"low|medium|high|critical","risk_score":87,
 "score_factors":{"severity":5,"asset_value":4,"confidence":0.9},
 "rules_triggered":[{"rule_id":"R-FILE-001","name":"Restricted file read","event_ids":["evt-0007"]}],
 "chain":["task_started","restricted_file_read","blocked_destination","contained"],
 "actions_taken":[{"action":"docker pause","ts":"...","ok":true},{"action":"network disconnect","ts":"...","ok":true}],
 "time_to_detect_ms":420,"time_to_contain_ms":1350,
 "evidence":{"log":"evidence/INC-.../events.jsonl","pcap":"evidence/INC-.../capture.pcap","chain_head":"sha256:..."}}
```

**Risk score**: `risk = round(100 * (severity/5) * (asset_value/5) * confidence)`, each of severity/asset_value in 1..5, confidence 0..1.

**Evidence chain** — `shared/runtime/evidence/<incident_id>/chain.jsonl`: each line `{"seq":n,"ts":...,"record":{...},"prev_hash":"sha256:...","hash":"sha256:..."}` where `hash = sha256(prev_hash + canonical_json(record))`. Genesis `prev_hash` = 64 zeros. Print the final `chain_head` in the report.

**Policy** — `shared/policy.json`: allowed paths, restricted paths (dummy secrets), blocked/allowed destinations, asset values. Header shows its SHA-256.

**Control** (B -> A): B writes a command file `shared/runtime/control.json` `{"cmd":"emergency_halt|run_benign|run_attack|reset","ts":...}`; A's engine polls it and replies by updating events/incidents. (HTTP instead is fine if both agree; keep file-based by default.)

**API** (Track B serves; used by dashboard): `GET /api/state` (counts + current state SAFE/SUSPICIOUS/CONTAINED), `GET /api/events`, `GET /api/incidents`, `GET /api/incidents/{id}/report` (HTML), `POST /api/control`, `GET /api/verify/{id}` (re-verifies the hash chain).

## 7. Repo layout

```
CLAUDE.md                 <- this file
TRACK_A_ABHINAV.md        <- engine (sandbox, monitor, detect, respond, evidence)
TRACK_B_MENVA.md          <- console (API, dashboard, report, test scenarios, metrics)
INTEGRATION.md            <- final merge + demo script
shared/policy.json
shared/fixtures/          <- sample events/incidents/evidence for B to build against
shared/runtime/           <- live files written at runtime (gitignored)
engine/                   <- Track A code
console/                  <- Track B code
```

## 8. Setup: Docker on Windows (both teammates; neither has Docker yet)

We use **WSL2 + Ubuntu + Docker Engine** (not Docker Desktop). The monitoring needs a real Linux kernel.

1. Open **PowerShell as Administrator** and run: `wsl --install -d Ubuntu`
2. **Restart** the PC. Ubuntu opens after reboot; create a username and password (password is invisible as you type).
   - If it errors about virtualization: reboot into BIOS and enable **Intel VT-x / AMD SVM**, then retry.
3. In the Ubuntu window:
   ```
   sudo apt update && sudo apt install -y docker.io tcpdump inotify-tools python3-pip python3-venv git
   sudo usermod -aG docker $USER
   ```
4. **Close and reopen** the Ubuntu window (reloads group membership), then:
   ```
   sudo service docker start
   docker run --rm hello-world
   ```
   Expect "Hello from Docker!". After every Windows reboot, run `sudo service docker start` again.
5. Get the code inside Ubuntu (faster than /mnt/c): 
   ```
   git clone https://github.com/AbhiNav-S-Biju/JAM-session.git ~/JAM-session && cd ~/JAM-session
   ```
   (Menva needs to be added as a collaborator first; Abhinav does this in GitHub repo Settings -> Collaborators.)
6. Python env: `python3 -m venv .venv && source .venv/bin/activate && pip install fastapi uvicorn scapy scikit-learn`
7. Windows browser can open `http://localhost:8000` for the dashboard while the server runs in WSL.

Troubleshooting: `Cannot connect to the Docker daemon` -> run `sudo service docker start`. `permission denied` on docker -> you skipped the group step or didn't reopen the terminal. Test Docker **before** anything else; it is the biggest risk.

## 9. Working rules

- Two people, two tracks, one repo. Work on branches `track-a` / `track-b`, merge to `main` only at integration (see INTEGRATION.md). Pull before you push.
- Never commit `.env`, secrets, PCAPs or `shared/runtime/`. Dummy secrets are fake and may live in `shared/fixtures/` only.
- Keep it simple: a working demo beats extra features. Cut stretch goals first.
- After modifying code, run `graphify update .` if a `graphify-out/` folder exists.
- Commit style: short imperative subject. Push with the `AbhiNav-S-Biju` GitHub account (Menva pushes with their own account once added as collaborator).

## 10. Timeline (2 days, today is 2026-11-13)

| When | Track A (Abhinav) | Track B (Menva) |
|---|---|---|
| Day 1 AM | WSL + Docker working, locked-down container, scripted agent | WSL + Docker, FastAPI skeleton, fixtures, dashboard layout |
| Day 1 PM | Monitor + rules + pause/disconnect working | Dashboard live on fixtures, timeline + stepper |
| Day 1 eve | Evidence chain + risk score + incidents.json | Report page, verify endpoint, control buttons |
| Day 2 AM | **Integration** (INTEGRATION.md) | **Integration** |
| Day 2 PM | Metrics runs, rehearse 3-min demo | Polish UI, rehearse |
