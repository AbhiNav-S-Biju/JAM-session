# Track A — Engine (Abhinav)

Read `CLAUDE.md` first (shared contract in section 6). You own everything that **produces** the data: sandbox, scripted agent, monitor, detection, risk score, response, evidence. You do **not** build the dashboard. Menva consumes your output files.

**Branch:** `track-a`. **Code lives in:** `engine/`. **You write to:** `shared/runtime/`.
**Independence:** you can finish and test this entirely from the terminal (no UI). Done = running one command produces correct `events.jsonl`, `incidents.json`, and evidence.

## Deliverables

### A1. Environment (do first, hour 1)
- Follow CLAUDE.md section 8. Confirm `docker run --rm hello-world` works. **If it doesn't within 1 hour, tell Menva and the team.**

### A2. Locked-down sandbox
- `engine/sandbox/Dockerfile` (small Python image, non-root user).
- `engine/sandbox/run_agent.sh` starting the container with: `--user 1000 --cap-drop=ALL --read-only --security-opt no-new-privileges --pids-limit 100 --memory 256m`, dedicated network `cagewatch-net`, `/work` tmpfs, a read-only mount of `/data/authorized/`, and a mount of dummy `/secrets/` (restricted by policy). No Docker socket, no `--privileged`.
- Dummy files: `engine/sandbox/data/authorized/report.txt`, `engine/sandbox/data/secrets/dummy_secret.txt` (fake content only).

### A3. Scripted agent (two modes)
- `engine/agent/agent.py --mode benign|attack` (and one extra `--mode benign_unusual` that does odd-but-allowed things, e.g. lists `/work`, so false positives are measurable).
- Every action first prints a **structured step line to stdout** (host captures with `docker logs -f`): `{"step_id":"step-3","action":"read_file","target":"/secrets/dummy_secret.txt","reason":"user doc told me to","tainted":true}`.
- Benign: reads authorized file, does calculations, writes result.
- Attack: reads an "untrusted doc" containing a fake injected instruction, then reads the dummy secret, then tries to connect to a blocked IP (use a non-routable/lab address like `203.0.113.10`, reserved for documentation) and tries to modify its own logs (should fail).

### A4. External collector (runs on the host, outside the container)
- `engine/collector/collector.py` merges three feeds into `shared/runtime/events.jsonl` in the contract format:
  1. Agent steps from `docker logs -f`.
  2. File access: `inotifywait -m -e open,access` on the host path of the mounted secrets/authorized dirs.
  3. Network: `tcpdump -i <bridge> -w capture.pcap` plus parsing of new destination IPs from the container's IP.
- Link system events to `step_id` by timestamp proximity (nearest preceding step).
- Stretch: Falco instead of the above, only if it works within 2 hours.

### A5. Detection engine
- `engine/detect/rules.py` reads `shared/policy.json`. Rules: `R-FILE-001` restricted file read, `R-NET-001` blocked/unknown destination, `R-INJ-001` action following tainted content, `R-TAMPER-001` attempt to modify logs. IoC list in `shared/policy.json`.
- Each event gets a `verdict`; rule hits create/extend an incident.
- Risk score per CLAUDE.md formula; write rule_id, factors and event_ids so the UI can explain the score.
- Stretch: Isolation Forest on step features (label as proof of concept).

### A6. Automatic response
- `engine/respond/respond.py`: on critical risk, in order: `docker pause <c>`, `docker network disconnect cagewatch-net <c>`, revoke temp token (a small token file/endpoint issued to the agent at start; delete it), snapshot evidence. Log each action with timestamp and success. Compute `time_to_detect_ms` and `time_to_contain_ms`.
- Honor `shared/runtime/control.json`: `run_benign`, `run_attack`, `emergency_halt`, `reset`.

### A7. Evidence vault
- `engine/evidence/vault.py`: copy incident events + PCAP into `shared/runtime/evidence/<incident_id>/`, build `chain.jsonl` per the contract, expose `verify_chain(path)` (used by Menva's `/api/verify`).
- Tamper test: edit one line of a chain, `verify_chain` must fail.

### A8. One-command runner
- `engine/run.py benign|attack|benign_unusual` starts everything and exits when the run ends. Also `engine/run.py serve-control` to poll control.json.

## Definition of done
- [ ] `python engine/run.py benign` -> events logged, **no incident**, verdicts all `allow`.
- [ ] `python engine/run.py attack` -> incident created, container paused, network disconnected, chain verifies, risk score matches formula.
- [ ] `benign_unusual` does not trigger a critical incident (or the false positive is documented).
- [ ] Output files validate against the contract in CLAUDE.md section 6.
- [ ] Container hardening flags verified (`docker inspect`).

## Hand-off to Menva
Push to `track-a`, and tell Menva: the exact output paths, one real sample `events.jsonl` + `incidents.json` (copy into `shared/fixtures/real/`), and any contract changes (should be none).
