# Integration — final merge and demo (both)

Do this only after both tracks meet their **Definition of done** (see `TRACK_A_ABHINAV.md`, `TRACK_B_MENVA.md`). Read `CLAUDE.md` for the contract.

## 1. Merge (about 15 min)

```
git checkout main && git pull
git merge track-a        # Abhinav's engine
git merge track-b        # Menva's console
git push origin main
```
Both pull `main` afterwards. Contract files are the only shared surface, so conflicts should be limited to `README.md`/`.gitignore`.

## 2. Wire up (about 1 hour)

1. Abhinav: copy one real run into `shared/fixtures/real/` (events + incidents + evidence).
2. Menva: point the console at live data: `CAGEWATCH_DATA=shared/runtime`.
3. Start (inside WSL, project root, venv active), in two terminals:
   - Terminal 1: `python engine/run.py serve-control`
   - Terminal 2: `uvicorn console.api:app --host 0.0.0.0 --port 8000`
4. Open `http://localhost:8000` in the Windows browser.
5. Click **Run benign**: expect SAFE, events stream, 0 violations.
6. Click **Run attack**: expect SUSPICIOUS -> CONTAINED, container paused (`docker ps` shows Paused), network disconnected, incident, risk score, playbook entries, evidence hashes.
7. Click **Verify chain**: passes. Edit a line of `chain.jsonl` by hand, verify again: **fails** (great demo moment).
8. Click **Reset**.

## 3. Integration checklist
- [ ] Real output matches the contract (no UI breakage)
- [ ] Control buttons trigger the engine
- [ ] State badge changes SAFE -> SUSPICIOUS -> CONTAINED in sync with reality
- [ ] Time-to-detect / time-to-contain shown
- [ ] Report prints correctly with real evidence hashes
- [ ] Metrics table generated from real runs (Menva's scenarios)
- [ ] Tamper test works (agent cannot edit monitor logs; chain verify catches edits)
- [ ] Container hardening confirmed: `docker inspect` shows cap-drop ALL, read-only, non-root

## 4. Three-minute demo script

| Time | Say / do | Who |
|---|---|---|
| 0:00-0:30 | Problem: agents can run commands and reach the network. Show architecture (agent in cage, monitor outside). State honest scope. | Menva |
| 0:30-1:00 | **Run benign.** Green SAFE, authorized file read, result. | Abhinav clicks, Menva narrates |
| 1:00-1:40 | **Run attack.** Agent reads untrusted doc, follows injected instruction, reads dummy secret, tries blocked IP. Amber SUSPICIOUS, intent-linked timeline lights up. | Abhinav |
| 1:40-2:15 | **CONTAINED.** Red banner, container paused, network cut, risk score with factors, time-to-contain. Show `docker ps`. | Menva |
| 2:15-2:40 | Evidence vault: hashes, verify chain passes; edit a line -> fails. Open the incident report. | Abhinav |
| 2:40-3:00 | Metrics (precision/recall/false positives, time-to-contain), limits, next steps. | Menva |

Rehearse at least 3 times. Have a **backup screen recording** of a clean run in case Docker misbehaves live. Start Docker (`sudo service docker start`) and pre-run once before presenting.

## 5. Pitch notes
- Lead with **intent-linked timeline** and **taint tracking**; mention Falco/OpenShell exist and say how we differ (agent-aware correlation).
- Say plainly: scripted agent, dummy secrets, own lab, detects/contains attempted violations, does not claim to stop all escapes.

## 6. If things break (cut in this order)
1. Isolation Forest / Falco (already stretch)
2. Node map and PDF polish
3. Live control buttons -> run the engine from the terminal and show the dashboard
4. Last resort: play the backup recording and walk through the real evidence files
