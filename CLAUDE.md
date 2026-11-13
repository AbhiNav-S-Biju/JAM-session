# Option A: Home Network Segmentation Simulator (read this first on every prompt)

A simulated home network (laptop, phone, thermostat, fridge, camera, doorbell, NVR, guest visitor).
The tool shows the **blast radius** of one compromised device under three policies
(`flat`, `vlan_only`, `vlan_deny`), checks what leaves the laptop, and raises alerts on unexpected flows.
**Everything is simulated.** No real network, no scanning, no router sign-in, no attack code.

Full plan, contracts and test oracle: `docs/TEAM_PLAN.md` (sections 3 and 11 are the contract).

## Step 0: find out who you are working for

Three people, three tracks. If the user has not said which one, ASK before doing anything:

| Person | File to read | Owns |
|---|---|---|
| Person 1 (Jeev) | `PERSON_1.md` | `src/contracts.py`, `model.py`, `policies.py`, `reach.py`, `sim_traffic.py`, integration, `tests/test_scenarios.py`, `tests/test_no_hardcoding.py` |
| Person 2 | `PERSON_2.md` | `src/outbound.py`, `src/alerts.py` and their tests |
| Person 3 | `PERSON_3.md` | `src/report.py`, `src/main.py`, `demo/`, `README.md` |

Read that person's file, then stay inside it.

## Rules (all tracks)

1. **Only edit your own files.** If you need a change in someone else's module, tell the user to ask the owner. Contract changes: edit `docs/TEAM_PLAN.md` first, then tell the user to tell the others.
2. **Nothing hardcoded.** Devices, zones, hosts, flows, policies, thresholds live in `scenarios/*.yaml` and `config/*.yaml`. Code only reads them.
3. **Never edit an `expect:` value to make a test pass.** Expected results were written by hand from the design. If a test fails, fix the code and report which expect values pass and fail.
4. **Simulated data only.** No attack code, no scanning, no real devices.
5. **One module per Claude Code run.** Give it the module's contract, build it, run `pytest -q`, stop.
6. **Run tests locally** (`pytest -q`). Use Claude Code to write or fix code, not to run tests for you.
7. Branch per person: Person 1 `engine-core`, Person 2 `outbound-alerts`, Person 3 `report-cli`. Merge only when your tests pass. Pull before you push. Never commit `out/`, `demo/results.js`, `.env`, `.mcp.json`.
8. Commit style: short imperative subject.
9. **Model choice:** Sonnet 5.5 for engine, outbound, alerts and the HTML view. Haiku 5.5 for tests, README and docs. Escalate only after two failed attempts.
10. Keep it simple. If a module is not working by 10 pm, cut it from the demo and say so. Do not show it broken.

## Decisions made while scaffolding (the plan left these open)

- Shared types live in `src/contracts.py` (Person 1 owns it). Not in the original layout, but outbound, alerts and report all need `Alert`, `Flow`, `Scenario`.
- A `Scenario` holds all cases; `model.with_case(scenario, case_id)` returns a copy whose `.flows` are that case's flows. `outbound`, `alerts` and `sim_traffic` read `scenario.flows`.
- `model.load_thresholds()` reads `config/thresholds.yaml` into a dict, passed to `check_laptop` and `check_baseline`.
- `reach.blast_radius(edges, foothold, device_ids)` takes device ids explicitly so it counts devices only (hosts are excluded).
- `flat` allows every device to every device AND every host. This is needed so the vendor case delivers 48 MB under `flat`.
- "Unlisted" means a host with `known: false`.
- `outbound_unlisted` fires on attempted laptop flows even when the policy blocks them. `outbound_over_limit` uses delivered bytes only.
- `expect.alerts` lists mean "these kinds must be present", not "exactly these".
- `thresholds.yaml` values (10 MB, 5 flows, 300 s) are our picks; the beacon case (5 flows over 240 s) is designed to trip them.
- 1 MB = 1,000,000 bytes (so 48,000,000 bytes = 48.0 MB).

## Layout

```
config/policies.yaml     policy rules (flat, vlan_only, vlan_deny)
config/thresholds.yaml   outbound MB limit, beacon count, beacon window
scenarios/home.yaml      zones, devices, hosts, baseline, cases, expected results (the oracle)
src/                     one module per file, see table above
tests/                   one test file per module, plus test_scenarios.py and test_no_hardcoding.py
demo/index.html          draws only what demo/results.js contains
out/                     generated, never committed
docs/TEAM_PLAN.md        the plan and the full spec
docs/TECH_GUIDE.md       concepts plus a file-by-file map (section 20)
docs/FRONTEND_HANDOFF.md for whoever owns the UI: data contract, what to touch, polish list
real/                    real-network viewer and attack demo for the owner's own home (Person 1). Opt-in network features need --i-own-this-network. Never commit real/input/ or real/out/
iot/                     3D sim page (three.js, vendored in iot/vendor/, do not edit). Reads window.RESULTS
```

Extra rules for `real/` and `iot/`: never ask for or store Wi-Fi names, passwords or router logins; MAC addresses stay masked in outputs unless `--show-mac`; anything that touches the network stays opt-in; the UI draws only what `window.RESULTS` contains.

Setup: `python -m venv .venv`, activate, `pip install -r requirements.txt`, then `pytest -q`.
Run: `python -m src.main scenarios/home.yaml --out out/`.
