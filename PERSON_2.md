# Person 2: laptop outbound check and baseline alerts

**Branch:** `outbound-alerts` · **Claude model:** Sonnet 5.5 for code, Haiku 5.5 for tests · **Budget:** shared account (one of Persons 2 and 3 runs Claude Code at a time).

Read `CLAUDE.md` and `docs/TEAM_PLAN.md` sections 3 and 11 first.

## You own (edit only these)
`src/outbound.py`, `src/alerts.py`, `tests/test_outbound.py`, `tests/test_alerts.py`.

Do not edit `src/contracts.py`, `config/`, or `scenarios/home.yaml`. They are Person 1's. Need a change? Ask.

## Your job
1. **alerts.py** `check_baseline(scenario, thresholds) -> list[Alert]`: runs on every flow in `scenario.flows`, whatever the policy.
   - `unlisted_flow`: flow not in `scenario.baseline` to a host with `known == False`.
   - `beaconing`: at least `beacon_min_count` flows from one src to one dst inside `beacon_window_s` seconds.
2. **outbound.py** `check_laptop(scenario, edges, thresholds) -> list[Alert]` and `delivered_mb(scenario, edges) -> float`:
   - `outbound_unlisted`: any laptop flow to an unknown host, even if the policy blocks it.
   - `outbound_over_limit`: delivered bytes (flows whose `(src, dst)` is in `edges`) above `outbound_mb_limit`.
   - 1 MB = 1,000,000 bytes.
3. **Tests** on a fixed seed. Hand-build small `Scenario` objects from `src/contracts.py` in the tests so you do not depend on Person 1's modules being finished. Also check against `scenarios/home.yaml` once `model.py` is merged.
4. Thresholds always come in through the `thresholds` argument. Never hardcode 10, 5 or 300.

## Expected results you must match (hand-written oracle in `scenarios/home.yaml`)
- vendor (laptop to unknown, 48,000,000 bytes): `flat` delivers 48.0 MB; `vlan_deny` delivers 0.0 MB but still raises `outbound_unlisted` and `unlisted_flow`.
- beacon (thermostat to unknown, 5 flows of 64 bytes at t = 0, 60, 120, 180, 240): `beaconing` under every policy.

## Exit check tonight
Outbound and alert tests pass on a fixed seed. Never edit an `expect:` value to make a test pass.

## Starter prompt for Claude Code
> I'm Person 2. Read CLAUDE.md and PERSON_2.md. Build `src/alerts.py` only, to the stub's contract. Write `tests/test_alerts.py` with hand-built Scenario objects, run `pytest -q`, and stop.

## Be ready to explain
Your two modules, plus one of the others' modules at the mock-interview practice.
