# Person 3: report, CLI, demo, README

**Branch:** `report-cli` · **Claude model:** Sonnet 5.5 for the HTML view, Haiku 5.5 for README and tests · **Budget:** shared account (one of Persons 2 and 3 at a time).

Read `CLAUDE.md` and `docs/TEAM_PLAN.md` sections 3 and 11 first.

## You own (edit only these)
`src/report.py`, `src/main.py`, `demo/index.html`, `README.md`, `tests/test_report.py`, `tests/test_main.py`.

Do not edit `src/contracts.py`, `config/`, or `scenarios/home.yaml`. They are Person 1's. Need a change? Ask.

## Your job
1. **report.py** `write_all(results, out_dir)`: writes `out/results.json`, `out/results.csv`, `out/report.md`, `out/before_after.html`, and `demo/results.js` (a single line: `window.RESULTS = {...};`, so the demo works from a double click with no server).
2. **main.py**: `python -m src.main scenarios/home.yaml --out out/` loads the scenario and thresholds, then for every case and every policy calls `with_case`, `apply_policy`, `blast_radius`, `check_laptop`, `check_baseline`. It builds `results`, calls `write_all`, and prints the before-and-after table.
3. **demo/index.html**: draws ONLY what `demo/results.js` contains: zones, devices, hosts with their x/y, scenario buttons, and a default-deny toggle. No layout, names or numbers hardcoded in the HTML or JS. It must show the same numbers as `out/report.md`.
4. **README.md**: keep setup and run steps accurate as the CLI changes.
5. Agree the shape of `results` with Person 1 and write it at the top of `report.py` as a docstring so both sides code to it.

## Until the engine is merged
Build against a hand-written `results` dict (copy the expected numbers from `scenarios/home.yaml`), so you are never blocked. Swap in the real engine once Person 1 merges `model` and `policies`.

## Exit check tonight
`python -m src.main scenarios/home.yaml --out out/` produces the four `out/` files and `demo/results.js`, and double-clicking `demo/index.html` shows the same numbers as `out/report.md`.

## Starter prompt for Claude Code
> I'm Person 3. Read CLAUDE.md and PERSON_3.md. Build `src/report.py` only, writing from a hand-made results dict. Add `tests/test_report.py`, run `pytest -q`, and stop.

## Be ready to explain
Your modules, plus one of the others' modules at the mock-interview practice.
