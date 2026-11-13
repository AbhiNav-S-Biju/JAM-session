# Home Network Segmentation Simulator (Option A)

Pick a compromised device in a simulated home network and see how far an attacker could reach
before and after default-deny rules. It also checks what leaves the laptop and alerts on
unexpected flows. All data is simulated; nothing touches a real network.

## New here? Start with your file

| You are | Read | Your branch |
|---|---|---|
| Person 1 (Jeev): engine, integration | [PERSON_1.md](PERSON_1.md) | `engine-core` |
| Person 2: laptop outbound check and alerts | [PERSON_2.md](PERSON_2.md) | `outbound-alerts` |
| Person 3: report, CLI, demo, README | [PERSON_3.md](PERSON_3.md) | `report-cli` |

Everyone: read [docs/TEAM_PLAN.md](docs/TEAM_PLAN.md) sections 3 and 11 (the contracts and the test oracle).
Using Claude Code? Start it in this folder; `CLAUDE.md` makes it ask who you are and read your file.

## Setup

```
python -m venv .venv
.venv\Scripts\activate        # Windows PowerShell. Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

## Run

```
python -m src.main scenarios/home.yaml --out out/
```
This runs every case under every policy, prints the before-and-after table and the expected-result
checks (exit code 1 if any `expect:` value fails), and writes:

| File | What it is |
|---|---|
| `out/results.json` | everything, in the shape documented at the top of `src/report.py` |
| `out/results.csv` | one row per case and policy |
| `out/report.md` | before-and-after table, alerts, expected-result checks |
| `out/before_after.html` | static before/after maps for every case |
| `demo/results.js` | the same results as one line, `window.RESULTS = {...};` |

Then double-click `demo/index.html` (no server needed). Pick a scenario, a policy, or flip the
default-deny toggle; it shows the same numbers as `out/report.md`. Options: `--policies`,
`--thresholds` (other config files) and `--demo` (where to write `results.js`).

## Repo map

`config/` policies and thresholds, `scenarios/` the demo home and expected results, `src/` the modules,
`tests/` one file per module, `demo/` the judge view, `docs/` the plan.

The earlier CageWatch work (Option B) is kept on the local branches `archive/cagewatch` and
`archive/cagewatch-console`.
