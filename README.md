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

## Run (once all modules are merged)

```
python -m src.main scenarios/home.yaml --out out/
```
Then double-click `demo/index.html`.

## Repo map

`config/` policies and thresholds, `scenarios/` the demo home and expected results, `src/` the modules,
`tests/` one file per module, `demo/` the judge view, `docs/` the plan.

The earlier CageWatch work (Option B) is kept on the local branches `archive/cagewatch` and
`archive/cagewatch-console`.
