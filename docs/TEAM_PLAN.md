# Option A Team Plan: Architecture, Work Split, Models

Nov 13, 2026 · @Jeev

The team has chosen Option A, the home network segmentation simulator (see Option A v2). This doc sets the architecture, splits the work across three people, and sets which Claude model to use for each task. It also covers the Claude Code usage budget and the repo cleanup.

## 1. Goal and scope for the prototype

A simulated home network with smart devices, a laptop, and a guest device. The tool shows the blast radius of one compromised device before and after default-deny rules. It also checks what leaves the laptop and raises alerts on unexpected flows. Everything runs on simulated data. Nothing touches a real network.

Out of scope for tomorrow: real device discovery, sign-in to a router, real traffic capture, and any attack code.

## 2. Architecture

```latex
\begin{tikzpicture}[node distance=12mm and 16mm,
  box/.style={draw, rounded corners, align=center, minimum width=38mm, minimum height=10mm}]
  \node[box] (scn) {scenarios/*.yaml\\(devices, zones, flows)};
  \node[box, right=of scn] (model) {model.py\\(load and validate)};
  \node[box, right=of model] (pol) {policies.py\\(flat, vlan_only, vlan_deny)};
  \node[box, below=of pol] (reach) {reach.py\\(blast radius)};
  \node[box, below=of model] (out) {outbound.py\\(laptop checks)};
  \node[box, below=of scn] (alerts) {alerts.py\\(baseline alerts)};
  \node[box, below=of reach] (rep) {report.py\\(CSV, Markdown, HTML)};
  \draw[->] (scn) -- (model);
  \draw[->] (model) -- (pol);
  \draw[->] (pol) -- (reach);
  \draw[->] (model) -- (out);
  \draw[->] (model) -- (alerts);
  \draw[->] (reach) -- (rep);
  \draw[->] (out) -- (rep);
  \draw[->] (alerts) -- (rep);
\end{tikzpicture}
```

main.py (CLI) calls these modules in order and writes everything to an out/ folder. sim\_traffic.py generates the simulated traffic log from the scenario file.

## 3. Module contracts (agree these before coding)

Each person codes only their own module. Other modules are called through these signatures, so nobody waits on anyone.

| Module | Owner | Function | Returns |
| --- | --- | --- | --- |
| model.py | Person 1 | load\_scenario(path) | Scenario: devices (name, zone, type, critical, compromised), zones, traffic (list of flows), laptop\_allow (list of destinations), allow\_lists per device |
| policies.py | Person 1 | apply\_policy(name, scenario) | set of allowed (src, dst) edges, name is one of flat, vlan\_only, vlan\_deny |
| reach.py | Person 1 | blast\_radius(edges, foothold) | ReachResult: reachable set, hops per device, critical assets reached |
| outbound.py | Person 2 | check\_laptop(scenario) | list of Alert for laptop flows to unlisted destinations or above the volume threshold |
| alerts.py | Person 2 | check\_baseline(scenario) | list of Alert for any device contacting a destination not on its allow list |
| sim\_traffic.py | Person 2 | make\_traffic(scenario, seed) | deterministic traffic list (same seed, same output) |
| report.py | Person 3 | write\_all(results, out\_dir) | results.csv, report.md, before\_after.html |
| main.py | Person 3 | CLI: python -m src.main scenarios/home.yaml --out out/ | runs all steps and prints the before-and-after table |

Scenario file shape (YAML): devices list with name, zone, type, critical, and allow list; zones list; laptop block with allow list and volume threshold; compromised device name; policy list to compare.

## 4. Work split (three people)

| Person | Owns | Main deliverable | Tonight's exit check |
| --- | --- | --- | --- |
| Person 1 | model.py, policies.py, reach.py, repo scrub, integration | Blast-radius engine | Acceptance tests 1 to 3 pass |
| Person 2 | outbound.py, alerts.py, sim\_traffic.py | Laptop outbound check and alerts | Outbound and alert tests pass on a fixed seed |
| Person 3 | report.py, main.py, README, demo runner | Before-and-after report and one-command run | out/ folder produced from one command |

Everyone also owns one explanation: the person who built a module explains it to the other two at the mock-interview practice. Each person should be able to explain all three modules' purposes, even if they only built one.

## 5. Model choice per task

| Task | Model | Reason |
| --- | --- | --- |
| Repo scrub and scaffold | Sonnet 5.5 | Deletes files, so it needs care, but the task is mechanical |
| Core engine code (model, policies, reach) | Sonnet 5.5 | Good balance of quality and usage cost |
| Review of reachability and policy logic | Sonnet 5.5 | One review pass to catch logic errors. Use once. |
| Outbound and alert code | Sonnet 5.5 | Same as core engine |
| Test files | Haiku 5.5 | Cheap and quick for repetitive test code |
| HTML before-and-after view | Sonnet 5.5 | Needs layout judgement |
| README, study guide, Q&A | Haiku 5.5 | Writing task, low cost |
| Stuck after two failed attempts | Sonnet 5.5 | Escalate only when needed |

Not needed for this project: Claude Fable 5.2 or Mythos-tier models. They cost more and add nothing the simulator needs.

## 6. Claude Code usage budget

The numbers below are the snapshot you gave. Check them before you start, because limits move.

| Account | Used by | Left now (5-hour window) | Reset | Plan |
| --- | --- | --- | --- | --- |
| Personal (Person 1) | Person 1 | about 93% | about 7:30 pm | Carries the heaviest build: engine and integration |
| Shared (Persons 2 and 3) | Persons 2 and 3 | about 79% | 5 pm, if that means today (assumed) | Module work and docs. One person runs Claude Code at a time. |

Rules to save usage:

- Run tests locally. Only call Claude Code to write or fix code.
- Give each Claude Code run one module and its contract from section 3.
- Use Haiku 5.5 for docs and tests.
- Use Sonnet 5.5 only for the single review pass.
- If the shared account runs low, Person 2 and Person 3 hand writing tasks (README, Q&A) to Person 1's account after its heavy build is done.

## 7. Timeline

- Now to 6 pm: Person 1 runs the repo scrub (prompt below). Persons 2 and 3 read the contracts and set up their branches.
- 6 pm to 9 pm: all three build their modules in parallel on separate branches.
- 9 pm to 10 pm: merge in this order: model and policies, then reach, then outbound and alerts, then report and CLI. Run all tests after each merge.
- 10 pm to 11 pm: run the full demo command twice. Fix only what breaks. Record a screen capture as a backup.
- Before the mock interview: each person explains their module out loud, and each person explains one other module.

If a module is not working by 10 pm, cut it from the demo and say so. Do not show it broken.

## 8. Integration rules

- One branch per person, named by module, for example engine-core, outbound-alerts, report-cli.
- Nobody edits another person's module. Ask the owner.
- Merge only when the module's tests pass.
- No attack code, no real network scanning, no real device access. Traffic is always simulated.

## 9. Risks

- Usage runs out on the shared account. Mitigation: section 6 rules.
- Modules do not fit the contracts. Mitigation: change the contract in this doc first, then tell both owners.
- The laptop check is too simple to say much. Mitigation: state that it is a teaching model with simulated traffic.
- Judges ask about Firewalla. Mitigation: the Option A v2 doc, section 6.

## 10. Repo cleanup

The repo currently holds Option B (CageWatch) work. The cleanup prompt keeps that work on an archive branch, removes it from the main branch, creates the Option A layout, and commits locally. It does not push. Run it once, and check the output before you push anything.

## 11. Build spec for Claude Code

One engine does all the detection. The judge demo and the report are read-only views over the engine's output, so what the judges see always matches what the tests check. Status: spec only. Nothing in this section has been run yet.

### Rule: nothing hardcoded

Devices, zones, hosts, flows, policies and thresholds live in YAML files. The code only reads them. Changing a value in a YAML file changes the report and the demo with no Python or JavaScript edit.

### Layout

```
config/policies.yaml     policy definitions: flat, vlan_only, vlan_deny
config/thresholds.yaml   outbound MB limit, beacon count, beacon window
scenarios/home.yaml      zones, devices, hosts, baseline, scenarios, expected results
src/model.py             load and validate scenario files
src/policies.py          apply_policy
src/reach.py             blast_radius
src/outbound.py          check_laptop
src/alerts.py            check_baseline
src/sim_traffic.py       make_traffic (seeded, deterministic)
src/report.py            write_all
src/main.py              CLI entry point
tests/                   one file per module, plus test_scenarios.py and test_no_hardcoding.py
demo/index.html          draws only what demo/results.js contains
out/                     generated, never committed
```

### Scenario file (shape)

```
zones:
  - {name: Trusted, x: 140, y: 70, w: 180, h: 180}
devices:
  - {id: laptop, name: Laptop, zone: Trusted, x: 230, y: 120}
hosts:
  - {id: weather, name: Weather service, known: true, x: 330, y: 30}
  - {id: unknown, name: UNLISTED server, known: false, x: 570, y: 525}
foothold: camera
baseline:
  - [laptop, weather]
  - [camera, nvr]
scenarios:
  - id: vendor
    name: Vendor app takes laptop files
    flows:
      - {src: laptop, dst: unknown, bytes: 48000000, t: 10}
    expect:
      laptop_outbound_mb: {flat: 48.0, vlan_deny: 0.0}
```

The baseline list is the only allow list. vlan\_deny uses it, and check\_baseline uses it to decide what counts as unusual. Coordinates are in the file, so the demo never carries its own layout.

The demo home has devices laptop, phone, thermostat, fridge, camera, nvr, doorbell (second camera, so vlan\_only shows the same-zone gap), and visitor. Hosts are weather, school, thermocloud (ThermoCo cloud, known) and unknown (UNLISTED).

### Module contracts

- `model.load_scenario(path) -> Scenario`. Validates every reference: each flow and baseline entry must name an existing device or host. A bad reference raises an error that names the line.
- `policies.apply_policy(name, scenario) -> set[(src, dst)]`. flat allows every device pair. vlan\_only allows pairs in the same zone and any device to a known host. vlan\_deny allows only the baseline pairs. Rules come from config/policies.yaml, not from the code.
- `reach.blast_radius(edges, foothold) -> ReachResult(reachable, count, total)`. Breadth-first search over the directed edges, counting devices only, not the foothold itself. total is the number of other devices.
- `outbound.check_laptop(scenario, edges, thresholds) -> list[Alert]`. Counts only delivered flows, meaning flows whose (src, dst) is in edges. Raises outbound\_unlisted for an unlisted destination, and outbound\_over\_limit when delivered bytes exceed outbound\_mb\_limit.
- `alerts.check_baseline(scenario, thresholds) -> list[Alert]`. Runs on every flow, whatever the policy, because the monitor is always on. Raises unlisted\_flow for any flow outside baseline to an unlisted host. Raises beaconing when there are at least beacon\_min\_count flows to one destination inside beacon\_window\_s seconds.
- `sim_traffic.make_traffic(scenario, seed) -> list[Flow]`. Expands each scenario's flows into timed events. The seed controls any jitter, so two runs give the same output.
- `report.write_all(results, out_dir)`. Writes out/results.json, out/results.csv, out/report.md, out/before\_after.html, and demo/results.js (a single line: window.RESULTS = ...). The demo loads that script tag, so it works from a double click with no server.

### Expected results (the test oracle)

Write these by hand from the design, then the tests compare the engine's output with them. Never copy them from output, or the tests check nothing.

- camera compromise, blast\_radius: flat 7 of 7, vlan\_only 2 (nvr, doorbell), vlan\_deny 1 (nvr).
- vendor, laptop\_outbound\_mb: flat 48.0, vlan\_deny 0.0 (blocked, but the alert still fires).
- vendor, alerts under vlan\_deny: outbound\_unlisted, unlisted\_flow.
- beacon (five 64-byte flows at t = 0, 60, 120, 180, 240 to unlisted): beaconing under every policy, because the monitor sees traffic even when default-deny blocks it.

### Acceptance criteria (Claude Code is done when all pass)

1. pytest -q passes, including every scenario's expect block.
2. python -m src.main scenarios/home.yaml --out out/ writes the four out/ files and demo/results.js.
3. Double-click demo/index.html (no server). The scenario buttons and the default-deny toggle show the same numbers as out/report.md.
4. test\_no\_hardcoding: copy home.yaml to a temp folder, move one device to another zone, rerun, and the blast radius changes with no code edit.
5. No attack code, no real network scanning, no real device access. All traffic is simulated.

### Prompt order for Claude Code

Build in this order and run the tests after each module: model, policies, reach, sim\_traffic, outbound, alerts, report, main, demo. If a test fails against an expect value, fix the code. Do not edit the expect value to match the output. Report which expect values pass and which do not.

Work split: Person 1 owns model, policies, reach and sim\_traffic. Person 2 owns outbound and alerts. Person 3 owns report, main, demo and README. Everyone runs the full test suite before merging.
