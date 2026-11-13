# Person 1 (Jeev): engine core and integration

**Branch:** `engine-core` · **Claude model:** Sonnet 5.5 (one review pass at the end, once) · **Budget:** personal account, carries the heaviest build.

Read `CLAUDE.md` and `docs/TEAM_PLAN.md` sections 3 and 11 first.

## You own (edit only these)
`src/contracts.py`, `src/model.py`, `src/policies.py`, `src/reach.py`, `src/sim_traffic.py`,
`tests/test_model.py`, `tests/test_policies.py`, `tests/test_reach.py`, `tests/test_sim_traffic.py`,
`tests/test_scenarios.py`, `tests/test_no_hardcoding.py`, and the shared files `config/*.yaml`, `scenarios/home.yaml`.

## Your job, in order (run `pytest -q` after each)
1. **model.py**: `load_scenario`, `load_thresholds`, `with_case`. Validate every reference; a bad one raises `ValueError` naming it.
2. **policies.py**: `apply_policy`. Interpret the rule names in `config/policies.yaml`. No `if name == "flat"` in Python.
3. **reach.py**: `blast_radius` (BFS over directed edges, devices only, foothold excluded).
4. **sim_traffic.py**: `make_traffic`, seeded and deterministic (`random.Random(seed)`).
5. **tests/test_scenarios.py**: for every case in `home.yaml`, run every policy and check the `expect:` block against the engine (outbound and alerts need Person 2's modules; start with `blast_radius`).
6. **tests/test_no_hardcoding.py**: copy `home.yaml` to a temp dir, move one device to another zone, rerun, assert the blast radius changes with no code edit.
7. **Repo integration**: at 9 pm merge in this order: model+policies, reach, outbound+alerts, report+CLI. Run all tests after each merge.
8. Use Sonnet 5.5 for **one** review pass of the reachability and policy logic.

## Exit check tonight
Camera compromise gives: `flat` 7 of 7, `vlan_only` 2 (nvr, doorbell), `vlan_deny` 1 (nvr). Acceptance tests 1 to 3 pass.

## Others depend on you
Persons 2 and 3 import `src/contracts.py` and call `model.load_scenario`, `with_case`, `policies.apply_policy`, `reach.blast_radius`. Push `contracts.py` and `model.py` first so they can unblock. If you change a type, edit `docs/TEAM_PLAN.md` first and tell them.

## Starter prompt for Claude Code
> I'm Person 1. Read CLAUDE.md and PERSON_1.md. Build `src/model.py` only, to the contract in the stub and docs/TEAM_PLAN.md section 11. Add `tests/test_model.py`, run `pytest -q`, and stop. Do not edit any `expect:` value.

## Be ready to explain
Your three modules, plus one of the others' modules at the mock-interview practice.
