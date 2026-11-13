# Tech Guide: how the simulator works and the concepts behind it

Audience: all three of us, before the mock interview. Each section ends with "Say it in one breath" so you can answer out loud.
Code you can open while reading: `src/` (modules), `config/` (policies, thresholds), `scenarios/home.yaml` (the demo home and the hand-written answers), `tests/`.

Status marker used below: **[built]** = merged and tested. **[spec]** = designed in `docs/TEAM_PLAN.md`, not built yet. Update these markers as modules land.

---

## 1. The big picture

We simulate a home network and ask two questions:

1. **If one device is hacked, what else can the attacker reach?** (blast radius, computed three times: with no segmentation, with VLANs, with default-deny)
2. **Is something leaving the network that shouldn't?** (laptop sending lots of data or talking to an unknown server; any device acting oddly)

Nothing is real. No scanning, no router login, no attack code. The "traffic" is a list of made-up flows in a YAML file.

### Data flow

```
scenarios/home.yaml  ->  model.load_scenario     -> Scenario (devices, zones, hosts, baseline, cases)
config/policies.yaml ->  policies.apply_policy   -> allowed edges  {(src, dst), ...}
                         reach.blast_radius      -> which devices the attacker reaches
scenario flows       ->  sim_traffic.make_traffic-> timed flows
                         outbound.check_laptop   -> laptop alerts
                         alerts.check_baseline   -> baseline alerts (beaconing, unlisted flow)
                         report.write_all        -> out/*.json/csv/md/html + demo/results.js
                         main.py                 -> runs everything, prints before/after table
                         demo/index.html         -> draws results.js only
```

One engine does all detection. The demo and the report are read-only views of its output, so what judges see always matches what the tests check.

### Who owns what

| Person | Files | Status |
|---|---|---|
| 1 (Jeev) | `contracts.py`, `model.py`, `policies.py`, `reach.py`, `sim_traffic.py`, scenario tests | **[built]** |
| 2 | `outbound.py`, `alerts.py` | **[built]** |
| 3 | `report.py`, `main.py`, `demo/index.html`, README | **[spec]** |

---

## 2. Code walkthrough (Person 1's modules)

### `src/contracts.py`: the shared vocabulary
Frozen `@dataclass`es: `Zone`, `Device`, `Host`, `Flow`, `Case`, `Scenario`, `Alert`, `ReachResult`.
- *Device* = something inside the home (laptop, camera). *Host* = something outside (weather service, an unlisted server). Devices have a zone; hosts have `known: true/false`.
- *Flow* = one connection: `src`, `dst`, `bytes`, `t` (seconds from start).
- *Scenario* holds everything loaded from YAML, plus `.flows` = the flows of the case currently running (empty until `with_case`).
- `frozen=True` means objects can't be changed after creation. Safer: nobody can accidentally mutate shared data; also makes them hashable. We use `tuple` and `frozenset` for the same reason.

### `src/model.py`: load and validate
- `load_scenario(path)`: `yaml.safe_load` the file, build the dataclasses, then **validate every reference** (a flow or baseline entry must name an existing device/host; foothold must be a device; every device's zone must exist; no duplicate ids; no id used for both a device and a host; flow `bytes` and `t` must be non-negative integers). A bad entry raises `ValueError` naming it, e.g. `baseline[8]: dst 'ghost' is not a device or host`.
- Why validate: a typo in YAML would otherwise silently produce a wrong blast radius. Fail loudly, early, with the line named.
- `load_thresholds()` reads `config/thresholds.yaml`. `with_case(scenario, case_id)` returns a **copy** (`dataclasses.replace`) with that case's flows set.

### `src/policies.py`: turn a policy name into allowed edges
- `config/policies.yaml` defines policies as lists of **rule names**. `RULES` maps each rule name to a small function:
  - `all_pairs`: every device to every other device and every host
  - `same_zone`: device to device when zones match
  - `device_to_known_host`: any device to a host with `known: true`
  - `baseline_only`: only the pairs in the scenario's baseline
- `apply_policy(name, scenario)` returns the **union** of its rules' edges. An edge is a directed pair `(src, dst)`.
- Result: `flat = all_pairs`, `vlan_only = same_zone + device_to_known_host`, `vlan_deny = baseline_only`. No `if name == "flat"` anywhere, so editing the YAML changes behaviour (tested).

### `src/reach.py`: blast radius
Breadth-first search (BFS). Start at the foothold, repeatedly visit everything reachable by an allowed edge. Count **devices only** (hosts are not counted, and are not stepped through; the foothold isn't counted). `total = number of devices - 1`.

```python
seen = {foothold}; queue = deque([foothold])
while queue:
    cur = queue.popleft()
    for nxt in out.get(cur, ()):      # out = adjacency list built from edges
        if nxt not in seen:           # the 'seen' set is what stops cycles
            seen.add(nxt); queue.append(nxt)
```
Time cost is O(devices + edges). The `seen` set is the key detail: without it, two devices that can reach each other would loop forever.

### `src/sim_traffic.py`: seeded, deterministic traffic
`make_traffic(scenario, seed, jitter_s=0)` returns the flows sorted by time. With `jitter_s > 0`, each flow's time shifts by a random whole number of seconds in `[-jitter_s, +jitter_s]`, using `random.Random(seed)` (a private generator, not the global one). Same seed gives identical output. Default `jitter_s=0` returns flows exactly as written so the hand-written answers hold.

### The oracle: `scenarios/home.yaml` `expect:` blocks
Hand-written from the design, before any code existed. `tests/test_scenarios.py` checks the engine against them. **If a test fails, fix the code, never the expected value** (see section 14).

---

## 3. Home network basics: subnets, VLANs, zones, and why a flat network spreads an attack

- **Subnet**: a block of IP addresses that can talk to each other directly (e.g. `192.168.1.0/24`). A typical home router puts everything in one subnet.
- **Flat network**: every device can reach every other device. If your camera is compromised, the attacker can try your laptop, phone and NVR.
- **VLAN** (virtual LAN): the same physical network split into separate logical networks. Devices on different VLANs can't talk directly; the router/firewall must route between them, and that's where rules apply.
- **Zone**: our word for a group of devices with the same trust level (Trusted, IoT, Security, Guest). In real life a zone is usually one VLAN or SSID.
- **Why flat spreads attacks**: no internal barriers. The attacker only needs one weak device (cheap camera, old fridge) to get a foothold, then moves sideways to valuable ones. In our `flat` policy the compromised camera reaches 7 of 7 devices.

*Say it in one breath:* "A flat network trusts everything inside it, so one weak device gives access to all of them. VLANs split it into zones so the router can enforce who talks to whom."

## 4. Firewalls and rules: default-deny, allow lists, rule order

- **Firewall rule**: match traffic (source, destination, port) then allow or deny.
- **Default-allow**: everything is permitted unless blocked. Easy, but you must anticipate every bad thing.
- **Default-deny**: everything is blocked unless explicitly allowed. You list only what you need. Safer, because unknown things fail closed.
- **Allow list**: the list of permitted pairs. Ours is `baseline` in `home.yaml`; `vlan_deny` allows exactly those edges, nothing more.
- **Rule order matters in real firewalls**: rules are evaluated top to bottom and the first match wins (iptables, most router firewalls). A broad "allow all" above a specific "deny" makes the deny useless; the usual layout is specific rules first, then a final catch-all "deny all". **Our simulator sidesteps order**: a policy is the union of allow rules with an implicit deny for anything not in the set, so order doesn't affect the result. Be ready to say that honestly: it's a simplification.

*Say it in one breath:* "Default-deny means nothing is allowed unless on the list. In real firewalls order matters because the first matching rule wins; our model uses a pure allow-set so order can't change the answer."

## 5. Lateral movement and blast radius, and computing reachability with BFS

- **Lateral movement**: after getting into one device, an attacker moves to others on the same network. Typically via weak or reused passwords, open services, or trust relationships.
- **Blast radius**: how many other things an attacker can reach from one compromised device. It's a way to quantify "how bad would one compromise be?"
- **Why BFS**: the network is a directed graph (devices/hosts are nodes, allowed flows are edges). "What can I reach from here?" is graph reachability. BFS (or DFS) visits each node once. Reachability is **transitive**: if camera reaches NVR and NVR reaches phone, the camera's blast radius includes the phone.
- **Directed edges**: allowing A to B doesn't allow B to A. Our test checks `a -> b -> c` from `c` reaches nothing.
- **Our numbers (camera foothold)**: `flat` 7 of 7; `vlan_only` 2 (NVR and doorbell are in the same Security zone); `vlan_deny` 1 (only the NVR, via the baseline pair `camera -> nvr`).
- We count devices only, because a host (outside server) isn't a thing in your home an attacker "takes over".

*Say it in one breath:* "We model the network as a directed graph, and the blast radius is BFS from the compromised device, counting each reachable device once."

## 6. Network segmentation: VLANs versus device isolation within a zone

- **VLAN/zone segmentation** separates *groups*. It stops the camera reaching the laptop, but devices inside the same zone can still reach each other. Our `vlan_only` shows this "same-zone gap": camera still reaches doorbell and NVR.
- **Device isolation** (also called client/AP isolation or microsegmentation) stops devices in the *same* zone from talking to each other, only to the gateway/internet. Ours is `vlan_deny`: even inside the Security zone, only `camera -> nvr` is allowed.
- That's why the demo home has a second camera (doorbell): it makes the same-zone gap visible.
- Trade-off: stricter isolation can break features (casting from phone to TV needs them to talk). Default-deny needs an allow list you maintain.

## 7. IoT security: default credentials, vendor cloud traffic, unpatched devices

- **Default credentials**: many IoT devices ship with `admin/admin` or a printed password nobody changes. Mirai-style botnets scan for these.
- **Vendor cloud traffic**: IoT devices phone home to the maker's servers (firmware updates, telemetry, remote view). Normal and expected, which is why `thermocloud` is a *known host* and the thermostat's baseline allows it. Danger: a hacked device can hide traffic among it, and you depend on the vendor's security.
- **Unpatched devices**: cheap devices rarely get updates, so known bugs stay open for years. You can't fix the device, so you contain it: put it in its own zone, allow it only what it needs.
- Why this matters for the project: IoT devices are the typical foothold, and segmentation is the practical defense.

## 8. Baseline monitoring: learn normal, flag the rest

- **Baseline**: the set of connections that are normal for this home. In our model, a list of `[device, destination]` pairs in `home.yaml`. In a real product, learned by watching traffic for days.
- Anything not in the baseline is "unusual", not necessarily malicious. A new device or a one-off site visit would also show up.
- Our `check_baseline` flags `unlisted_flow` when a flow is outside the baseline **and** goes to a host with `known: false`. We only alert on that combination to keep noise down (see section 11).
- **Single source of truth**: the same `baseline` list drives `vlan_deny` (what's allowed) and `check_baseline` (what's unusual). They can't disagree.

## 9. Outbound data detection: volume thresholds and unlisted destinations

The laptop holds the valuable stuff, so we watch what leaves it. Two checks, both from `config/thresholds.yaml`:
- **`outbound_unlisted`**: the laptop sent a flow to a host with `known: false`. Fires **even if the policy blocked it**, because the attempt itself is a signal.
- **`outbound_over_limit`**: **delivered** bytes (flows whose edge the policy allows) exceed `outbound_mb_limit` (10 MB). Counts only delivered bytes, because blocked data didn't actually leave.
- Example: the `vendor` case sends 48,000,000 bytes (**48.0 MB**, using 1 MB = 1,000,000 bytes) to the unlisted server. `flat` delivers all 48.0 MB; `vlan_deny` delivers 0.0 MB but still raises `outbound_unlisted`.
- Limits to admit: a fixed volume threshold misses slow exfiltration (a little at a time), and it flags big legitimate uploads (a cloud backup). Real systems learn per-device volumes.

## 10. Beaconing: regular small check-ins

- **Beaconing**: malware "calling home" at regular intervals with tiny messages (heartbeat, checking for commands). The signal is regularity and repetition to one destination, not volume.
- Our rule (`check_baseline`): at least `beacon_min_count` (5) flows from one source to one destination inside `beacon_window_s` (300 s). The `beacon` case sends five 64-byte flows from the thermostat to the unlisted server at t = 0, 60, 120, 180, 240 (240 s span, inside 300).
- It fires under **every** policy, because the monitor sees the traffic regardless of blocking (section 11).
- Limits to admit: a count in a window is a crude check. Real detectors look at interval regularity (low variance between connections) and attackers add "jitter" to hide. That is exactly why `make_traffic` has an optional `jitter_s`.

## 11. Alert design: false positives, and why the monitor runs even when traffic is blocked

- **False positive** = alert on harmless activity. Too many and people ignore alerts (alert fatigue). Our defence: `unlisted_flow` requires *both* "not in baseline" and "unlisted host"; thresholds live in config so they can be tuned; known hosts don't alert.
- **False negative** = missed real attack. Reducing one raises the other; thresholds balance them. Don't claim perfect accuracy, our expected results are on a small designed scenario.
- **Why the monitor runs when traffic is blocked**: a block stops the damage, but the *attempt* tells you a device is compromised or misbehaving. If a hacked thermostat keeps trying to reach an unlisted server and default-deny quietly drops every packet, with no monitoring you'd never know. So `check_baseline` runs on all flows regardless of policy, and `outbound_unlisted` fires on attempts.
- Think of default-deny as the lock, and the monitor as the alarm.

## 12. Existing tools: what they do, and where they stop

> ⚠️ This is from general knowledge, and product features change. Check each vendor's current page before presenting, and use the "Option A v2" doc section 6 if you have it.

| Tool | What it broadly does | Where it stops, relative to us |
|---|---|---|
| **Firewalla** | Hardware box on your network: device inventory, per-device rules, network segmentation/groups, alerts on new devices and unusual traffic, ad/threat blocking | Works on a live real network and is a product; it doesn't offer a "what-if blast radius under three policies" view as the core idea |
| **Fing** | Network scanner/app: finds devices, flags unknown ones, checks for some weaknesses, alerts on intruders | Discovery and visibility focus; doesn't enforce segmentation or compute reachability |
| **Trend Micro Home Network Security** | Router-attached protection: blocks malicious sites, intrusion prevention, device checks | Protection against threats from outside/inside traffic; not a segmentation planner (check whether it is still sold) |
| **Kaspersky** (smart home / home-network features) | Shows devices on the Wi-Fi and flags weaknesses as part of its security products | Visibility and endpoint-style checks; not a segmentation planning tool |

Our honest positioning: **an educational what-if simulator**. It teaches and visualises why segmentation matters and compares policies side by side on simulated data. It is not a replacement for those products and doesn't touch a real network. Don't claim to be novel in detection; the angle is the clear before/after blast-radius comparison.

## 13. Python for this build

- **Dataclasses** (`@dataclass(frozen=True)`): classes whose boilerplate (`__init__`, `__eq__`, `__repr__`) is generated. `frozen` makes them immutable and hashable. `dataclasses.replace(obj, field=...)` makes a modified copy (used in `with_case`).
- **YAML parsing**: `yaml.safe_load(f)` turns the file into dicts and lists. Always `safe_load`, never `load` (which can run arbitrary code). Watch YAML gotchas: `no`/`yes` become booleans, indentation matters.
- **Graph search**: BFS with `collections.deque` (fast pop from the left) and a `seen` set.
- **Type hints and `from __future__ import annotations`**: documentation and tooling help; not enforced at runtime.
- **Sets**: edges are `set[tuple[str,str]]`, so union (`|`), membership and subset (`<=`) are natural. "vlan_deny is a subset of flat" is literally `<=` in a test.
- **pytest**: plain `assert`, `pytest.mark.parametrize` for table-driven tests, `tmp_path` for temp files, `pytest.raises(ValueError, match=...)`, `pytest.skip`. Run with `pytest -q`.
- **CLI argument handling** (Person 3, `main.py`): `argparse`. `python -m src.main scenarios/home.yaml --out out/` means positional `scenario` plus optional `--out`. `-m` runs it as a module so `from .contracts import ...` works.

## 14. Simulation design: seeded randomness, deterministic output, why traffic is always simulated

- **Seeded randomness**: a pseudo-random generator started from a fixed seed gives the same sequence every time. `random.Random(seed)` is a private generator, so other code using `random` can't disturb it.
- **Deterministic output**: same inputs give identical output. Needed so tests are repeatable, results match between runs, and a live demo can't surprise us.
- **Why jitter defaults to zero**: the hand-written expected results assume exact timings; jitter is an optional realism knob (still deterministic per seed).
- **Why always simulated**: safety and legality (no scanning or attacking real networks), reproducibility, and nothing to break. Out of scope: real device discovery, router sign-in, real packet capture, any attack code.

## 15. Testing against hand-set expected values, not values copied from output

- The expected numbers (7/2/1, 48.0 / 0.0, the alert kinds) were **written from the design first**, in `home.yaml`. Tests compare engine output against them.
- **Why this matters**: if you run the code and paste its output as the expected value, the test can only ever confirm the code agrees with itself, including its bugs. A hand-set value is an independent check. The rule: **never edit an `expect:` value to make a test pass**; if a test fails, fix the code and report which values pass or fail.
- Test types in the repo:
  - unit tests per module (`test_model.py`, `test_policies.py`, `test_reach.py`, `test_sim_traffic.py`)
  - oracle test (`test_scenarios.py`): every `expect:` block versus the engine
  - `test_no_hardcoding.py`: change the YAML (move a device, add a baseline pair, change the foothold) and the results change with no code edit
- Currently 6 oracle checks **skip** until Person 2's `outbound.py` and `alerts.py` exist; they become the integration gate.

## 16. Front-end basics for the demo (Person 3)

- **SVG drawing**: SVG is XML for vector graphics, drawn in the browser. `<rect>` for zones, `<circle>` for devices, `<line>` for allowed or blocked connections, `<text>` for labels. Coordinates come from `x`/`y` in `home.yaml`, so the demo never carries its own layout.
- **Reading a generated JavaScript data file**: `report.py` writes `demo/results.js` containing one line, `window.RESULTS = {...};`. `index.html` loads it with `<script src="results.js">`. Why not `fetch('results.json')`? Browsers block `fetch` of local files when you double-click an HTML file (file:// origin), so a script tag is the trick that works with no server.
- **Animation timing**: use CSS transitions/animations or `setTimeout`/`requestAnimationFrame` to reveal the attacker's spread hop by hop (the BFS hops), e.g. step n lights up devices at distance n after `n * delay` ms. Keep delays in one constant, and make the end state match the numbers in `out/report.md`.
- Rule: the demo draws **only** what `results.js` contains. No hardcoded names, numbers or positions.

---

## 17. Worked example: camera compromise, end to end

1. `load_scenario("scenarios/home.yaml")` gives 8 devices, 4 hosts, foothold `camera`, 8 baseline pairs.
2. `with_case(s, "camera")` (this case has no flows).
3. `apply_policy("vlan_only", s)`: same-zone pairs (camera, doorbell, nvr in Security) plus every device to known hosts.
4. `blast_radius(edges, "camera", device_ids)`: camera reaches doorbell and nvr; doorbell reaches camera and nvr; neither has an edge to other zones. `ReachResult(reachable={doorbell, nvr}, count=2, total=7)`.
5. Same with `vlan_deny`: edges are only the baseline; `camera -> nvr` and nothing leaves nvr, so count = 1.
6. Same with `flat`: every device reaches every device, count = 7.

Headline: **7 to 2 to 1**.

## 18. Likely questions, with short answers

1. *Why BFS and not DFS?* Either works for reachability. BFS also gives hop counts (how far the attacker spreads), which the demo animates.
2. *Why directed edges?* Allowing A to B doesn't allow B to A; firewall rules are directional.
3. *Does rule order matter in your model?* No, we use an allow-set with implicit deny. In real firewalls it does (first match wins); we simplified.
4. *Why does the monitor run when traffic is blocked?* The attempt is evidence of compromise; blocking hides it without monitoring.
5. *How do you avoid false positives?* Two-condition alerts (outside baseline and unlisted host), tunable thresholds in config, known hosts don't alert. We don't claim zero false positives.
6. *What would a real baseline look like?* Learned from days of observed traffic per device, not a hand-written list.
7. *Why aren't the expected values generated from output?* Independent check; otherwise the tests can't catch bugs.
8. *Why is nothing hardcoded?* Changing a YAML value changes the report and demo with no code edit; we test that.
9. *How do you know it's deterministic?* Seeded `random.Random(seed)`, jitter defaults to 0, same seed same output (tested).
10. *How is this different from Firewalla?* They're products on live networks; we're an educational what-if simulator comparing policies on simulated data. (See section 12; verify claims.)
11. *What does this not do?* No real discovery, no real traffic, no learning, a crude beaconing check, no port- or protocol-level rules.

## 19. Glossary

**Allow list**: permitted pairs. **Baseline**: normal traffic. **Beaconing**: regular small check-ins to one destination. **Blast radius**: devices reachable from a compromised one. **BFS**: breadth-first search. **Default-deny**: block everything not explicitly allowed. **Edge**: allowed `(src, dst)` connection. **Exfiltration**: data leaving the network. **Flat network**: no segmentation. **Foothold**: the first compromised device. **Host**: an outside destination. **IoT**: internet-connected gadget. **Lateral movement**: attacker hopping device to device. **Oracle**: hand-written expected results. **Subnet**: a block of IP addresses. **VLAN**: logical network split on shared hardware. **Zone**: group of devices with the same trust level.
