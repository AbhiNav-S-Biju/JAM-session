# real/: your own house Wi-Fi, on the same engine

Shows the devices on **your own** network, how they connect, and the blast radius from one device under
`flat`, `vlan_only` and `vlan_deny`. It reuses `src/` unchanged (`policies`, `reach`, `outbound`, `alerts`,
and the demo page). Then you can replay **simulated** attacks on the real map to show how the platform reacts.

## Quick start

```
python -m real.main --input real/tests/fixtures --out real/out_test      # fake data, try this first
python -m real.main --input real/input --out real/out [--show-mac]       # your own files
```
Open `real/out/map.html` by double-clicking it. Outputs: `devices.json`, `connections.json`, `report.md`,
`map.html` (plus `enforcement_plan.json` with `--enforce plan`). Everything stays in `real/out/`.
MAC addresses are masked to the last 3 octets unless you pass `--show-mac`.

## Your files (put them in `real/input/`, which git ignores)

| File | Needed | What |
|---|---|---|
| `router_devices.csv` | yes | Export from your router/Firewalla. Columns are matched by **name** (`name`, `ip`, `mac`, optional `status`); other columns are kept as-is |
| `zones.yaml` | yes | You write it: `foothold`, each device's `zone` (plus optional `type: laptop`, `critical`, `x`, `y`), `allowed` pairs, `known_hosts`. See `real/tests/fixtures/zones.yaml` |
| `arp.txt` | no | `arp -a > real/input/arp.txt` (Windows, macOS and Linux formats both work) |
| `router_traffic.csv` | no | `source,destination,bytes,time` (header names are matched; ISO time or epoch seconds) |

A missing or unrecognised file stops the run with an error that names the file. Nothing is guessed.

## What it can and cannot claim

- The blast radius comes from the zones and allowed pairs **you declared**. It does **not** read your
  router's real firewall rules, so "vlan_deny reaches 1 device" means "if my declared rules were enforced".
- Links on the map come only from `router_traffic.csv`. If that file has no device-to-device rows, the report
  says so and draws none. Many home routers log device-to-internet traffic only, because local traffic between two
  Wi-Fi devices may never pass through the router. Check what yours exports.
- A device seen only in `arp.txt` (or live discovery) is flagged "not in router_devices.csv".

## Opt-in features that touch the network (off by default)

Each needs `--i-own-this-network`. Use them only on a network you own.

| Flag | What it does | What it does NOT do |
|---|---|---|
| `--live-discover --subnet 192.168.1.0/24` | One ping per address in that subnet, then reads your computer's ARP table | No port scanning, no probing services, no logins. Refuses anything outside 10/8, 172.16/12, 192.168/16, or bigger than /22 |
| `--send-test-traffic URL --test-mb 1` | One upload of harmless dummy bytes (max 50 MB) from this computer to a server **you control** | Sends nothing anywhere else. The record of the send is this tool's own, not an independent capture |
| `--attack-demo` | Adds `[SIMULATED]` cases (takeover, exfiltration, beaconing) on your real device map | Sends no packets to any device |
| `--enforce plan` | Writes the router rules that would enforce default-deny, and a quarantine of the foothold | Sends nothing. `--enforce apply` is refused until a router adapter exists for your router model |

Router passwords and Wi-Fi names are never asked for or stored. When an adapter is added, credentials will come
from environment variables only, and a rollback plan is written first.

## Tests

```
pytest real -q
```
Fixtures in `real/tests/fixtures/` are fake. The blast-radius expectations (7 / 2 / 1) were worked out by hand
before the code ran.
