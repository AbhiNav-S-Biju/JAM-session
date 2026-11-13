"""Real-network viewer and attack demo for YOUR OWN home network.

    python -m real.main --input real/input --out real/out [--show-mac]

By default it reads local files only and opens no network connection. Anything that touches the
network is opt-in, one flag each, and explained in real/README.md:

    --live-discover --subnet 192.168.1.0/24 --i-own-this-network     ping the subnet once, read `arp -a`
    --send-test-traffic URL [--test-mb 1] --i-own-this-network       one harmless upload to YOUR server
    --attack-demo                                                    simulated attacks on the real map (no packets)
    --enforce plan|apply                                             router rules (plan only for now)
"""
from __future__ import annotations

import argparse
import sys

from . import attack, build, discover, enforce, output
from .ingest import InputError, mask_mac


def run(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Real home network viewer (your own network, your own files).")
    ap.add_argument("--input", default="real/input", help="folder with router_devices.csv, zones.yaml, ...")
    ap.add_argument("--out", default="real/out")
    ap.add_argument("--show-mac", action="store_true", help="show full MAC addresses (default: last 3 octets)")
    ap.add_argument("--policies", default="config/policies.yaml")
    ap.add_argument("--thresholds", default="config/thresholds.yaml")
    ap.add_argument("--attack-demo", action="store_true", help="add [SIMULATED] attack cases on the real map")
    ap.add_argument("--quick", action="store_true",
                    help="quick look: discover devices live (needs --subnet), no router export or zones.yaml needed")
    ap.add_argument("--foothold", help="device name to treat as compromised (overrides zones.yaml)")
    ap.add_argument("--live-discover", action="store_true")
    ap.add_argument("--subnet", help="private subnet to discover, e.g. 192.168.1.0/24")
    ap.add_argument("--send-test-traffic", metavar="URL")
    ap.add_argument("--test-mb", type=float, default=1.0)
    ap.add_argument("--i-own-this-network", action="store_true",
                    help="required for anything that touches the network: confirms it is your own")
    ap.add_argument("--enforce", choices=["plan", "apply"], default=None)
    ap.add_argument("--router", choices=["archer-c6"], default=None,
                    help="add by-hand steps for this router to the enforcement plan")
    a = ap.parse_args(argv)

    if a.quick:
        a.live_discover = True
    touches_network = a.live_discover or a.send_test_traffic
    if touches_network and not a.i_own_this_network:
        raise InputError("--live-discover / --send-test-traffic touch the network. "
                         "Add --i-own-this-network to confirm it is your own network.")
    if a.live_discover and not a.subnet:
        raise InputError("--live-discover / --quick needs --subnet, e.g. --subnet 192.168.1.0/24")
    if a.enforce == "apply":
        enforce.apply_plan({}, None)   # refuses until a router adapter exists

    live = discover.discover(a.subnet) if a.live_discover else None
    inputs = build.load_inputs(a.input, live, quick=a.quick, foothold=a.foothold)
    devices = build.merge_devices(inputs["router"], inputs["arp"], inputs["live"], inputs["names"])
    thresholds = build.load_thresholds_default(a.thresholds)

    test_upload = None
    if a.send_test_traffic:
        sent = attack.send_test_upload(a.send_test_traffic, a.test_mb)
        if sent["ok"]:
            test_upload = sent
            print(f"Test upload sent: {sent['bytes']} bytes to {sent['host']} (HTTP {sent['status']}).")
        else:
            print(f"Test upload FAILED ({sent['error']}); no live_test case added.", file=sys.stderr)

    results, extras = build.assemble(inputs, devices, thresholds, a.policies, a.attack_demo, test_upload)
    plan = enforce.make_plan(results, devices, a.show_mac, mask_mac, a.router) if a.enforce else None
    paths = output.write_all(a.out, results, extras, a.show_mac, inputs["traffic"] is not None, plan)

    print(f"Foothold: {extras['names'][results['foothold']]}   before = {results['before_policy']}, "
          f"after = {results['after_policy']}\n")
    print(output.console_table(results))
    for n in extras["notes"]:
        print(f"note: {n}")
    if a.quick:
        paths.append(output.write_zones_template(a.input, devices, extras["names"][results["foothold"]]))
    print("\nWrote: " + ", ".join(str(p) for p in paths))
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
