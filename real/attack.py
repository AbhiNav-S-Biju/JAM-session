"""The attack DEMO. Nothing here attacks anything.

1. sim_cases: pretend-attacks replayed on your real device map. The flows are synthetic and the
   cases are labelled [SIMULATED]. No packet is sent to any device.
2. send_test_upload: OPT-IN. Sends one clearly-labelled, harmless upload of dummy bytes from THIS
   computer to a server YOU control (--send-test-traffic URL), so the demo includes one real flow.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from src.contracts import Case, Device, Flow, Host

from .ingest import InputError

SIM_HOST_ID = "sim-unlisted"
SIM_HOST_NAME = "198.51.100.99 (simulated unlisted server)"   # TEST-NET-2: documentation range, not routable
MAX_TEST_MB = 50


def pick_laptop(devices: list[Device]) -> Device:
    laptops = [d for d in devices if d.type == "laptop"]
    if not laptops:
        raise InputError("zones.yaml: no device has 'type: laptop'; needed for the exfiltration demo / test upload")
    return laptops[0]


def sim_cases(devices: list[Device], foothold: str, thresholds: dict) -> tuple[list[Case], Host, list[str]]:
    """Synthetic cases sized from config/thresholds.yaml so they are guaranteed to trip the detectors."""
    cases = [Case(id="sim_takeover", name="[SIMULATED] Foothold device is taken over", flows=(), expect={})]
    notes: list[str] = []
    limit_b = int(thresholds["outbound_mb_limit"] * 4 * 1_000_000)
    laptops = [d for d in devices if d.type == "laptop"]
    if laptops:
        cases.append(Case(id="sim_exfil", name="[SIMULATED] Laptop uploads files to an unlisted server",
                          flows=(Flow(src=laptops[0].id, dst=SIM_HOST_ID, bytes=limit_b, t=10),), expect={}))
    else:
        notes.append("Skipped the simulated exfiltration case: no device has 'type: laptop' in zones.yaml.")
    count, window = int(thresholds["beacon_min_count"]), int(thresholds["beacon_window_s"])
    step = max(window // count, 1)
    cases.append(Case(id="sim_beacon", name="[SIMULATED] Foothold phones home on a timer",
                      flows=tuple(Flow(src=foothold, dst=SIM_HOST_ID, bytes=64, t=i * step) for i in range(count)),
                      expect={}))
    return cases, Host(id=SIM_HOST_ID, name=SIM_HOST_NAME, known=False, x=0, y=0), notes


def send_test_upload(url: str, mb: float, opener=urllib.request.urlopen) -> dict:
    """POST `mb` megabytes of dummy text to `url` (a server you control). Returns what happened."""
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise InputError(f"--send-test-traffic {url!r}: must be an http:// or https:// URL")
    if not 0 < mb <= MAX_TEST_MB:
        raise InputError(f"--test-mb must be above 0 and at most {MAX_TEST_MB}")
    line = b"CAGEWATCH-HARMLESS-TEST-DATA\n"
    payload = line * (int(mb * 1_000_000) // len(line) + 1)
    payload = payload[:int(mb * 1_000_000)]
    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "Content-Type": "text/plain", "X-CageWatch-Test": "harmless dummy data"})
    result = {"ok": False, "status": None, "bytes": len(payload), "host": parts.hostname, "error": None}
    try:
        with opener(req, timeout=20) as resp:
            result["status"] = getattr(resp, "status", None)
            result["ok"] = True
    except (urllib.error.URLError, OSError, ValueError) as e:
        result["error"] = str(e)
    return result
