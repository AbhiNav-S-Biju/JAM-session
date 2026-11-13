import shutil
from pathlib import Path

import pytest

from real import build
from real.ingest import InputError

FIX = Path(__file__).parent / "fixtures"
THRESH = {"outbound_mb_limit": 10, "beacon_min_count": 5, "beacon_window_s": 300}
POL = "config/policies.yaml"


def run(input_dir=FIX, **kw):
    inputs = build.load_inputs(input_dir)
    devices = build.merge_devices(inputs["router"], inputs["arp"], inputs["live"])
    return build.assemble(inputs, devices, THRESH, POL, **kw), devices


def test_device_in_both_sources_merges_into_one():
    (_, extras), devices = run()
    cams = [d for d in devices if d.name == "Camera"]
    assert len(cams) == 1 and cams[0].sources == ["router", "arp"]
    assert cams[0].flags == []


def test_arp_only_devices_are_flagged():
    _, devices = run()
    flagged = sorted(d.name for d in devices if d.flags)
    assert flagged == ["unknown-00-00-99", "unknown-00-00-ff"]
    assert all(d.sources == ["arp"] for d in devices if d.flags)


def test_missing_optional_files_do_not_crash(tmp_path):
    shutil.copy(FIX / "router_devices.csv", tmp_path / "router_devices.csv")
    shutil.copy(FIX / "zones.yaml", tmp_path / "zones.yaml")
    (results, extras), _ = run(tmp_path)
    assert any("No router_traffic.csv" in n for n in extras["notes"])
    assert results["cases"][0]["flows"] == []


def test_missing_required_file_names_it(tmp_path):
    with pytest.raises(InputError, match="router_devices.csv: file not found"):
        build.load_inputs(tmp_path)
    shutil.copy(FIX / "router_devices.csv", tmp_path / "router_devices.csv")
    with pytest.raises(InputError, match="zones.yaml: file not found"):
        build.load_inputs(tmp_path)


# Hand-computed BEFORE running (8 devices -> 7 others besides the Camera foothold):
#   flat       : every device reaches every device                   -> 7
#   vlan_only  : Cameras zone = Camera, Doorbell, NVR                -> Doorbell, NVR = 2
#   vlan_deny  : only the declared pair Camera -> NVR                -> NVR = 1
HAND = {"flat": 7, "vlan_only": 2, "vlan_deny": 1}


@pytest.mark.parametrize("policy,expected", HAND.items())
def test_blast_radius_matches_hand_computed(policy, expected):
    (results, _), _ = run()
    r = results["cases"][0]["results"][policy]
    assert (r["blast_radius"], r["total"]) == (expected, 7)
    if policy == "vlan_deny":
        assert r["reachable"] == ["nvr"]
    if policy == "vlan_only":
        assert r["reachable"] == ["doorbell", "nvr"]


def test_device_to_device_rows_are_counted_and_unknown_source_skipped():
    (_, extras), _ = run()
    assert extras["device_to_device_rows"] == 2           # Camera->NVR, Doorbell->NVR
    assert extras["skipped"] == ["unknown source 'Ghost'"]


def test_no_device_to_device_rows_is_stated_not_invented(tmp_path):
    for f in ("router_devices.csv", "zones.yaml"):
        shutil.copy(FIX / f, tmp_path / f)
    (tmp_path / "router_traffic.csv").write_text(
        "source,destination,bytes,time\nLaptop,weather.example,10,2026-11-13T10:00:00\n")
    (_, extras), _ = run(tmp_path)
    assert extras["device_to_device_rows"] == 0
    assert any("NO device-to-device rows" in n for n in extras["notes"])


def test_unlisted_destination_raises_alert_under_default_deny():
    (results, _), _ = run()
    kinds = {a["kind"] for a in results["cases"][0]["results"]["vlan_deny"]["alerts"]}
    assert "unlisted_flow" in kinds          # Camera -> 198.51.100.7, not in the declared pairs


def test_foothold_must_exist(tmp_path):
    for f in ("router_devices.csv", "router_traffic.csv"):
        shutil.copy(FIX / f, tmp_path / f)
    (tmp_path / "zones.yaml").write_text("foothold: Toaster\ndevices: {Laptop: {zone: A}}\n")
    inputs = build.load_inputs(tmp_path)
    devices = build.merge_devices(inputs["router"], inputs["arp"])
    with pytest.raises(InputError, match="foothold 'Toaster'"):
        build.assemble(inputs, devices, THRESH, POL)


def test_positions_come_from_zones_yaml_when_given(tmp_path):
    for f in ("router_devices.csv", "router_traffic.csv"):
        shutil.copy(FIX / f, tmp_path / f)
    (tmp_path / "zones.yaml").write_text(
        "foothold: Camera\nzones:\n  - {name: Cameras, x: 500, y: 400, w: 200, h: 120}\n"
        "devices:\n  Camera: {zone: Cameras, x: 530, y: 440}\n  Laptop: {zone: Trusted}\n")
    (results, _), _ = run(tmp_path)
    z = next(z for z in results["zones"] if z["name"] == "Cameras")
    cam = next(d for d in results["devices"] if d["name"] == "Camera")
    assert (z["x"], z["y"], cam["x"], cam["y"]) == (500, 400, 530, 440)
