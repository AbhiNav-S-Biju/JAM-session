from pathlib import Path

import pytest

from real.ingest import (InputError, mask_mac, norm_mac, parse_arp, parse_arp_file,
                         parse_router_devices, parse_traffic, parse_zones)

FIX = Path(__file__).parent / "fixtures"


def test_router_csv_is_read_by_header_name_not_position():
    rows = parse_router_devices(FIX / "router_devices.csv")   # columns are in a shuffled order
    cam = next(r for r in rows if r["name"] == "Camera")
    assert cam["ip"] == "192.168.50.20" and cam["mac"] == "aa:bb:cc:00:00:03"
    assert cam["extra"] == {"vendor": "CamCo"}                  # unknown columns kept as-is


def test_header_aliases(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("Device Name,IP Address,MAC Address\nTV,10.0.0.5,AA-BB-CC-DD-EE-FF\n")
    assert parse_router_devices(p)[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_bad_header_raises_clear_error_naming_the_file(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("foo,bar\n1,2\n")
    with pytest.raises(InputError) as e:
        parse_router_devices(p)
    assert "bad.csv" in str(e.value) and "missing column" in str(e.value)


def test_missing_file_names_the_file(tmp_path):
    with pytest.raises(InputError, match="nope.csv: file not found"):
        parse_router_devices(tmp_path / "nope.csv")


def test_bad_mac_names_file_and_row(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("name,ip,mac\nTV,10.0.0.5,not-a-mac\n")
    with pytest.raises(InputError, match="row 2"):
        parse_router_devices(p)


def test_arp_windows_format():
    got = {e["mac"]: e["ip"] for e in parse_arp_file(FIX / "arp_windows.txt")}
    assert got == {"aa:bb:cc:00:00:ff": "192.168.50.1", "aa:bb:cc:00:00:03": "192.168.50.20",
                   "aa:bb:cc:00:00:99": "192.168.50.99"}     # broadcast and multicast dropped


def test_arp_unix_format_pads_octets_and_skips_incomplete():
    got = {e["mac"]: e["ip"] for e in parse_arp_file(FIX / "arp_unix.txt")}
    assert got == {"aa:bb:cc:00:00:03": "192.168.50.20", "aa:bb:cc:00:00:99": "192.168.50.99",
                   "aa:bb:cc:00:00:ff": "192.168.50.1"}


def test_arp_unrecognised_format_is_an_error():
    with pytest.raises(InputError, match="unrecognised format"):
        parse_arp("this is not arp output\nat all\n", "arp.txt")


def test_traffic_bad_time_and_header(tmp_path):
    p = tmp_path / "t.csv"
    p.write_text("source,destination,bytes,time\nA,B,5,yesterday\n")
    with pytest.raises(InputError, match="row 2"):
        parse_traffic(p)
    p.write_text("a,b\n1,2\n")
    with pytest.raises(InputError, match="missing column"):
        parse_traffic(p)


def test_zones_requires_foothold(tmp_path):
    p = tmp_path / "z.yaml"
    p.write_text("devices: {A: {zone: X}}\n")
    with pytest.raises(InputError, match="foothold"):
        parse_zones(p)


def test_mac_masking():
    assert mask_mac("aa:bb:cc:00:00:03") == "xx:xx:xx:00:00:03"
    assert norm_mac("A-B-C-0-0-3") == "0a:0b:0c:00:00:03"
