import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from real import attack, discover, main as real_main
from real.ingest import InputError

FIX = Path(__file__).parent / "fixtures"
FULL_MACS = ["aa:bb:cc:00:00:03", "aa-bb-cc-00-00-03", "aa:bb:cc:00:00:99", "aa:bb:cc:00:00:ff"]


def cli(tmp_path, *extra):
    out = tmp_path / "out"
    code = real_main.main(["--input", str(FIX), "--out", str(out), *extra])
    return code, out


def test_all_four_files_are_produced(tmp_path):
    code, out = cli(tmp_path)
    assert code == 0
    for name in ("devices.json", "connections.json", "report.md", "map.html"):
        assert (out / name).is_file(), name


def test_default_run_opens_no_network_connection(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    code, _ = cli(tmp_path)
    assert code == 0


def test_macs_are_masked_by_default_everywhere(tmp_path):
    _, out = cli(tmp_path)
    for f in out.iterdir():
        text = f.read_text(encoding="utf-8").lower()
        assert not any(m in text for m in FULL_MACS), f.name
    devices = json.loads((out / "devices.json").read_text())
    assert next(d for d in devices if d["name"] == "Camera")["mac"] == "xx:xx:xx:00:00:03"


def test_show_mac_reveals_full_macs_in_devices_json(tmp_path):
    _, out = cli(tmp_path, "--show-mac")
    devices = json.loads((out / "devices.json").read_text())
    assert next(d for d in devices if d["name"] == "Camera")["mac"] == "aa:bb:cc:00:00:03"


def test_map_is_self_contained_and_uses_the_demo_page(tmp_path):
    _, out = cli(tmp_path)
    html = (out / "map.html").read_text(encoding="utf-8")
    assert "window.RESULTS =" in html and 'src="results.js"' not in html
    assert "Camera" in html and "Simulated data from" not in html


def test_connections_json_says_when_there_are_no_device_links(tmp_path):
    _, out = cli(tmp_path)
    c = json.loads((out / "connections.json").read_text())
    assert c["device_to_device_rows"] == 2 and c["traffic_file_provided"] is True


def test_bad_input_exits_with_clear_error(tmp_path, capsys):
    (tmp_path / "router_devices.csv").write_text("foo,bar\n1,2\n")
    code = real_main.main(["--input", str(tmp_path), "--out", str(tmp_path / "o")])
    assert code == 2 and "router_devices.csv" in capsys.readouterr().err


# ---------- opt-in network features are fenced ----------

def test_network_flags_require_the_ownership_confirmation(tmp_path, capsys):
    for flags in (["--live-discover", "--subnet", "192.168.50.0/24"],
                  ["--send-test-traffic", "http://127.0.0.1:9/"]):
        code, _ = cli(tmp_path, *flags)
        assert code == 2
    assert "--i-own-this-network" in capsys.readouterr().err


@pytest.mark.parametrize("bad", ["8.8.8.0/24", "1.1.1.1/32", "10.0.0.0/8", "172.15.0.0/24", "nonsense"])
def test_discovery_refuses_non_private_or_huge_subnets(bad):
    with pytest.raises(InputError):
        discover.validate_subnet(bad)


def test_discovery_pings_once_and_reads_arp_only(monkeypatch):
    calls = []

    class R:
        def __init__(self, rc=0, out=""):
            self.returncode, self.stdout = rc, out

    def fake(cmd, **kw):
        calls.append(cmd)
        if cmd[0] == "arp":
            return R(0, "  192.168.50.20  aa-bb-cc-00-00-03  dynamic\n  192.168.60.5  aa-bb-cc-00-00-77  dynamic\n")
        return R(0)

    rows = discover.discover("192.168.50.0/24", runner=fake)
    assert [r["ip"] for r in rows] == ["192.168.50.20"]               # the 192.168.60.x entry is filtered out
    pings = [c for c in calls if c[0] == "ping"]
    assert len(pings) == 254                                          # one ping per host address, nothing else
    assert all(c[-1].startswith("192.168.50.") for c in pings)
    assert all(not any(x in c for x in ("-p", "nmap", "-sS")) for c in calls)   # no port scanning


class _Sink(BaseHTTPRequestHandler):
    got = []

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        _Sink.got.append((self.rfile.read(n), self.headers.get("X-CageWatch-Test")))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_test_upload_goes_only_to_the_url_given_and_creates_a_live_case(tmp_path):
    _Sink.got.clear()
    srv = HTTPServer(("127.0.0.1", 0), _Sink)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        code, out = cli(tmp_path, "--send-test-traffic", f"http://127.0.0.1:{srv.server_port}/up",
                        "--test-mb", "0.5", "--i-own-this-network")
    finally:
        srv.shutdown()
    assert code == 0
    body, marker = _Sink.got[0]
    assert len(body) == 500_000 and marker == "harmless dummy data"
    assert body.startswith(b"CAGEWATCH-HARMLESS-TEST-DATA\n")
    html = (out / "map.html").read_text(encoding="utf-8")
    assert "live_test" in html and "REAL test upload" in html


def test_test_upload_limits(tmp_path):
    with pytest.raises(InputError):
        attack.send_test_upload("ftp://example.com/x", 1)
    with pytest.raises(InputError):
        attack.send_test_upload("http://127.0.0.1/", attack.MAX_TEST_MB + 1)


def test_failed_upload_is_reported_not_fatal(tmp_path, capsys):
    code, out = cli(tmp_path, "--send-test-traffic", "http://127.0.0.1:9/nothing-here",
                    "--i-own-this-network")
    assert code == 0 and "FAILED" in capsys.readouterr().err
    assert "live_test" not in (out / "map.html").read_text(encoding="utf-8")


# ---------- attack demo and enforcement ----------

def test_attack_demo_adds_labelled_simulated_cases_that_trip_the_detectors(tmp_path):
    _, out = cli(tmp_path, "--attack-demo")
    html = (out / "map.html").read_text(encoding="utf-8")
    start = html.index("window.RESULTS = ") + len("window.RESULTS = ")
    results = json.loads(html[start:html.index(";</script>", start)].replace("<\\/", "</"))
    cases = {c["id"]: c for c in results["cases"]}
    assert all(cases[i]["name"].startswith("[SIMULATED]") for i in ("sim_takeover", "sim_exfil", "sim_beacon"))
    exfil = cases["sim_exfil"]["results"]
    assert exfil["flat"]["laptop_outbound_mb"] == 40.0 and exfil["vlan_deny"]["laptop_outbound_mb"] == 0.0
    assert "outbound_over_limit" in {a["kind"] for a in exfil["flat"]["alerts"]}
    assert "beaconing" in {a["kind"] for a in cases["sim_beacon"]["results"]["vlan_deny"]["alerts"]}


def test_enforce_plan_is_dry_run_with_masked_macs(tmp_path):
    code, out = cli(tmp_path, "--enforce", "plan")
    plan = json.loads((out / "enforcement_plan.json").read_text())
    assert code == 0 and plan["mode"].startswith("dry-run")
    assert plan["quarantine"]["device"] == "Camera" and plan["quarantine"]["mac"] == "xx:xx:xx:00:00:03"
    assert {(r["src"], r["dst"]) for r in plan["allow"]} >= {("Camera", "NVR")}


def test_enforce_apply_is_refused_without_a_router_adapter(tmp_path, capsys):
    code, _ = cli(tmp_path, "--enforce", "apply")
    assert code == 2 and "no router adapter" in capsys.readouterr().err


# ---------- quick look: no router export, no zones.yaml ----------

LIVE = [{"ip": "192.168.50.10", "mac": "aa:bb:cc:00:00:01"}, {"ip": "192.168.50.20", "mac": "aa:bb:cc:00:00:03"}]


def test_quick_requires_subnet_and_ownership_confirmation(tmp_path, capsys):
    assert real_main.main(["--quick", "--input", str(tmp_path), "--out", str(tmp_path / "o")]) == 2
    assert "--i-own-this-network" in capsys.readouterr().err
    assert real_main.main(["--quick", "--i-own-this-network", "--input", str(tmp_path),
                           "--out", str(tmp_path / "o")]) == 2
    assert "--subnet" in capsys.readouterr().err


def test_quick_look_works_with_only_live_discovery(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "discover", lambda subnet, runner=None: list(LIVE))
    inp, out = tmp_path / "in", tmp_path / "out"
    code = real_main.main(["--quick", "--subnet", "192.168.50.0/24", "--i-own-this-network",
                           "--input", str(inp), "--out", str(out)])
    assert code == 0
    devices = json.loads((out / "devices.json").read_text())
    assert [d["name"] for d in devices] == ["unknown-00-00-01", "unknown-00-00-03"]
    assert all(d["zone"] == "unassigned" and d["sources"] == ["live"] for d in devices)
    assert all(d["mac"].startswith("xx:xx:xx:") for d in devices)
    assert "No foothold was named" in (out / "report.md").read_text()
    template = (inp / "zones.template.yaml").read_text()
    assert "unknown-00-00-03" in template and not (inp / "zones.yaml").exists()
    assert "REAL NETWORK" in (out / "map.html").read_text(encoding="utf-8")


def test_quick_look_foothold_override(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "discover", lambda subnet, runner=None: list(LIVE))
    out = tmp_path / "out"
    real_main.main(["--quick", "--subnet", "192.168.50.0/24", "--i-own-this-network", "--foothold",
                    "unknown-00-00-03", "--input", str(tmp_path / "in"), "--out", str(out)])
    html = (out / "map.html").read_text(encoding="utf-8")
    assert '"foothold": "unknown-00-00-03"' in html


def test_without_quick_the_files_are_still_required(tmp_path, capsys):
    assert real_main.main(["--input", str(tmp_path), "--out", str(tmp_path / "o")]) == 2
    assert "router_devices.csv: file not found" in capsys.readouterr().err


def test_archer_c6_plan_has_manual_steps_and_is_honest_about_limits(tmp_path):
    code, out = cli(tmp_path, "--enforce", "plan", "--router", "archer-c6")
    plan = json.loads((out / "enforcement_plan.json").read_text())
    assert code == 0 and plan["router"].startswith("TP-Link Archer C6")
    assert "Camera (192.168.50.20)" in " ".join(plan["manual_steps"])
    assert "no VLANs" in plan["cannot_enforce"] and plan["quarantine"]["mac"] == "xx:xx:xx:00:00:03"
    assert not any("password" in step.lower() and "enter" in step.lower() for step in plan["manual_steps"])


def test_default_foothold_skips_the_router(tmp_path, monkeypatch):
    rows = [{"ip": "192.168.0.1", "mac": "aa:bb:cc:00:00:01"}, {"ip": "192.168.0.101", "mac": "aa:bb:cc:00:00:02"}]
    monkeypatch.setattr(discover, "discover", lambda subnet, runner=None: list(rows))
    out = tmp_path / "out"
    real_main.main(["--quick", "--subnet", "192.168.0.0/24", "--i-own-this-network",
                    "--input", str(tmp_path / "in"), "--out", str(out)])
    assert '"foothold": "unknown-00-00-02"' in (out / "map.html").read_text(encoding="utf-8")


def test_names_csv_renames_devices_by_ip(tmp_path, monkeypatch):
    rows = [{"ip": "192.168.0.101", "mac": "aa:bb:cc:00:00:02"}, {"ip": "192.168.0.102", "mac": "aa:bb:cc:00:00:03"}]
    monkeypatch.setattr(discover, "discover", lambda subnet, runner=None: list(rows))
    inp, out = tmp_path / "in", tmp_path / "out"
    inp.mkdir()
    (inp / "names.csv").write_text("ip,name\n192.168.0.101,Jeev-Phone\n")
    real_main.main(["--quick", "--subnet", "192.168.0.0/24", "--i-own-this-network",
                    "--input", str(inp), "--out", str(out)])
    names = [d["name"] for d in json.loads((out / "devices.json").read_text())]
    assert names == ["Jeev-Phone", "unknown-00-00-03"]
    assert "Jeev-Phone" in (inp / "names.template.csv").read_text()


def test_names_csv_bad_header_names_the_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(discover, "discover", lambda subnet, runner=None: [])
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "names.csv").write_text("foo,bar\n1,2\n")
    code = real_main.main(["--quick", "--subnet", "192.168.0.0/24", "--i-own-this-network",
                           "--input", str(inp), "--out", str(tmp_path / "o")])
    assert code == 2 and "names.csv" in capsys.readouterr().err


def test_templates_are_never_overwritten(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "discover", lambda subnet, runner=None: [{"ip": "192.168.0.101", "mac": "aa:bb:cc:00:00:02"}])
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "names.template.csv").write_text("ip,name\n192.168.0.101,MY-EDIT\n")
    (inp / "zones.template.yaml").write_text("# my edit\n")
    real_main.main(["--quick", "--subnet", "192.168.0.0/24", "--i-own-this-network",
                    "--input", str(inp), "--out", str(tmp_path / "o")])
    assert "MY-EDIT" in (inp / "names.template.csv").read_text()
    assert (inp / "zones.template.yaml").read_text() == "# my edit\n"


IPCONFIG = """Windows IP Configuration

Ethernet adapter vEthernet (WSL):

   Physical Address. . . . . . . . . : 00-15-5D-AA-BB-CC
   IPv4 Address. . . . . . . . . . . : 172.24.16.1(Preferred)

Wireless LAN adapter Wi-Fi:

   Description . . . . . . . . . . . : Fake Wi-Fi Card
   Physical Address. . . . . . . . . : AA-BB-CC-11-22-33
   IPv4 Address. . . . . . . . . . . : 192.168.0.106(Preferred)
   Default Gateway . . . . . . . . . : 192.168.0.1
"""


class _Out:
    returncode, stdout = 0, IPCONFIG


def test_own_entry_finds_this_computer_on_the_subnet_only():
    net = discover.validate_subnet("192.168.0.0/24")
    assert discover.own_entry(net, runner=lambda *a, **k: _Out, system="Windows") == \
        {"ip": "192.168.0.106", "mac": "aa:bb:cc:11:22:33"}        # not the 172.24.x virtual adapter
    assert discover.own_entry(net, runner=lambda *a, **k: _Out, system="Linux") is None
    other = discover.validate_subnet("10.0.0.0/24")
    assert discover.own_entry(other, runner=lambda *a, **k: _Out, system="Windows") is None


def test_discover_adds_this_computer_once(monkeypatch):
    monkeypatch.setattr(discover, "own_entry", lambda net, runner=None: {"ip": "192.168.0.106", "mac": "aa:bb:cc:11:22:33"})

    class R:
        returncode = 0
        stdout = "  192.168.0.101  aa-bb-cc-00-00-02  dynamic\n"
    rows = discover.discover("192.168.0.0/24", runner=lambda *a, **k: R)
    assert sorted(r["ip"] for r in rows) == ["192.168.0.101", "192.168.0.106"]
