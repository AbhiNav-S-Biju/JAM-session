"""main: one command produces every output, the numbers match the oracle, and YAML edits change them."""
import shutil

import yaml

from src.main import build_results, main


def test_cli_writes_everything_and_prints_table(tmp_path, capsys):
    rc = main(["scenarios/home.yaml", "--out", str(tmp_path / "out"), "--demo", str(tmp_path / "demo")])
    assert rc == 0
    for name in ("results.json", "results.csv", "report.md", "before_after.html"):
        assert (tmp_path / "out" / name).is_file()
    assert (tmp_path / "demo" / "results.js").is_file()
    out = capsys.readouterr().out
    assert "Blast radius" in out and "7 of 7" in out and "Expected results: 9 of 9 pass" in out


def test_every_expect_value_passes():
    results = build_results("scenarios/home.yaml")
    checks = [(c["id"], ch) for c in results["cases"] for ch in c["checks"]]
    assert checks, "the scenario file has expect: blocks"
    assert [(cid, ch["policy"], ch["key"]) for cid, ch in checks if not ch["pass"]] == []


def test_policies_and_before_after_come_from_config():
    results = build_results("scenarios/home.yaml")
    ids = list(yaml.safe_load(open("config/policies.yaml", encoding="utf-8"))["policies"])
    assert [p["id"] for p in results["policies"]] == ids
    assert (results["before_policy"], results["after_policy"]) == (ids[0], ids[-1])


def test_blocked_flow_is_marked_not_delivered():
    vendor = next(c for c in build_results("scenarios/home.yaml")["cases"] if c["id"] == "vendor")
    assert vendor["results"]["flat"]["delivered"] == [True]
    assert vendor["results"]["vlan_deny"]["delivered"] == [False]


def test_reach_edges_connect_foothold_to_every_reachable_device():
    results = build_results("scenarios/home.yaml")
    for c in results["cases"]:
        for r in c["results"].values():
            assert {d for _, d in r["reach_edges"]} == set(r["reachable"])


def test_yaml_edit_changes_results_without_code_edit(tmp_path):
    p = tmp_path / "home.yaml"
    shutil.copy("scenarios/home.yaml", p)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    next(d for d in data["devices"] if d["id"] == "doorbell")["zone"] = "IoT"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    camera = next(c for c in build_results(str(p))["cases"] if c["id"] == "camera")
    assert camera["results"]["vlan_only"]["reachable"] == ["nvr"]


def test_failing_expect_gives_nonzero_exit(tmp_path, capsys):
    p = tmp_path / "home.yaml"
    shutil.copy("scenarios/home.yaml", p)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    data["devices"] = [d for d in data["devices"] if d["id"] != "visitor"]
    data["baseline"] = [b for b in data["baseline"] if "visitor" not in b]
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    rc = main([str(p), "--out", str(tmp_path / "out"), "--demo", str(tmp_path / "demo")])
    assert rc == 1 and "FAIL flat blast_radius" in capsys.readouterr().out
