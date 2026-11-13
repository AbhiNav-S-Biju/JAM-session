import copy

import pytest
import yaml

from src.model import load_scenario, load_thresholds, with_case

HOME = "scenarios/home.yaml"


def _write(tmp_path, mutate):
    data = yaml.safe_load(open(HOME, encoding="utf-8"))
    mutate(data)
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


def test_loads_home():
    s = load_scenario(HOME)
    assert len(s.devices) == 8
    assert len(s.hosts) == 4
    assert s.foothold == "camera"
    assert ("camera", "nvr") in s.baseline
    assert [c.id for c in s.cases] == ["camera", "vendor", "beacon"]
    assert s.flows == ()


def test_unknown_host_flag():
    s = load_scenario(HOME)
    assert {h.id for h in s.hosts if not h.known} == {"unknown"}


def test_with_case_sets_flows_and_leaves_original():
    s = load_scenario(HOME)
    v = with_case(s, "vendor")
    assert len(v.flows) == 1 and v.flows[0].bytes == 48_000_000
    assert s.flows == ()
    assert len(with_case(s, "beacon").flows) == 5


def test_with_case_unknown():
    with pytest.raises(ValueError, match="nope"):
        with_case(load_scenario(HOME), "nope")


def test_thresholds():
    t = load_thresholds()
    assert t == {"outbound_mb_limit": 10, "beacon_min_count": 5, "beacon_window_s": 300}


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d["baseline"].append(["laptop", "ghost"]), "baseline"),
    (lambda d: d["baseline"].append(["ghost", "weather"]), "baseline"),
    (lambda d: d["scenarios"][1]["flows"].append({"src": "laptop", "dst": "ghost", "bytes": 1, "t": 0}), "vendor"),
    (lambda d: d.update(foothold="weather"), "foothold"),
    (lambda d: d["devices"][0].update(zone="Nowhere"), "laptop"),
    (lambda d: d["devices"].append(copy.deepcopy(d["devices"][0])), "duplicate"),
    (lambda d: d["hosts"][0].update(id="laptop"), "both a device and a host"),
    (lambda d: d.pop("baseline"), "baseline"),
])
def test_bad_reference_raises_and_names_it(tmp_path, mutate, needle):
    with pytest.raises(ValueError, match=needle):
        load_scenario(_write(tmp_path, mutate))
