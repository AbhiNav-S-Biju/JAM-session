"""Acceptance criterion 4: change the YAML, the results change, with no code edit."""
import shutil

import yaml

from src.model import load_scenario
from src.policies import apply_policy
from src.reach import blast_radius

HOME = "scenarios/home.yaml"


def _radius(path, policy):
    s = load_scenario(path)
    return blast_radius(apply_policy(policy, s), s.foothold, [d.id for d in s.devices])


def _edit(tmp_path, mutate):
    p = tmp_path / "home.yaml"
    shutil.copy(HOME, p)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    mutate(data)
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


def test_untouched_copy_matches_original(tmp_path):
    p = _edit(tmp_path, lambda d: None)
    assert _radius(p, "vlan_only").reachable == _radius(HOME, "vlan_only").reachable


def test_moving_a_device_to_another_zone_changes_vlan_only(tmp_path):
    assert _radius(HOME, "vlan_only").reachable == {"nvr", "doorbell"}

    def move(d):
        next(x for x in d["devices"] if x["id"] == "doorbell")["zone"] = "IoT"

    p = _edit(tmp_path, move)
    assert _radius(p, "vlan_only").reachable == {"nvr"}
    assert _radius(p, "flat").count == 7          # flat ignores zones


def test_editing_the_baseline_changes_vlan_deny(tmp_path):
    assert _radius(HOME, "vlan_deny").reachable == {"nvr"}
    p = _edit(tmp_path, lambda d: d["baseline"].append(["nvr", "phone"]))
    assert _radius(p, "vlan_deny").reachable == {"nvr", "phone"}


def test_changing_the_foothold_changes_the_result(tmp_path):
    p = _edit(tmp_path, lambda d: d.update(foothold="visitor"))
    assert _radius(p, "vlan_deny").count == 0     # visitor only reaches the weather host
    assert _radius(p, "vlan_only").count == 0     # alone in the Guest zone
    assert _radius(p, "flat").count == 7
