import pytest
import yaml

from src.model import load_scenario
from src.policies import apply_policy

S = load_scenario("scenarios/home.yaml")


def test_flat_allows_every_device_to_every_node():
    e = apply_policy("flat", S)
    assert ("laptop", "unknown") in e          # device -> unlisted host
    assert ("fridge", "visitor") in e          # device -> device across zones
    assert ("laptop", "laptop") not in e
    assert len(e) == 8 * 7 + 8 * 4             # 56 device pairs + 32 device->host


def test_vlan_only_same_zone_and_known_hosts():
    e = apply_policy("vlan_only", S)
    assert ("camera", "doorbell") in e and ("camera", "nvr") in e   # same zone open
    assert ("camera", "laptop") not in e                            # cross zone blocked
    assert ("camera", "weather") in e                               # known host
    assert ("laptop", "unknown") not in e                           # unlisted host blocked


def test_vlan_deny_is_exactly_the_baseline():
    assert apply_policy("vlan_deny", S) == set(S.baseline)


def test_policies_nest():
    assert apply_policy("vlan_deny", S) <= apply_policy("flat", S)
    assert apply_policy("vlan_only", S) <= apply_policy("flat", S)


def test_unknown_policy():
    with pytest.raises(ValueError, match="unknown policy"):
        apply_policy("nope", S)


def test_unknown_rule_and_config_drives_behaviour(tmp_path):
    cfg = tmp_path / "p.yaml"
    cfg.write_text(yaml.safe_dump({"policies": {"x": {"rules": ["bogus"]}}}))
    with pytest.raises(ValueError, match="unknown rule"):
        apply_policy("x", S, str(cfg))
    # Changing the config changes behaviour with no code edit.
    cfg.write_text(yaml.safe_dump({"policies": {"x": {"rules": ["baseline_only"]}}}))
    assert apply_policy("x", S, str(cfg)) == set(S.baseline)
