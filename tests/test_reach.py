import pytest

from src.model import load_scenario
from src.policies import apply_policy
from src.reach import blast_radius

DEVS = ["a", "b", "c", "d"]


def test_chain_is_directed():
    r = blast_radius({("a", "b"), ("b", "c")}, "a", DEVS)
    assert r.reachable == {"b", "c"} and r.count == 2 and r.total == 3
    assert blast_radius({("a", "b"), ("b", "c")}, "c", DEVS).count == 0


def test_cycle_terminates_and_excludes_foothold():
    r = blast_radius({("a", "b"), ("b", "a")}, "a", DEVS)
    assert r.reachable == {"b"}


def test_hosts_are_not_counted_or_traversed():
    r = blast_radius({("a", "weather"), ("weather", "c")}, "a", DEVS)
    assert r.count == 0


def test_no_edges():
    assert blast_radius(set(), "a", DEVS).count == 0


def test_bad_foothold():
    with pytest.raises(ValueError):
        blast_radius(set(), "zzz", DEVS)


@pytest.mark.parametrize("policy,count,names", [
    ("flat", 7, None),
    ("vlan_only", 2, {"nvr", "doorbell"}),
    ("vlan_deny", 1, {"nvr"}),
])
def test_camera_oracle(policy, count, names):
    s = load_scenario("scenarios/home.yaml")
    r = blast_radius(apply_policy(policy, s), s.foothold, [d.id for d in s.devices])
    assert (r.count, r.total) == (count, 7)
    if names:
        assert r.reachable == names
