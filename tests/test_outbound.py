"""Tests for src/outbound.py. Hand-built Scenario objects, so they do not depend on model.py.

Expected values are written from the design (1 MB = 1,000,000 bytes), not copied from output.
"""
import pytest

from src.contracts import Device, Flow, Host, Scenario, Zone
from src.outbound import check_laptop, delivered_mb

TH = {"outbound_mb_limit": 10}
OK = ("laptop", "weather")
BAD = ("laptop", "evil")


def make(flows=(), devices=None):
    devices = devices if devices is not None else (
        Device("laptop", "Laptop", "Z", 0, 0, type="laptop"),
        Device("cam", "Camera", "Z", 0, 0, type="camera"),
    )
    return Scenario(
        zones=(Zone("Z", 0, 0, 10, 10),),
        devices=tuple(devices),
        hosts=(Host("weather", "Weather", True, 0, 0), Host("evil", "Unlisted", False, 0, 0),
               Host("evil2", "Unlisted 2", False, 0, 0)),
        foothold="cam", baseline=frozenset(), cases=(), flows=tuple(flows))


def kinds(alerts):
    return [a.kind for a in alerts]


# ---- delivered_mb ----

def test_delivered_counts_only_allowed_edges():
    s = make([Flow("laptop", "evil", 48_000_000, 10)])
    assert delivered_mb(s, {BAD}) == pytest.approx(48.0)
    assert delivered_mb(s, set()) == 0.0


def test_one_mb_is_a_million_bytes():
    assert delivered_mb(make([Flow("laptop", "weather", 1_000_000, 1)]), {OK}) == pytest.approx(1.0)
    assert delivered_mb(make([Flow("laptop", "weather", 500_000, 1)]), {OK}) == pytest.approx(0.5)


def test_delivered_sums_across_flows_and_hosts():
    s = make([Flow("laptop", "weather", 3_000_000, 1), Flow("laptop", "evil", 4_000_000, 2),
              Flow("laptop", "weather", 1_000_000, 3)])
    assert delivered_mb(s, {OK, BAD}) == pytest.approx(8.0)
    assert delivered_mb(s, {OK}) == pytest.approx(4.0)


def test_device_to_device_is_not_outbound():
    assert delivered_mb(make([Flow("laptop", "cam", 9_000_000, 1)]), {("laptop", "cam")}) == 0.0


def test_other_devices_do_not_count_as_the_laptop():
    assert delivered_mb(make([Flow("cam", "evil", 9_000_000, 1)]), {("cam", "evil")}) == 0.0


def test_no_flows_is_zero():
    assert delivered_mb(make(), {OK}) == 0.0


def test_laptop_is_found_by_type_not_by_id():
    devs = (Device("pc1", "Work PC", "Z", 0, 0, type="laptop"), Device("cam", "Camera", "Z", 0, 0, type="camera"))
    s = make([Flow("pc1", "evil", 2_000_000, 1)], devices=devs)
    assert delivered_mb(s, {("pc1", "evil")}) == pytest.approx(2.0)


def test_no_laptop_device_means_nothing_to_check():
    devs = (Device("cam", "Camera", "Z", 0, 0, type="camera"),)
    s = make([Flow("cam", "evil", 99_000_000, 1)], devices=devs)
    assert delivered_mb(s, {("cam", "evil")}) == 0.0
    assert check_laptop(s, {("cam", "evil")}, TH) == []


# ---- outbound_unlisted ----

def test_unlisted_fires_even_when_blocked():
    a = check_laptop(make([Flow("laptop", "evil", 1000, 5)]), set(), TH)
    assert kinds(a) == ["outbound_unlisted"]
    assert (a[0].src, a[0].dst) == ("laptop", "evil")
    assert "blocked" in a[0].message


def test_unlisted_fires_when_delivered_and_says_so():
    a = check_laptop(make([Flow("laptop", "evil", 1000, 5)]), {BAD}, TH)
    assert kinds(a) == ["outbound_unlisted"] and "delivered" in a[0].message


def test_known_host_does_not_raise_unlisted():
    assert check_laptop(make([Flow("laptop", "weather", 1000, 5)]), {OK}, TH) == []


def test_unlisted_is_one_alert_per_flow():
    s = make([Flow("laptop", "evil", 1, 1), Flow("laptop", "evil2", 1, 2)])
    assert kinds(check_laptop(s, set(), TH)) == ["outbound_unlisted", "outbound_unlisted"]


def test_other_devices_to_unlisted_do_not_raise_laptop_alerts():
    assert check_laptop(make([Flow("cam", "evil", 99_000_000, 1)]), {("cam", "evil")}, TH) == []


def test_device_to_device_raises_nothing():
    assert check_laptop(make([Flow("laptop", "cam", 99_000_000, 1)]), {("laptop", "cam")}, TH) == []


# ---- outbound_over_limit ----

def test_over_limit_when_delivered():
    a = check_laptop(make([Flow("laptop", "evil", 48_000_000, 10)]), {BAD}, TH)
    assert set(kinds(a)) == {"outbound_unlisted", "outbound_over_limit"}


def test_blocked_bytes_never_count_toward_the_limit():
    a = check_laptop(make([Flow("laptop", "evil", 48_000_000, 10)]), set(), TH)
    assert kinds(a) == ["outbound_unlisted"]


def test_exactly_at_the_limit_does_not_fire():
    assert check_laptop(make([Flow("laptop", "weather", 10_000_000, 1)]), {OK}, TH) == []


def test_one_byte_over_the_limit_fires():
    a = check_laptop(make([Flow("laptop", "weather", 10_000_001, 1)]), {OK}, TH)
    assert kinds(a) == ["outbound_over_limit"]


def test_big_upload_to_known_host_is_over_limit_but_not_unlisted():
    a = check_laptop(make([Flow("laptop", "weather", 20_000_000, 1)]), {OK}, TH)
    assert kinds(a) == ["outbound_over_limit"]


def test_limit_is_the_sum_across_flows_and_hosts():
    s = make([Flow("laptop", "weather", 6_000_000, 1), Flow("laptop", "evil", 6_000_000, 2)])
    a = check_laptop(s, {OK, BAD}, TH)
    assert kinds(a).count("outbound_over_limit") == 1  # one alert for the laptop, not two


def test_over_limit_names_the_biggest_receiver():
    s = make([Flow("laptop", "weather", 3_000_000, 1), Flow("laptop", "evil", 9_000_000, 2)])
    a = [x for x in check_laptop(s, {OK, BAD}, TH) if x.kind == "outbound_over_limit"]
    assert a[0].dst == "evil"


def test_only_delivered_part_counts_when_some_flows_are_blocked():
    s = make([Flow("laptop", "weather", 4_000_000, 1), Flow("laptop", "evil", 50_000_000, 2)])
    assert "outbound_over_limit" not in kinds(check_laptop(s, {OK}, TH))


# ---- thresholds come from the argument ----

def test_limit_is_read_from_the_argument():
    s = make([Flow("laptop", "weather", 3_000_000, 1)])
    assert check_laptop(s, {OK}, {"outbound_mb_limit": 10}) == []
    assert kinds(check_laptop(s, {OK}, {"outbound_mb_limit": 2})) == ["outbound_over_limit"]
    assert kinds(check_laptop(s, {OK}, {"outbound_mb_limit": 2.5})) == ["outbound_over_limit"]


def test_missing_limit_raises():
    with pytest.raises(ValueError, match="outbound_mb_limit"):
        check_laptop(make(), set(), {})


@pytest.mark.parametrize("bad", [-1, "10", None, True])
def test_nonsense_limit_raises(bad):
    with pytest.raises(ValueError, match="outbound_mb_limit"):
        check_laptop(make(), set(), {"outbound_mb_limit": bad})


def test_same_output_every_call():
    s = make([Flow("laptop", "evil", 48_000_000, 10), Flow("laptop", "evil2", 1, 3)])
    assert check_laptop(s, {BAD}, TH) == check_laptop(s, {BAD}, TH)


# ---- against the real demo home (hand-written oracle in scenarios/home.yaml) ----

def _home(case_id, policy):
    from src.model import load_scenario, load_thresholds, with_case
    from src.policies import apply_policy
    s = with_case(load_scenario("scenarios/home.yaml"), case_id)
    return s, apply_policy(policy, s), load_thresholds()


@pytest.mark.parametrize("policy,mb", [("flat", 48.0), ("vlan_only", 0.0), ("vlan_deny", 0.0)])
def test_home_vendor_delivered_mb(policy, mb):
    s, edges, _ = _home("vendor", policy)
    assert delivered_mb(s, edges) == pytest.approx(mb)


def test_home_vendor_flat_alerts_both_kinds():
    s, edges, th = _home("vendor", "flat")
    assert set(kinds(check_laptop(s, edges, th))) == {"outbound_unlisted", "outbound_over_limit"}


def test_home_vendor_vlan_deny_blocks_but_still_alerts():
    s, edges, th = _home("vendor", "vlan_deny")
    assert kinds(check_laptop(s, edges, th)) == ["outbound_unlisted"]


@pytest.mark.parametrize("case_id", ["camera", "beacon"])
def test_home_other_cases_have_no_laptop_alerts(case_id):
    s, edges, th = _home(case_id, "flat")
    assert check_laptop(s, edges, th) == []
