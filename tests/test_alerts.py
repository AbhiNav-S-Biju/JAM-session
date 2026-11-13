"""Tests for src/alerts.py. Hand-built Scenario objects, so they do not depend on model.py.

Thresholds are passed in; the expected values below are written from the design, not from output.
"""
import pytest

from src.alerts import check_baseline
from src.contracts import Device, Flow, Host, Scenario, Zone

TH = {"beacon_min_count": 5, "beacon_window_s": 300}


def make(flows=(), baseline=()):
    return Scenario(
        zones=(Zone("Z", 0, 0, 10, 10),),
        devices=(Device("laptop", "Laptop", "Z", 0, 0), Device("thermo", "Thermostat", "Z", 0, 0),
                 Device("cam", "Camera", "Z", 0, 0)),
        hosts=(Host("weather", "Weather", True, 0, 0), Host("evil", "Unlisted", False, 0, 0),
               Host("evil2", "Unlisted 2", False, 0, 0)),
        foothold="cam",
        baseline=frozenset(baseline),
        cases=(),
        flows=tuple(flows),
    )


def kinds(alerts):
    return [a.kind for a in alerts]


def beacon_flows(times, src="thermo", dst="evil"):
    return [Flow(src, dst, 64, t) for t in times]


# ---- unlisted_flow ----

def test_unlisted_flow_fires_outside_baseline_to_unlisted_host():
    a = check_baseline(make([Flow("laptop", "evil", 100, 5)]), TH)
    assert kinds(a) == ["unlisted_flow"]
    assert (a[0].src, a[0].dst) == ("laptop", "evil")


def test_baseline_pair_to_unlisted_host_does_not_fire():
    s = make([Flow("laptop", "evil", 100, 5)], baseline=[("laptop", "evil")])
    assert check_baseline(s, TH) == []


def test_known_host_outside_baseline_does_not_fire():
    assert check_baseline(make([Flow("laptop", "weather", 100, 5)]), TH) == []


def test_device_to_device_does_not_fire():
    assert check_baseline(make([Flow("laptop", "cam", 100, 5)]), TH) == []


def test_one_unlisted_alert_per_flow():
    s = make([Flow("laptop", "evil", 1, 1), Flow("laptop", "evil2", 1, 2)])
    assert kinds(check_baseline(s, TH)) == ["unlisted_flow", "unlisted_flow"]


def test_no_flows_no_alerts():
    assert check_baseline(make(), TH) == []


# ---- beaconing ----

def test_beaconing_five_flows_in_window():
    a = check_baseline(make(beacon_flows([0, 60, 120, 180, 240])), TH)
    assert kinds(a).count("beaconing") == 1
    b = next(x for x in a if x.kind == "beaconing")
    assert (b.src, b.dst) == ("thermo", "evil")


def test_four_flows_is_not_beaconing():
    assert "beaconing" not in kinds(check_baseline(make(beacon_flows([0, 60, 120, 180])), TH))


def test_span_exactly_at_window_counts():
    assert "beaconing" in kinds(check_baseline(make(beacon_flows([0, 75, 150, 225, 300])), TH))


def test_span_just_over_window_does_not_count():
    assert "beaconing" not in kinds(check_baseline(make(beacon_flows([0, 75, 150, 225, 301])), TH))


def test_window_slides_over_later_burst():
    # an early flow, a long gap, then five flows close together
    flows = beacon_flows([0, 1000, 1010, 1020, 1030, 1040])
    assert "beaconing" in kinds(check_baseline(make(flows), TH))


def test_flows_to_different_destinations_are_not_merged():
    flows = beacon_flows([0, 60, 120], dst="evil") + beacon_flows([180, 240], dst="evil2")
    assert "beaconing" not in kinds(check_baseline(make(flows), TH))


def test_flows_from_different_sources_are_not_merged():
    flows = beacon_flows([0, 60, 120], src="thermo") + beacon_flows([180, 240], src="laptop")
    assert "beaconing" not in kinds(check_baseline(make(flows), TH))


def test_beaconing_fires_to_known_host_too():
    # regular check-ins are the signal, whoever the destination is
    flows = beacon_flows([0, 60, 120, 180, 240], dst="weather")
    a = check_baseline(make(flows, baseline=[("thermo", "weather")]), TH)
    assert kinds(a) == ["beaconing"]


def test_input_order_does_not_matter():
    assert "beaconing" in kinds(check_baseline(make(beacon_flows([240, 0, 180, 60, 120])), TH))


def test_two_beaconing_pairs_give_two_alerts():
    flows = beacon_flows([0, 10, 20, 30, 40], dst="evil") + beacon_flows([0, 10, 20, 30, 40], dst="evil2")
    assert kinds(check_baseline(make(flows), TH)).count("beaconing") == 2


# ---- thresholds come from the argument ----

def test_beacon_count_threshold_is_read_from_argument():
    flows = beacon_flows([0, 60, 120])
    assert "beaconing" not in kinds(check_baseline(make(flows), TH))
    assert "beaconing" in kinds(check_baseline(make(flows), {**TH, "beacon_min_count": 3}))


def test_beacon_window_threshold_is_read_from_argument():
    flows = beacon_flows([0, 60, 120, 180, 240])
    assert "beaconing" not in kinds(check_baseline(make(flows), {**TH, "beacon_window_s": 100}))


@pytest.mark.parametrize("missing", ["beacon_min_count", "beacon_window_s"])
def test_missing_threshold_raises(missing):
    th = {k: v for k, v in TH.items() if k != missing}
    with pytest.raises(ValueError, match=missing):
        check_baseline(make(), th)


def test_nonsense_thresholds_raise():
    with pytest.raises(ValueError):
        check_baseline(make(), {**TH, "beacon_min_count": 0})
    with pytest.raises(ValueError):
        check_baseline(make(), {**TH, "beacon_window_s": -1})


# ---- the monitor does not depend on any policy ----

def test_same_output_every_call():
    s = make(beacon_flows([0, 60, 120, 180, 240]) + [Flow("laptop", "evil", 9, 3)])
    assert check_baseline(s, TH) == check_baseline(s, TH)


# ---- against the real demo home (hand-written oracle in scenarios/home.yaml) ----

def _home_case(case_id):
    from src.model import load_scenario, load_thresholds, with_case
    return with_case(load_scenario("scenarios/home.yaml"), case_id), load_thresholds()


def test_home_beacon_case_raises_beaconing():
    s, th = _home_case("beacon")
    assert "beaconing" in kinds(check_baseline(s, th))


def test_home_vendor_case_raises_unlisted_flow_not_beaconing():
    s, th = _home_case("vendor")
    k = kinds(check_baseline(s, th))
    assert "unlisted_flow" in k and "beaconing" not in k


def test_home_camera_case_is_quiet():
    s, th = _home_case("camera")
    assert check_baseline(s, th) == []
