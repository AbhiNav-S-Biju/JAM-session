import pytest

from src.model import load_scenario, with_case
from src.sim_traffic import make_traffic

S = load_scenario("scenarios/home.yaml")
BEACON = with_case(S, "beacon")


def test_no_jitter_returns_flows_as_written():
    assert make_traffic(BEACON, seed=1) == list(BEACON.flows)


def test_same_seed_same_output():
    assert make_traffic(BEACON, 42, jitter_s=5) == make_traffic(BEACON, 42, jitter_s=5)


def test_different_seed_can_differ():
    outs = {tuple(make_traffic(BEACON, s, jitter_s=20)) for s in range(10)}
    assert len(outs) > 1


def test_jitter_bounded_and_sorted():
    out = make_traffic(BEACON, 3, jitter_s=10)
    ts = [f.t for f in out]
    assert ts == sorted(ts) and min(ts) >= 0
    assert len(out) == len(BEACON.flows)
    assert all(f.bytes == 64 for f in out)


def test_empty_case_and_bad_jitter():
    assert make_traffic(with_case(S, "camera"), 1) == []
    with pytest.raises(ValueError):
        make_traffic(BEACON, 1, jitter_s=-1)
