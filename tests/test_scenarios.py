"""Check every `expect:` block in scenarios/home.yaml against the engine.

The expected values are the hand-written oracle. NEVER edit them to make a test pass.
Checks that need Person 2's modules (outbound, alerts) skip until those are merged.
"""
import pytest

from src.model import load_scenario, load_thresholds, with_case
from src.policies import apply_policy
from src.reach import blast_radius

SCENARIO = load_scenario("scenarios/home.yaml")
THRESHOLDS = load_thresholds()


def _expectations(key):
    """List of (case_id, policy, expected_value) params for every expect[key] entry."""
    return [
        pytest.param(case.id, policy, value, id=f"{case.id}-{policy}")
        for case in SCENARIO.cases
        for policy, value in (case.expect.get(key) or {}).items()
    ]


def _skip_if_missing(fn, *args):
    try:
        return fn(*args)
    except NotImplementedError:
        pytest.skip(f"{fn.__module__}.{fn.__name__} not implemented yet")


@pytest.mark.parametrize("case_id,policy,expected", _expectations("blast_radius"))
def test_blast_radius(case_id, policy, expected):
    s = with_case(SCENARIO, case_id)
    r = blast_radius(apply_policy(policy, s), s.foothold, [d.id for d in s.devices])
    assert r.count == expected


@pytest.mark.parametrize("case_id,policy,expected", _expectations("laptop_outbound_mb"))
def test_laptop_outbound_mb(case_id, policy, expected):
    from src.outbound import delivered_mb
    s = with_case(SCENARIO, case_id)
    got = _skip_if_missing(delivered_mb, s, apply_policy(policy, s))
    assert got == pytest.approx(expected)


@pytest.mark.parametrize("case_id,policy,expected", _expectations("alerts"))
def test_alerts_include_expected_kinds(case_id, policy, expected):
    from src.alerts import check_baseline
    from src.outbound import check_laptop
    s = with_case(SCENARIO, case_id)
    edges = apply_policy(policy, s)
    alerts = _skip_if_missing(check_laptop, s, edges, THRESHOLDS) \
        + _skip_if_missing(check_baseline, s, THRESHOLDS)
    kinds = {a.kind for a in alerts}
    assert set(expected) <= kinds, f"missing {set(expected) - kinds}; got {sorted(kinds)}"
