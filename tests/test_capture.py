"""Capture-recapture estimators and matching (ARB-172).

Simulated populations with a known total: independent detectors must put the
true total inside the 95% interval at close to the nominal rate; detectors
sharing a per-defect 'easiness' must pull the estimate DOWN (the documented
bias that makes the published number a floor)."""
from __future__ import annotations

import math

import pytest

from arbiter import capture as c


# --- matching -----------------------------------------------------------------

def _f(det, line, path="a.py", fam="sql-injection", repo="r", rule="x"):
    return {"detector": det, "line": line, "path": path, "family": fam, "repo": repo, "rule": rule}


def test_same_file_family_and_nearby_line_is_one_site():
    sites = c.cluster_sites([_f("arbiter", 10), _f("semgrep", 12), _f("bandit", 13)])
    assert len(sites) == 1 and sites[0]["detectors"] == ["arbiter", "bandit", "semgrep"]


def test_matching_is_anchored_not_chained():
    sites = c.cluster_sites([_f("arbiter", 10), _f("semgrep", 13), _f("bandit", 16)])
    assert [s["line"] for s in sites] == [10, 16]
    assert [s["detectors"] for s in sites] == [["arbiter", "semgrep"], ["bandit"]]


def test_tolerance_boundary():
    assert len(c.cluster_sites([_f("a", 10), _f("b", 13)], tolerance=3)) == 1
    assert len(c.cluster_sites([_f("a", 10), _f("b", 14)], tolerance=3)) == 2


@pytest.mark.parametrize("other", [{"path": "b.py"}, {"fam": "xss"}, {"repo": "s"}])
def test_different_file_family_or_repo_never_match(other):
    sites = c.cluster_sites([_f("arbiter", 10), _f("semgrep", 10, **other)])
    assert len(sites) == 2


def test_one_capture_per_detector_per_site():
    sites = c.cluster_sites([_f("semgrep", 10, rule="r1"), _f("semgrep", 11, rule="r2")])
    assert len(sites) == 1
    assert c.histories(sites, ["arbiter", "semgrep"]) == {(0, 1): 1.0}


def test_cluster_order_independent():
    rows = [_f("arbiter", 10), _f("semgrep", 12), _f("bandit", 30), _f("semgrep", 31)]
    a = c.cluster_sites(rows)
    b = c.cluster_sites(list(reversed(rows)))
    assert [(s["line"], s["detectors"]) for s in a] == [(s["line"], s["detectors"]) for s in b]


def test_family_of_rule_override_beats_cwe():
    # Bandit files its XML parser checks under CWE-20; the defect is XXE.
    assert c.family_of("bandit", "bandit/B314", ["CWE-20"]) == "xxe"
    assert c.family_of("bandit", "bandit/B102", ["CWE-78"]) == "code-injection"
    assert c.family_of("semgrep", "semgrep/x", ["CWE-89"]) == "sql-injection"
    assert c.family_of("arbiter", "arbiter/python.http-no-timeout", ["CWE-400"]) == "missing-timeout"


def test_family_of_picks_lowest_cwe_and_is_order_free():
    assert c.family_of("x", "r", ["CWE-338", "CWE-327"]) == c.family_of("x", "r", ["CWE-327", "CWE-338"])
    assert c.family_of("x", "r", ["CWE-327", "CWE-338"]) == "weak-crypto"
    assert c.family_of("x", "r", ["CWE-1"]) is None
    assert c.family_of("x", "r", []) is None


# --- estimators: exact values ------------------------------------------------

def test_chapman_textbook_value():
    # (n1+1)(n2+1)/(m+1) - 1
    e = c.chapman(60, 50, 30)
    assert e["n_hat"] == pytest.approx(61 * 51 / 31 - 1)
    assert e["observed"] == 80
    assert e["lo"] >= 80 and e["lo"] < e["n_hat"] < e["hi"]


def test_chapman_no_overlap_has_no_upper_bound():
    assert c.chapman(10, 10, 0)["hi"] == math.inf


def test_chao_formula():
    hist = {(1, 0, 0): 20, (0, 1, 0): 10, (1, 1, 0): 8, (0, 1, 1): 2, (1, 1, 1): 5}
    e = c.chao_lower_bound(hist)
    assert e["f1"] == 30 and e["f2"] == 10
    assert e["n_hat"] == pytest.approx(45 + (2 / 3) * 900 / 20)


def test_chao_f2_zero_uses_bias_corrected_form():
    e = c.chao_lower_bound({(1, 0): 4, (0, 1): 2})
    assert e["n_hat"] == pytest.approx(6 + 0.5 * 6 * 5 / 2)


def test_loglinear_independence_matches_chapman_scale():
    h = c.simulate(400, [0.4, 0.5, 0.6], "ind-check")
    ll = c.loglinear(h)
    assert ll["lo"] <= ll["n_hat"] <= ll["hi"]
    assert 340 < ll["n_hat"] < 460
    assert all(m["df"] >= 1 for m in [ll])


def test_catch_rate_interval_swaps_bounds():
    r = c.catch_rate(50, {"n_hat": 100.0, "lo": 80.0, "hi": 125.0})
    assert r["rate"] == 0.5 and r["lo"] == pytest.approx(0.4) and r["hi"] == pytest.approx(50 / 80)


def test_estimate_dispatch():
    assert c.estimate({(1, 1): 5, (1, 0): 5, (0, 1): 5})["method"] == "chapman"
    assert c.estimate(c.simulate(200, [0.5, 0.5, 0.5], "d"))["method"] == "loglinear"
    with pytest.raises(ValueError):
        c.estimate({})


# --- simulation: coverage and bias ------------------------------------------

def test_independent_detectors_ci_coverage_near_nominal():
    n, runs = 300, 120
    hit_ch = hit_ll = 0
    for i in range(runs):
        h = c.simulate(n, [0.3, 0.4, 0.5], f"cov|{i}")
        two = c.two_way(h)
        hit_ch += two["lo"] <= n <= two["hi"]
        ll = c.loglinear(h)
        hit_ll += ll["lo"] <= n <= ll["hi"]
    assert hit_ch / runs >= 0.88
    assert hit_ll / runs >= 0.85


def test_independent_estimates_unbiased_on_average():
    vals = [c.two_way(c.simulate(300, [0.3, 0.4], f"bias|{i}"))["n_hat"] for i in range(200)]
    assert abs(sum(vals) / len(vals) - 300) < 10


def test_correlated_detectors_bias_estimate_low():
    """Shared 'easiness' (detectors written from the same pattern ideas):
    every estimator here lands below the truth, which is why the published
    number is a lower bound on the total and on what was missed."""
    n, runs = 300, 60
    ch = sum(c.two_way(c.simulate(n, [0.3, 0.4, 0.5], f"cor|{i}", spread=1.0))["n_hat"]
             for i in range(runs)) / runs
    chao = sum(c.chao_lower_bound(c.simulate(n, [0.3, 0.4, 0.5], f"cor|{i}", spread=1.0))["n_hat"]
               for i in range(runs)) / runs
    ll = sum(c.loglinear(c.simulate(n, [0.3, 0.4, 0.5], f"cor|{i}", spread=1.0))["n_hat"]
             for i in range(runs)) / runs
    assert ch < 0.7 * n
    assert chao < 0.9 * n
    assert ll < n


def test_simulate_and_estimates_deterministic():
    a = c.simulate(200, [0.3, 0.6, 0.4], "same")
    b = c.simulate(200, [0.3, 0.6, 0.4], "same")
    assert a == b
    assert c.loglinear(a) == c.loglinear(b)


def test_bootstrap_over_repositories_deterministic_and_brackets():
    groups = [c.simulate(40, [0.4, 0.5], f"repo|{i}") for i in range(12)]
    stat = lambda h: c.two_way(h)["n_hat"]
    a = c.bootstrap_ci(groups, stat, b=200, seed="x")
    assert a == c.bootstrap_ci(groups, stat, b=200, seed="x")
    assert a[0] < 480 < a[1]
    assert c.bootstrap_ci(groups[:1], stat) is None
