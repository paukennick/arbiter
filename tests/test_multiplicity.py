"""Multiple-comparison control for rule admission (ARB-171, D9).

Synthetic families where the truth is known first (rules exactly at the bar,
the least favourable null, mixed with rules well above it), then the
committed ledger, read for its aggregates only."""
from __future__ import annotations

import json
import math
import random

import pytest
from helpers import ROOT

from arbiter import multiplicity as M
from arbiter import precision as P


def _exact_sf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k, n + 1))


# ---------------------------------------------------------------------------
# The exact test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("k,n,p", [(0, 5, 0.3), (1, 5, 0.3), (3, 10, 0.5), (9, 10, 0.97),
                                   (28, 30, 0.97), (30, 30, 0.97), (40, 41, 0.99), (6, 5, 0.5)])
def test_the_tail_matches_an_exact_sum(k, n, p):
    want = _exact_sf(k, n, p) if k <= n else 0.0
    assert M.binom_sf(k, n, p) == pytest.approx(want, rel=1e-12, abs=1e-300)


def test_all_true_positives_give_bar_to_the_n():
    assert M.p_value(690, 690, 0.99) == pytest.approx(0.99 ** 690, rel=1e-12)
    assert M.cp_lower(30, 30, 0.025) == pytest.approx(0.025 ** (1 / 30), rel=1e-12)


def test_a_non_integer_size_is_refused_not_rounded():
    with pytest.raises(ValueError):
        M.binom_sf(29.5, 30, 0.97)


@pytest.mark.parametrize("k,n", [(218, 219), (445, 448), (99, 101), (30, 30), (5, 40)])
def test_p_value_and_clopper_pearson_bound_agree(k, n):
    """p <= a exactly when the level-a lower bound reaches the bar."""
    lo = M.cp_lower(k, n, M.ALPHA)
    assert M.binom_sf(k, n, lo) == pytest.approx(M.ALPHA, rel=1e-6) or lo == 0.0
    for bar in (lo - 1e-4, lo + 1e-4):
        if 0 < bar < 1:
            assert (M.p_value(k, n, bar) <= M.ALPHA) == (lo >= bar)


# ---------------------------------------------------------------------------
# Adjustments
# ---------------------------------------------------------------------------

def test_holm_and_bh_by_hand():
    ps = [0.01, 0.04, 0.03, 0.005]
    assert M.holm(ps) == pytest.approx([0.03, 0.06, 0.06, 0.02])
    assert M.bh(ps) == pytest.approx([0.02, 0.04, 0.04, 0.02])
    h = 1 + 1 / 2 + 1 / 3 + 1 / 4
    assert M.by(ps) == pytest.approx([min(1, 0.02 * h), min(1, 0.04 * h), min(1, 0.04 * h), min(1, 0.02 * h)])


def _fixed_p(monkeypatch, ps: dict[str, float]) -> dict[str, dict]:
    """run_family over rules whose p-values are set (k carries the name)."""
    names = sorted(ps)
    monkeypatch.setattr(M, "p_value", lambda k, n, bar: ps[names[k]])
    return M.run_family({r: (i, 10) for i, r in enumerate(names)}, 0.97)


def test_a_p_value_exactly_at_the_threshold_passes(monkeypatch):
    """Rejection is `<=`: a p-value equal to alpha/m (Holm) or i*q/m (BH)
    passes, one a hair above does not."""
    at = _fixed_p(monkeypatch, {"a": 0.00625, "b": 0.9, "c": 0.9, "d": 0.9})   # 4 * 0.00625 == 0.025
    assert at["a"]["p_holm"] == M.ALPHA and at["a"]["pass_holm"] and at["a"]["pass_unadjusted"]
    above = _fixed_p(monkeypatch, {"a": 0.0063, "b": 0.9, "c": 0.9, "d": 0.9})
    assert not above["a"]["pass_holm"]
    at = _fixed_p(monkeypatch, {"a": 0.001, "b": 0.0125, "c": 0.9, "d": 0.9})  # 4 * 0.0125 / 2 == 0.025
    assert at["b"]["p_bh"] == M.Q and at["b"]["pass_bh"]
    above = _fixed_p(monkeypatch, {"a": 0.001, "b": 0.0126, "c": 0.9, "d": 0.9})
    assert not above["b"]["pass_bh"]
    at = _fixed_p(monkeypatch, {"a": M.ALPHA})
    assert at["a"]["pass_unadjusted"]


def test_one_rule_is_the_unadjusted_test():
    for k, n in [(218, 219), (445, 448), (690, 690), (99, 101), (29, 30), (30, 30)]:
        for bar in (0.97, 0.99):
            r = M.run_family({"x": (k, n)}, bar)["x"]
            assert r["p_holm"] == r["p_bh"] == r["p_by"] == r["p"]
            assert r["pass_holm"] == r["pass_bh"] == r["pass_by"] == r["pass_unadjusted"]
            assert r["lower_bonferroni"] == r["lower_holm"] == r["lower_unadjusted"]


# ---------------------------------------------------------------------------
# Simulations: rules at the bar (null) mixed with rules above it
# ---------------------------------------------------------------------------

def _simulate(reps: int, m_null: int, m_alt: int, n: int, bar: float, alt: float, seed: int):
    rng = random.Random(seed)
    any_false, shares = 0, []
    for _ in range(reps):
        rows, truth = {}, {}
        for i in range(m_null + m_alt):
            p = bar if i < m_null else alt
            k = sum(rng.random() < p for _ in range(n))
            rows[f"r{i:03d}"] = (k, n)
            truth[f"r{i:03d}"] = i < m_null
        names = sorted(rows)
        ps = [M.p_value(*rows[r], bar) for r in names]   # run_family's decision, without its bounds
        holm_pass = {r for r, a in zip(names, M.holm(ps, names)) if a <= M.LEVEL["holm"]}
        bh_pass = {r for r, a in zip(names, M.bh(ps, names)) if a <= M.LEVEL["bh"]}
        any_false += any(truth[r] for r in holm_pass)
        passed = sorted(bh_pass)
        shares.append(sum(truth[r] for r in passed) / len(passed) if passed else 0.0)
    return any_false / reps, sum(shares) / reps


def _slack(rate: float, reps: int) -> float:
    return 3 * math.sqrt(rate * (1 - rate) / reps)


def test_holm_keeps_any_false_admission_within_alpha_and_bh_the_false_share_within_q():
    """20 rules exactly at a 0.90 bar and 10 at 0.97, 150 labels each (a
    bar of 0.90 rather than 0.97 so that 150 labels can pass at all and the
    simulation stays fast; the arithmetic is the same). Unadjusted, the
    chance some at-bar rule passes is far above alpha; Holm keeps it <=
    alpha and BH keeps the false share <= q, each within Monte Carlo error
    (3 standard errors)."""
    reps = 400
    fwer, fdr = _simulate(reps, 20, 10, 150, 0.90, 0.97, seed=171)
    assert fwer <= M.ALPHA + _slack(M.ALPHA, reps)
    assert fdr <= M.Q + _slack(M.Q, reps)
    # without the correction the same family admits a false rule far more often
    rng = random.Random(171)
    hits = 0
    for _ in range(reps):
        ks = [sum(rng.random() < 0.90 for _ in range(150)) for _ in range(20)]
        hits += any(M.p_value(k, 150, 0.90) <= M.ALPHA for k in ks)
    assert hits / reps > 6 * M.ALPHA


def test_with_every_rule_above_the_bar_holm_still_admits_most():
    fwer, fdr = _simulate(100, 0, 10, 300, 0.97, 0.999, seed=7)
    assert fwer == 0 and fdr == 0


def test_the_output_is_deterministic():
    a = _simulate(30, 5, 5, 60, 0.97, 0.995, seed=3)
    b = _simulate(30, 5, 5, 60, 0.97, 0.995, seed=3)
    assert a == b
    rules = _ledger()["rules"]
    bar = P.effective_bar(_ledger().get("bar"))
    assert json.dumps(M.family_block(rules, bar)) == json.dumps(M.family_block(rules, bar))


# ---------------------------------------------------------------------------
# The family and the committed ledger (aggregates only)
# ---------------------------------------------------------------------------

def _ledger() -> dict:
    return json.loads((ROOT / "tools" / "gold" / "precision.json").read_text(encoding="utf-8"))


def test_the_family_is_held_out_labels_not_results():
    bar = dict(P.DEFAULT_BAR)
    rules = {
        "few": {"tp": 100, "fp": 0, "held_out": {"tp": 29, "fp": 0}, "admitted": True,
                "strata": [{"language": "go"}]},
        "bad": {"tp": 10, "fp": 30, "held_out": {"tp": 10, "fp": 30}, "admitted": False,
                "strata": [{"language": "go"}]},
        "good": {"tp": 400, "fp": 0, "held_out": {"tp": 300, "fp": 0}, "admitted": True,
                 "strata": [{"language": "go"}, {"language": "java"}]},
    }
    b = M.family_block(rules, bar)
    t = b["tests"]["rule_lower"]
    assert set(t["overall"]) == {"bad", "good"} and t["m"] == 2
    assert b["outside_family"] == ["few"]
    assert set(t["languages"]) == {"go", "java"} and t["languages"]["java"]["m"] == 1
    assert t["overall"]["good"]["k"] == 400            # tested on admission's counts
    assert b["held_out"]["rule_lower"]["overall"]["good"]["k"] == 300


def test_the_committed_ledger_carries_the_block_it_would_rebuild_to():
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location("precision_ledger", ROOT / "tools" / "precision_ledger.py")
    PL = importlib.util.module_from_spec(spec)
    sys.modules["precision_ledger"] = PL
    spec.loader.exec_module(PL)
    led = P.load_ledger(ROOT / "tools" / "gold" / "precision.json")
    want = PL.multiplicity(led["rules"], led["bar"], PL.declared_verified())
    assert json.loads(json.dumps(want)) == _ledger()["multiplicity"]


def test_which_admitted_rules_survive_on_the_committed_ledger():
    """Recorded on 2026-10-26 (alpha = q = 0.025, family m = 14). A rebuild
    with new labels may move these; update them with the ledger. The two
    rules with a lot of evidence survive every method; the weak-random rule
    (218 TP of 219) passes alone but not once the family is counted."""
    b = _ledger()["multiplicity"]
    held = [e for e in _ledger()["rules"].values()
            if e["held_out"]["tp"] + e["held_out"]["fp"] >= P.DEFAULT_BAR["rule_min_n"]]
    assert b["tests"]["rule_lower"]["m"] == len(held)   # 14 on 2026-10-26; grows with labels
    s = b["survive"]["rule_lower"]
    both = ["arbiter/assurance.blanket-suppression", "arbiter/supply.unpinned-action"]
    assert s["unadjusted"] == sorted(both + ["arbiter/java.weak-random-for-secret"])
    assert s["holm"] == s["bh"] == s["by"] == both
    assert b["survive"]["offline_lower"]["holm"] == ["arbiter/supply.unpinned-action"]
    assert b["language_claims"]["yaml"]["holm"]["claim"] is True
