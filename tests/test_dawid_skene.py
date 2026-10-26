"""Dawid-Skene labeller-weighted precision (ARB-167): src/arbiter/dawid_skene.py
and its place in the precision ledger, next to strict unanimity."""
from __future__ import annotations

import importlib.util
import json
import random
import sys

from helpers import ROOT

from arbiter import dawid_skene as DS
from arbiter import precision as P


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


PL = _load("precision_ledger")
RULE = "arbiter/python.sql-injection"


def _synthetic(n: int, prevalence: float, rates: dict[str, tuple[float, float]], seed: int,
               prefix: str = "f", truth_known: bool = False) -> list[dict]:
    """n findings, each voted on by every rater with its (sens, spec)."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        tp = rng.random() < prevalence
        votes = []
        for r, (sens, spec) in sorted(rates.items()):
            right = rng.random() < (sens if tp else spec)
            votes.append((r, ("tp" if tp else "fp") if right else ("fp" if tp else "tp")))
        out.append({"id": f"{prefix}{i}", "group": RULE, "category": "injection", "votes": votes,
                    "truth": ("tp" if tp else "fp") if truth_known else None, "_true": tp})
    return out


RATES = {"good": (0.95, 0.90), "fair": (0.85, 0.80), "noisy": (0.75, 0.70)}


# ---------------------------------------------------------------------------
# EM recovers what it should
# ---------------------------------------------------------------------------

def test_em_recovers_known_error_rates_without_anchors():
    items = _synthetic(4000, 0.6, RATES, seed=1)
    fit = DS.fit(items)
    assert fit["converged"]
    for r, (sens, spec) in RATES.items():
        got = fit["raters"][r]
        assert abs(got["sens"] - sens) < 0.03, (r, got)
        assert abs(got["spec"] - spec) < 0.03, (r, got)
    assert abs(fit["prevalence"][RULE] - 0.6) < 0.03


def test_em_recovers_error_rates_from_anchors_when_raters_agree_a_lot():
    """Two raters only: without truth the data cannot tell their errors
    apart from the prevalence. Anchors (known-truth calibration) can."""
    rates = {"prosecutor": (0.97, 0.90), "defender": (0.93, 0.98)}
    anchors = _synthetic(3000, 0.5, rates, seed=2, prefix="cal", truth_known=True)
    items = _synthetic(1000, 0.7, rates, seed=3)
    fit = DS.fit(items, anchors)
    for r, (sens, spec) in rates.items():
        assert abs(fit["raters"][r]["sens"] - sens) < 0.02, (r, fit["raters"][r])
        assert abs(fit["raters"][r]["spec"] - spec) < 0.02, (r, fit["raters"][r])
    assert fit["raters"]["prosecutor"]["pooled_from"] == "anchors"


def test_posteriors_track_the_hidden_truth():
    items = _synthetic(3000, 0.4, RATES, seed=4)
    fit = DS.fit(items)
    right = sum((fit["posteriors"][it["id"]] >= 0.5) == it["_true"] for it in items)
    majority = sum((sum(v == "tp" for _, v in it["votes"]) >= 2) == it["_true"] for it in items)
    assert right >= majority  # weighting votes by skill is never worse than counting them
    assert right / len(items) > 0.93


def test_unanchored_category_uses_the_raters_pooled_matrix():
    rates = {"a": (0.95, 0.95), "b": (0.95, 0.95)}
    anchors = _synthetic(400, 0.5, rates, seed=5, prefix="cal", truth_known=True)
    items = _synthetic(200, 0.5, rates, seed=6)
    for it in items:
        it["category"] = "supply-chain"
    fit = DS.fit(items, anchors)
    cat = fit["raters"]["a"]["by_category"]["supply-chain"]
    assert cat["anchored_votes"] == 0 and cat["estimate"].startswith("pooled")
    assert (cat["sens"], cat["spec"]) == (fit["raters"]["a"]["sens"], fit["raters"]["a"]["spec"])


# ---------------------------------------------------------------------------
# Agreement with unanimity where it must agree
# ---------------------------------------------------------------------------

def test_perfect_labellers_give_the_unanimity_verdicts_and_bounds():
    """Criterion: the same hard verdict on every finding (posterior >= 0.5
    is tp), and precision and lower bound within 0.005 of unanimity's.
    Exact equality is impossible: the Beta priors keep every estimated
    error rate above 0, so an agreeing pair is never quite certain."""
    rng = random.Random(7)
    recs, verdict = [], {}
    for i in range(300):
        lab = "tp" if rng.random() < 0.8 else "fp"
        verdict[f"f{i}"] = lab
        for m in ("model-a", "model-b"):
            recs.append({"finding_id": f"f{i}", "rule_id": RULE, "label": lab, "labeller": m,
                         "source": "gold", "held_out": True, "role": "labeller", "repo": f"r{i % 30}",
                         "category": "injection"})
    fit = DS.fit(PL.ds_items(recs))
    hard = {k: ("tp" if p >= 0.5 else "fp") for k, p in fit["posteriors"].items()}
    assert hard == verdict
    tp = sum(v == "tp" for v in verdict.values())
    ds = DS.summarise(fit["posteriors"].values())
    assert abs(ds["precision"] - tp / 300) < 0.005
    assert abs(ds["lower"] - P.wilson(tp, 300)[0]) < 0.005


def test_certain_posteriors_reduce_exactly_to_wilson():
    s = DS.summarise([1.0] * 97 + [0.0] * 3)
    lo, hi = P.wilson(97, 100)
    assert (s["lower"], s["upper"]) == (round(lo, 4), round(hi, 4))
    assert s["precision"] == 0.97


def test_label_uncertainty_widens_the_interval():
    sure = DS.summarise([1.0] * 74 + [0.0] * 26)
    unsure = DS.summarise([0.9] * 80 + [0.1] * 20)          # the same 74 expected tp, held less firmly
    assert sure["precision"] == unsure["precision"] == 0.74
    assert unsure["lower"] < sure["lower"] - 0.005 and unsure["upper"] > sure["upper"] + 0.005


def test_ground_truth_findings_are_fixed_and_unvoted():
    recs = [{"finding_id": "g1", "rule_id": RULE, "label": "fp", "labeller": "ground-truth", "source": "owasp",
             "held_out": True, "role": "labeller"}]
    item = PL.ds_items(recs)[0]
    assert item["truth"] == "fp" and item["votes"] == []
    assert DS.fit([item])["posteriors"]["g1"] == 0.0


def test_a_model_record_is_split_into_one_rater_per_role():
    rec = {"finding_id": "f", "rule_id": RULE, "label": "tp", "role": "labeller", "source": "gold",
           "held_out": True, "labeller": "claude-opus-5-5:prosecutor+defender+adjudicator/v3",
           "votes": {"prosecutor": {"label": "tp"}, "defender": {"label": "fp"}, "adjudicator": {"label": "tp"}}}
    assert PL._ds_votes(rec) == [("claude-opus-5-5:adjudicator/v3", "tp"), ("claude-opus-5-5:defender/v3", "fp"),
                                 ("claude-opus-5-5:prosecutor/v3", "tp")]


def test_unsure_votes_are_missing_and_an_all_unsure_finding_has_no_posterior():
    items = [{"id": "x", "group": RULE, "votes": [("a", "unsure"), ("b", "unsure")]},
             {"id": "y", "group": RULE, "votes": [("a", "tp"), ("b", "tp")]}]
    fit = DS.fit(items)
    assert fit["posteriors"]["x"] is None and fit["posteriors"]["y"] > 0.5
    assert DS.summarise(fit["posteriors"].values())["n"] == 1


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_output_is_deterministic_and_independent_of_input_order():
    items = _synthetic(800, 0.6, RATES, seed=8)
    anchors = _synthetic(200, 0.5, RATES, seed=9, prefix="cal", truth_known=True)
    a = DS.fit(items, anchors)
    shuffled = list(items)
    random.Random(10).shuffle(shuffled)
    b = DS.fit(shuffled, list(reversed(anchors)))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["iterations"] <= DS.MAX_ITER


def test_independence_check_flags_shared_mistakes():
    anchors = []
    for i in range(100):
        wrong = i < 10
        v = "fp" if wrong else "tp"
        anchors.append({"truth": "tp", "votes": [("p", v), ("d", v)]})
    c = DS.independence_check(anchors, "p", "d")
    assert c["both_wrong"] == 0.1 and c["both_wrong_if_independent"] == 0.01 and c["ratio"] == 10.0


# ---------------------------------------------------------------------------
# In the ledger: alongside, never instead
# ---------------------------------------------------------------------------

def _ledger_records():
    recs = []
    for i in range(60):
        lab = "tp" if i < 55 else "fp"
        votes = {"prosecutor": {"label": lab}, "defender": {"label": lab if i != 54 else "fp"}}
        recs.append({"finding_id": f"f{i}", "rule_id": RULE, "label": lab if i != 54 else "unsure",
                     "labeller": "claude-opus-5-5:prosecutor+defender/v3", "source": "gold", "held_out": True,
                     "role": "labeller", "repo": f"r{i % 6}", "category": "injection", "votes": votes,
                     "stratum_size": 80, "stratum_held_out_size": 80, "rule_population": 80,
                     "rule_held_out_population": 80})
    return recs


def _anchors():
    return [{"finding_id": f"c{i}", "rule_id": RULE, "label": "tp", "truth": "tp" if i % 3 else "fp",
             "labeller": "claude-opus-5-5:prosecutor+defender/v3", "source": "calibration:owasp-python",
             "held_out": True, "role": "labeller", "category": "injection",
             "votes": {"prosecutor": {"label": "tp" if i % 3 else "fp"},
                       "defender": {"label": "tp" if i % 3 else "fp"}}} for i in range(60)]


def test_admission_and_claim_do_not_depend_on_the_new_estimates():
    recs = _ledger_records()
    with_anchors = PL.build(recs, None, "2026-10-26", {RULE}, anchors=_anchors())
    without = PL.build(recs, None, "2026-10-26", {RULE})
    moved = [dict(r, repo="one-repo") for r in recs]
    clustered_once = PL.build(moved, None, "2026-10-26", {RULE})
    for other in (without, clustered_once):
        assert json.dumps(with_anchors["rules"], sort_keys=True) == json.dumps(other["rules"], sort_keys=True)
        assert json.dumps(with_anchors["tier"], sort_keys=True) == json.dumps(other["tier"], sort_keys=True)
    assert "dawid_skene" in with_anchors and "clustered" in with_anchors


def test_ledger_reports_both_side_by_side_and_counts_changed_verdicts():
    led = PL.build(_ledger_records(), None, "2026-10-26", {RULE}, anchors=_anchors())
    ds = led["dawid_skene"]["rules"][RULE]
    assert led["rules"][RULE]["n"] == 59 and ds["all"]["n"] == 60   # the disputed finding is weighed, not dropped
    assert ds["verdicts_changed"] == 1
    assert led["dawid_skene"]["method"]["anchors"] == 60
    assert led["dawid_skene"]["method"]["converged"]
