"""Dawid-Skene label aggregation (ARB-167): labeller-weighted verdicts.

The precision ledger's verdict today is strict unanimity: a finding counts
as tp or fp only when every decided label agrees, and a disagreement nobody
adjudicated is `unsure`. Dawid-Skene instead estimates how often each
labeller is right and weighs its votes by that, giving each finding a
posterior probability that it is a true positive.

Model (binary, one labeller = one "rater"):

* each finding has a hidden true class, tp or fp, with prior probability
  `prevalence[group]` of tp (the group is the finding's rule);
* each rater, in each category (`label_models.category`), reports tp on a
  true tp with probability `sens` and fp on a true fp with probability
  `spec`, independently of the other raters given the true class;
* `unsure` is a missing vote, not a third class.

EM alternates between posteriors (E) and rater/prevalence estimates (M).
Three things keep it stable on this project's data:

* **Anchors.** Items with known truth -- the ledger's ground-truth findings
  and the `calibration:` records (benchmark items the labellers labelled
  blind) -- enter with their true class fixed. They pin each rater's
  confusion matrix where truth exists, and they break the label-switching
  symmetry (EM could otherwise explain "raters agree" equally well with tp
  and fp swapped). Anchors inform the raters only, never a rule's
  prevalence: calibration items are drawn from benchmarks, not from the
  scanned code.
* **Beta priors.** A rater's pooled sens/spec have a Beta(2, 1) prior
  ("better than a coin", worth three votes); a category's sens/spec are
  shrunk toward the rater's pooled value with `SHRINK` pseudo-votes, so a
  category with three labels does not collapse to 0 or 1. A rule's
  prevalence has a Beta(1, 1) prior.
* **Determinism.** Inputs are sorted, the iteration limit and tolerance are
  fixed, and nothing is random, so the same labels give the same output.

The interval (`summarise`) widens Wilson's interval by the label
uncertainty the posteriors carry. It does not include the uncertainty in
the estimated confusion matrices themselves.
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Iterable

from arbiter.precision import Z95, wilson

RATER_PRIOR = (2.0, 1.0)     # Beta(a, b) on a rater's pooled sens and spec
SHRINK = 10.0                # pseudo-votes pulling a category toward the rater's pooled matrix
PREVALENCE_PRIOR = (1.0, 1.0)
MAX_ITER = 500
TOL = 1e-10
_EPS = 1e-6


def _clamp(x: float) -> float:
    return min(1.0 - _EPS, max(_EPS, x))


def _norm_items(items: Iterable[dict], anchor: bool) -> list[dict]:
    out = []
    for it in items:
        votes = sorted((str(r), lab) for r, lab in it.get("votes") or () if lab in ("tp", "fp"))
        truth = it.get("truth")
        if truth not in ("tp", "fp"):
            truth = None
        if anchor and truth is None:
            continue
        out.append({"id": str(it.get("id", "")), "group": str(it.get("group", "")),
                    "category": str(it.get("category") or "other"), "votes": votes,
                    "truth": truth, "anchor": anchor})
    return sorted(out, key=lambda x: (x["anchor"], x["id"], x["group"], x["votes"]))


def fit(items: Iterable[dict], anchors: Iterable[dict] = (), max_iter: int = MAX_ITER,
        tol: float = TOL) -> dict:
    """Fit Dawid-Skene.

    `items`: the findings, each {"id", "group" (rule), "category", "votes":
    [(rater, "tp"|"fp"|"unsure"), ...], "truth": None|"tp"|"fp"}.
    `anchors`: known-truth calibration items, same shape, `truth` required.

    Returns {"posteriors": {id: P(tp) or None}, "raters": {...},
    "prevalence": {group: p}, "iterations", "converged"}. A finding with
    neither truth nor a decided vote has posterior None: there is nothing to
    weigh, and it stays out of every count, as `unsure` does under unanimity.
    """
    rows = _norm_items(items, anchor=False) + _norm_items(anchors, anchor=True)
    raters = sorted({r for x in rows for r, _ in x["votes"]})
    groups = sorted({x["group"] for x in rows if not x["anchor"]})
    # T: current P(tp) per row; None = uninformative (excluded everywhere).
    T: list[float | None] = []
    for x in rows:
        if x["truth"] is not None:
            T.append(1.0 if x["truth"] == "tp" else 0.0)
        elif x["votes"]:
            T.append(sum(lab == "tp" for _, lab in x["votes"]) / len(x["votes"]))
        else:
            T.append(None)

    params: dict = {}
    prev: dict[str, float] = {}
    converged = False
    it = 0
    for it in range(1, max_iter + 1):
        params, prev = _m_step(rows, T, raters, groups)
        delta = 0.0
        for i, x in enumerate(rows):
            if x["truth"] is not None or T[i] is None:
                continue
            new = _posterior(x, params, prev[x["group"]])
            delta = max(delta, abs(new - T[i]))
            T[i] = new
        if delta < tol:
            converged = True
            break
    posteriors = {x["id"]: T[i] for i, x in enumerate(rows) if not x["anchor"]}
    return {"posteriors": posteriors, "raters": _rater_report(rows, T, params),
            "prevalence": {g: round(p, 6) for g, p in sorted(prev.items())},
            "iterations": it, "converged": converged}


def _m_step(rows: list[dict], T: list, raters: list[str], groups: list[str]):
    """Rater matrices and rule prevalences from the current posteriors.

    A rater's pooled matrix comes from the known-truth anchors when it has
    any (Beta-smoothed), else from every item (classic Dawid-Skene). A
    category's matrix is shrunk toward the pooled one by SHRINK pseudo-votes;
    a category with no anchored vote of a rater that has anchors elsewhere
    uses the pooled matrix as is: with two raters that agree, the votes of
    an unanchored category cannot tell an accurate pair from a pair that
    shares its mistakes, so they are not allowed to move it."""
    def acc():
        return [0.0, 0.0, 0.0, 0.0]   # tp votes on tp weight, tp weight, fp votes on fp weight, fp weight
    allp = {r: acc() for r in raters}
    anch = {r: acc() for r in raters}
    by_cat: dict[str, dict] = {r: defaultdict(acc) for r in raters}
    cat_anch: dict[str, dict] = {r: defaultdict(int) for r in raters}
    gsum = {g: [0.0, 0.0] for g in groups}
    for x, t in zip(rows, T):
        if t is None:
            continue
        if not x["anchor"]:
            gsum[x["group"]][0] += t
            gsum[x["group"]][1] += 1.0
        known = x["truth"] is not None
        for r, lab in x["votes"]:
            targets = [allp[r], by_cat[r][x["category"]]] + ([anch[r]] if known else [])
            if known:
                cat_anch[r][x["category"]] += 1
            for a_ in targets:
                a_[1] += t
                a_[3] += 1.0 - t
                if lab == "tp":
                    a_[0] += t
                else:
                    a_[2] += 1.0 - t
    a, b = RATER_PRIOR
    params = {}
    for r in raters:
        anchored = anch[r][1] + anch[r][3] > 0
        s_num, s_den, f_num, f_den = anch[r] if anchored else allp[r]
        sens_r = (s_num + a) / (s_den + a + b)
        spec_r = (f_num + a) / (f_den + a + b)
        cats, srcs = {}, {}
        for c, (cs_num, cs_den, cf_num, cf_den) in sorted(by_cat[r].items()):
            if anchored and not cat_anch[r][c]:
                cats[c] = (_clamp(sens_r), _clamp(spec_r))
                srcs[c] = "pooled (no anchored vote in this category)"
                continue
            cats[c] = (_clamp((cs_num + SHRINK * sens_r) / (cs_den + SHRINK)),
                       _clamp((cf_num + SHRINK * spec_r) / (cf_den + SHRINK)))
            srcs[c] = "anchored" if anchored else "unanchored (no known-truth item for this rater)"
        params[r] = {"pooled": (_clamp(sens_r), _clamp(spec_r)), "by_category": cats, "source": srcs,
                     "pooled_source": "anchors" if anchored else "all items"}
    pa, pb = PREVALENCE_PRIOR
    prev = {g: _clamp((s_ + pa) / (n_ + pa + pb)) for g, (s_, n_) in gsum.items()}
    return params, prev


def _posterior(x: dict, params: dict, prevalence: float) -> float:
    logit = math.log(prevalence) - math.log(1.0 - prevalence)
    for r, lab in x["votes"]:
        p = params[r]
        sens, spec = p["by_category"].get(x["category"], p["pooled"])
        if lab == "tp":
            logit += math.log(sens) - math.log(1.0 - spec)
        else:
            logit += math.log(1.0 - sens) - math.log(spec)
    if logit >= 0:
        return 1.0 / (1.0 + math.exp(-logit))
    e = math.exp(logit)
    return e / (1.0 + e)


def _rater_report(rows: list[dict], T: list, params: dict) -> dict:
    """Per rater: pooled and per-category sens/spec, with how many votes
    (and how many on known-truth anchors) each estimate rests on."""
    votes = defaultdict(lambda: defaultdict(lambda: [0, 0]))   # r -> c -> [votes, anchored votes]
    for x, t in zip(rows, T):
        if t is None:
            continue
        for r, _ in x["votes"]:
            votes[r][x["category"]][0] += 1
            if x["truth"] is not None:
                votes[r][x["category"]][1] += 1
    out = {}
    for r in sorted(params):
        p = params[r]
        cats = {c: {"sens": round(s, 4), "spec": round(f, 4), "votes": votes[r][c][0],
                    "anchored_votes": votes[r][c][1], "estimate": p["source"][c]}
                for c, (s, f) in sorted(p["by_category"].items())}
        out[r] = {"sens": round(p["pooled"][0], 4), "spec": round(p["pooled"][1], 4),
                  "pooled_from": p["pooled_source"],
                  "votes": sum(v[0] for v in votes[r].values()),
                  "anchored_votes": sum(v[1] for v in votes[r].values()), "by_category": cats}
    return out


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def widen(lo: float, hi: float, v_sampling: float, v_label: float, z: float = Z95) -> tuple[float, float]:
    """Widen a sampling interval by the label uncertainty.

    The share of tp among the labelled findings is uncertain for two
    reasons: which findings were sampled (variance v_sampling, what Wilson
    covers) and what each sampled finding's label really is (variance
    v_label = sum p_i(1-p_i) / n^2 for posteriors p_i). The interval moves
    out by the extra normal half-width the label variance adds,
    z * (sqrt(v_sampling + v_label) - sqrt(v_sampling)). With every
    posterior 0 or 1, v_label is 0 and this is the sampling interval as
    is."""
    extra = z * (math.sqrt(max(0.0, v_sampling) + max(0.0, v_label)) - math.sqrt(max(0.0, v_sampling)))
    return max(0.0, lo - extra), min(1.0, hi + extra)


def summarise(posteriors: Iterable[float | None]) -> dict:
    """Mean-posterior precision and its interval over some findings.

    `n` counts findings with a posterior; `expected_tp` is the sum of the
    posteriors; the interval is Wilson's on (expected_tp, n), widened by
    the label variance (`widen`). When every posterior is 0 or 1 this is
    the unanimity arithmetic exactly.
    """
    ps = [p for p in posteriors if p is not None]
    return summarise_sums(len(ps), math.fsum(ps), math.fsum(p * (1.0 - p) for p in ps))


def summarise_sums(n: float, sum_p: float, sum_pq: float) -> dict:
    if n <= 0:
        return {"n": 0, "expected_tp": 0.0, "precision": None, "lower": None, "upper": None}
    p = sum_p / n
    lo, hi = wilson(sum_p, n)
    lo, hi = widen(lo, hi, p * (1.0 - p) / n, sum_pq / (n * n))
    return {"n": int(n), "expected_tp": round(sum_p, 3), "precision": round(p, 4),
            "lower": round(lo, 4), "upper": round(hi, 4)}


def independence_check(anchors: Iterable[dict], a: str, b: str) -> dict:
    """On known-truth items both raters decided: how often both are wrong,
    against what independence predicts (the product of their own error
    rates). Dawid-Skene assumes independence given the true class; two
    roles of one model reading one excerpt can share mistakes, and a ratio
    above 1 means agreeing pairs are trusted more than they deserve."""
    n = wa = wb = both = 0
    for it in anchors:
        truth = it.get("truth")
        if truth not in ("tp", "fp"):
            continue
        v = dict(it.get("votes") or ())
        if v.get(a) not in ("tp", "fp") or v.get(b) not in ("tp", "fp"):
            continue
        n += 1
        ea, eb = v[a] != truth, v[b] != truth
        wa += ea
        wb += eb
        both += ea and eb
    if not n:
        return {"items": 0}
    expected = (wa / n) * (wb / n)
    return {"items": n, "a": a, "b": b, "error_a": round(wa / n, 4), "error_b": round(wb / n, 4),
            "both_wrong": round(both / n, 4), "both_wrong_if_independent": round(expected, 5),
            "ratio": round((both / n) / expected, 2) if expected > 0 else None}
