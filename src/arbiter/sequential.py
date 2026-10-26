"""Sequential labelling: stop labelling a rule once it has clearly passed or
failed the precision bar (ARB-170, accuracy plan Workstream D1).

The fixed design labels every rule to a set size (381 labels for a 0.99
Wilson lower bound with no false positive). Re-checking that Wilson bound
after every batch and stopping the first time it crosses the bar ("peeking")
is not allowed: each look is another chance for a run of luck to cross it, so
the real false-pass rate climbs well above the nominal 2.5-5%. Everything
here stays valid however often it is checked and whenever labelling stops.

**Pass side: an anytime-valid lower confidence bound.** For a candidate
precision ``q`` the statistic is a mixture likelihood ratio

    M_q(tp, fp) = mean_j  (p_j / q) ** tp * ((1 - p_j) / (1 - q)) ** fp,
    p_j = 1 - (1 - q) * g_j,   g in GAPS = (0.05, 0.2, 0.5)

that is, the alternatives are "this rule's false-positive rate is 5%, 20% or
50% of the rate the bar allows". When the true precision is at most ``q``
every factor has expectation at most 1, so ``M_q`` is a non-negative
supermartingale and by Ville's inequality the chance it *ever* reaches
``1 / alpha`` is at most ``alpha`` -- under any stopping rule. The set of
``q`` not rejected is a confidence sequence; its lower end is the reported
bound, and "pass-0.99" means ``M_0.99 >= 1 / alpha``: a real 95% guarantee.

**Fail side: Wald's SPRT, one boundary.** H0: p <= p0 against H1: p >= p1
(defaults 0.93 and 0.97: "clearly bad" against the admission bar). The
log-likelihood ratio is ``tp * log(p1/p0) + fp * log((1-p1)/(1-p0))``; the
rule fails when it falls to ``log(beta)``. The ratio L0/L1 is a
supermartingale whenever p >= p1, so by Ville again a rule whose precision is
at least p1 (admissible) is failed with probability at most ``beta``. There is no upper
SPRT boundary: passing is the confidence sequence's job.

**Futility.** If even every remaining label in the rule's plan were a true
positive the 0.97 bar could be reached neither by this test nor by the
ledger's own fixed Wilson bound at the end of the plan, the rule fails
("cannot reach") -- a statement about the budget, not a measurement. When 0.99 is out of
reach but 0.97 is not, a pass at 0.97 is final.

Decisions count tp and fp only (unsure labels are not evidence either way,
as in the ledger). Pure and deterministic; nothing here reads a file.
"""

from __future__ import annotations

import math
from functools import lru_cache

METHOD = "mixture-cs+sprt"
GAPS = (0.05, 0.2, 0.5)
DEFAULTS = {"method": METHOD, "alpha": 0.05, "beta": 0.05, "p0": 0.93, "p1": 0.97, "batch": 25}
BARS = (0.97, 0.99)
STATES = ("continue", "pass-0.97", "pass-0.99", "fail")
FINAL = ("pass-0.99", "fail")
_GRID = 10000                 # lower bound resolution: 1e-4
_MAX_TP = 200000


def validate(cfg: dict) -> dict:
    """The pre-registered `sequential` block, checked and completed with the
    defaults. Raises ValueError on an unknown method or out-of-range value."""
    if not isinstance(cfg, dict):
        raise ValueError("sequential: expected an object")
    unknown = set(cfg) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"sequential: unknown key(s) {sorted(unknown)}")
    out = {**DEFAULTS, **cfg}
    if out["method"] != METHOD:
        raise ValueError(f"sequential: method must be {METHOD!r}, not {out['method']!r}")
    for k in ("alpha", "beta"):
        if not 0 < float(out[k]) < 0.5:
            raise ValueError(f"sequential: {k} must be in (0, 0.5)")
    if not 0 < float(out["p0"]) < float(out["p1"]) < 1:
        raise ValueError("sequential: need 0 < p0 < p1 < 1")
    if int(out["batch"]) < 1:
        raise ValueError("sequential: batch must be at least 1")
    out["batch"] = int(out["batch"])
    for k in ("alpha", "beta", "p0", "p1"):
        out[k] = float(out[k])
    return out


def log_mixture(tp: int, fp: int, q: float) -> float:
    """log M_q(tp, fp), the pass-side test statistic at candidate precision q."""
    if q <= 0:
        return math.inf if fp == 0 and tp > 0 else 0.0
    if q >= 1:
        return -math.inf if fp else 0.0
    terms = []
    for g in GAPS:
        p = 1 - (1 - q) * g
        terms.append(tp * math.log(p / q) + fp * math.log(g))
    m = max(terms)
    return m + math.log(sum(math.exp(t - m) for t in terms) / len(terms))


def rejects(tp: int, fp: int, q: float, alpha: float) -> bool:
    """True when the data rule out precision <= q at level alpha (anytime-valid)."""
    return log_mixture(tp, fp, q) >= math.log(1 / alpha)


@lru_cache(maxsize=None)
def tp_needed(fp: int, bar: float, alpha: float) -> int:
    """Fewest true positives that, with `fp` false positives, pass `bar`. The
    statistic rises with tp at fixed fp, so this is a threshold."""
    lo, hi = 0, _MAX_TP
    if not rejects(hi, fp, bar, alpha):
        return _MAX_TP + 1
    while lo < hi:
        mid = (lo + hi) // 2
        if rejects(mid, fp, bar, alpha):
            hi = mid
        else:
            lo = mid + 1
    return lo


def labels_needed(fp: int, bar: float, alpha: float) -> int:
    """Labels (tp + fp) the sequential design needs to pass `bar` with `fp` FPs."""
    return tp_needed(fp, bar, alpha) + fp


def lower_bound(tp: int, fp: int, alpha: float) -> float:
    """Lower end of the confidence sequence: the largest grid q (step 1e-4)
    such that every grid r <= q is rejected. 0.0 when nothing is."""
    if tp + fp == 0:
        return 0.0
    thr = math.log(1 / alpha)
    last = 0.0
    for i in range(1, _GRID):
        q = i / _GRID
        if log_mixture(tp, fp, q) < thr:
            break
        last = q
    return last


def sprt_llr(tp: int, fp: int, p0: float, p1: float) -> float:
    """Wald's log-likelihood ratio of H1 (p = p1) over H0 (p = p0)."""
    return tp * math.log(p1 / p0) + fp * math.log((1 - p1) / (1 - p0))


def sprt_fails(tp: int, fp: int, cfg: dict) -> bool:
    return sprt_llr(tp, fp, cfg["p0"], cfg["p1"]) <= math.log(cfg["beta"])


def reachable(tp: int, fp: int, remaining: int | None, bar: float, alpha: float) -> bool:
    """Could `bar` still be passed if every one of `remaining` labels were tp?
    `remaining=None` means unbounded."""
    if remaining is None:
        return True
    rem = max(0, remaining)
    if tp + rem >= tp_needed(fp, bar, alpha):
        return True
    w = wilson_lower(tp + rem, tp + rem + fp)
    return w is not None and w >= bar


def wilson_lower(k: int, n: int, z: float = 1.959964) -> float | None:
    """The ledger's fixed-size Wilson lower bound (arbiter.precision.wilson)."""
    from arbiter.precision import wilson
    w = wilson(k, n, z)
    return None if w is None else w[0]


def decide(tp: int, fp: int, cfg: dict | None = None, remaining: int | None = None) -> dict:
    """The sequential state of one rule from its held-out tp and fp counts.

    Returns {state, reason, stop, lower, n, tp, fp, basis}; `basis` is
    "budget" for a futility fail (the plan is too small to show 0.97, which is
    not a measurement of the rule) and "measured" otherwise. `stop` is True when labelling
    this rule further cannot change what it can claim: pass-0.99, fail, or a
    pass at 0.97 when 0.99 is out of reach of the remaining plan."""
    cfg = validate(cfg or {})
    a = cfg["alpha"]
    lower = lower_bound(tp, fp, a)
    out = {"n": tp + fp, "tp": tp, "fp": fp, "lower": round(lower, 4), "basis": "measured"}
    can99 = reachable(tp, fp, remaining, 0.99, a)
    if rejects(tp, fp, 0.99, a):
        return {**out, "state": "pass-0.99", "reason": "anytime-valid lower bound >= 0.99", "stop": True}
    if sprt_fails(tp, fp, cfg):
        return {**out, "state": "fail",
                "reason": f"SPRT: evidence for p <= {cfg['p0']} over p >= {cfg['p1']}", "stop": True}
    if rejects(tp, fp, 0.97, a):
        return {**out, "state": "pass-0.97", "reason": "anytime-valid lower bound >= 0.97"
                + ("" if can99 else "; 0.99 cannot be reached"), "stop": not can99}
    if not reachable(tp, fp, remaining, 0.97, a):
        return {**out, "state": "fail", "reason": "cannot reach 0.97 even if every remaining label is tp",
                "stop": True, "basis": "budget"}
    return {**out, "state": "continue", "reason": "undecided", "stop": False}


def wilson_fixed_n(fp: int, bar: float, z: float) -> int:
    """Labels a single, fixed-size Wilson bound at `z` needs to reach `bar`
    with `fp` false positives (the comparison column, valid for one look)."""
    n = fp + 1
    while True:
        k = n - fp
        p = k / n
        den = 1 + z * z / n
        centre = (p + z * z / (2 * n)) / den
        half = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n))) / den
        if centre - half >= bar:
            return n
        n += 1


def label_count_table(fps=(0, 1, 2), bars=BARS, batch: int = 25) -> list[dict]:
    """The comparison table of docs/precision.md, computed rather than typed."""
    rows = []
    for bar in bars:
        for fp in fps:
            s05 = labels_needed(fp, bar, 0.05)
            rows.append({"bar": bar, "fp": fp,
                         "wilson_975": wilson_fixed_n(fp, bar, 1.959964),
                         "wilson_95": wilson_fixed_n(fp, bar, 1.644854),
                         "seq_05": s05, "seq_05_batched": -(-s05 // batch) * batch,
                         "seq_025": labels_needed(fp, bar, 0.025)})
    return rows


def stop_state(tp: int, fp: int, cfg: dict, remaining: int | None = None) -> str | None:
    """The state `decide` would stop on, or None to continue -- the same
    rules through the integer thresholds only, fast enough for simulation."""
    a = cfg["alpha"]
    if tp >= tp_needed(fp, 0.99, a):
        return "pass-0.99"
    if sprt_fails(tp, fp, cfg):
        return "fail"
    if remaining is not None:
        if tp >= tp_needed(fp, 0.97, a) and not reachable(tp, fp, remaining, 0.99, a):
            return "pass-0.97"
        if not reachable(tp, fp, remaining, 0.97, a):
            return "fail"
    return None


def simulate(p: float, runs: int, seed: int, cfg: dict | None = None,
             max_labels: int = 2000, population: int | None = None) -> dict:
    """Run the sequential design `runs` times on a rule of true precision `p`.

    Labels are drawn in batches; each run stops on `stop_state` or at
    `max_labels` (the fixed plan). With `population`, each run first draws a
    finite population of that size at rate `p` and then labels it without
    replacement, as a real per-rule plan does. Returns counts per final
    state and the mean labels used. Seeded, so deterministic."""
    import random
    cfg = validate(cfg or {})
    rng = random.Random(seed)
    states = {s: 0 for s in ("pass-0.99", "pass-0.97", "fail", "continue")}
    used = 0
    b = cfg["batch"]
    for _ in range(runs):
        if population is not None:
            plan = [rng.random() < p for _ in range(population)]
            limit = population
        else:
            plan, limit = None, max_labels
        tp = fp = n = 0
        state = None
        while n < limit and state is None:
            for _ in range(min(b, limit - n)):
                ok = plan[n] if plan is not None else rng.random() < p
                tp, fp, n = tp + ok, fp + (not ok), n + 1
            state = stop_state(tp, fp, cfg, limit - n if plan is not None else None)
        if state is None:
            state = "pass-0.97" if tp >= tp_needed(fp, 0.97, cfg["alpha"]) else "continue"
        states[state] += 1
        used += n
    return {"p": p, "runs": runs, **states, "mean_labels": round(used / runs, 1)}


def ledger_status(rules: dict, cfg: dict | None = None) -> dict[str, dict]:
    """The sequential state of every ledger rule with held-out labels, from
    its held-out tp / fp only (the ledger's `held_out` block). `remaining` is
    the rule's held-out population less what is already labelled, so a rule
    whose whole held-out population cannot reach 0.97 shows "fail" (cannot
    reach). Reported beside admission, which it does not change."""
    out = {}
    for name in sorted(rules):
        e = rules[name] or {}
        ho = e.get("held_out") or {}
        tp, fp, uns = int(ho.get("tp", 0)), int(ho.get("fp", 0)), int(ho.get("unsure", 0))
        if tp + fp == 0:
            continue
        pop = e.get("held_out_population")
        remaining = None if not isinstance(pop, int) or pop <= 0 else max(0, pop - tp - fp - uns)
        out[name] = {**decide(tp, fp, cfg, remaining), "remaining": remaining,
                     "admitted": bool(e.get("admitted"))}
    return out


def render_status(status: dict[str, dict], cfg: dict | None = None) -> str:
    """The `precision_ledger.py report` section: one line per rule."""
    c = validate(cfg or {})
    lines = [f"Sequential status (ARB-170; held-out labels only; {c['method']}, alpha={c['alpha']}, "
             f"beta={c['beta']}, SPRT p0={c['p0']} p1={c['p1']}). Beside admission; changes nothing.",
             f"{'rule':<56} {'TP':>5} {'FP':>4} {'left':>6} {'lower':>7}  {'state':<10} {'basis':<8} admitted"]
    for name, d in status.items():
        left = "-" if d["remaining"] is None else str(d["remaining"])
        lines.append(f"{name:<56} {d['tp']:>5} {d['fp']:>4} {left:>6} {d['lower']:>7.4f}  "
                     f"{d['state']:<10} {d['basis']:<8} {'yes' if d['admitted'] else 'no'}")
    counts: dict[str, int] = {}
    for d in status.values():
        counts[d["state"]] = counts.get(d["state"], 0) + 1
    budget = sum(1 for d in status.values() if d["basis"] == "budget")
    lines.append("states: " + ", ".join(f"{k} {counts.get(k, 0)}" for k in STATES)
                 + f" ({budget} of the fails only because too few held-out findings remain)")
    return "\n".join(lines)
