"""Capture-recapture: how many real defects no detector found (ARB-172, D6).

Arbiter has no human audit, so its catch rate on real code was measurable only
on benchmarks whose answers are known. Capture-recapture borrows the wildlife
census trick: if two independent detectors each find many of the same confirmed
defects, few remain that both missed; if they rarely overlap, many do. The
overlap gives an estimate N-hat of the total, and found / N-hat is a catch rate.

Three pieces, all pure Python (the package's runtime dependencies are PyYAML
and tomli; nothing here needs numpy):

* `family_of` / `cluster_sites` -- when two detectors' findings are the same
  defect: same repository, same file, same CWE family, and lines within a
  tolerance of the site's first line (anchored, so matching is not transitive
  and every detector gets at most one capture per site).
* Estimators: Lincoln-Petersen with Chapman's correction (two detectors),
  Chao's lower bound from f1/f2 (incidence form), and log-linear Poisson
  models with pairwise detector interactions chosen by AIC (Rcapture-style),
  with profile-likelihood intervals; `bootstrap_ci` resamples repositories.
* `simulate` -- populations with a known total, independent or positively
  correlated detectors, for the tests and the documented bias.

Every estimate here assumes each detector looked at the whole population. The
detectors share pattern ideas (they were written from the same CWE lists), so
a defect one finds is more likely to be found by another: positive dependence,
which pushes N-hat DOWN. Read N-hat as a floor on the total and N-hat minus
found as a floor on what was missed.
"""
from __future__ import annotations

import fnmatch
import math
import random
from itertools import combinations
from typing import Callable, Iterable, Sequence

Z95 = 1.959963984540054
CHI2_95 = 3.841458820694124  # chi-square, 1 df, 0.95

# ---------------------------------------------------------------------------
# CWE families. A finding belongs to one family; rule-level overrides come
# first because tools disagree on which CWE to stamp (Bandit files its XML
# parser checks under CWE-20; the defect they mean is XXE, CWE-611).
# ---------------------------------------------------------------------------

FAMILIES: dict[str, frozenset[str]] = {
    "sql-injection": frozenset({"CWE-89", "CWE-564"}),
    "command-injection": frozenset({"CWE-78", "CWE-77", "CWE-88"}),
    "code-injection": frozenset({"CWE-94", "CWE-95"}),
    "deserialization": frozenset({"CWE-502"}),
    "path-traversal": frozenset({"CWE-22", "CWE-23", "CWE-36", "CWE-73"}),
    "xss": frozenset({"CWE-79", "CWE-80", "CWE-81", "CWE-83"}),
    "xxe": frozenset({"CWE-611", "CWE-776"}),
    "weak-crypto": frozenset({"CWE-326", "CWE-327", "CWE-328", "CWE-916"}),
    "weak-random": frozenset({"CWE-330", "CWE-338"}),
    "ssrf": frozenset({"CWE-918"}),
    "open-redirect": frozenset({"CWE-601"}),
    "insecure-cookie": frozenset({"CWE-614", "CWE-1004"}),
    "tls-verification": frozenset({"CWE-295"}),
    "hardcoded-secret": frozenset({"CWE-798", "CWE-259", "CWE-321"}),
    "info-exposure": frozenset({"CWE-209", "CWE-497", "CWE-215"}),
    "ldap-injection": frozenset({"CWE-90"}),
    "xpath-injection": frozenset({"CWE-643"}),
    "trust-boundary": frozenset({"CWE-501"}),
    "integer-overflow": frozenset({"CWE-190", "CWE-191"}),
}

# (detector, rule glob) -> family. Checked before the CWE table.
RULE_FAMILIES: list[tuple[str, str, str]] = [
    ("*", "*http-no-timeout*", "missing-timeout"),
    ("*", "*request*-without-timeout*", "missing-timeout"),
    ("*", "*no-timeout*", "missing-timeout"),
    ("bandit", "bandit/B113", "missing-timeout"),
    ("semgrep", "*use-timeout", "missing-timeout"),   # python/requests/best-practice
    ("*", "*mutable-action-tag*", "unpinned-action"),
    ("bandit", "bandit/B31[3-9]", "xxe"),
    ("bandit", "bandit/B320", "xxe"),
    ("bandit", "bandit/B40[5-9]", "xxe"),
    ("bandit", "bandit/B410", "xxe"),
    ("bandit", "bandit/B10[2]", "code-injection"),   # exec: Bandit says CWE-78
    ("bandit", "bandit/B307", "code-injection"),
    ("*", "*unpinned-action*", "unpinned-action"),
    ("*", "*third-party-action-not-pinned*", "unpinned-action"),
]

_BY_CWE = {c: fam for fam, cwes in FAMILIES.items() for c in cwes}


def family_of(detector: str, rule: str, cwes: Iterable[str]) -> str | None:
    """The one CWE family a finding is about, or None when it is about none.

    Rule overrides win; otherwise the lowest-numbered CWE that has a family
    (sorted, so the answer never depends on the order a tool lists them)."""
    for det, pat, fam in RULE_FAMILIES:
        if (det == "*" or det == detector) and fnmatch.fnmatchcase(rule, pat):
            return fam
    hits = sorted((int(c.split("-")[1]), _BY_CWE[c]) for c in cwes
                  if c in _BY_CWE and c.split("-")[1].isdigit())
    return hits[0][1] if hits else None


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

LINE_TOLERANCE = 3


def cluster_sites(findings: Sequence[dict], tolerance: int = LINE_TOLERANCE,
                  key: Callable[[dict], tuple] | None = None) -> list[dict]:
    """Group findings into defect sites.

    Each finding needs `detector`, `repo`, `path`, `line` and `family` (or
    whatever `key` reads). Findings with the same (repo, path, family) are
    sorted by line; a site opens at the first unassigned line and takes every
    finding within `tolerance` lines of that ANCHOR -- not of its nearest
    neighbour, so lines 10, 13, 16 at tolerance 3 are two sites, never one
    chain. A detector captures a site at most once however many of its
    findings fall in it.

    Returns sites sorted by (repo, path, family, anchor): each
    {repo, path, family, line, detectors: sorted list, members: [findings]}.
    """
    key = key or (lambda f: (f["repo"], f["path"], f["family"]))
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        groups.setdefault(key(f), []).append(f)
    sites = []
    for k in sorted(groups):
        rows = sorted(groups[k], key=lambda f: (int(f.get("line") or 0), f["detector"],
                                                f.get("rule", "")))
        i = 0
        while i < len(rows):
            anchor = int(rows[i].get("line") or 0)
            j = i
            while j < len(rows) and int(rows[j].get("line") or 0) - anchor <= tolerance:
                j += 1
            members = rows[i:j]
            sites.append({"key": k, "line": anchor,
                          "detectors": sorted({m["detector"] for m in members}),
                          "members": members})
            i = j
    return sites


def histories(sites: Iterable[dict], detectors: Sequence[str],
              weight: Callable[[dict], float] | None = None) -> dict[tuple[int, ...], float]:
    """Capture-history counts: (1,0,1) -> number of sites caught by detectors
    0 and 2 only. `weight` lets a sampled site stand for several (default 1)."""
    out: dict[tuple[int, ...], float] = {}
    for s in sites:
        h = tuple(1 if d in s["detectors"] else 0 for d in detectors)
        if any(h):
            out[h] = out.get(h, 0.0) + (weight(s) if weight else 1.0)
    return out


# ---------------------------------------------------------------------------
# Estimators. Each returns {"n_hat", "lo", "hi", "observed", "method", ...};
# `hi` is math.inf when the data cannot bound the total.
# ---------------------------------------------------------------------------

def _lognormal_ci(observed: float, n_hat: float, var: float) -> tuple[float, float]:
    """Chao (1987) interval: log-normal on the unseen part f0 = N - S, so the
    lower end never drops below what was actually seen."""
    f0 = n_hat - observed
    if f0 <= 1e-9 or var <= 0:
        return observed, max(observed, n_hat)
    c = math.exp(Z95 * math.sqrt(math.log(1 + var / f0 ** 2)))
    return observed + f0 / c, observed + f0 * c


def chapman(n1: float, n2: float, m: float) -> dict:
    """Lincoln-Petersen with Chapman's correction, two detectors.

    n1, n2: sites each found; m: sites both found. Nearly unbiased for
    independent detectors when n1 + n2 >= N (Chapman 1951); with m = 0 the
    point estimate exists but the data put no upper bound on N."""
    s = n1 + n2 - m
    n_hat = (n1 + 1) * (n2 + 1) / (m + 1) - 1
    var = (n1 + 1) * (n2 + 1) * (n1 - m) * (n2 - m) / ((m + 1) ** 2 * (m + 2))
    lo, hi = _lognormal_ci(s, n_hat, var)
    if m == 0:
        hi = math.inf
    return {"method": "chapman", "n_hat": n_hat, "lo": lo, "hi": hi, "observed": s,
            "se": math.sqrt(var)}


def chao_lower_bound(hist: dict[tuple[int, ...], float]) -> dict:
    """Chao's lower bound, incidence form (detectors are the occasions).

    N >= S + ((t-1)/t) * f1^2 / (2 f2), f1/f2 = sites caught by exactly one /
    exactly two detectors (Chao 1987; Chao et al. 2014 for the (t-1)/t
    factor). It holds under heterogeneity between defects, which is why it is
    a lower bound rather than an estimate. Bias-corrected form when f2 = 0."""
    t = len(next(iter(hist))) if hist else 2
    s = sum(hist.values())
    f1 = sum(v for h, v in hist.items() if sum(h) == 1)
    f2 = sum(v for h, v in hist.items() if sum(h) == 2)
    a = (t - 1) / t
    if f2 > 0:
        n_hat = s + a * f1 * f1 / (2 * f2)
        r = f1 / f2
        var = f2 * (a / 2 * r ** 2 + a * a * r ** 3 + a * a / 4 * r ** 4)
    else:
        n_hat = s + a * f1 * max(f1 - 1, 0) / 2
        var = (a * f1 * (f1 - 1) / 2 + a * a * f1 * (2 * f1 - 1) ** 2 / 4
               - a * a * f1 ** 4 / 4 / max(n_hat, 1e-9)) if f1 > 1 else 0.0
        var = max(var, 0.0)
    lo, hi = _lognormal_ci(s, n_hat, var)
    return {"method": "chao", "n_hat": n_hat, "lo": lo, "hi": hi, "observed": s,
            "f1": f1, "f2": f2, "se": math.sqrt(var)}


# --- Log-linear models ------------------------------------------------------

def _solve(a: list[list[float]], b: list[float]) -> list[float] | None:
    """Gaussian elimination with partial pivoting; None if singular."""
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(m[r][c]))
        if abs(m[p][c]) < 1e-12:
            return None
        m[c], m[p] = m[p], m[c]
        for r in range(c + 1, n):
            f = m[r][c] / m[c][c]
            if f:
                for k in range(c, n + 1):
                    m[r][k] -= f * m[c][k]
    x = [0.0] * n
    for r in range(n - 1, -1, -1):
        x[r] = (m[r][n] - sum(m[r][k] * x[k] for k in range(r + 1, n))) / m[r][r]
    return x


def _poisson_fit(rows: list[list[float]], y: list[float], iters: int = 100) -> list[float] | None:
    """Poisson GLM, log link, by iteratively reweighted least squares."""
    """Zero cells (common: benchmarks' detectors often agree on everything)
    put the maximum at the boundary, a parameter heading to minus infinity.
    The fitted means there go to zero, which is the right answer, so the
    linear predictor is clamped at -30 (mean ~1e-13) and the fit stops when
    the deviance stops changing rather than when the parameters do. A tiny
    ridge keeps the weighted cross-product invertible at that boundary."""
    k = len(rows[0])
    mean = max(sum(y) / len(y), 0.5)
    beta = [math.log(mean)] + [0.0] * (k - 1)
    prev = math.inf
    for _ in range(iters):
        eta = [min(max(sum(b * x for b, x in zip(beta, r)), -30.0), 700.0) for r in rows]
        mu = [math.exp(e) for e in eta]
        dev = sum((yi * math.log(yi / m) if yi > 0 else 0.0) - (yi - m) for yi, m in zip(y, mu))
        if abs(prev - dev) < 1e-9:
            return beta
        prev = dev
        z = [e + (yi - m) / m for e, yi, m in zip(eta, y, mu)]
        xtwx = [[sum(m * r[i] * r[j] for m, r in zip(mu, rows)) + (1e-9 if i == j else 0.0)
                 for j in range(k)] for i in range(k)]
        xtwz = [sum(m * r[i] * zi for m, r, zi in zip(mu, rows, z)) for i in range(k)]
        new = _solve(xtwx, xtwz)
        if new is None:
            return None
        beta = [max(min(b, 700.0), -700.0) for b in new]
    return beta


def _design(h: tuple[int, ...], pairs: Sequence[tuple[int, int]]) -> list[float]:
    return [1.0] + [float(x) for x in h] + [float(h[i] * h[j]) for i, j in pairs]


def _all_cells(t: int) -> list[tuple[int, ...]]:
    return [tuple((c >> (t - 1 - i)) & 1 for i in range(t)) for c in range(2 ** t)]


def _loglinear_point(hist: dict, t: int, pairs) -> dict | None:
    cells = [h for h in _all_cells(t) if any(h)]
    y = [hist.get(h, 0.0) for h in cells]
    rows = [_design(h, pairs) for h in cells]
    if len(rows[0]) > len(rows):
        return None
    beta = _poisson_fit(rows, y)
    if beta is None:
        return None
    mu = [math.exp(sum(b * x for b, x in zip(beta, r))) for r in rows]
    ll = sum((yi * math.log(m) if yi > 0 else 0.0) - m - math.lgamma(yi + 1) for yi, m in zip(y, mu))
    f0 = math.exp(beta[0])
    return {"beta": beta, "f0": f0, "loglik": ll, "aic": -2 * ll + 2 * len(beta)}


def _profile_loglik(hist: dict, t: int, pairs, n: float) -> float:
    """Multinomial log-likelihood of the full table with N = n, the model refit
    with the unseen cell set to n - S (Cormack 1992)."""
    s = sum(hist.values())
    cells = _all_cells(t)
    y = [hist.get(h, 0.0) if any(h) else n - s for h in cells]
    rows = [_design(h, pairs) for h in cells]
    beta = _poisson_fit(rows, y)
    if beta is None:
        return -math.inf
    ll = math.lgamma(n + 1) - math.lgamma(n - s + 1)
    for yi, r in zip(y, rows):
        if yi > 0:
            mu = math.exp(sum(b * x for b, x in zip(beta, r)))
            ll += yi * math.log(mu / n)
    return ll


def _profile_ci(hist: dict, t: int, pairs, n_hat: float, cap: float) -> tuple[float, float]:
    s = sum(hist.values())
    peak_n = max(n_hat, s + 1e-6)
    peak = _profile_loglik(hist, t, pairs, peak_n)
    cut = peak - CHI2_95 / 2

    def below(n: float) -> bool:
        return _profile_loglik(hist, t, pairs, n) < cut

    def bisect(a: float, b: float) -> float:   # a inside, b outside
        for _ in range(40):
            mid = (a + b) / 2
            if below(mid):
                b = mid
            else:
                a = mid
        return (a + b) / 2

    lo = s if not below(s + 1e-6) else bisect(peak_n, s + 1e-6)
    hi_probe = peak_n
    while not below(hi_probe):
        hi_probe = s + (hi_probe - s) * 2 + 1
        if hi_probe > cap:
            return lo, math.inf
    return lo, bisect(peak_n, hi_probe)


def loglinear_models(hist: dict) -> list[dict]:
    """Every log-linear model from independence up to all pairwise detector
    interactions, sorted by AIC. The t-way interaction is never estimable
    (it is confounded with the unseen cell), so models stop at pairs; a model
    with as many parameters as observed cells has zero degrees of freedom and
    is fitted but is not distinguishable from the data by AIC alone."""
    t = len(next(iter(hist))) if hist else 0
    if t < 2:
        return []
    s = sum(hist.values())
    all_pairs = list(combinations(range(t), 2))
    out = []
    for r in range(len(all_pairs) + 1):
        for pairs in combinations(all_pairs, r):
            fit = _loglinear_point(hist, t, pairs)
            if fit is None:
                continue
            out.append({"method": "loglinear", "pairs": [list(p) for p in pairs],
                        "n_hat": s + fit["f0"], "observed": s, "aic": fit["aic"],
                        "df": (2 ** t - 1) - (1 + t + len(pairs))})
    out.sort(key=lambda m: (m["aic"], len(m["pairs"]), m["pairs"]))
    return out


def loglinear(hist: dict, cap_factor: float = 1000.0) -> dict | None:
    """The AIC-best log-linear model with at least one residual degree of
    freedom, with a profile-likelihood 95% interval. Ties go to the simpler
    model. None when no model could be fitted.

    Why not the zero-df model: with three detectors the all-pairs model fits
    the seven observed cells exactly, so AIC nearly always prefers it, and
    under the shared "this defect is easy" dependence detectors have it
    swings far HIGH (median 517 for a true 300 in the simulation the tests
    pin) with a huge spread. Restricted to df >= 1 the selected model is
    unbiased for independent detectors and biased low under dependence, so
    the result keeps one direction of error: a floor."""
    models = [m for m in loglinear_models(hist) if m["df"] >= 1]
    if not models:
        return None
    best = dict(models[0])
    t = len(next(iter(hist)))
    pairs = [tuple(p) for p in best["pairs"]]
    s = best["observed"]
    if best["n_hat"] > cap_factor * max(s, 1):
        best.update(lo=s, hi=math.inf, unstable=True)
    else:
        best["lo"], best["hi"] = _profile_ci(hist, t, pairs, best["n_hat"], cap_factor * max(s, 1))
    best["candidates"] = [{"pairs": m["pairs"], "aic": round(m["aic"], 3),
                           "n_hat": round(m["n_hat"], 2)} for m in models]
    return best


# ---------------------------------------------------------------------------
# Choice of estimator, catch rates, repository bootstrap
# ---------------------------------------------------------------------------

def two_way(hist: dict, i: int = 0, j: int = 1) -> dict:
    n1 = sum(v for h, v in hist.items() if h[i])
    n2 = sum(v for h, v in hist.items() if h[j])
    m = sum(v for h, v in hist.items() if h[i] and h[j])
    out = chapman(n1, n2, m)
    out.update(n1=n1, n2=n2, m=m)
    return out


def estimate(hist: dict) -> dict:
    """The pre-registered primary estimate: Chapman for two detectors, the
    AIC-best log-linear model for three or more (Chao reported beside it)."""
    t = len(next(iter(hist))) if hist else 0
    if t == 2:
        return two_way(hist)
    if t >= 3:
        ll = loglinear(hist)
        if ll is not None:
            return ll
        return chao_lower_bound(hist)
    raise ValueError("capture-recapture needs at least two detectors")


def catch_rate(found: float, est: dict) -> dict:
    """found / N-hat with the interval carried over from N-hat's interval
    (the bounds swap: a larger total means a lower catch rate)."""
    n = est["n_hat"]
    return {"found": found, "rate": found / n if n > 0 else None,
            "lo": found / est["hi"] if est["hi"] not in (0, math.inf) else 0.0,
            "hi": min(1.0, found / est["lo"]) if est["lo"] > 0 else None}


def bootstrap_ci(groups: Sequence[dict], stat: Callable[[dict], float], b: int = 400,
                 seed: str = "capture") -> tuple[float, float] | None:
    """Percentile 95% interval resampling whole repositories with replacement.

    `groups` is one capture-history dict per repository; `stat` maps a summed
    history to a number. Findings in one repository are not independent
    (D10), so the repository, not the site, is the unit resampled. Seeded by
    string so adding a stratum does not move another stratum's interval."""
    if len(groups) < 2:
        return None
    rng = random.Random(seed)
    vals = []
    for _ in range(b):
        tot: dict = {}
        for g in (groups[rng.randrange(len(groups))] for _ in groups):
            for h, v in g.items():
                tot[h] = tot.get(h, 0.0) + v
        if not tot:
            continue
        try:
            v = stat(tot)
        except (ValueError, ZeroDivisionError, OverflowError):
            continue
        if v is not None and math.isfinite(v):
            vals.append(v)
    if len(vals) < b // 2:
        return None
    vals.sort()
    return vals[int(0.025 * (len(vals) - 1))], vals[int(math.ceil(0.975 * (len(vals) - 1)))]


# ---------------------------------------------------------------------------
# Simulation (tests and the documented bias)
# ---------------------------------------------------------------------------

def simulate(n: int, probs: Sequence[float], seed: str, spread: float = 0.0) -> dict:
    """Capture histories for `n` defects and detectors with catch rates
    `probs`. spread = 0: independent detectors. spread > 0: every defect gets
    one shared 'easiness' (log-normal, sd `spread`) that scales every
    detector's chance -- the positive dependence shared pattern ideas create."""
    rng = random.Random(seed)
    hist: dict = {}
    for _ in range(n):
        ease = math.exp(rng.gauss(0, spread) - spread * spread / 2) if spread else 1.0
        h = tuple(1 if rng.random() < min(1.0, p * ease) else 0 for p in probs)
        if any(h):
            hist[h] = hist.get(h, 0) + 1
    return hist
