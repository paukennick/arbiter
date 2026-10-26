"""Multiple-comparison control for rule admission (ARB-171, plan item D9).

## What it guards against

Every labelled rule is tested against the bar on its own: a Wilson 95% lower
bound of at least 0.97 admits it, 0.99 lets it stand alone without a model
check. Each test, taken alone, lets a rule whose true precision is *at* the
bar through about 2.5% of the time. With a hundred such tests some rule will
pass by luck. This module says how many of today's passes survive once the
whole set of tests is taken into account, and records that beside the
current result. It changes no admission: `precision.admission` still
decides, until Nick switches the gate to read this.

## The test

Each rule is a one-sided test of H0: precision <= bar against H1:
precision > bar, at each bar (`rule_lower` 0.97 and `offline_lower` 0.99).
The p-value is the exact binomial tail P(X >= tp | n, bar): the chance of at
least this many true positives out of `n` decided labels if the rule were
exactly at the bar (the least favourable point of H0, so the test is valid
for every precision below it too).

This is the test the Clopper--Pearson interval inverts: p <= a exactly when
the one-sided Clopper--Pearson lower bound at level a is >= the bar. The
ledger's bound is Wilson, which is not exact and sits slightly above
Clopper--Pearson near 1, so a rule can pass the Wilson bar and miss the
exact test at the same level (or, rarely, the reverse). The exact test is
used here because a p-value is what Holm and Benjamini--Hochberg adjust,
and only the exact one guarantees its own level.

The level is one-sided `ALPHA` = 0.025: the share of the two-sided 95%
Wilson interval that lies below the lower bound. A family of one rule is
therefore held to exactly today's per-rule level, and the adjustment only
ever tightens. It is fixed here, before any result was read; it is not a
tuning knob.

## The family

A guarantee is only as good as the set it covers, and a set chosen after
looking at the results is itself a form of peeking. So the family is fixed
by a rule that reads no outcome:

* every rule in the ledger with at least `rule_min_n` decided **held-out**
  labels -- every rule with enough held-out evidence to be a candidate for
  admission, whatever its result and whether or not it is declared
  verified;
* overall (one family over every language), and per language (the rules
  with a labelled stratum in that language, as the per-language tier claim
  groups them; a rule in three languages is in three language families).

The counts a rule is tested on are the counts admission reads today (every
decided label, development and held-out), so "passes under Holm" means
today's decision, corrected. Development labels were looked at while the
rules were tuned, which favours the rule; the held-out-only result is
therefore reported beside it as a sensitivity check (`held_out`). Which of
the two the gate should read is Nick's decision.

A rule admitted today but outside the family (fewer held-out labels than
`rule_min_n`) carries no family-wide guarantee; it is listed under
`outside_family` rather than silently tested.

## The methods

* **Holm** (step-down Bonferroni) controls the family-wise error rate: the
  chance that *any* rule at or below the bar is admitted is <= ALPHA, under
  any dependence between the rules.
* **Benjamini--Hochberg** controls the false discovery rate: the expected
  *share* of admitted rules that are really below the bar is <= Q. That
  holds when the p-values are independent or positively dependent (PRDS).
  Rules labelled on the same repositories by the same labellers are plausibly
  positively dependent, but it is not proven.
* **Benjamini--Yekutieli** is BH with Q divided by 1 + 1/2 + ... + 1/m; it
  controls the FDR under *any* dependence, at a cost in power. It is the
  conservative variant to use if the PRDS assumption is not accepted.

The equivalent lower bounds: `lower_bonferroni` is the Clopper--Pearson
lower bound at level ALPHA/m (a rule passes Bonferroni exactly when it is
>= the bar); `lower_holm` is the bound at the level Holm gives the rule at
its rank, ALPHA/(m - rank + 1). Holm's pass also needs every rule ranked
before it to pass, which the adjusted p-value already accounts for.

## Hooks

`counts_for` is the one place a rule's (k, n) is read. Dawid--Skene label
estimates and the repository-clustering design effect (D4/D10, r7-stats)
replace it: pass `counts=` to `family_block`. Effective sizes that are not
integers need the regularised incomplete beta in place of `binom_sf`'s
term sum; `binom_sf` refuses them rather than rounding. A sequential test
(D1, r7-seq) spends each rule's share of the family level across its looks:
Holm/Bonferroni give rule i the level ALPHA/m (ALPHA/(m - rank + 1) under
Holm), and the rule's alpha-spending function spends that share, never
ALPHA itself; for BH, feed the sequential test's always-valid p-values into
`bh` (or e-values into e-BH). See docs/precision.md.

Pure and deterministic: no randomness, fixed bisection steps, rounded output.
"""
from __future__ import annotations

import math
from typing import Callable, Iterable

ALPHA = 0.025          # one-sided family-wise level (Holm)
Q = 0.025              # false discovery rate (BH, BY)
BARS = ("rule_lower", "offline_lower")
METHODS = ("holm", "bh", "by")
_BISECT_STEPS = 60


# ---------------------------------------------------------------------------
# Exact binomial test
# ---------------------------------------------------------------------------

def _int(x, name: str) -> int:
    if isinstance(x, bool) or int(x) != x:
        raise ValueError(f"{name}={x!r}: the exact tail needs whole counts; an effective "
                         "(non-integer) size needs the incomplete beta")
    return int(x)


def binom_sf(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p), summed term by term in log space."""
    k, n = _int(k, "k"), _int(n, "n")
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    lp, lq = math.log(p), math.log1p(-p)
    base = math.lgamma(n + 1)
    logs = [base - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
            for i in range(k, n + 1)]
    top = max(logs)
    return min(1.0, math.exp(top) * math.fsum(math.exp(v - top) for v in logs))


def p_value(k: int, n: int, bar: float) -> float:
    """One-sided exact p-value of H0: precision <= bar, from k TP in n."""
    if n <= 0:
        return 1.0
    return binom_sf(k, n, bar)


def cp_lower(k: int, n: int, level: float) -> float:
    """One-sided Clopper--Pearson lower bound at `level`: the p at which
    P(X >= k | n, p) = level (0 when k is 0). Bisection, fixed steps."""
    if n <= 0 or k <= 0:
        return 0.0
    if k == n:
        return level ** (1.0 / n)
    lo, hi = 0.0, 1.0
    for _ in range(_BISECT_STEPS):
        mid = (lo + hi) / 2
        if binom_sf(k, n, mid) > level:
            hi = mid
        else:
            lo = mid
    return lo


# ---------------------------------------------------------------------------
# Adjustments -- each returns adjusted p-values in the input order
# ---------------------------------------------------------------------------

def _order(ps: list[float], keys: list[str] | None) -> list[int]:
    keys = keys or [f"{i:09d}" for i in range(len(ps))]
    return sorted(range(len(ps)), key=lambda i: (ps[i], keys[i]))


def holm(ps: list[float], keys: list[str] | None = None) -> list[float]:
    m = len(ps)
    out = [1.0] * m
    run = 0.0
    for rank, i in enumerate(_order(ps, keys)):
        run = max(run, min(1.0, (m - rank) * ps[i]))
        out[i] = run
    return out


def bh(ps: list[float], keys: list[str] | None = None, scale: float = 1.0) -> list[float]:
    m = len(ps)
    out = [1.0] * m
    order = _order(ps, keys)
    run = 1.0
    for rank in range(m - 1, -1, -1):
        i = order[rank]
        run = min(run, min(1.0, scale * m * ps[i] / (rank + 1)))
        out[i] = run
    return out


def by(ps: list[float], keys: list[str] | None = None) -> list[float]:
    return bh(ps, keys, scale=sum(1.0 / j for j in range(1, len(ps) + 1)))


ADJUST: dict[str, Callable] = {"holm": holm, "bh": bh, "by": by}
LEVEL = {"holm": ALPHA, "bh": Q, "by": Q}


def holm_ranks(ps: list[float], keys: list[str] | None = None) -> list[int]:
    """1-based rank of each p-value in the Holm order."""
    out = [0] * len(ps)
    for rank, i in enumerate(_order(ps, keys)):
        out[i] = rank + 1
    return out


# ---------------------------------------------------------------------------
# Family
# ---------------------------------------------------------------------------

def counts_for(entry: dict, basis: str = "all") -> tuple[int, int]:
    """(TP, TP+FP) a rule is tested on. `all`: every decided label, as
    admission reads today; `held_out`: held-out labels only. The hook for
    Dawid--Skene / clustered estimates (pass a replacement as `counts=`)."""
    if basis == "held_out":
        h = entry.get("held_out") or {}
        tp, fp = int(h.get("tp", 0)), int(h.get("fp", 0))
    else:
        tp, fp = int(entry.get("tp", 0)), int(entry.get("fp", 0))
    return tp, tp + fp


def in_family(entry: dict, bar: dict) -> bool:
    """Fixed before looking: enough held-out labels to be a candidate."""
    return counts_for(entry, "held_out")[1] >= int(bar["rule_min_n"])


def rule_languages(entry: dict) -> list[str]:
    return sorted({s.get("language") or "-" for s in entry.get("strata") or []})


def _sig(x: float) -> float:
    return float(f"{x:.6g}")


def run_family(rows: dict[str, tuple[int, int]], bar_value: float) -> dict[str, dict]:
    """Per rule: raw p, adjusted p and pass under each method, and the
    adjusted lower bounds, for one family {rule: (k, n)} at one bar."""
    names = sorted(rows)
    if not names:
        return {}
    m = len(names)
    ps = [p_value(*rows[r], bar_value) for r in names]
    adj = {meth: ADJUST[meth](ps, names) for meth in METHODS}
    ranks = holm_ranks(ps, names)
    out = {}
    for i, r in enumerate(names):
        k, n = rows[r]
        row = {"k": k, "n": n, "p": _sig(ps[i]), "pass_unadjusted": ps[i] <= ALPHA}
        for meth in METHODS:
            row[f"p_{meth}"] = _sig(adj[meth][i])
            row[f"pass_{meth}"] = adj[meth][i] <= LEVEL[meth]
        row["lower_unadjusted"] = round(cp_lower(k, n, ALPHA), 4)
        row["lower_bonferroni"] = round(cp_lower(k, n, ALPHA / m), 4)
        row["lower_holm"] = round(cp_lower(k, n, ALPHA / (m - ranks[i] + 1)), 4)
        out[r] = row
    return out


def _families(rules: dict[str, dict], bar: dict, basis: str,
              counts: Callable[[dict, str], tuple[int, int]]) -> dict:
    members = {r: e for r, e in rules.items() if in_family(e, bar)}
    langs: dict[str, list[str]] = {}
    for r, e in members.items():
        for lang in rule_languages(e):
            langs.setdefault(lang, []).append(r)
    out = {}
    for key in BARS:
        b = float(bar[key])
        overall = run_family({r: counts(e, basis) for r, e in members.items()}, b)
        per_lang = {lang: run_family({r: counts(members[r], basis) for r in rs}, b)
                    for lang, rs in sorted(langs.items())}
        out[key] = {"bar": b, "m": len(overall), "overall": overall,
                    "languages": {lang: {"m": len(t), "rules": t} for lang, t in per_lang.items()}}
    return out


def survivors(tests: dict[str, dict], admitted: Iterable[str], method: str) -> list[str]:
    return sorted(r for r in admitted if r in tests and tests[r][f"pass_{method}"])


def family_block(rules: dict[str, dict], bar: dict,
                 language_claims: Callable[[dict], dict] | None = None,
                 counts: Callable[[dict, str], tuple[int, int]] = counts_for) -> dict:
    """The ledger's `multiplicity` key. `language_claims(rules) -> {lang:
    claim}` is the per-language tier claim; given it, the claim is
    recomputed with admission restricted to each method's survivors (on the
    overall family, at the admission bar) so the effect on each language's
    `claim` is visible. Admission itself is not changed."""
    admitted = sorted(r for r, e in rules.items() if e.get("admitted"))
    fam = _families(rules, bar, "all", counts)
    held = _families(rules, bar, "held_out", counts)
    overall = fam["rule_lower"]["overall"]
    admitted_in = [r for r in admitted if r in overall]
    block = {
        "about": "ARB-171: exact one-sided binomial test of H0 precision <= bar per rule, adjusted "
                 "over the family (rules with >= rule_min_n held-out labels), overall and per "
                 "language. Reported beside admission; admission is unchanged. docs/precision.md",
        "alpha": ALPHA, "q": Q, "test": "exact binomial, one-sided (Clopper-Pearson)",
        "family": "rules with >= rule_min_n decided held-out labels",
        "counts": "all decided labels (as admission); held_out = sensitivity",
        "admitted": admitted,
        "outside_family": sorted(set(admitted) - set(admitted_in)),
        "survive": {key: {meth: survivors(fam[key]["overall"], admitted_in, meth)
                          for meth in ("unadjusted",) + METHODS}
                    for key in BARS},
        "survive_by_language": {key: {lang: {meth: survivors(t["rules"], admitted_in, meth)
                                             for meth in ("unadjusted",) + METHODS}
                                      for lang, t in fam[key]["languages"].items()
                                      if any(r in t["rules"] for r in admitted_in)}
                                for key in BARS},
        "tests": fam,
        "held_out": {key: {"m": held[key]["m"],
                           "overall": {r: {f: t[f] for f in ("k", "n", "p", "p_holm", "p_bh",
                                                             "pass_unadjusted", "pass_holm", "pass_bh")}
                                       for r, t in held[key]["overall"].items()},
                           "survive": {meth: survivors(held[key]["overall"], admitted_in, meth)
                                       for meth in ("unadjusted",) + METHODS}}
                     for key in BARS},
    }
    if language_claims is not None:
        before = language_claims(rules)
        effect = {}
        for meth in METHODS:
            keep = set(block["survive"]["rule_lower"][meth])
            after = language_claims({r: {**e, "admitted": bool(e.get("admitted")) and r in keep}
                                     for r, e in rules.items()})
            effect[meth] = after
        block["language_claims"] = {
            lang: {"now": {"claim": c.get("claim"), "claim_lower": c.get("claim_lower"),
                           "rules_admitted": c.get("rules_admitted")},
                   **{meth: {"claim": effect[meth][lang].get("claim"),
                             "claim_lower": effect[meth][lang].get("claim_lower"),
                             "rules_admitted": effect[meth][lang].get("rules_admitted")}
                      for meth in METHODS}}
            for lang, c in before.items()
            if c.get("rules_admitted") or any(effect[m][lang].get("rules_admitted") for m in METHODS)}
    return block


def _p(x: float) -> str:
    return f"{x:.2e}" if x < 0.001 else f"{x:.4f}"


def render(block: dict) -> str:
    """The `report` section: one table per bar over the overall family."""
    if not block:
        return "multiple-comparison control: no `multiplicity` block in this ledger"
    lines = [f"multiple-comparison control (ARB-171; reported only, admission unchanged): "
             f"exact one-sided binomial, Holm at alpha {block['alpha']}, BH/BY at q {block['q']}",
             f"family: {block['family']}; counts: {block['counts']}"]
    for key in BARS:
        t = block["tests"][key]
        lines.append(f"bar {key} {t['bar']}  (overall family m = {t['m']})")
        lines.append(f"  {'rule':<46} {'TP/n':>10} {'p':>9} {'p_holm':>9} {'p_bh':>9} {'p_by':>9} "
                     f"{'lo_bonf':>7}  now holm bh by")
        for r, x in t["overall"].items():
            yn = lambda b: "yes" if b else "no"  # noqa: E731
            lines.append(f"  {r:<46} {x['k']:>5}/{x['n']:<4} {_p(x['p']):>9} {_p(x['p_holm']):>9} "
                         f"{_p(x['p_bh']):>9} {_p(x['p_by']):>9} {x['lower_bonferroni']:>7.4f}  "
                         f"{yn(x['pass_unadjusted']):>3} {yn(x['pass_holm']):>4} {yn(x['pass_bh']):>2} "
                         f"{yn(x['pass_by']):>2}")
        s = block["survive"][key]
        lines.append(f"  admitted today ({len(block['admitted'])}) that pass: "
                     + "; ".join(f"{m} {', '.join(s[m]) or 'none'}" for m in ("unadjusted",) + METHODS))
        for lang, sl in block["survive_by_language"][key].items():
            m_lang = block["tests"][key]["languages"][lang]["m"]
            lines.append(f"  within {lang} only (m = {m_lang}): "
                         + "; ".join(f"{m} {', '.join(sl[m]) or 'none'}" for m in ("unadjusted",) + METHODS))
        h = block["held_out"][key]["survive"]
        lines.append(f"  held-out labels only (sensitivity): "
                     + "; ".join(f"{m} {', '.join(h[m]) or 'none'}" for m in ("unadjusted",) + METHODS))
    if block.get("outside_family"):
        lines.append(f"admitted but outside the family (no family-wide guarantee): "
                     f"{', '.join(block['outside_family'])}")
    lc = block.get("language_claims")
    if lc:
        lines.append("per-language 99% claim if admission read each method (overall family, bar rule_lower):")
        for lang, c in lc.items():
            def cell(d):
                lo = "-" if d["claim_lower"] is None else f"{d['claim_lower']:.4f}"
                return f"{'yes' if d['claim'] else 'no'} ({d['rules_admitted']} rule(s), lower {lo})"
            lines.append(f"  {lang:<12} now {cell(c['now'])}; "
                         + "; ".join(f"{m} {cell(c[m])}" for m in METHODS))
    return "\n".join(lines)
