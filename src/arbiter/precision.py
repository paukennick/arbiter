"""Precision tiers: which findings may block a gate, on what evidence.

## Tiers

Every finding gets a `tier` and a one-line `tier_reason`:

* `verified`  -- gate-eligible. The rule is declared verified (rule metadata
  `tier: verified`, or `precision.verified_rules` in arbiter.yaml) **and**
  the precision ledger admits it (Wilson 95% lower bound >= 0.97 on >= 30
  labels, labeller kappa >= 0.8 where two labellers looked), **and** either
  the model verification pass confirmed this finding, or the profile cannot
  call a model and the rule's lower bound alone is >= 0.99.
* `advisory`  -- shown, never blocks a tiered gate. Everything else: a rule
  on probation, a rule below its bar, a finding the model rejected or was
  unsure of, a finding the model did not look at.
* `inferred`  -- found by a model (`provenance == "inferred"`).

The verdict is read from `finding.verification` (the verify pass) when it is
there, through `getattr`, so this module works with or without that pass.

## Ledger

`tools/gold/precision.json`, shipped as `packs/precision.json` so the gate
can read it at scan time. Built by `tools/precision_ledger.py` from label
files; see docs/precision.md for the label format. The ledger is evidence;
the declaration (`tier: verified`) is intent; the CI precision guard
(`tools/precision_guard.py`) fails when intent outruns evidence.

## Gate

`gate.tier_mode: tiered` (the default since ARB-100) gates only on findings
whose tier is in `gate.tiers` (default `[verified]`), so a build fails on
what the ledger has measured and on nothing else. `legacy` gates on
severity over every active finding, as before tiers; it is an explicit
opt-in. With an empty ledger a tiered gate blocks nothing, and the gate
block says so (`excluded_by_tier`).

## View

What a person is shown is a separate decision from what can block the
gate (ARB-100, ARB-103). `report.show: all` (the default since ARB-103)
renders every tier, verified first, then advisory, then inferred, each in a
labelled section, with one line of counts that says which tiers can block
the gate (`tier_line`). `verified` (or `--verified-only`) is an opt-in that
renders the verified tier only, with one line saying how many advisory and
inferred findings were left out. The report's top-level `tiers` block
(`view_block`) records which view was in force and the counts per tier;
report.json always carries every finding.

ARB-100 made `verified` the default. With one verified rule that hid nearly
everything Arbiter found, which defeats a tool whose job is to catch
mistakes; blocking (`gate.tier_mode`) and showing (`report.show`) are now
separate decisions (FAIL-071).
"""
from __future__ import annotations

import fnmatch
import json
import math
from pathlib import Path
from typing import Any, Iterable

Z95 = 1.959964
PACKAGED_LEDGER = Path(__file__).parent / "packs" / "precision.json"
VERDICTS_DEMOTE = ("rejected", "unsure")
DEFAULT_BAR = {
    "rule_lower": 0.97,      # a rule is admitted at this Wilson lower bound ...
    "rule_min_n": 30,        # ... on at least this many TP+FP labels
    "kappa_min": 0.8,        # two labellers must agree at least this well
    "offline_lower": 0.99,   # with no model check, the rule alone must reach this
    "tier_lower": 0.99,      # the claim: the verified tier's held-out lower bound
}
DETERMINISTIC_PROFILES = ("offline", "ci")


# ---------------------------------------------------------------------------
# Statistics -- pure
# ---------------------------------------------------------------------------

def wilson(k: float, n: float, z: float = Z95) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials (n may be an
    effective, non-integer sample size). None when n is 0."""
    if n <= 0:
        return None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n))) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def cohens_kappa(a: list[str], b: list[str]) -> float | None:
    if not a or len(a) != len(b):
        return None
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca: dict[str, int] = {}
    cb: dict[str, int] = {}
    for x in a:
        ca[x] = ca.get(x, 0) + 1
    for y in b:
        cb[y] = cb.get(y, 0) + 1
    pe = sum(ca.get(c, 0) * cb.get(c, 0) for c in set(ca) | set(cb)) / (n * n)
    if pe >= 1.0:
        return None
    return (po - pe) / (1 - pe)


class UnknownPopulation(ValueError):
    """A stratum has labels but no recorded population, so it cannot be
    weighted. The caller reports it; nothing here guesses one."""


def weighted_precision(strata: Iterable[dict]) -> dict | None:
    """Stratified (population-weighted) precision over strata
    {tp, fp, population}, with a Wilson interval on an effective sample size.

    Point estimate: p = sum_h W_h * p_h, where p_h = tp_h / n_h over the
    stratum's decided labels and W_h = N_h / N over the strata that have
    any. N_h is the number of findings the stratum's labels were drawn from.
    It must be recorded: a stratum with labels and no population raises
    `UnknownPopulation` (the label count is not a population), and one with
    fewer findings than labels is a data error.

    Interval: Wilson on an effective sample size n_eff, the smaller of
      * Kish's 1 / sum(W_h^2 / n_h), the loss from unequal weights, which
        stays defined when every stratum is all-TP, and
      * the design-based p(1-p) / V with V = sum W_h^2 p_h(1-p_h) / n_h,
        the stratified variance, which is smaller when a heavy stratum is
        both thinly labelled and less precise than the rest.
    Both equal n_h for one stratum, so one stratum gives its plain Wilson
    interval. No finite-population correction: the claim is about the rule
    on code like the corpus, not about these particular findings, so a
    census stratum still carries the sampling error of its n_h.
    """
    rows = [s for s in strata if (s.get("tp", 0) + s.get("fp", 0)) > 0]
    if not rows:
        return None
    pops = []
    for s in rows:
        n = s["tp"] + s["fp"]
        pop = s.get("population")
        if pop is None:
            raise UnknownPopulation(f"stratum {s.get('key', '?')} has {n} label(s) and no recorded population")
        if pop < n:
            raise ValueError(f"stratum {s.get('key', '?')}: population {pop} is below its {n} label(s)")
        pops.append(float(pop))
    total = sum(pops)
    ws = [w / total for w in pops]
    ns = [s["tp"] + s["fp"] for s in rows]
    ps = [s["tp"] / n for s, n in zip(rows, ns)]
    p = sum(w * q for w, q in zip(ws, ps))
    kish = 1.0 / sum(w * w / n for w, n in zip(ws, ns))
    var = sum(w * w * q * (1 - q) / n for w, q, n in zip(ws, ps, ns))
    n_eff = min(kish, p * (1 - p) / var) if var > 0 else kish
    lo, hi = wilson(p * n_eff, n_eff)
    tp, fp = sum(s["tp"] for s in rows), sum(s["fp"] for s in rows)
    return {"precision": round(p, 4), "wilson_lower": round(lo, 4), "wilson_upper": round(hi, 4),
            "n_eff": round(n_eff, 1), "n_eff_kish": round(kish, 1), "tp": tp, "fp": fp,
            "population": int(total), "strata": len(rows),
            "pooled": {"precision": round(tp / (tp + fp), 4),
                       "wilson_lower": round(wilson(tp, tp + fp)[0], 4)}}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

def empty_ledger() -> dict:
    return {"version": 1, "bar": dict(DEFAULT_BAR), "generated": "", "rules": {}, "tier": {}}


def load_ledger(path: str | Path | None = None) -> dict:
    """The ledger at `path`, else the packaged one, else an empty ledger.
    A ledger that cannot be read is an error, not an empty ledger: silently
    treating it as empty would demote every rule without saying why."""
    p = Path(path) if path else PACKAGED_LEDGER
    if not p.is_file():
        if path:
            raise RuntimeError(f"precision ledger {p} not found")
        return empty_ledger()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"could not read precision ledger {p}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules", {}), dict):
        raise RuntimeError(f"precision ledger {p}: expected a mapping with a `rules` mapping")
    out = empty_ledger()
    out.update(data)
    out["bar"] = {**DEFAULT_BAR, **(data.get("bar") or {})}
    return out


def admission(entry: dict | None, bar: dict) -> tuple[bool, str]:
    """Whether a ledger entry admits its rule, and why or why not. Computed
    from the counts, never read from the entry's own `admitted` flag."""
    if not entry:
        return False, "no ledger entry"
    tp, fp = int(entry.get("tp", 0)), int(entry.get("fp", 0))
    n = tp + fp
    if n < int(bar["rule_min_n"]):
        return False, f"{n} label(s), {bar['rule_min_n']} needed"
    lo = wilson(tp, n)[0]
    if lo < float(bar["rule_lower"]):
        return False, f"lower bound {lo:.3f} on {n} labels, below {bar['rule_lower']}"
    kappa = entry.get("kappa")
    if kappa is not None and float(kappa) < float(bar["kappa_min"]):
        return False, f"labeller kappa {float(kappa):.2f} below {bar['kappa_min']}"
    return True, f"lower bound {lo:.3f} on {n} labels"


def rule_lower(entry: dict | None) -> float:
    if not entry:
        return 0.0
    n = int(entry.get("tp", 0)) + int(entry.get("fp", 0))
    return wilson(int(entry.get("tp", 0)), n)[0] if n else 0.0


# ---------------------------------------------------------------------------
# Tier assignment
# ---------------------------------------------------------------------------

def _settings(config: dict | None) -> dict:
    return (config or {}).get("precision") or {}


def declared_verified(rule_id: str, config: dict | None) -> bool:
    from .rule_meta import declared_tier
    if declared_tier(rule_id) == "verified":
        return True
    return any(rule_id == g or fnmatch.fnmatch(rule_id, g)
               for g in _settings(config).get("verified_rules") or [])


def _verdict(f: Any) -> tuple[str, str]:
    v = getattr(f, "verification", None)
    if v is None and isinstance(f, dict):
        v = f.get("verification")
    if not isinstance(v, dict):
        return "", ""
    return str(v.get("verdict") or ""), str(v.get("reason") or "")


def tier_for(f: Any, ledger: dict, config: dict | None, profile: str) -> tuple[str, str]:
    """(tier, reason) for one finding. Pure apart from rule metadata."""
    from .rule_meta import ledger_key
    if getattr(f, "provenance", "") == "inferred":
        return "inferred", "found by a model: provenance inferred"
    rule = f.rule_id
    if not declared_verified(rule, config):
        return "advisory", "rule on probation: not declared verified"
    bar = ledger.get("bar") or DEFAULT_BAR
    entry = (ledger.get("rules") or {}).get(ledger_key(rule))
    ok, why = admission(entry, bar)
    if not ok:
        return "advisory", f"ledger does not admit the rule: {why}"
    verdict, reason = _verdict(f)
    if verdict == "confirmed":
        return "verified", f"ledger-admitted ({why}) and model-confirmed"
    if verdict in VERDICTS_DEMOTE:
        return "advisory", f"model {verdict}" + (f": {reason}" if reason else "")
    deterministic = _settings(config).get("deterministic_profiles") or DETERMINISTIC_PROFILES
    lo = rule_lower(entry)
    if profile in deterministic and lo >= float(bar["offline_lower"]):
        return "verified", (f"ledger lower bound {lo:.3f} >= {bar['offline_lower']} "
                            f"with no model check (profile {profile})")
    if profile in deterministic:
        return "advisory", (f"not model-verified, and lower bound {lo:.3f} is below the "
                            f"{bar['offline_lower']} a rule needs on its own")
    return "advisory", "not model-verified" + (f": {reason}" if reason else "")


def assign_tiers(findings: list, ledger: dict, config: dict | None, profile: str = "offline") -> dict:
    """Set `tier` and `tier_reason` on every finding; return the counts."""
    counts = {"verified": 0, "advisory": 0, "inferred": 0}
    for f in findings:
        f.tier, f.tier_reason = tier_for(f, ledger, config, profile)
        if not f.suppressed:
            counts[f.tier] = counts.get(f.tier, 0) + 1
    return counts


def annotate(findings: list, config: dict | None, profile: str) -> dict:
    """Requirements from rule metadata, then tiers. The summary goes into
    `report.scan_scope["tiers"]`."""
    from .rule_meta import requirements_of
    for f in findings:
        if not f.requirements:
            f.requirements = requirements_of(f.rule_id)
    ledger = load_ledger(_settings(config).get("ledger"))
    counts = assign_tiers(findings, ledger, config, profile)
    admitted = sorted(r for r, e in (ledger.get("rules") or {}).items()
                      if admission(e, ledger["bar"])[0])
    return {"counts": counts, "ledger_rules": len(ledger.get("rules") or {}),
            "admitted_rules": len(admitted), "ledger_generated": ledger.get("generated", "")}


SHOW_VERIFIED = "verified"
SHOW_ALL = "all"
TIER_ORDER = ("verified", "advisory", "inferred")


def shown_tiers(show: str) -> tuple[str, ...]:
    """The tiers a rendering lists under `show`."""
    return TIER_ORDER if show == SHOW_ALL else ("verified",)


def view_block(findings: list, show: str, failing: set | frozenset | tuple = ()) -> dict:
    """The report's top-level `tiers` block: which view the renderings use,
    the active count per tier, and what that view leaves out. `failing` is
    the gate's `failing_ids`: a finding that failed the gate is shown
    whatever its tier (report.py), so it is never counted as not shown.
    `not_shown` is empty under `all`; a reader who sees it non-empty knows
    the human-facing output was a subset of `findings`."""
    counts = {t: 0 for t in TIER_ORDER}
    hidden = {t: 0 for t in TIER_ORDER}
    listed = shown_tiers(show)
    for f in findings:
        if getattr(f, "suppressed", False):
            continue
        t = getattr(f, "tier", "") or "advisory"
        counts[t] = counts.get(t, 0) + 1
        if t not in listed and getattr(f, "id", None) not in failing:
            hidden[t] = hidden.get(t, 0) + 1
    active = sum(counts.values())
    return {
        "shown": show,
        "counts": counts,
        "shown_count": active - sum(hidden.values()),
        "not_shown": {t: n for t, n in hidden.items() if n},
    }


def gating_tiers(gate: dict | None) -> tuple[str, ...]:
    """The tiers whose findings can fail this gate block, in tier order.

    `tiered` (the default): the tiers in `gate.tiers`, inferred only when
    `gate_on_inferred` is also set. `legacy`: verified and advisory, and
    inferred under `gate_on_inferred`. A report with no gate block is read
    as the default gate (verified only)."""
    gate = gate or {}
    inferred = bool(gate.get("gate_on_inferred"))
    if gate.get("tier_mode") == "legacy":
        allowed = {"verified", "advisory"} | ({"inferred"} if inferred else set())
    else:
        allowed = set(gate.get("tiers") or ["verified"])
        if not inferred:
            allowed.discard("inferred")
    return tuple(t for t in TIER_ORDER if t in allowed)


def tier_line(counts: dict, gating: Iterable[str]) -> str:
    """`2 verified (can block the gate) · 71 advisory (shown, not gating) ·
    0 inferred`: the summary line of the `all` view. A tier with findings
    says whether they can fail the gate; a zero says nothing more."""
    gating = set(gating)
    parts = []
    for t in TIER_ORDER:
        n = int(counts.get(t, 0) or 0)
        note = "" if not n else (" (can block the gate)" if t in gating else " (shown, not gating)")
        parts.append(f"{n} {t}{note}")
    return " · ".join(parts)


TIER_MEANING = {
    "verified": "measured at least 99% precise",
    "advisory": "not confirmed",
    "inferred": "found by a model, not confirmed",
}


def tier_note(tier: str, gating: Iterable[str]) -> str:
    """What a tier's section heading says after the tier's name: what the
    tier means and whether it can block the gate, so an advisory finding
    never reads as a verified one (`not confirmed; shown, cannot block the
    gate`)."""
    gate = "can block the gate" if tier in set(gating) else "shown, cannot block the gate"
    return f"{TIER_MEANING.get(tier, tier)}; {gate}"


def set_view(report, show: str) -> None:
    """Re-point a report's view (for `--advisory` or `--verified-only` on a
    report read back from JSON); the findings are untouched."""
    failing = set((report.gate or {}).get("failing_ids") or [])
    report.tiers = view_block(report.findings, show, failing)


def default_tier(d: dict) -> tuple[str, str]:
    """The tier of a finding read from a report written before tiers: from
    its provenance and its rule's declared tier. A report never upgrades a
    finding to verified on load -- that needs the ledger and the scan."""
    if d.get("provenance") == "inferred":
        return "inferred", "found by a model: provenance inferred"
    return "advisory", "report predates tiers; rule tier not evaluated against the ledger"


def rules_block(findings: list) -> list[dict]:
    """The report's top-level `rules` list: one row per rule that fired."""
    from .rule_meta import declared_tier, requirements_of
    out = {}
    for f in findings:
        if f.rule_id not in out:
            out[f.rule_id] = {"id": f.rule_id,
                              "requirements": list(f.requirements) or requirements_of(f.rule_id),
                              "tier": declared_tier(f.rule_id)}
    return [out[k] for k in sorted(out)]
