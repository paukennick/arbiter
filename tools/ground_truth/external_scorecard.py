#!/usr/bin/env python3
"""External conformance scorecard: Arbiter against benchmarks it did not write (ARB-120).

    python tools/ground_truth/external_scorecard.py --aggregate-only \\
        --corpus ~/wt/corpus-gold --gt ~/wt/corpus-gt \\
        --out docs/external-scorecard.json --markdown docs/external-scorecard.md
    python tools/ground_truth/external_scorecard.py --aggregate-only --only owasp-python ...

Scans the pinned Arbiter (offline profile, no adapters, no cache) over the
outside benchmarks already wired into the repository and writes one run
record per benchmark in the shape of `run_record_template` in
docs/accuracy-benchmark-manifest.json, plus per-CWE and per-rule case-level
counts and the weak spots ranked by distance from the 0.99 bar:

* **OWASP Benchmark Java 1.2 / Python 0.1** (`tools/gold/benchmarks.json`,
  pinned in `tools/fetch_corpus.sh`): one unit per `expectedresults` row.
  The unit is flagged when a finding in the case's file carries the case's
  CWE or a benchmark alias -- the matching rule of
  `gold_benchmark.score_recall`, which the tests hold this to. Vulnerable or
  safe is the benchmark's published answer.
* **Juliet Java 1.3** (`fetch_gt.sh`, archive SHA-256 pinned): one test case
  is every file sharing a stem once the `a`..`e` part letter and the
  `_bad`/`_base`/`_good*` class suffix are removed. Arbiter-defined units, not
  a published case list: each case is one *vulnerable* unit (a matching-CWE
  finding inside its `bad` code, decided by `benchmarks_gt.juliet_side`) and
  one *safe* unit (a matching-CWE finding inside its `good*` code).
* **CVE fix pairs** (`tools/ground_truth/cve_pairs.json`, 70 GitHub
  advisories): Arbiter-defined units. Each pair is one *vulnerable* unit (a
  matching-CWE finding within `NEAR` lines of a hunk the fix changed, on the
  vulnerable side) and one *safe* unit (the same test on the fixed side).
  Project-level rules are left out, as in `cve_pairs.classify`.

Every number is a benchmark-conformance figure scoped to that benchmark and
its label method, never a 99% or production-population claim. Output is
aggregate-only: no case names, file paths, advisory IDs or excerpts.
Precision here is labelled-*case* precision -- of the units Arbiter flagged,
the share the benchmark marks vulnerable -- not finding precision.

Intervals: Wilson 95% on units. OWASP and Juliet are each one repository,
so one cluster; their interval is case-level only and says nothing about
other code. CVE pairs come from 70 repositories and also get a
repository-cluster percentile bootstrap.

Nothing scanned is built or run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import random
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _p in (str(ROOT / "src"), str(ROOT / "tools"), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import benchmarks_gt as bgt
import cve_pairs as cvp
import gold_benchmark as gb
import gt_common as g

SCHEMA_VERSION = 1
EVALUATOR_VERSION = "external-scorecard@1"
BAR = 0.99
MANIFEST = ROOT / "docs" / "accuracy-benchmark-manifest.json"
BENCHMARKS = ROOT / "tools" / "gold" / "benchmarks.json"
CVE_PAIRS = ROOT / "tools" / "ground_truth" / "cve_pairs.json"
FETCH_SCRIPT = ROOT / "tools" / "fetch_corpus.sh"
ALL = ("owasp-java", "owasp-python", "juliet-java", "cve-fix-pairs")
OWASP = {"owasp-java": "owasp-benchmark-java", "owasp-python": "owasp-benchmark-python"}
CLAIM_SCOPE = ("{name} benchmark conformance only: case-level agreement with this benchmark's "
               "labels under the matching rules stated here; not Arbiter finding precision, not "
               "production-population accuracy, not a 99% certification.")


# ---------------------------------------------------------------------------
# Units and statistics -- pure
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Unit:
    """One scored unit: a benchmark case (or one side of it) the benchmark
    labels vulnerable or safe, and the rules whose CWE-matching findings
    landed on it."""
    stratum: str
    vulnerable: bool
    rules: frozenset = frozenset()
    cluster: str = ""
    language: str = ""
    in_scope: bool | None = None  # None: the stratum decides

    @property
    def flagged(self) -> bool:
        return bool(self.rules)


@dataclass
class Stratum:
    """A weakness stratum: the CWEs a finding may carry to be about it, and
    whether any Arbiter rule for the language claims one of them."""
    cwe: str
    truth: frozenset
    in_scope: bool
    categories: tuple = ()


@dataclass
class Scored:
    units: list = field(default_factory=list)
    strata: dict = field(default_factory=dict)
    unassessed: Counter = field(default_factory=Counter)   # reason -> findings
    not_assessed_units: Counter = field(default_factory=Counter)  # reason -> cases
    findings: int = 0


def wilson(k: int, n: int) -> list | None:
    from arbiter.precision import wilson as _w
    w = _w(k, n)
    return [round(w[0], 4), round(w[1], 4)] if w else None


def rate(k: int, n: int) -> dict:
    return {"numerator": k, "denominator": n, "value": round(k / n, 4) if n else None,
            "wilson_95": wilson(k, n)}


def confusion(units) -> dict:
    c = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for u in units:
        c[("tp" if u.flagged else "fn") if u.vulnerable else ("fp" if u.flagged else "tn")] += 1
    return c


def metrics(c: dict) -> dict:
    return {"precision": rate(c["tp"], c["tp"] + c["fp"]),
            "recall": rate(c["tp"], c["tp"] + c["fn"]),
            "safe_case_false_positive_rate": rate(c["fp"], c["fp"] + c["tn"])}


def _lower(m: dict, key: str) -> float:
    w = m[key]["wilson_95"]
    return w[0] if w else 0.0


def row(name: str, units, **extra) -> dict:
    c = confusion(units)
    return {"name": name, "vulnerable": c["tp"] + c["fn"], "safe": c["fp"] + c["tn"],
            **c, **metrics(c), **extra}


def _percentile(values: list, q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    return round(s[lo] * (1 - (pos - lo)) + s[hi] * (pos - lo), 4)


def cluster_bootstrap(clusters: list[dict], replicates: int = 10_000, seed: int = 0) -> dict:
    """Repository-cluster percentile bootstrap over per-cluster confusion
    counts (the RealVuln pilot's method and defaults, 8198df7): clusters are
    resampled whole, so units from one repository never count as
    independent evidence."""
    rng = random.Random(seed)
    out = {"precision": [], "recall": [], "safe_case_false_positive_rate": []}
    for _ in range(replicates if clusters else 0):
        s = [rng.choice(clusters) for _ in clusters]
        tp, fp, fn, tn = (sum(r[k] for r in s) for k in ("tp", "fp", "fn", "tn"))
        if tp + fp:
            out["precision"].append(tp / (tp + fp))
        if tp + fn:
            out["recall"].append(tp / (tp + fn))
        if fp + tn:
            out["safe_case_false_positive_rate"].append(fp / (fp + tn))
    return {"method": "repository-cluster bootstrap; percentile interval", "confidence_level": 0.95,
            "replicates": replicates, "seed": seed, "clusters": len(clusters),
            **{f"{k}_interval": [_percentile(v, 0.025), _percentile(v, 0.975)] for k, v in out.items()},
            **{f"{k}_valid_replicates": len(v) for k, v in out.items()}}


def rule_rows(units, strata: dict, rule_cwes: dict[str, set]) -> list[dict]:
    """Per rule: TP/FP are units it flagged; FN/TN are units of the strata it
    claims (its CWEs meet the stratum's) that it did not flag. A rule that
    fires outside its claimed CWEs has those strata added, so nothing it
    flagged falls out of its denominator."""
    rules = set(rule_cwes)
    for u in units:
        rules |= u.rules
    out = []
    for r in sorted(rules):
        pack = gb.rule_pack(r)
        # a language pack's rule is only answerable for units in its language
        own = [u for u in units if not (pack and u.language
                                        and gb.LANG_GROUP.get(u.language, u.language) != pack)]
        claimed = {k for k, s in strata.items() if set(rule_cwes.get(r, ())) & s.truth}
        claimed |= {u.stratum for u in own if r in u.rules}
        mine = [Unit(u.stratum, u.vulnerable, frozenset({r}) if r in u.rules else frozenset())
                for u in own if u.stratum in claimed]
        if not mine:
            continue
        out.append(row(r, mine, strata=sorted(claimed, key=_cwe_key)))
    return out


def weak_spots(benchmark: str, per_cwe: list[dict], per_rule: list[dict]) -> list[dict]:
    """Distance of each in-scope CWE and each rule from the bar: 0.99 minus
    the smaller of its precision and recall Wilson lower bounds (an empty
    denominator counts as 0)."""
    out = []
    for kind, rows in (("cwe", [r for r in per_cwe if r.get("in_scope")]), ("rule", per_rule)):
        for r in rows:
            p, rc = _lower(r, "precision"), _lower(r, "recall")
            out.append({"benchmark": benchmark, "kind": kind, "name": r["name"],
                        "precision_lower_95": round(p, 4), "recall_lower_95": round(rc, 4),
                        "gap_to_bar": round(BAR - min(p, rc), 4),
                        "limiting": "recall" if rc <= p else "precision",
                        "vulnerable": r["vulnerable"], "safe": r["safe"], "flagged": r["tp"] + r["fp"]})
    return out


def _cwe_key(s: str):
    m = re.search(r"\d+", s)
    return (int(m.group()) if m else 10**9, s)


def _truth(cwe: str, aliases: dict) -> frozenset:
    return frozenset({cwe, *aliases.get(cwe, [])})


# ---------------------------------------------------------------------------
# Benchmark adapters -- pure, given findings
# ---------------------------------------------------------------------------

def owasp_score(expected: dict, findings: list[dict], aliases: dict, test_dir: str,
                claimed: set, language: str) -> Scored:
    prefix = test_dir.rstrip("/") + "/"
    by_file: dict[str, list[dict]] = defaultdict(list)
    sc = Scored(findings=len(findings))
    for f in findings:
        if f["path"].startswith(prefix):
            by_file[Path(f["path"]).stem].append(f)
        else:
            sc.unassessed["outside case files (benchmark harness)"] += 1
    for name, fs in by_file.items():
        if name not in expected:
            sc.unassessed["case file without expected result"] += len(fs)
    cats: dict[str, set] = defaultdict(set)
    for name, e in expected.items():
        truth = _truth(e["cwe"], aliases)
        cats[e["cwe"]].add(e["category"])
        if e["cwe"] not in sc.strata:
            sc.strata[e["cwe"]] = Stratum(e["cwe"], truth, bool(truth & claimed))
        hit, miss = set(), 0
        for f in by_file.get(name, ()):
            if g.cwe_match(f.get("cwe") or [], [e["cwe"]], aliases):
                hit.add(f["rule"])
            else:
                miss += 1
        sc.unassessed["finding CWE not the case's CWE"] += miss
        sc.units.append(Unit(e["cwe"], e["real"], frozenset(hit), "", language))
    for k, s in sc.strata.items():
        s.categories = tuple(sorted(cats[k]))
    return sc


_JULIET_CASE = re.compile(r"^(?P<case>.+?_\d+)(?:[a-z]|_bad|_base|_good\w*)?$")


def juliet_case_id(stem: str) -> str:
    """`..._54a`, `..._81_bad`, `..._81_goodG2B`, `..._81_base` -> the shared
    case stem (`..._54`, `..._81`); a stem with no case number is its own case."""
    m = _JULIET_CASE.match(stem)
    return m.group("case") if m else stem


def juliet_score(case_files: dict[str, list[str]], findings: dict[str, list[dict]],
                 side_of, claimed: set) -> Scored:
    """`case_files`: directory -> every case file path in it; `findings`:
    directory -> its findings; `side_of(finding)` -> 'bad' | 'good' | None."""
    sc = Scored()
    for d, files in case_files.items():
        truth = frozenset(bgt.JULIET_DIRS[d])
        cwe = "CWE-" + re.match(r"CWE(\d+)", d).group(1)
        sc.strata[d] = Stratum(cwe, truth, bool(truth & claimed))
        bad: dict[str, set] = defaultdict(set)
        good: dict[str, set] = defaultdict(set)
        fs = findings.get(d, [])
        sc.findings += len(fs)
        for f in fs:
            if not g.cwe_match(f.get("cwe") or [], list(truth), {}):
                sc.unassessed["finding CWE not the directory's CWE"] += 1
                continue
            side = side_of(f)
            if side is None:
                sc.unassessed["outside any bad/good method"] += 1
                continue
            (bad if side == "bad" else good)[juliet_case_id(Path(f["path"]).stem)].add(f["rule"])
        for case in sorted({juliet_case_id(Path(p).stem) for p in files}):
            sc.units.append(Unit(d, True, frozenset(bad.get(case, ())), "", "java"))
            sc.units.append(Unit(d, False, frozenset(good.get(case, ())), "", "java"))
    return sc


def _window(r: range) -> tuple[int, int]:
    return (r.start, r.stop) if len(r) else (r.start, r.start)


def cve_pair_units(pair: dict, vuln: list[dict], fix: list[dict],
                   texts: dict[str, tuple[list[str], list[str]]], claimed: set) -> tuple:
    """(vulnerable unit, safe unit, Counter of unassessed findings) for one
    pair. A finding counts when it is within `cve_pairs.NEAR` lines of a hunk
    the fix changed -- the same window on both sides -- and its CWE meets the
    advisory's (`cve_pairs.CWE_ALIASES`)."""
    hunks = {p: cvp.changed_lines(old, new) for p, (old, new) in texts.items()}
    skipped: Counter = Counter()

    def hits(findings: list[dict], side: int) -> set:
        out = set()
        for f in findings:
            if f["rule"].startswith(cvp.PROJECT_RULES):
                skipped["project-level rule"] += 1
                continue
            near = f["path"] in hunks and any(lo - cvp.NEAR <= f["line"] < hi + cvp.NEAR
                                              for h in hunks[f["path"]] for lo, hi in [_window(h[side])])
            if not near:
                skipped["away from the hunks the fix changed"] += 1
                continue
            if g.cwe_match(f.get("cwe") or [], pair["cwes"], cvp.CWE_ALIASES):
                out.add(f["rule"])
            else:
                skipped["finding CWE not the advisory's CWE"] += 1
        return out

    stratum = pair.get("selected_for") or pair["cwes"][0]
    cl, lang = pair["repo"], pair["language"]
    scope = bool({t for c in pair["cwes"] for t in _truth(c, cvp.CWE_ALIASES)} & claimed)
    return (Unit(stratum, True, frozenset(hits(vuln, 0)), cl, lang, scope),
            Unit(stratum, False, frozenset(hits(fix, 1)), cl, lang, scope), skipped)


def cve_truth(pairs: list[dict], claimed_by_lang: dict[str, set]) -> dict:
    """Strata for the CVE pairs: the selected CWE plus every advisory CWE of
    the pairs selected for it, with aliases; in scope when the language's
    rules claim one of them."""
    out: dict[str, Stratum] = {}
    for p in pairs:
        k = p.get("selected_for") or p["cwes"][0]
        t = set()
        for c in p["cwes"]:
            t |= _truth(c, cvp.CWE_ALIASES)
        s = out.setdefault(k, Stratum(k, frozenset(), False))
        s.truth = frozenset(s.truth | t)
        s.in_scope = s.in_scope or bool(t & claimed_by_lang.get(p["language"], set()))
    return out


# ---------------------------------------------------------------------------
# Assembly -- pure
# ---------------------------------------------------------------------------

def summarise(name: str, sc: Scored, rule_cwes: dict[str, set], *, multi_cluster: bool,
              replicates: int, seed: int) -> dict:
    per_cwe = []
    for k in sorted(sc.strata, key=_cwe_key):
        s = sc.strata[k]
        us = [u for u in sc.units if u.stratum == k]
        per_cwe.append(row(k, us, cwe=s.cwe, in_scope=s.in_scope, categories=list(s.categories),
                           not_assessed_reason=None if s.in_scope else
                           "no Arbiter rule for this language claims this CWE"))
    in_scope = {k for k, s in sc.strata.items() if s.in_scope}
    per_rule = rule_rows(sc.units, sc.strata, rule_cwes)
    scoped = [u for u in sc.units if (u.in_scope if u.in_scope is not None else u.stratum in in_scope)]
    out = {"benchmark": name, "overall": row("all", sc.units), "in_scope": row("in-scope", scoped),
           "per_cwe": per_cwe, "per_rule": per_rule,
           "weak_spots": weak_spots(name, per_cwe, per_rule),
           "unassessed_findings": dict(sorted(sc.unassessed.items())),
           "not_assessed_cases": dict(sorted(sc.not_assessed_units.items())),
           "findings_scanned": sc.findings,
           "not_assessed_strata": sorted(set(sc.strata) - in_scope, key=_cwe_key)}
    clusters = sorted({u.cluster for u in sc.units})
    if multi_cluster:
        by: dict[str, list] = defaultdict(list)
        for u in sc.units:
            by[u.cluster].append(u)
        out["cluster_bootstrap"] = cluster_bootstrap([confusion(v) for _, v in sorted(by.items())],
                                                     replicates, seed)
        langs = sorted({u.language for u in sc.units})
        out["per_language"] = [row(lang, [u for u in sc.units if u.language == lang]) for lang in langs]
        out["uncertainty_note"] = (f"{len(clusters)} repository clusters; Wilson intervals are "
                                   "case-level, the bootstrap resamples whole repositories.")
    else:
        out["uncertainty_note"] = ("One repository, so one cluster: the Wilson intervals are "
                                   "case-level only and do not generalise beyond this benchmark.")
    out["clusters"] = len(clusters) if multi_cluster else 1
    return out


def run_record(result: dict, provenance: dict) -> dict:
    """The manifest's `run_record_template` filled in; `counts` and `metrics`
    hold exactly the template's keys, everything else sits beside them."""
    o = result["overall"]
    boot = result.get("cluster_bootstrap")
    method = ("case-level Wilson 95% score interval (arbiter.precision.wilson)"
              + ("; repository-cluster percentile bootstrap in cluster_bootstrap" if boot else
                 "; one cluster, no cluster-aware interval") + f"; {EVALUATOR_VERSION}")
    unl = sum(result["unassessed_findings"].values())
    return {**provenance,
            "counts": {"repositories": result["clusters"], "clusters": result["clusters"],
                       "labelled_findings": result["findings_scanned"] - unl,
                       "unlabelled_findings": unl,
                       "known_defects": o["vulnerable"],
                       "not_assessed_strata": len(result["not_assessed_strata"])},
            "metrics": {"precision": o["precision"]["value"],
                        "precision_lower_95": o["precision"]["wilson_95"][0] if o["precision"]["wilson_95"] else None,
                        "recall": o["recall"]["value"],
                        "recall_lower_95": o["recall"]["wilson_95"][0] if o["recall"]["wilson_95"] else None,
                        "effective_sample_size": result["clusters"] if boot else None,
                        "method_and_version": method}}


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _fmt(m: dict) -> str:
    if m["value"] is None:
        return "-"
    w = m["wilson_95"]
    return f"{m['value']:.3f} [{w[0]:.3f}, {w[1]:.3f}]"


def render_markdown(card: dict, top: int = 20) -> str:
    out = ["# External conformance scorecard", "",
           ("Generated by `tools/ground_truth/external_scorecard.py` (ARB-120). "
           "**Benchmark-conformance results only**: each figure is agreement with one outside "
           "benchmark's labels under the matching rules below, not Arbiter finding precision, "
           "not production-population accuracy and not a 99% certification. Aggregate-only."), "",
           ("Precision is labelled-case precision (flagged units the benchmark marks vulnerable); "
           "recall is vulnerable units flagged; safe FPR is safe units flagged. Brackets are "
           "Wilson 95% intervals on units."), "",
           "## Headline", "",
           "| benchmark | units (vuln/safe) | clusters | precision | recall | in-scope recall | safe FPR | unassessed findings |",
           "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, b in card["benchmarks"].items():
        r = b["result"]
        o = r["overall"]
        out.append(f"| {name} | {o['vulnerable'] + o['safe']} ({o['vulnerable']}/{o['safe']}) "
                   f"| {r['clusters']} | {_fmt(o['precision'])} | {_fmt(o['recall'])} "
                   f"| {_fmt(r['in_scope']['recall'])} | {_fmt(o['safe_case_false_positive_rate'])} "
                   f"| {sum(r['unassessed_findings'].values())} |")
    boots = [(n, b["result"]["cluster_bootstrap"]) for n, b in card["benchmarks"].items()
             if "cluster_bootstrap" in b["result"]]
    for n, bt in boots:
        out += ["", (f"{n}: repository-cluster bootstrap ({bt['clusters']} clusters, "
                f"{bt['replicates']} replicates, seed {bt['seed']}): precision "
                f"{bt['precision_interval']}, recall {bt['recall_interval']}, safe FPR "
                f"{bt['safe_case_false_positive_rate_interval']}.")]
    out += ["", ("OWASP and Juliet are each one repository (one cluster): their intervals are "
            "case-level only. The Juliet and CVE vulnerable/safe units are Arbiter-defined (see "
            "Matching), not lists those benchmarks publish."), "",
            "## Weak spots", "",
            ("Gap = 0.99 minus the smaller of the precision and recall Wilson lower bounds; an "
            "empty denominator counts as 0. In-scope CWEs and rules only; the JSON's "
            "`weak_spots` holds the full ranking."), "",
            f"### Fires, but short of the bar (top {top} by gap)", "",
            "| benchmark | kind | name | precision lower | recall lower | limiting | vuln | safe | flagged | gap |",
            "|---|---|---|---:|---:|---|---:|---:|---:|---:|"]
    fired = [w for w in card["weak_spots"] if w["flagged"]]
    for w in fired[:top]:
        out.append(f"| {w['benchmark']} | {w['kind']} | `{w['name']}` | {w['precision_lower_95']:.3f} "
                   f"| {w['recall_lower_95']:.3f} | {w['limiting']} | {w['vulnerable']} | {w['safe']} "
                   f"| {w['flagged']} | {w['gap_to_bar']:.3f} |")
    silent = [w for w in card["weak_spots"] if not w["flagged"]]
    out += ["", "### Claims the CWE, flags nothing (gap 0.990, by vulnerable units)", "",
            "| benchmark | kind | name | vulnerable units missed |", "|---|---|---|---:|"]
    for w in silent[:top]:
        out.append(f"| {w['benchmark']} | {w['kind']} | `{w['name']}` | {w['vulnerable']} |")
    if len(silent) > top:
        out.append(f"\n{len(silent) - top} more in the JSON.")
    for name, b in card["benchmarks"].items():
        r = b["result"]
        out += ["", f"## {name}", "", r["uncertainty_note"], "",
                "| stratum | in scope | vuln | safe | TP | FN | FP | TN | precision | recall | safe FPR |",
                "|---|:-:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for c in r["per_cwe"]:
            out.append(f"| {c['name']} | {'yes' if c['in_scope'] else 'no'} | {c['vulnerable']} | {c['safe']} "
                       f"| {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} | {_fmt(c['precision'])} "
                       f"| {_fmt(c['recall'])} | {_fmt(c['safe_case_false_positive_rate'])} |")
        if r.get("per_language"):
            out += ["", "| language | vuln | safe | TP | FN | FP | TN | precision | recall | safe FPR |",
                    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
            for c in r["per_language"]:
                out.append(f"| {c['name']} | {c['vulnerable']} | {c['safe']} | {c['tp']} | {c['fn']} "
                           f"| {c['fp']} | {c['tn']} | {_fmt(c['precision'])} | {_fmt(c['recall'])} "
                           f"| {_fmt(c['safe_case_false_positive_rate'])} |")
        fired = [x for x in r["per_rule"] if x["tp"] + x["fp"]]
        out += ["", (f"Rules claiming a benchmark CWE: {len(r['per_rule'])}; of them flagged at "
                f"least one unit: {len(fired)}."), ""]
        if fired:
            out += ["| rule | TP | FP | FN | precision | recall over its claimed strata |",
                    "|---|---:|---:|---:|---:|---:|"]
            for x in sorted(fired, key=lambda x: -(x["tp"] + x["fp"])):
                out.append(f"| `{x['name']}` | {x['tp']} | {x['fp']} | {x['fn']} "
                           f"| {_fmt(x['precision'])} | {_fmt(x['recall'])} |")
        if r["unassessed_findings"] or r["not_assessed_cases"]:
            out += ["", "Not assessed: " + "; ".join(
                [f"{v} findings: {k}" for k, v in r["unassessed_findings"].items()]
                + [f"{v} cases: {k}" for k, v in r["not_assessed_cases"].items()]) + "."]
        rr = b["run_record"]
        out += ["", (f"Run: Arbiter `{(rr['arbiter_commit'] or '?')[:12]}` (worktree clean: "
                f"{rr['arbiter_worktree_clean']}), snapshot `{rr['benchmark_snapshot_or_pin']}`, "
                f"profile `{rr['profile']}`, cache `{rr['cache_policy']}`, {rr['started_at_utc']} to "
                f"{rr['completed_at_utc']}.")]
    out += ["", "## Matching", ""] + [f"- **{k}**: {v}" for k, v in MATCHING.items()]
    out += ["", "## Reproduce", "", "```bash", card["command"], "```", ""]
    return "\n".join(out)


MATCHING = {
    "owasp": ("one unit per expectedresults row; flagged when an active finding in the case's file "
              "carries the case's CWE or a benchmark alias (tools/gold/benchmarks.json), the rule of "
              "gold_benchmark.score_recall. Labels are the benchmark's own."),
    "juliet-java": ("Arbiter-defined units: files sharing a case stem form one case; each case is a "
                    "vulnerable unit (matching-CWE finding inside bad code, benchmarks_gt.juliet_side) "
                    "and a safe unit (inside good* code). Findings outside any bad/good method are "
                    "counted unassessed."),
    "cve-fix-pairs": ("Arbiter-defined units: per GitHub advisory fix pair, a vulnerable unit (matching-"
                      "CWE finding within 2 lines of a hunk the fix changed, vulnerable side) and a safe "
                      "unit (same window, fixed side); project-level rules excluded; stratum is the CWE "
                      "the pair was selected for."),
}


# ---------------------------------------------------------------------------
# Scanning and provenance -- impure
# ---------------------------------------------------------------------------

def scan_dir(root: Path, keep_probes: Counter | None = None) -> list[dict]:
    """Active findings under `root`, paths relative to it: offline profile,
    no adapters, no cache, Arbiter's default configuration."""
    from arbiter.engine import run_scan
    from arbiter.policy import load_config
    report = run_scan([str(root)], load_config(None), profile="offline", use_adapters=False,
                      use_cache=False, model_verify=False)
    if keep_probes is not None:
        for p in report.probes:
            keep_probes[f"{p.name}:{p.status}"] += 1
    return [{"rule": f.rule_id, "path": f.location.path, "line": f.location.start_line,
             "cwe": list(f.cwe)} for f in report.active()]


def _git(*args: str) -> str:
    try:
        r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True,
                           timeout=30, check=False)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _versions() -> str:
    from arbiter import __version__
    parts = [f"arbiter {__version__} (native probes only, no adapters)"]
    for pkg in ("tree-sitter", "tree-sitter-language-pack", "PyYAML"):
        try:
            parts.append(f"{pkg} {importlib.metadata.version(pkg)}")
        except importlib.metadata.PackageNotFoundError:
            parts.append(f"{pkg} not installed")
    return "; ".join(parts)


def _config_digest() -> str:
    from arbiter.policy import load_config
    cfg = {"config": load_config(None), "profile": "offline", "use_adapters": False,
           "use_cache": False, "model_verify": False}
    return hashlib.sha256(json.dumps(cfg, sort_keys=True, default=str).encode()).hexdigest()


def git_state() -> dict:
    """Taken once, before any output is written, so the scorecard's own
    files never make a later benchmark's record look dirty."""
    return {"arbiter_commit": _git("rev-parse", "HEAD") or None,
            "arbiter_worktree_clean": _git("status", "--porcelain") == ""}


def provenance(snapshot: str, started: str, state: dict) -> dict:
    return {**state,
            "benchmark_manifest_digest": "sha256:" + _sha256_file(MANIFEST),
            "benchmark_snapshot_or_pin": snapshot,
            "evaluator_commit": (_git("log", "-1", "--format=%H", "--", str(Path(__file__).resolve()))
                                 or None),
            "evaluator_sha256": _sha256_file(Path(__file__).resolve()),
            "configuration_digest": "sha256:" + _config_digest(),
            "analyzer_and_ruleset_versions": _versions(),
            "vulnerability_database_snapshot": None,
            "operating_system_image": platform.platform(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "profile": "offline",
            "cache_policy": "disabled (use_cache=False, no adapters, no model verification)",
            "started_at_utc": started, "completed_at_utc": None}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _rule_cwes(language: str) -> dict[str, set]:
    from arbiter.lang_rules import load_packs
    pack = gb.LANG_GROUP.get(language, language)
    return {f"arbiter/{pack}.{r['id']}": set(r.get("cwe") or [])
            for r in load_packs().get(pack, {}).get("rules", [])}


def _merge_rule_cwes(base: dict, findings_cwes: dict) -> dict:
    out = {k: set(v) for k, v in base.items()}
    for r, c in findings_cwes.items():
        out.setdefault(r, set()).update(c)
    return out


def run_owasp(key: str, corpus: Path) -> tuple[Scored, str, dict, Counter]:
    name = OWASP[key]
    cfg = json.loads(BENCHMARKS.read_text(encoding="utf-8"))[name]
    pin = {p.name: p for p in gb.parse_pins(FETCH_SCRIPT.read_text(encoding="utf-8"))}[name]
    repo = corpus / name
    head = gb._head(repo)
    if head != pin.sha:
        raise SystemExit(f"{name}: HEAD {head[:12] or 'missing'} is not the pin {pin.sha[:12]}; "
                         "run tools/fetch_corpus.sh")
    probes: Counter = Counter()
    findings = scan_dir(repo, probes)
    expected = gb.read_expected(repo / cfg["expected_results"])
    sc = owasp_score(expected, findings, cfg.get("cwe_aliases", {}), cfg["test_dir"],
                     gb.claimed_cwes(cfg["language"]), cfg["language"])
    seen = defaultdict(set)
    for f in findings:
        seen[f["rule"]].update(f["cwe"])
    rc = _merge_rule_cwes(_rule_cwes(cfg["language"]), seen)
    return sc, f"{pin.url}@{pin.sha} ({cfg['expected_results']})", rc, probes


def run_juliet(gt: Path) -> tuple[Scored, str, dict, Counter]:
    root = gt / "juliet-java"
    zip_ = gt / "juliet-java-dl" / "juliet-java-1.3.zip"
    if zip_.is_file() and _sha256_file(zip_) != bgt.JULIET_SHA256:
        raise SystemExit("Juliet archive SHA-256 does not match the pin")
    base = root / "Java" / "src" / "testcases"
    case_files, findings, probes = {}, {}, Counter()
    for d in bgt.JULIET_DIRS:
        if not (base / d).is_dir():
            raise SystemExit(f"missing {base / d}: run tools/ground_truth/fetch_gt.sh")
        case_files[d] = sorted(p.relative_to(base / d).as_posix() for p in (base / d).rglob("*.java"))
        findings[d] = [{**f, "dir": d} for f in scan_dir(base / d, probes)]
        print(f"  juliet {d}: {len(case_files[d])} files, {len(findings[d])} findings",
              file=sys.stderr, flush=True)
    texts: dict[str, str] = {}

    def side_of(f: dict):
        p = base / f["dir"] / f["path"]
        if str(p) not in texts:
            texts[str(p)] = p.read_text(encoding="utf-8", errors="replace")
        return bgt.juliet_side(texts[str(p)], str(p), f["line"])

    sc = juliet_score(case_files, findings, side_of, gb.claimed_cwes("java"))
    seen = defaultdict(set)
    for fs in findings.values():
        for f in fs:
            seen[f["rule"]].update(f["cwe"])
    rc = _merge_rule_cwes(_rule_cwes("java"), seen)
    return sc, f"juliet-java-1.3.zip sha256:{bgt.JULIET_SHA256} ({len(bgt.JULIET_DIRS)} CWE directories)", rc, probes


def run_cve(gt: Path) -> tuple[Scored, str, dict, Counter]:
    pairs = json.loads(CVE_PAIRS.read_text(encoding="utf-8"))["pairs"]
    langs = sorted({p["language"] for p in pairs})
    claimed = {lang: gb.claimed_cwes(lang) for lang in langs}
    sc = Scored(strata=cve_truth(pairs, claimed))
    probes: Counter = Counter()
    rc: dict[str, set] = {}
    for lang in langs:
        for r, c in _rule_cwes(lang).items():
            rc.setdefault(r, set()).update(c)
    dest = gt / "cve"
    for i, p in enumerate(pairs, 1):
        root = dest / p["ghsa"]
        if not (root / "vuln").is_dir() or not (root / "fix").is_dir():
            sc.not_assessed_units["pair not fetched"] += 1
            continue
        texts = {}
        for path in p["files"]:
            try:
                texts[path] = ((root / "vuln" / path).read_text(encoding="utf-8", errors="replace").splitlines(),
                               (root / "fix" / path).read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                continue
        if not texts:
            sc.not_assessed_units["pair files missing"] += 1
            continue
        vuln, fix = scan_dir(root / "vuln", probes), scan_dir(root / "fix", probes)
        sc.findings += len(vuln) + len(fix)
        for f in vuln + fix:
            rc.setdefault(f["rule"], set()).update(f["cwe"])
        v, s, skipped = cve_pair_units(p, vuln, fix, texts, claimed[p["language"]])
        sc.units += [v, s]
        sc.unassessed.update(skipped)
        if i % 10 == 0:
            print(f"  cve {i}/{len(pairs)}", file=sys.stderr, flush=True)
    return sc, f"tools/ground_truth/cve_pairs.json sha256:{_sha256_file(CVE_PAIRS)} ({len(pairs)} pairs)", rc, probes


def evaluate(key: str, corpus: Path, gt: Path, replicates: int, seed: int, state: dict) -> dict:
    started = _now()
    t0 = time.time()
    if key in OWASP:
        sc, snap, rc, probes = run_owasp(key, corpus)
    elif key == "juliet-java":
        sc, snap, rc, probes = run_juliet(gt)
    else:
        sc, snap, rc, probes = run_cve(gt)
    prov = provenance(snap, started, state)
    result = summarise(key, sc, rc, multi_cluster=key == "cve-fix-pairs", replicates=replicates, seed=seed)
    result["claim_scope"] = CLAIM_SCOPE.format(name=key)
    result["general_99_percent_claim"] = False
    result["matching"] = MATCHING["owasp" if key in OWASP else key]
    result["probe_outcomes"] = dict(sorted(probes.items()))
    result["seconds"] = round(time.time() - t0, 1)
    prov["completed_at_utc"] = _now()
    return {"run_record": run_record(result, prov), "result": result}


def assemble(benchmarks: dict, command: str) -> dict:
    spots = [w for b in benchmarks.values() for w in b["result"]["weak_spots"]]
    spots.sort(key=lambda w: (-w["gap_to_bar"], -(w["vulnerable"] + w["safe"]), w["benchmark"], w["name"]))
    return {"schema_version": SCHEMA_VERSION, "kind": "external-conformance-scorecard",
            "requirement": "ARB-120", "evaluator": EVALUATOR_VERSION, "bar_lower_95": BAR,
            "status": "benchmark_conformance_not_certification", "general_99_percent_claim": False,
            "aggregate_only": True, "command": command,
            "benchmarks": benchmarks, "weak_spots": spots}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", type=Path, default=Path("~/wt/corpus-gold"),
                    help="where tools/fetch_corpus.sh put the OWASP Benchmark repositories")
    ap.add_argument("--gt", type=Path, default=Path("~/wt/corpus-gt"),
                    help="where tools/ground_truth/fetch_gt.sh put Juliet and the CVE pairs")
    ap.add_argument("--only", default=",".join(ALL), help=f"comma-separated subset of {', '.join(ALL)}")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "external-scorecard.json")
    ap.add_argument("--markdown", type=Path, default=ROOT / "docs" / "external-scorecard.md")
    ap.add_argument("--bootstrap-replicates", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--aggregate-only", action="store_true",
                    help="required: write counts and rates only, never case names, paths or excerpts")
    args = ap.parse_args(argv)
    if not args.aggregate_only:
        ap.error("--aggregate-only is required")
    wanted = [k for k in args.only.split(",") if k]
    bad = set(wanted) - set(ALL)
    if bad:
        ap.error(f"unknown benchmark(s): {', '.join(sorted(bad))}")
    benchmarks = {}
    if args.out.is_file() and set(wanted) != set(ALL):
        benchmarks = json.loads(args.out.read_text(encoding="utf-8")).get("benchmarks", {})
    command = ("python tools/ground_truth/external_scorecard.py --aggregate-only "
               "--corpus ~/wt/corpus-gold --gt ~/wt/corpus-gt "
               "--out docs/external-scorecard.json --markdown docs/external-scorecard.md")
    state = git_state()
    for key in wanted:
        print(f"{key} ...", file=sys.stderr, flush=True)
        benchmarks[key] = evaluate(key, args.corpus.expanduser(), args.gt.expanduser(),
                                   args.bootstrap_replicates, args.seed, state)
        ordered = {k: benchmarks[k] for k in ALL if k in benchmarks}
        card = assemble(ordered, command)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(card, indent=1, sort_keys=False) + "\n", encoding="utf-8")
        args.markdown.write_text(render_markdown(card), encoding="utf-8")
        o = benchmarks[key]["result"]["overall"]
        print(f"{key}: precision {o['precision']['value']} recall {o['recall']['value']} "
              f"safe FPR {o['safe_case_false_positive_rate']['value']} "
              f"({benchmarks[key]['result']['seconds']}s)", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
