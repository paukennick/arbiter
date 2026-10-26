#!/usr/bin/env python3
"""Outputs for the ARB-112 preregistration (docs/accuracy-prereg-b.md).

    python tools/prereg_b_analysis.py --cohort labels/arb109-model.jsonl \\
        --calibration labels/arb109-calibration.jsonl --json out.json --markdown out.md

Committed before any label exists. It computes, and nothing else:
per-rule and overall tp/fp/unsure counts with Wilson 95% intervals (counts
only below 10 findings), a percentile cluster bootstrap over repositories
(10,000 resamples, seed 109), the `unsure` rate, and the calibration block.
`unsure` is never counted as tp or fp. Model-labelled conformance, not a
precision estimate for Python code in general.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

MIN_RULE_N = 10
RELIABILITY = 0.80
BOOT_N = 10_000
BOOT_SEED = 109


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _labels():
    sys.path.insert(0, str(ROOT / "tools" / "ground_truth"))
    return _load("label_models", ROOT / "tools" / "label_models.py")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _wilson(k: int, n: int):
    lm = _labels()
    w = lm.ls.wilson(k, n)
    return list(w) if w else None


def tally(recs: list[dict]) -> dict:
    c = Counter(r["label"] for r in recs)
    tp, fp, un = c["tp"], c["fp"], c["unsure"]
    n = tp + fp
    out = {"findings": len(recs), "tp": tp, "fp": fp, "unsure": un,
           "unsure_rate": round(un / len(recs), 3) if recs else None,
           "precision": round(tp / n, 3) if n else None, "wilson95": None}
    if len(recs) >= MIN_RULE_N and n:
        out["wilson95"] = _wilson(tp, n)
    return out


def cluster_bootstrap(recs: list[dict], n_boot: int = BOOT_N, seed: int = BOOT_SEED) -> dict:
    """Percentile interval for tp/(tp+fp), resampling whole repositories."""
    by_repo: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in recs:
        if r["label"] == "tp":
            by_repo[r["repo"]][0] += 1
        elif r["label"] == "fp":
            by_repo[r["repo"]][1] += 1
    repos = [v for v in by_repo.values() if v[0] + v[1]]
    out = {"repositories_with_findings": len(repos), "repositories_total": len({r["repo"] for r in recs}),
           "resamples": n_boot, "seed": seed, "interval95": None}
    if len(repos) < 2:
        return out
    rng = random.Random(seed)
    stats = []
    for _ in range(n_boot):
        tp = fp = 0
        for _ in repos:
            a, b = repos[rng.randrange(len(repos))]
            tp += a
            fp += b
        if tp + fp:
            stats.append(tp / (tp + fp))
    stats.sort()
    if stats:
        out["interval95"] = [round(stats[int(0.025 * (len(stats) - 1))], 3),
                             round(stats[int(0.975 * (len(stats) - 1))], 3)]
    return out


def calibration_block(recs: list[dict]) -> dict:
    if not recs:
        return {"n": 0, "reliable": False, "reason": "no calibration labels"}
    cal = _labels().calibration(recs)
    acc = cal["final"]["accuracy_decided"]
    return {"n": len(recs), "final": cal["final"], "prosecutor": cal["prosecutor"],
            "defender": cal["defender"], "kappa_prosecutor_defender": cal["kappa_prosecutor_defender"],
            "kappa_final_vs_truth": cal["kappa_final_vs_truth"],
            "agreement_with_truth": acc, "threshold": RELIABILITY,
            "reliable": acc is not None and acc >= RELIABILITY}


def analyse(cohort: list[dict], calibration: list[dict]) -> dict:
    cal = calibration_block(calibration)
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for r in cohort:
        by_rule[r["rule_id"]].append(r)
    res = {"status": "model-labelled conformance on an 11-repository convenience cohort",
           "calibration": cal,
           "overall": tally(cohort),
           "by_rule": {k: tally(v) for k, v in sorted(by_rule.items())},
           "cluster": cluster_bootstrap(cohort)}
    if not cal["reliable"]:
        # Counts only: no rate is published when the labeller failed calibration.
        for e in [res["overall"], *res["by_rule"].values()]:
            e["precision"] = None
            e["wilson95"] = None
        res["cluster"]["interval95"] = None
        res["low_reliability"] = True
    return res


def render(res: dict) -> str:
    cal = res["calibration"]
    agree = cal.get("agreement_with_truth")
    o = res["overall"]
    lines = [f"Model-labelled conformance on an 11-repository convenience cohort; "
             f"calibration agreement with truth {agree if agree is not None else 'n/a'} "
             f"(n={cal['n']}, threshold {RELIABILITY}).", ""]
    if res.get("low_reliability"):
        lines += ["**Low reliability: counts only, no rates.**", ""]
    lines += ["| rule | findings | tp | fp | unsure | unsure rate | tp/(tp+fp) | Wilson 95% |",
              "|---|---:|---:|---:|---:|---:|---:|---|"]

    def row(name, e):
        w = e["wilson95"]
        return (f"| {name} | {e['findings']} | {e['tp']} | {e['fp']} | {e['unsure']} | "
                f"{e['unsure_rate']} | {e['precision'] if e['precision'] is not None else '-'} | "
                f"{w if w else '-'} |")

    lines += [row(f"`{k}`", e) for k, e in res["by_rule"].items()]
    lines.append(row("**all**", o))
    c = res["cluster"]
    lines += ["", f"Cluster bootstrap over repositories: {c['repositories_with_findings']} of "
              f"{c['repositories_total']} contributed findings; 95% interval "
              f"{c['interval95'] if c['interval95'] else '-'} "
              f"({c['resamples']} resamples, seed {c['seed']})."]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cohort", type=Path, required=True)
    ap.add_argument("--calibration", type=Path, required=True)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    a = ap.parse_args(argv)
    res = analyse(read_jsonl(a.cohort), read_jsonl(a.calibration))
    if a.json:
        a.json.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    text = render(res)
    if a.markdown:
        a.markdown.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
