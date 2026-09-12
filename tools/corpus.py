#!/usr/bin/env python3
"""Run Arbiter across a corpus of repositories and summarize signal vs noise.

The corpus deliberately mixes two populations:

  * repositories built to be vulnerable, where a high finding count is correct
  * well-maintained repositories, where almost every finding is noise

Rules are tuned against the second group. A rule that fires on `requests` or
`flask` is telling you about the rule, not about the code.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from arbiter.engine import run_scan  # noqa: E402
from arbiter.policy import load_config  # noqa: E402

# name -> expectation. "vulnerable" repos should be loud; "clean" repos are the
# false-positive measurement.
CORPUS = {
    # deliberately vulnerable — a high finding count is the correct answer
    "terragoat":        ("vulnerable", "terraform"),
    "cfngoat":          ("vulnerable", "cloudformation"),
    "nodegoat":         ("vulnerable", "node"),
    "kustomizegoat":    ("vulnerable", "kubernetes"),
    "nodejs-goof":      ("vulnerable", "node"),
    # well-maintained — every finding here is a candidate false positive
    "tf-aws-s3-bucket": ("clean", "terraform"),
    "tf-aws-vpc":       ("clean", "terraform"),
    "tf-aws-iam":       ("clean", "terraform"),
    "tf-provider-rand": ("clean", "go"),
    "cfn-templates":    ("clean", "cloudformation"),
    "cdk-examples":     ("clean", "aws_cdk"),
    "k8s-examples":     ("clean", "kubernetes"),
    "helm-charts":      ("clean", "kubernetes"),
    "compose-awesome":  ("clean", "docker"),
    "requests":         ("clean", "python"),
    "flask":            ("clean", "python"),
    "pipx":             ("clean", "python"),
    "express":          ("clean", "javascript"),
    "ts-zod":           ("clean", "typescript"),
    "go-cobra":         ("clean", "go"),
    "rust-ripgrep":     ("clean", "rust"),
    "cpp-json":         ("clean", "cpp"),
    "java-gson":        ("clean", "java"),
    "ruby-sinatra":     ("clean", "ruby"),
    "php-guzzle":       ("clean", "php"),
    "r-stringr":        ("clean", "r"),
    "shell-nvm":        ("clean", "shell"),
}

NATIVE = ["secrets", "resource_policy", "quality", "ast_metrics",
          "supply_chain", "doc_drift", "house_rules", "house_rules_ast"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/tmp/corpus")
    ap.add_argument("--out", default="/tmp/corpus-out")
    ap.add_argument("--only", default=",".join(NATIVE))
    args = ap.parse_args()

    root = Path(args.root)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    cfg = load_config(None)
    only = [p for p in args.only.split(",") if p]

    rows = []
    rule_counts: dict[str, Counter] = {"clean": Counter(), "vulnerable": Counter()}

    for name, (expectation, stack_label) in CORPUS.items():
        path = root / name
        if not path.is_dir():
            print(f"  skip {name}: not cloned")
            continue
        t0 = time.time()
        rep = run_scan([str(path)], cfg, only=only, use_adapters=False)
        elapsed = time.time() - t0
        active = rep.active()
        loc = max(1, sum(r.loc for r in rep.repos))
        sev = Counter(f.severity for f in active)
        for f in active:
            rule_counts[expectation][f.rule_id] += 1
        rows.append({
            "repo": name,
            "expectation": expectation,
            "loc": loc,
            "findings": len(active),
            "per_kloc": round(len(active) / (loc / 1000), 2),
            "critical": sev["critical"], "high": sev["high"],
            "medium": sev["medium"], "low": sev["low"],
            "seconds": round(elapsed, 2),
            "stacks": rep.stacks,
            "stack_label": stack_label,
        })
        (outdir / f"{name}.json").write_text(json.dumps(rep.to_dict(), indent=2))

    print(f"\n  {'REPO':<20}{'STACK':<15}{'KIND':<11}{'LOC':>8}{'FIND':>6}"
          f"{'CRIT':>5}{'HIGH':>5}{'MED':>5}{'LOW':>5}{'SEC':>7}")
    for r in sorted(rows, key=lambda r: (r["expectation"], r["stack_label"], -r["per_kloc"])):
        print(f"  {r['repo']:<20}{r['stack_label']:<15}{r['expectation']:<11}{r['loc']:>8}"
              f"{r['findings']:>6}{r['critical']:>5}{r['high']:>5}{r['medium']:>5}"
              f"{r['low']:>5}{r['seconds']:>7}")

    for kind in ("clean", "vulnerable"):
        group = [r for r in rows if r["expectation"] == kind]
        if not group:
            continue
        total_loc = sum(r["loc"] for r in group)
        total_f = sum(r["findings"] for r in group)
        print(f"\n  {kind}: {total_f} findings over {total_loc:,} lines "
              f"= {total_f / (total_loc / 1000):.2f} per KLOC")

    print("\n  NOISIEST RULES ON WELL-MAINTAINED CODE")
    print("  (every one of these is a candidate false positive)")
    for rule, n in rule_counts["clean"].most_common(18):
        vuln = rule_counts["vulnerable"][rule]
        print(f"    {n:>5} clean  {vuln:>5} vulnerable   {rule}")

    (outdir / "summary.json").write_text(json.dumps({
        "rows": rows,
        "rule_counts": {k: dict(v) for k, v in rule_counts.items()},
    }, indent=2))
    print(f"\n  wrote {outdir}/summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
