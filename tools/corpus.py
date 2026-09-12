#!/usr/bin/env python3
"""Run Arbiter across a corpus of repositories and summarize signal vs noise.

The corpus deliberately mixes three populations:

  * "vulnerable" — repositories built to be insecure on purpose. A high finding
    count here is the correct answer.
  * "clean" — well-maintained production code. Almost every finding here is
    noise, so this is the group the rules are tuned against. A rule that fires
    on `requests` or `flask` is telling you about the rule, not about the code.
  * "examples" — collections of teaching samples and starter templates
    (reference CloudFormation stacks, CDK samples, Helm charts). These are a
    third thing and must not be counted as either of the first two. They are
    written to be short and readable rather than production-ready, so they
    genuinely lack resource limits, security contexts and pinned versions. A
    finding here is usually correct about the file and useless as a measure of
    false-positive rate. Mixing them into "clean" made the noise rate look
    roughly four times worse than it is: 2,211 of 2,904 clean findings came
    from five example repositories.
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

# name -> (expectation, stack_label). "vulnerable" repos should be loud;
# "clean" repos are the false-positive measurement; "examples" are teaching
# material and are reported separately so they distort neither number.
POPULATIONS = ("vulnerable", "clean", "examples")

# Repositories never used to tune a rule, and never read while deciding one.
#
# Every figure in this project so far was measured on repositories the rules
# were tuned against. That is how a tool ends up fitted to its own practice
# set: each false positive gets a regression test naming the repository it came
# from, the number improves, and nothing says whether the improvement
# generalizes or was just memorised.
#
# These five are held out. They span the stacks that matter most here and
# include one of each population, so the held-out numbers are comparable to
# the tuned ones. The rule is simple and only works if it is kept: when a
# finding on a held-out repository turns out to be a false positive, the fix
# and its regression test must be driven by a repository from the tuning set,
# or the holdout has been spent.
HOLDOUT = frozenset({
    "argo-cd",          # clean, kubernetes — large, production manifests
    "php-guzzle",       # clean, php
    "dvwa",             # vulnerable, php
    "cdkgoat",          # vulnerable, aws_cdk
    "compose-awesome",  # examples, docker
})

CORPUS = {
    # deliberately vulnerable — a high finding count is the correct answer
    "terragoat":        ("vulnerable", "terraform"),
    "cfngoat":          ("vulnerable", "cloudformation"),
    "nodegoat":         ("vulnerable", "node"),
    "kustomizegoat":    ("vulnerable", "kubernetes"),
    "nodejs-goof":      ("vulnerable", "node"),
    # Added to give every stack a broken counterpart. Before these, eight of
    # the thirteen languages had no vulnerable repository at all, so any rule
    # covering them had nothing to be measured against.
    "kubernetes-goat":  ("vulnerable", "kubernetes"),
    "sadcloud":         ("vulnerable", "terraform"),
    "cdkgoat":          ("vulnerable", "aws_cdk"),
    "pygoat":           ("vulnerable", "python"),
    "webgoat":          ("vulnerable", "java"),
    "railsgoat":        ("vulnerable", "ruby"),
    "dvwa":             ("vulnerable", "php"),
    "juice-shop":       ("vulnerable", "typescript"),
    "vulhub":           ("vulnerable", "docker"),
    # Added after tools/worklist.py reported Go as 811,194 lines of
    # well-maintained code with 62 lines of broken code to compare against.
    "govwa":            ("vulnerable", "go"),
    "go-test-bench":    ("vulnerable", "go"),
    #
    # Still open, and deliberately left open: C++ and Rust have no broken
    # counterpart. Two candidates were rejected rather than mislabelled --
    # one was 1.1 GB of vendored fuzzing engine with a handful of C files
    # attached, the other was an advisory database, which is metadata about
    # vulnerabilities rather than vulnerable code. Labelling either would
    # repeat the mistake that put teaching templates in the "clean" group and
    # made the noise rate look four times worse than it was. The worklist
    # will keep reporting this gap until a real one is found.
    # well-maintained — every finding here is a candidate false positive
    "tf-aws-s3-bucket": ("clean", "terraform"),
    "tf-aws-vpc":       ("clean", "terraform"),
    "tf-aws-iam":       ("clean", "terraform"),
    "tf-provider-rand": ("clean", "go"),
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
    # Splitting the teaching material out left Kubernetes and Docker with no
    # well-maintained population at all. These are production projects that
    # ship hardened manifests and compose files.
    "k8s-metrics-srv":  ("clean", "kubernetes"),
    "argo-cd":          ("clean", "kubernetes"),
    "traefik":          ("clean", "docker"),
    # teaching material and starter templates — short on purpose, so findings
    # here are usually right about the file and wrong as a noise measurement
    "cfn-templates":    ("examples", "cloudformation"),
    "cdk-examples":     ("examples", "aws_cdk"),
    "k8s-examples":     ("examples", "kubernetes"),
    "helm-charts":      ("examples", "kubernetes"),
    "compose-awesome":  ("examples", "docker"),
}

NATIVE = ["secrets", "resource_policy", "quality", "ast_metrics",
          "supply_chain", "doc_drift", "house_rules", "house_rules_ast",
          "assurance", "authored"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/tmp/corpus")
    ap.add_argument("--out", default="/tmp/corpus-out")
    ap.add_argument("--only", default=",".join(NATIVE))
    ap.add_argument("--holdout", choices=["exclude", "only", "both"], default="both",
                    help="exclude: tuning set only. only: the held-out set. "
                         "both (default): everything, reported separately.")
    args = ap.parse_args()

    root = Path(args.root)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    cfg = load_config(None)
    only = [p for p in args.only.split(",") if p]

    rows = []
    rule_counts: dict[str, Counter] = {p: Counter() for p in POPULATIONS}
    loc_by_pop: Counter = Counter()

    for name, (expectation, stack_label) in CORPUS.items():
        if args.holdout == "exclude" and name in HOLDOUT:
            continue
        if args.holdout == "only" and name not in HOLDOUT:
            continue
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
        loc_by_pop[expectation] += loc
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
            "holdout": name in HOLDOUT,
        })
        (outdir / f"{name}.json").write_text(json.dumps(rep.to_dict(), indent=2))

    print(f"\n  {'REPO':<20}{'STACK':<15}{'KIND':<11}{'LOC':>8}{'FIND':>6}"
          f"{'CRIT':>5}{'HIGH':>5}{'MED':>5}{'LOW':>5}{'SEC':>7}")
    for r in sorted(rows, key=lambda r: (r["expectation"], r["stack_label"], -r["per_kloc"])):
        print(f"  {r['repo']:<20}{r['stack_label']:<15}{r['expectation']:<11}{r['loc']:>8}"
              f"{r['findings']:>6}{r['critical']:>5}{r['high']:>5}{r['medium']:>5}"
              f"{r['low']:>5}{r['seconds']:>7}")

    notes = {
        "vulnerable": "a high count is the correct answer",
        "clean": "the false-positive measurement — this is the number that matters",
        "examples": "teaching material, reported separately and not counted as noise",
    }
    for kind in POPULATIONS:
        group = [r for r in rows if r["expectation"] == kind]
        if not group:
            continue
        total_loc = sum(r["loc"] for r in group)
        total_f = sum(r["findings"] for r in group)
        print(f"\n  {kind}: {total_f} findings over {total_loc:,} lines "
              f"= {total_f / (total_loc / 1000):.2f} per KLOC")
        print(f"    ({len(group)} repos; {notes[kind]})")

    print("\n  NOISIEST RULES ON WELL-MAINTAINED PRODUCTION CODE")
    print("  (every one of these is a candidate false positive)")
    print(f"    {'CLEAN':>6}{'VULN':>6}{'EXAMPLE':>9}   RULE")
    for rule, n in rule_counts["clean"].most_common(18):
        print(f"    {n:>6}{rule_counts['vulnerable'][rule]:>6}"
              f"{rule_counts['examples'][rule]:>9}   {rule}")

    # The comparison that says whether the tuning generalized. If the
    # well-maintained rate is much worse on repositories the rules never saw,
    # the rules were fitted to the practice set rather than to good code.
    tuned = [r for r in rows if not r["holdout"] and r["expectation"] == "clean"]
    held = [r for r in rows if r["holdout"] and r["expectation"] == "clean"]
    if tuned and held:
        def rate(g):
            lo = sum(x["loc"] for x in g) or 1
            return sum(x["findings"] for x in g) / (lo / 1000)
        t, h = rate(tuned), rate(held)
        print("\n  DOES THE TUNING GENERALIZE?")
        print(f"    well-maintained, tuned on ({len(tuned)} repos): {t:.2f} per KLOC")
        print(f"    well-maintained, HELD OUT ({len(held)} repos): {h:.2f} per KLOC")
        crit = sum(x["critical"] for x in held) + sum(x["high"] for x in held)
        print(f"    critical or high on held-out well-maintained code: {crit}")
        if t:
            ratio = h / t
            verdict = ("the rules behave the same on code they have never seen"
                       if ratio <= 1.5 else
                       "the held-out rate is materially worse — the rules may be "
                       "fitted to the\n    repositories they were tuned against")
            print(f"    ratio {ratio:.2f}x — {verdict}")

    print("\n  RULES THAT FIRE MOSTLY ON TEACHING MATERIAL")
    print("  (correct about the file, but not evidence of a noisy rule)")
    example_only = [
        (rule, n) for rule, n in rule_counts["examples"].most_common()
        if n >= 4 * max(1, rule_counts["clean"][rule])
    ]
    for rule, n in example_only[:12]:
        print(f"    {n:>6}{rule_counts['clean'][rule]:>6} on clean   {rule}")
    if not example_only:
        print("    none")

    (outdir / "summary.json").write_text(json.dumps({
        "rows": rows,
        "populations": list(POPULATIONS),
        "loc_by_population": dict(loc_by_pop),
        "rule_counts": {k: dict(v) for k, v in rule_counts.items()},
    }, indent=2))
    print(f"\n  wrote {outdir}/summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
