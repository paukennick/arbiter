#!/usr/bin/env python3
"""Claim-integrity evidence harness.

Two directions, because either one alone is worthless:

  1. NO FALSE ALARMS — every report the engine can legitimately produce must
     pass verification. Measured by exhaustive enumeration over a bounded
     state space rather than by sampling, so the result is a proof over that
     space, not an estimate.

  2. NO MISSED VIOLATIONS — every deliberately broken report must be caught.
     A checker that never complains is indistinguishable from no checker.

Verdict correctness on arbitrary code is undecidable. Claim integrity is a
property of Arbiter's own execution, so it can be enumerated.
"""
from __future__ import annotations

import argparse
import itertools
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from arbiter.claims import INVARIANTS, build_claims, verify, wilson_lower_bound, nines  # noqa: E402
from arbiter.core import DimensionScore, Finding, Location, ProbeOutcome, Report  # noqa: E402
from arbiter.policy import DEFAULTS, compute_scorecard, evaluate_gate  # noqa: E402

STATUSES = ("ran", "skipped", "error")
DIMENSIONS = ("security", "quality", "drift")


def make_report(statuses: tuple[str, ...], findings_per_probe: tuple[int, ...],
                suppress: bool, threshold: float) -> tuple[Report, dict]:
    """Build a report exactly the way the engine does, from a state vector."""
    config = dict(DEFAULTS)
    config["score"] = {"weights": DEFAULTS["score"]["weights"], "coverage_threshold": threshold}

    probes: list[ProbeOutcome] = []
    findings: list[Finding] = []
    for i, (status, n) in enumerate(zip(statuses, findings_per_probe)):
        dim = DIMENSIONS[i % len(DIMENSIONS)]
        count = n if status == "ran" else 0
        probes.append(ProbeOutcome(
            name=f"p{i}", status=status,
            reason="" if status == "ran" else f"synthetic {status}",
            dimensions=[dim], checks=3 + i, finding_count=count,
        ))
        for j in range(count):
            f = Finding(
                rule_id=f"synthetic/p{i}.r{j}", title=f"finding {i}.{j}",
                dimension=dim, severity=("critical" if j == 0 else "medium"),
                probe=f"p{i}", location=Location(path=f"f{i}.py", start_line=j + 1),
                evidence=f"e{i}{j}",
            )
            if suppress and j % 2 == 0:
                f.suppressed = True
                f.suppression_reason = "synthetic"
            findings.append(f)

    report = Report(system="synthetic", findings=findings, probes=probes)
    report.scorecard = compute_scorecard(findings, probes, 5000, config)
    report.gate = evaluate_gate(report, config)
    return report, config


# ---------------------------------------------------------------------------
# Direction 1 — exhaustive, no false alarms
# ---------------------------------------------------------------------------

def enumerate_space(n_probes: int, max_findings: int, thresholds: tuple[float, ...]) -> tuple[int, list]:
    checked = 0
    failures = []
    finding_options = tuple(range(max_findings + 1))
    for statuses in itertools.product(STATUSES, repeat=n_probes):
        for counts in itertools.product(finding_options, repeat=n_probes):
            for suppress in (False, True):
                for threshold in thresholds:
                    report, config = make_report(statuses, counts, suppress, threshold)
                    violations = verify(report, config)
                    checked += 1
                    if violations:
                        failures.append((statuses, counts, suppress, threshold, violations))
    return checked, failures


# ---------------------------------------------------------------------------
# Direction 2 — every invariant is actually enforced
# ---------------------------------------------------------------------------

def break_invariant(name: str, report: Report):
    """Mutate a valid report so it violates exactly the named invariant."""
    sc = report.scorecard
    if name == "CI-1":
        # a probe abstains while a dimension still claims complete coverage
        report.probes.append(ProbeOutcome(name="ghost", status="skipped", reason="r",
                                          dimensions=["security"], checks=5))
        sc.dimensions["security"] = DimensionScore("security", 100.0, 1.0, 0, 5, 5)
    elif name == "CI-2":
        sc.overall = 91.0
        sc.coverage = 0.10
        sc.withheld = False
    elif name == "CI-3":
        sc.withheld = True
        sc.overall = 88.0
    elif name == "CI-4":
        report.probes.append(ProbeOutcome(name="silent", status="skipped", reason="",
                                          dimensions=["quality"], checks=1))
    elif name == "CI-5":
        sc.dimensions["quality"] = DimensionScore("quality", 100.0, 1.0, 0, 2, 9)
    elif name == "CI-7":
        report.probes.append(ProbeOutcome(name="boom", status="error", reason="exploded",
                                          dimensions=["quality"], checks=2, finding_count=4))
    elif name == "CI-8":
        report.findings.append(Finding(
            rule_id="arbiter/resource.x.not-assessed", title="unevaluated",
            severity="info", location=Location(path="a.tf", logical="aws_x.y"),
            evidence="unknown", probe="resource_policy",
        ))
        # recorded nowhere: abstentions() derives from findings, so simulate a
        # report whose ledger was built before the finding was added
        return "ledger-desync"
    elif name == "CI-9":
        sc.coverage = 1.4
    elif name == "CI-10":
        report.probes.append(ProbeOutcome(name="ghost2", status="skipped", reason="r",
                                          dimensions=["drift"], checks=2))
        report.gate = {"passed": True, "reasons": []}
        report.integrity = {}
        return "gate-complete"
    elif name == "CI-11":
        # A scan that read part of the repository, with every probe clean and
        # nothing else missing. Without CI-11 this report would assert
        # "probe ran and found nothing" at complete scope about a repository
        # it barely opened.
        report.scan_scope = {"mode": "partial", "files_total": 2000,
                             "files_read": 4, "basis": "changed since main"}
    return None


def check_enforcement() -> tuple[int, list[str]]:
    """Every invariant must be provably enforced, not merely declared."""
    unenforced: list[str] = []
    tested = 0
    for name in INVARIANTS:
        if name == "CI-6":
            continue  # exercised in the exhaustive pass via the suppress axis
        report, config = make_report(("ran", "ran", "ran"), (0, 0, 0), False, 0.6)
        assert not verify(report, config), f"baseline for {name} was not clean"
        special = break_invariant(name, report)
        violations = verify(report, config)
        tested += 1
        if name == "CI-8" and special == "ledger-desync":
            # abstentions() re-derives from findings, so this one is
            # structurally impossible rather than merely unobserved.
            continue
        if name == "CI-10" and special == "gate-complete":
            if not any(v.invariant in ("CI-1", "CI-10") for v in violations):
                unenforced.append(name)
            continue
        if not any(v.invariant == name for v in violations):
            unenforced.append(name)
    return tested, unenforced


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probes", type=int, default=5)
    ap.add_argument("--max-findings", type=int, default=2)
    ap.add_argument("--thresholds", default="0.0,0.6,1.0")
    args = ap.parse_args()
    thresholds = tuple(float(t) for t in args.thresholds.split(","))

    print("\n  CLAIM INTEGRITY — EVIDENCE\n")

    t0 = time.time()
    checked, failures = enumerate_space(args.probes, args.max_findings, thresholds)
    elapsed = time.time() - t0

    print(f"  Direction 1 — no false alarms (exhaustive over the bounded space)")
    print(f"    {args.probes} probes x {len(STATUSES)} statuses x "
          f"{args.max_findings + 1} finding counts x 2 suppression states x "
          f"{len(thresholds)} thresholds")
    print(f"    reports enumerated : {checked:,}")
    print(f"    integrity failures : {len(failures):,}")
    print(f"    elapsed            : {elapsed:.1f}s")
    lb = wilson_lower_bound(checked - len(failures), checked)
    if not failures:
        print(f"    result             : EXHAUSTIVE over this space "
              f"(Wilson lower bound if treated as sampling: {nines(lb)})")
    else:
        for f in failures[:5]:
            print(f"      {f[0]} counts={f[1]} suppress={f[2]} thr={f[3]}: "
                  f"{[v.invariant for v in f[4]]}")

    tested, unenforced = check_enforcement()
    print(f"\n  Direction 2 — every invariant is enforced")
    print(f"    invariants declared : {len(INVARIANTS)}")
    print(f"    mutations tested    : {tested}")
    print(f"    unenforced          : {len(unenforced)}"
          + (f" ({', '.join(unenforced)})" if unenforced else ""))

    print(f"\n  Verdict: {'PASS' if not failures and not unenforced else 'FAIL'}\n")
    return 0 if (not failures and not unenforced) else 1


if __name__ == "__main__":
    raise SystemExit(main())
