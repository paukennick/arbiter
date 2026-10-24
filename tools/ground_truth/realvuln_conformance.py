#!/usr/bin/env python3
"""Aggregate-only case-level conformance scoring for the approved RealVuln slice."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path, PurePosixPath
from typing import Any


BENCHMARK_ID = "realvuln-3.1.0-python-cwe89-licensed-subset"
REQUIRED_PROBE = "lang_python"
DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "docs" / "accuracy-benchmark-manifest.json"


class EvaluationError(ValueError):
    """Invalid or incomplete benchmark evaluation input."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvaluationError(f"cannot read evaluation input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"invalid JSON evaluation input: {path}") from exc
    if not isinstance(data, dict):
        raise EvaluationError(f"expected a JSON object: {path}")
    return data


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvaluationError(f"{label} must be a non-empty relative path")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    has_windows_drive = len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/"
    if path.is_absolute() or has_windows_drive or ".." in path.parts:
        raise EvaluationError(f"{label} must stay within its repository")
    return path.as_posix()


def _line(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise EvaluationError(f"{label} must be a positive line number")
    return value


def _candidate(manifest: dict[str, Any]) -> dict[str, Any]:
    candidates = manifest.get("candidate_sources")
    if not isinstance(candidates, list):
        raise EvaluationError("manifest candidate_sources must be a list")
    candidate = next(
        (item for item in candidates if isinstance(item, dict) and item.get("id") == BENCHMARK_ID),
        None,
    )
    if candidate is None:
        raise EvaluationError(f"manifest is missing candidate {BENCHMARK_ID}")
    if candidate.get("accuracy_claim_eligible") is not False:
        raise EvaluationError("RealVuln conformance must not be marked accuracy-claim eligible")
    if candidate.get("status") != "approved_for_aggregate_only_pilot":
        raise EvaluationError("RealVuln candidate is not approved for aggregate-only evaluation")
    if candidate.get("published_version") != "3.1.0" or candidate.get("ground_truth_version") != "3.0.0":
        raise EvaluationError("unexpected RealVuln benchmark or ground-truth version")
    benchmark_commit = candidate.get("benchmark_commit")
    if not isinstance(benchmark_commit, str) or len(benchmark_commit) != 40 or any(
        char not in "0123456789abcdef" for char in benchmark_commit
    ):
        raise EvaluationError("benchmark_commit must be a full lowercase Git SHA")

    repositories = candidate.get("selected_repositories")
    if not isinstance(repositories, list) or not repositories:
        raise EvaluationError("RealVuln candidate has no selected repositories")
    seen: set[str] = set()
    seen_ground_truth_ids: set[str] = set()
    for repo in repositories:
        if not isinstance(repo, dict):
            raise EvaluationError("selected repository entry must be an object")
        repo_id = repo.get("repo_id")
        if not isinstance(repo_id, str) or not repo_id or repo_id in seen:
            raise EvaluationError("selected repository IDs must be non-empty and unique")
        seen.add(repo_id)
        ground_truth_repo_id = repo.get("ground_truth_repo_id")
        if not isinstance(ground_truth_repo_id, str) or not ground_truth_repo_id:
            raise EvaluationError("selected repository ground_truth_repo_id must be non-empty")
        if ground_truth_repo_id in seen_ground_truth_ids:
            raise EvaluationError("selected ground-truth repository IDs must be unique")
        seen_ground_truth_ids.add(ground_truth_repo_id)
        if repo.get("source_license") not in {"MIT", "Unlicense"}:
            raise EvaluationError("selected repositories must have MIT or Unlicense at the pinned commit")
        commit = repo.get("source_commit")
        if not isinstance(commit, str) or len(commit) != 40 or any(
            char not in "0123456789abcdef" for char in commit
        ):
            raise EvaluationError("selected repository source_commit must be a full lowercase Git SHA")
        for count_key in ("vulnerable_cases", "safe_trap_cases"):
            if type(repo.get(count_key)) is not int or repo[count_key] < 0:
                raise EvaluationError(f"selected repository {count_key} must be a non-negative integer")

    aggregate = candidate.get("aggregate_metadata")
    if not isinstance(aggregate, dict):
        raise EvaluationError("RealVuln candidate aggregate_metadata must be an object")
    expected = {
        "selected_repositories": len(repositories),
        "selected_vulnerable_cases": sum(repo["vulnerable_cases"] for repo in repositories),
        "selected_safe_trap_cases": sum(repo["safe_trap_cases"] for repo in repositories),
    }
    for key, value in expected.items():
        if aggregate.get(key) != value:
            raise EvaluationError(f"manifest aggregate_metadata mismatch for {key}")
    return candidate


def _case_matches(finding: dict[str, Any], case: dict[str, Any], tolerance: int) -> bool:
    location = finding.get("location")
    if not isinstance(location, dict):
        return False
    try:
        finding_path = _relative_path(location.get("path"), "finding path")
    except EvaluationError:
        return False
    if finding_path != case["file"]:
        return False

    finding_cwes = finding.get("cwe")
    if not isinstance(finding_cwes, list) or not all(isinstance(cwe, str) for cwe in finding_cwes):
        return False
    if not set(case["cwes"]).intersection(finding_cwes):
        return False

    start = location.get("start_line")
    end = location.get("end_line", start)
    if end is None:
        end = start
    if type(start) is not int or start < 1 or type(end) is not int or end < start:
        return False
    return start <= case["end_line"] + tolerance and end >= case["start_line"] - tolerance


def _cases_for_repo(
    repo_id: str,
    repo: dict[str, Any],
    ground_truth_root: Path,
    reports_root: Path,
    tolerance: int,
    ground_truth_version: str,
) -> tuple[dict[str, int], int, bool, str, dict[str, int]]:
    truth = _read_json(ground_truth_root / repo_id / "ground-truth.json")
    if truth.get("repo_id") != repo["ground_truth_repo_id"] or truth.get("language") != "python":
        raise EvaluationError(f"ground-truth identity mismatch for selected repository {repo_id}")
    if truth.get("commit_sha") != repo["source_commit"]:
        raise EvaluationError(f"ground-truth source pin mismatch for selected repository {repo_id}")
    if truth.get("benchmark_version") != ground_truth_version:
        raise EvaluationError(f"ground-truth benchmark version mismatch for selected repository {repo_id}")
    if truth.get("ground_truth_version") != ground_truth_version:
        raise EvaluationError(f"ground-truth version mismatch for selected repository {repo_id}")

    cases: list[dict[str, Any]] = []
    counts = {"positive": 0, "safe_trap": 0}
    provenance_counts = {"manual_review": 0, "manually_verified": 0}
    entries = truth.get("findings")
    if not isinstance(entries, list):
        raise EvaluationError(f"ground-truth findings must be a list for selected repository {repo_id}")
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("primary_cwe") != "CWE-89":
            continue
        if entry.get("scoring") == "non_scoring":
            continue
        vulnerable = entry.get("is_vulnerable")
        if type(vulnerable) is not bool:
            raise EvaluationError(f"unscorable CWE-89 label in selected repository {repo_id}")
        evidence = entry.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("source") != "manual_review":
            raise EvaluationError(f"unexpected CWE-89 evidence provenance in selected repository {repo_id}")
        provenance_counts["manual_review"] += 1
        manually_verified = evidence.get("manually_verified")
        if manually_verified is True:
            provenance_counts["manually_verified"] += 1
        elif manually_verified not in (None, False):
            raise EvaluationError(f"invalid verification flag in selected repository {repo_id}")

        file_path = _relative_path(entry.get("file"), "ground-truth file")
        location = entry.get("location")
        if not isinstance(location, dict):
            raise EvaluationError(f"missing CWE-89 location in selected repository {repo_id}")
        start_line = _line(location.get("start_line"), "ground-truth start_line")
        end_line = _line(location.get("end_line", start_line), "ground-truth end_line")
        if end_line < start_line:
            raise EvaluationError(f"invalid CWE-89 line span in selected repository {repo_id}")
        accepted_cwes = entry.get("acceptable_cwes") or ["CWE-89"]
        if not isinstance(accepted_cwes, list) or not all(isinstance(cwe, str) for cwe in accepted_cwes):
            raise EvaluationError(f"invalid accepted CWE list in selected repository {repo_id}")
        cwes = set(accepted_cwes)
        cwes.add("CWE-89")
        cases.append(
            {
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "cwes": cwes,
                "vulnerable": vulnerable,
            }
        )
        counts["positive" if vulnerable else "safe_trap"] += 1

    if counts["positive"] != repo["vulnerable_cases"] or counts["safe_trap"] != repo["safe_trap_cases"]:
        raise EvaluationError(f"ground-truth label-count mismatch for selected repository {repo_id}")

    report = _read_json(reports_root / repo_id / "report.json")
    if report.get("profile") != "offline":
        raise EvaluationError(f"non-offline scan report for selected repository {repo_id}")
    probes = report.get("probes")
    python_probe = next(
        (probe for probe in probes if isinstance(probe, dict) and probe.get("name") == REQUIRED_PROBE),
        None,
    ) if isinstance(probes, list) else None
    if python_probe is None or python_probe.get("status") != "ran":
        raise EvaluationError(f"Python rules probe was not assessed for selected repository {repo_id}")

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise EvaluationError(f"scan report findings must be a list for selected repository {repo_id}")
    accepted_cwes = {"CWE-89"}
    for case in cases:
        accepted_cwes.update(case["cwes"])
    cwe89_findings = [
        finding
        for finding in findings
        if isinstance(finding, dict)
        and isinstance(finding.get("cwe"), list)
        and any(isinstance(cwe, str) and cwe in accepted_cwes for cwe in finding["cwe"])
    ]

    for case in cases:
        case["detected"] = any(_case_matches(finding, case, tolerance) for finding in cwe89_findings)
    matched_findings = sum(
        any(_case_matches(finding, case, tolerance) for case in cases)
        for finding in cwe89_findings
    )
    confusion = {
        "tp": sum(case["vulnerable"] and case["detected"] for case in cases),
        "fn": sum(case["vulnerable"] and not case["detected"] for case in cases),
        "fp": sum(not case["vulnerable"] and case["detected"] for case in cases),
        "tn": sum(not case["vulnerable"] and not case["detected"] for case in cases),
    }
    scorecard = report.get("scorecard")
    if not isinstance(scorecard, dict) or type(scorecard.get("withheld")) is not bool:
        raise EvaluationError(f"scan report has invalid scorecard metadata for selected repository {repo_id}")
    version = report.get("arbiter_version")
    if not isinstance(version, str) or not version:
        raise EvaluationError(f"scan report is missing Arbiter version for selected repository {repo_id}")
    return confusion, len(cwe89_findings) - matched_findings, scorecard["withheld"], version, provenance_counts


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _cluster_bootstrap(
    clusters: list[dict[str, int]],
    replicates: int,
    seed: int,
) -> dict[str, Any]:
    rng = random.Random(seed)
    precision_values: list[float] = []
    recall_values: list[float] = []
    for _ in range(replicates):
        sample = [rng.choice(clusters) for _ in clusters]
        tp = sum(row["tp"] for row in sample)
        fp = sum(row["fp"] for row in sample)
        fn = sum(row["fn"] for row in sample)
        if tp + fp:
            precision_values.append(tp / (tp + fp))
        if tp + fn:
            recall_values.append(tp / (tp + fn))
    return {
        "method": "repository-cluster bootstrap; percentile interval",
        "confidence_level": 0.95,
        "replicates": replicates,
        "seed": seed,
        "precision_interval": [
            _percentile(precision_values, 0.025),
            _percentile(precision_values, 0.975),
        ],
        "precision_valid_replicates": len(precision_values),
        "recall_interval": [
            _percentile(recall_values, 0.025),
            _percentile(recall_values, 0.975),
        ],
        "recall_valid_replicates": len(recall_values),
        "interpretation": (
            "Descriptive stability within this curated 11-repository benchmark subset only; "
            "not an interval for production repositories or a 99% certification."
        ),
    }


def evaluate(
    manifest: dict[str, Any],
    ground_truth_root: Path,
    reports_root: Path,
    tolerance: int = 10,
    bootstrap_replicates: int = 10_000,
    seed: int = 0,
) -> dict[str, Any]:
    if tolerance < 0:
        raise EvaluationError("line tolerance must be non-negative")
    if bootstrap_replicates < 1:
        raise EvaluationError("bootstrap_replicates must be positive")
    candidate = _candidate(manifest)
    selected = candidate["selected_repositories"]
    clusters: list[dict[str, int]] = []
    unmatched_findings = 0
    withheld_scorecards = 0
    versions: set[str] = set()
    provenance_counts = {"manual_review": 0, "manually_verified": 0}
    for repo in selected:
        confusion, unmatched, withheld, version, provenance = _cases_for_repo(
            repo["repo_id"],
            repo,
            ground_truth_root,
            reports_root,
            tolerance,
            candidate["ground_truth_version"],
        )
        clusters.append(confusion)
        unmatched_findings += unmatched
        withheld_scorecards += int(withheld)
        versions.add(version)
        for key in provenance_counts:
            provenance_counts[key] += provenance[key]
    if len(versions) != 1:
        raise EvaluationError("scan reports contain inconsistent Arbiter versions")

    totals = {key: sum(cluster[key] for cluster in clusters) for key in ("tp", "fn", "fp", "tn")}
    positives = totals["tp"] + totals["fn"]
    safe_traps = totals["fp"] + totals["tn"]
    aggregate = candidate["aggregate_metadata"]
    expected_provenance = {
        "manual_review": aggregate["selected_entries_manual_review"],
        "manually_verified": aggregate["selected_entries_explicitly_manually_verified"],
    }
    if provenance_counts != expected_provenance:
        raise EvaluationError("ground-truth evidence provenance does not match manifest aggregates")
    if positives != aggregate["selected_vulnerable_cases"] or safe_traps != aggregate["selected_safe_trap_cases"]:
        raise EvaluationError("evaluated label totals do not match manifest aggregates")

    precision_denominator = totals["tp"] + totals["fp"]
    summary = {
        "benchmark": {
            "id": candidate["id"],
            "version": candidate["published_version"],
            "ground_truth_version": candidate["ground_truth_version"],
            "commit": candidate["benchmark_commit"],
            "primary_cwe": "CWE-89",
        },
        "run": {
            "arbiter_version": next(iter(versions)),
            "profile": "offline",
            "probe": REQUIRED_PROBE,
            "repositories": len(selected),
            "python_probe_assessed_repositories": len(selected),
            "overall_scorecards_withheld": withheld_scorecards,
            "line_tolerance": tolerance,
            "cache_policy": "disabled by the pinned scan command; each scan uses --no-cache",
            "manifest_sha256": hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        },
        "labelled_cases": {
            "positive": positives,
            "safe_traps": safe_traps,
            "total": positives + safe_traps,
        },
        "label_provenance_counts": provenance_counts,
        "case_level_confusion": totals,
        "metrics": {
            "labelled_case_precision": {
                "numerator": totals["tp"],
                "denominator": precision_denominator,
                "value": _ratio(totals["tp"], precision_denominator),
            },
            "labelled_case_recall": {
                "numerator": totals["tp"],
                "denominator": positives,
                "value": _ratio(totals["tp"], positives),
            },
            "safe_trap_false_positive_rate": {
                "numerator": totals["fp"],
                "denominator": safe_traps,
                "value": _ratio(totals["fp"], safe_traps),
            },
            "cluster_bootstrap": _cluster_bootstrap(clusters, bootstrap_replicates, seed),
        },
        "unmatched_cwe89_findings_unassessed": unmatched_findings,
        "claim_scope": (
            "RealVuln 3.1.0 approved Python CWE-89 case-level conformance only; "
            "not Arbiter finding precision or production-population accuracy."
        ),
        "general_99_percent_claim": False,
    }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--ground-truth-root", type=Path, required=True)
    parser.add_argument("--reports-root", type=Path, required=True)
    parser.add_argument("--tolerance", type=int, default=10)
    parser.add_argument("--bootstrap-replicates", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--aggregate-only",
        action="store_true",
        help="required: emit counts and metrics only, never case, file, or rule details",
    )
    args = parser.parse_args(argv)
    if not args.aggregate_only:
        parser.error("--aggregate-only is required")
    try:
        result = evaluate(
            _read_json(args.manifest),
            args.ground_truth_root,
            args.reports_root,
            args.tolerance,
            args.bootstrap_replicates,
            args.seed,
        )
    except EvaluationError as exc:
        print(f"evaluation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
