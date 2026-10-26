"""Tests for the aggregate-only RealVuln CWE-89 evaluator."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
from helpers import ROOT

_spec = importlib.util.spec_from_file_location(
    "realvuln_conformance",
    ROOT / "tools" / "ground_truth" / "realvuln_conformance.py",
)
conformance = importlib.util.module_from_spec(_spec)
sys.modules["realvuln_conformance"] = conformance
_spec.loader.exec_module(conformance)


def _inputs(tmp_path: Path) -> tuple[dict, Path, Path]:
    repo_id = "public-app"
    ground_truth_repo_id = "public-ground-truth-id"
    candidate = {
        "id": conformance.BENCHMARK_ID,
        "status": "approved_for_aggregate_only_pilot",
        "accuracy_claim_eligible": False,
        "published_version": "3.1.0",
        "ground_truth_version": "3.0.0",
        "benchmark_commit": "a" * 40,
        "aggregate_metadata": {
            "selected_repositories": 1,
            "selected_vulnerable_cases": 1,
            "selected_safe_trap_cases": 1,
            "selected_entries_manual_review": 2,
            "selected_entries_explicitly_manually_verified": 1,
        },
        "selected_repositories": [
            {
                "repo_id": repo_id,
                "ground_truth_repo_id": ground_truth_repo_id,
                "source_commit": "b" * 40,
                "source_license": "MIT",
                "vulnerable_cases": 1,
                "safe_trap_cases": 1,
            }
        ],
    }
    manifest = {"candidate_sources": [candidate]}
    truth_root = tmp_path / "ground-truth"
    report_root = tmp_path / "reports"
    truth_dir = truth_root / repo_id
    report_dir = report_root / repo_id
    truth_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    truth = {
        "repo_id": ground_truth_repo_id,
        "language": "python",
        "benchmark_version": "3.0.0",
        "ground_truth_version": "3.0.0",
        "commit_sha": "b" * 40,
        "findings": [
            {
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89", "CWE-943"],
                "is_vulnerable": True,
                "file": "app.py",
                "location": {"start_line": 10, "end_line": 11},
                "evidence": {"source": "manual_review", "manually_verified": True},
            },
            {
                "primary_cwe": "CWE-89",
                "acceptable_cwes": ["CWE-89"],
                "is_vulnerable": False,
                "file": "app.py",
                "location": {"start_line": 30, "end_line": 30},
                "evidence": {"source": "manual_review"},
            },
        ],
    }
    report = {
        "profile": "offline",
        "arbiter_version": "0.1.0",
        "scorecard": {"withheld": True},
        "probes": [{"name": "lang_python", "status": "ran"}],
        "findings": [
            {
                "rule_id": "arbiter/python.sql-injection",
                "cwe": ["CWE-89"],
                "location": {"path": "app.py", "start_line": 12, "end_line": 12},
            },
            {
                "rule_id": "arbiter/python.other",
                "cwe": ["CWE-79"],
                "location": {"path": "app.py", "start_line": 30, "end_line": 30},
            },
            {
                "rule_id": "arbiter/python.sql-injection",
                "cwe": ["CWE-89"],
                "location": {"path": "unlabelled.py", "start_line": 1, "end_line": 1},
            },
        ],
    }
    (truth_dir / "ground-truth.json").write_text(json.dumps(truth), encoding="utf-8")
    (report_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return manifest, truth_root, report_root



def test_evaluate_rejects_ground_truth_benchmark_version_mismatch(tmp_path: Path) -> None:
    manifest, truth_root, report_root = _inputs(tmp_path)
    truth_path = truth_root / "public-app" / "ground-truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    truth["benchmark_version"] = "3.1.0"
    truth_path.write_text(json.dumps(truth), encoding="utf-8")

    with pytest.raises(conformance.EvaluationError, match="ground-truth benchmark version mismatch"):
        conformance.evaluate(manifest, truth_root, report_root)


def test_evaluate_maps_ground_truth_id_and_reports_case_metrics(tmp_path: Path) -> None:
    manifest, truth_root, report_root = _inputs(tmp_path)
    result = conformance.evaluate(manifest, truth_root, report_root, bootstrap_replicates=100)
    assert result["case_level_confusion"] == {"tp": 1, "fn": 0, "fp": 0, "tn": 1}
    assert result["unmatched_cwe89_findings_unassessed"] == 1
    assert result["metrics"]["labelled_case_precision"]["value"] == 1.0
    assert result["metrics"]["labelled_case_recall"]["value"] == 1.0
    assert result["run"]["overall_scorecards_withheld"] == 1


def test_multi_cwe_scores_manual_review_cases_and_excludes_tool_labels(tmp_path: Path) -> None:
    manifest, truth_root, report_root = _inputs(tmp_path)
    truth_path = truth_root / "public-app" / "ground-truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    truth["findings"].extend(
        [
            {
                "primary_cwe": "CWE-79",
                "acceptable_cwes": ["CWE-79"],
                "is_vulnerable": True,
                "file": "app.py",
                "location": {"start_line": 50, "end_line": 51},
                "evidence": {"source": "manual_review"},
            },
            {
                "primary_cwe": "CWE-79",
                "acceptable_cwes": ["CWE-79"],
                "is_vulnerable": False,
                "file": "app.py",
                "location": {"start_line": 70, "end_line": 70},
                "evidence": {"source": "manual_review"},
            },
            {
                "primary_cwe": "CWE-22",
                "is_vulnerable": True,
                "file": "excluded.py",
                "location": {"start_line": 1, "end_line": 1},
                "evidence": {"source": "our-scanner"},
            },
        ]
    )
    truth_path.write_text(json.dumps(truth), encoding="utf-8")

    report_path = report_root / "public-app" / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["findings"].extend(
        [
            {
                "rule_id": "arbiter/python.xss",
                "cwe": ["CWE-79"],
                "location": {"path": "app.py", "start_line": 52, "end_line": 52},
            },
            {
                "rule_id": "arbiter/python.xss",
                "cwe": ["CWE-79"],
                "location": {"path": "app.py", "start_line": 70, "end_line": 70},
            },
            {
                "rule_id": "arbiter/python.path-traversal",
                "cwe": ["CWE-22"],
                "location": {"path": "excluded.py", "start_line": 1, "end_line": 1},
            },
        ]
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = conformance.evaluate_multi_cwe(
        manifest,
        truth_root,
        report_root,
        bootstrap_replicates=100,
    )

    assert result["labelled_cases"] == {"positive": 2, "safe_traps": 2, "total": 4}
    assert result["case_level_confusion"] == {"tp": 2, "fn": 0, "fp": 1, "tn": 1}
    assert result["metrics"]["labelled_case_precision"]["value"] == pytest.approx(2 / 3)
    assert result["metrics"]["labelled_case_recall"]["value"] == 1
    assert result["metrics"]["repository_cluster_bootstrap"]["replicates"] == 100
    assert result["by_primary_cwe"]["CWE-89"]["case_level_confusion"] == {
        "tp": 1,
        "fn": 0,
        "fp": 0,
        "tn": 1,
    }
    assert result["by_primary_cwe"]["CWE-79"]["repositories_with_labels"] == 1
    assert result["label_provenance"]["available_cases_by_source"] == {
        "manual_review": 4,
        "our-scanner": 1,
    }
    assert result["label_provenance"]["available_label_count"] == 5
    assert result["label_provenance"]["excluded_cases_by_source"] == {"our-scanner": 1}
    assert result["label_provenance"]["included_cases_with_manually_verified_flag"] == 1
    assert result["unmatched_findings_unassessed"] == 2
    assert result["accuracy_claim_eligible"] is False
    assert result["general_99_percent_claim"] is False

    historical = conformance.evaluate(manifest, truth_root, report_root, bootstrap_replicates=100)
    assert historical["case_level_confusion"] == {"tp": 1, "fn": 0, "fp": 0, "tn": 1}


def test_evaluate_does_not_match_a_zero_end_line(tmp_path: Path) -> None:
    manifest, truth_root, report_root = _inputs(tmp_path)
    report_path = report_root / "public-app" / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["findings"][0]["location"]["end_line"] = 0
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = conformance.evaluate(manifest, truth_root, report_root, bootstrap_replicates=100)
    assert result["case_level_confusion"] == {"tp": 0, "fn": 1, "fp": 0, "tn": 1}
    assert result["unmatched_cwe89_findings_unassessed"] == 2


def test_evaluate_requires_the_python_probe_to_have_run(tmp_path):
    manifest, truth_root, report_root = _inputs(tmp_path)
    report_path = report_root / "public-app" / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["probes"][0]["status"] = "not_assessed"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(conformance.EvaluationError, match="not assessed"):
        conformance.evaluate(manifest, truth_root, report_root)


def test_evaluate_rejects_unlicensed_selected_sources_and_label_count_drift(tmp_path):
    manifest, truth_root, report_root = _inputs(tmp_path)
    manifest["candidate_sources"][0]["selected_repositories"][0]["source_license"] = "NOASSERTION"
    with pytest.raises(conformance.EvaluationError, match="MIT or Unlicense"):
        conformance.evaluate(manifest, truth_root, report_root)

    manifest["candidate_sources"][0]["selected_repositories"][0]["source_license"] = "MIT"
    manifest["candidate_sources"][0]["selected_repositories"][0]["vulnerable_cases"] = 2
    manifest["candidate_sources"][0]["aggregate_metadata"]["selected_vulnerable_cases"] = 2
    with pytest.raises(conformance.EvaluationError, match="label-count mismatch"):
        conformance.evaluate(manifest, truth_root, report_root)


def test_evaluate_rejects_non_offline_reports_and_path_traversal(tmp_path):
    manifest, truth_root, report_root = _inputs(tmp_path)
    report_path = report_root / "public-app" / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["profile"] = "assisted"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(conformance.EvaluationError, match="non-offline"):
        conformance.evaluate(manifest, truth_root, report_root)

    report["profile"] = "offline"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    truth_path = truth_root / "public-app" / "ground-truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    truth["findings"][0]["file"] = "../escape.py"
    truth_path.write_text(json.dumps(truth), encoding="utf-8")
    with pytest.raises(conformance.EvaluationError, match="must stay within its repository"):
        conformance.evaluate(manifest, truth_root, report_root)


def test_cluster_bootstrap_is_seeded_and_reports_descriptive_intervals():
    clusters = [
        {"tp": 2, "fn": 0, "fp": 1, "tn": 2},
        {"tp": 1, "fn": 1, "fp": 0, "tn": 3},
    ]

    first = conformance._cluster_bootstrap(clusters, 1000, 17)
    second = conformance._cluster_bootstrap(clusters, 1000, 17)

    assert first == second
    assert first["method"] == "repository-cluster bootstrap; percentile interval"
    assert first["precision_interval"][0] <= first["precision_interval"][1]
    assert first["recall_interval"][0] <= first["recall_interval"][1]
    assert "not an interval for production repositories" in first["interpretation"]


def test_committed_manifest_registers_the_pinned_licensed_subset():
    manifest = json.loads((ROOT / "docs" / "accuracy-benchmark-manifest.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "docs" / "accuracy-benchmark-manifest.schema.json").read_text(encoding="utf-8"))
    candidate = conformance._candidate(manifest)
    candidate_schema = schema["properties"]["candidate_sources"]["items"]["properties"]

    assert len(candidate["selected_repositories"]) == 11
    assert all(repo["source_license"] in {"MIT", "Unlicense"} for repo in candidate["selected_repositories"])
    assert candidate["aggregate_metadata"]["selected_vulnerable_cases"] == 26
    assert candidate["aggregate_metadata"]["selected_safe_trap_cases"] == 34
    assert re.fullmatch(candidate_schema["id"]["pattern"], candidate["id"])


def test_committed_multi_cwe_run_is_aggregate_only_and_digest_bound():
    manifest = json.loads((ROOT / "docs" / "accuracy-benchmark-manifest.json").read_text(encoding="utf-8"))
    candidate = conformance._candidate(manifest)
    run = candidate["multi_cwe_evaluation_run"]
    report_path = ROOT / "docs" / run["report_path"]
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)

    assert hashlib.sha256(report_bytes).hexdigest() == run["report_sha256"]
    assert report["status"] == "completed_aggregate_only"
    assert report["execution"]["target_code_executed"] is False
    assert report["evaluation"]["case_level_confusion"] == run["case_level_confusion"]
    assert report["evaluation"]["accuracy_claim_eligible"] is False
    assert report["evaluation"]["general_99_percent_claim"] is False
    assert "findings" not in report
