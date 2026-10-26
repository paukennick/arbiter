"""Repository-clustered precision bounds (ARB-168): findings in one
repository are not independent, so they are worth fewer than their count."""
from __future__ import annotations

import importlib.util
import random
import sys

import pytest
from helpers import ROOT

from arbiter import precision as P


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


PL = _load("precision_ledger")
RULE = "arbiter/python.sql-injection"


def test_findings_that_copy_their_repository_count_as_one_each():
    """Every finding in a repository has that repository's label: n_eff is
    the number of repositories."""
    clusters = [(20, 20)] * 30 + [(0, 20)] * 10
    d = P.cluster_design_effect(clusters)
    assert d["deff_source"] == "estimated"
    assert d["n_eff"] == pytest.approx(40, rel=0.01)
    assert d["icc"] == pytest.approx(1.0, abs=0.01)


def test_independent_findings_keep_their_count():
    rng = random.Random(1)
    sizes = [rng.randrange(1, 40) for _ in range(300)]
    clusters = [(sum(rng.random() < 0.85 for _ in range(m)), m) for m in sizes]
    n = sum(sizes)
    d = P.cluster_design_effect(clusters)
    assert d["n_eff"] == pytest.approx(n, rel=0.15)
    assert abs(d["icc"]) < 0.02


def test_one_finding_per_repository_is_independent_by_construction():
    d = P.cluster_design_effect([(1, 1)] * 70 + [(0, 1)] * 30)
    assert d["deff"] == 1.0 and d["n_eff"] == 100


def test_a_single_repository_is_worth_one_finding():
    """Correlation is not estimable from one repository; the worst case
    (its findings are copies) is used, never the independent count."""
    d = P.cluster_design_effect([(40, 50)])
    assert d["clusters"] == 1 and d["n_eff"] == 1.0
    assert d["deff_source"].startswith("worst case")


def test_all_true_positives_fall_back_to_the_number_of_repositories():
    d = P.cluster_design_effect([(10, 10)] * 7)
    assert d["n_eff"] == 7.0 and d["deff_source"].startswith("worst case")


def test_a_borrowed_icc_replaces_only_the_worst_case():
    worst = P.cluster_design_effect([(10, 10)] * 7)
    borrowed = P.cluster_design_effect([(10, 10)] * 7, icc=0.1)
    assert borrowed["deff"] == pytest.approx(1 + 9 * 0.1) and borrowed["n_eff"] > worst["n_eff"]
    est = P.cluster_design_effect([(8, 10), (10, 10), (9, 10)], icc=0.9)
    assert est["deff_source"] == "estimated"


def test_clustering_never_tightens_the_bound():
    rng = random.Random(2)
    clusters = [(sum(rng.random() < 0.9 for _ in range(5)), 5) for _ in range(200)]
    tp = sum(t for t, _ in clusters)
    n = sum(m for _, m in clusters)
    d = P.cluster_design_effect(clusters)
    assert d["deff"] >= 1.0
    assert P.clustered_wilson(tp / n, n, d["deff"])[0] <= P.wilson(tp, n)[0] + 1e-12


def test_stratified_design_compares_each_finding_with_its_own_stratum():
    """Two strata at different rates, each repository holding one of each:
    pooling them as one sample would read the rate gap as clustering."""
    rows = [{"weight": 100, "tp": 100, "fp": 0, "clusters": {f"r{i}": [10, 0] for i in range(10)}},
            {"weight": 100, "tp": 50, "fp": 50,
             "clusters": {f"r{i}": [1, 1] for i in range(50)}}]
    d = P.cluster_design(rows)
    assert d["deff"] == 1.0


def test_juliet_variants_and_benchmark_files_are_their_own_clusters():
    j = {"source": "juliet-java", "repo": "juliet-java-1.3",
         "path": "Java/src/testcases/CWE89/s01/CWE89_SQL_Injection__connect_tcp_executeBatch_07.java"}
    j2 = dict(j, path=j["path"].replace("_07.java", "_81a.java"))
    o = {"source": "owasp-java", "repo": "owasp-benchmark-java", "path": "src/BenchmarkTest00001.java"}
    g = {"source": "gold-model", "repo": "py-celery", "path": "a.py"}
    assert PL.finding_cluster([j]) == PL.finding_cluster([j2]) == \
        "juliet-java:CWE89_SQL_Injection__connect_tcp_executeBatch"
    assert PL.finding_cluster([o]) == "owasp-java:src/BenchmarkTest00001.java"
    assert PL.finding_cluster([g]) == "py-celery"


def _recs(per_repo: dict[str, tuple[int, int]]):
    out = []
    for repo, (tp, fp) in sorted(per_repo.items()):
        for i in range(tp + fp):
            for m in ("model-a", "model-b"):
                out.append({"finding_id": f"{repo}-{i}", "rule_id": RULE, "label": "tp" if i < tp else "fp",
                            "labeller": m, "source": "gold", "held_out": True, "role": "labeller", "repo": repo,
                            "stratum_size": 400, "stratum_held_out_size": 400, "rule_population": 400,
                            "rule_held_out_population": 400})
    return out


def test_ledger_reports_the_clustered_bound_next_to_the_current_one():
    led = PL.build(_recs({f"r{i}": (9, 1) for i in range(10)} | {"big": (100, 0)}), None, "2026-10-26", {RULE})
    cl = led["clustered"]["rules"][RULE]
    assert cl["design"]["clusters"] == 11 and cl["design"]["n"] == 200
    assert cl["wilson_lower"] <= led["rules"][RULE]["wilson_lower"]
    assert cl["bootstrap"]["lower"] is not None
    assert led["clustered"]["tier"]["rules"] == led["tier"]["rules"]


def test_bootstrap_says_degenerate_instead_of_reporting_one():
    led = PL.build(_recs({f"r{i}": (10, 0) for i in range(5)}), None, "2026-10-26", set())
    b = led["clustered"]["rules"][RULE]["bootstrap"]
    assert b["lower"] is None and b["note"].startswith("degenerate")
