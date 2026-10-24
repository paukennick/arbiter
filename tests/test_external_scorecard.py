"""External conformance scorecard (ARB-120): case units, matching, intervals,
run-record shape and the aggregate-only guarantee. No network, no
benchmark: everything runs on tiny synthetic inputs built here."""
from __future__ import annotations

import importlib.util
import json
import re
import sys

import pytest
from helpers import ROOT

from arbiter.precision import wilson

_spec = importlib.util.spec_from_file_location(
    "external_scorecard", ROOT / "tools" / "ground_truth" / "external_scorecard.py")
es = importlib.util.module_from_spec(_spec)
sys.modules["external_scorecard"] = es
_spec.loader.exec_module(es)
gb = es.gb

ALIASES = {"CWE-330": ["CWE-338"], "CWE-89": ["CWE-564"]}
TEST_DIR = "src/testcode"


def _f(rule, path, cwe, line=5):
    return {"rule": rule, "path": path, "line": line, "cwe": cwe}


def _owasp_fixture():
    expected = {
        "T001": {"category": "sqli", "real": True, "cwe": "CWE-89"},
        "T002": {"category": "sqli", "real": False, "cwe": "CWE-89"},
        "T003": {"category": "sqli", "real": True, "cwe": "CWE-89"},
        "T004": {"category": "weakrand", "real": True, "cwe": "CWE-330"},
        "T005": {"category": "weakrand", "real": False, "cwe": "CWE-330"},
        "T006": {"category": "xpathi", "real": True, "cwe": "CWE-643"},
    }
    findings = [
        _f("arbiter/java.sql", f"{TEST_DIR}/T001.java", ["CWE-89"]),
        _f("arbiter/java.sql", f"{TEST_DIR}/T002.java", ["CWE-564"]),      # alias
        _f("arbiter/java.rand", f"{TEST_DIR}/T004.java", ["CWE-338"]),     # alias
        _f("arbiter/java.rand", f"{TEST_DIR}/T006.java", ["CWE-338"]),     # wrong CWE for the case
        _f("arbiter/java.sql", "src/helpers/Db.java", ["CWE-89"]),         # harness, ignored
    ]
    return expected, findings


# --- OWASP ---------------------------------------------------------------------

def test_owasp_units_follow_the_case_cwe_and_benchmark_aliases():
    expected, findings = _owasp_fixture()
    sc = es.owasp_score(expected, findings, ALIASES, TEST_DIR, {"CWE-89", "CWE-338"}, "java")
    by = {(u.stratum, u.vulnerable, u.flagged) for u in sc.units}
    assert len(sc.units) == 6
    assert es.confusion(sc.units) == {"tp": 2, "fn": 2, "fp": 1, "tn": 1}
    assert ("CWE-643", True, False) in by, "a finding with another CWE does not flag the case"
    assert sc.unassessed == {"outside case files (benchmark harness)": 1,
                             "finding CWE not the case's CWE": 1}
    assert sc.strata["CWE-330"].in_scope and not sc.strata["CWE-643"].in_scope


def test_owasp_counts_match_gold_benchmark_score_recall():
    """The scorecard and the existing recall scorer agree on every CWE."""
    expected, findings = _owasp_fixture()
    sc = es.owasp_score(expected, findings, ALIASES, TEST_DIR, set(), "java")
    ref = gb.score_recall(expected, findings, ALIASES, TEST_DIR)
    for r in ref["per_cwe"]:
        mine = es.confusion([u for u in sc.units if u.stratum == r["cwe"]])
        assert mine == {k: r[k] for k in ("tp", "fn", "fp", "tn")}, r["cwe"]


# --- Juliet --------------------------------------------------------------------

@pytest.mark.parametrize("stem,case", [
    ("CWE89_SQL_Injection__Environment_executeBatch_01", "CWE89_SQL_Injection__Environment_executeBatch_01"),
    ("CWE89_SQL_Injection__Environment_executeBatch_54a", "CWE89_SQL_Injection__Environment_executeBatch_54"),
    ("CWE89_SQL_Injection__Environment_executeBatch_54e", "CWE89_SQL_Injection__Environment_executeBatch_54"),
    ("CWE78_OS_Command_Injection__File_81_bad", "CWE78_OS_Command_Injection__File_81"),
    ("CWE78_OS_Command_Injection__File_81_goodG2B", "CWE78_OS_Command_Injection__File_81"),
    ("CWE78_OS_Command_Injection__File_81_base", "CWE78_OS_Command_Injection__File_81"),
    ("CWE78_OS_Command_Injection__File_81a", "CWE78_OS_Command_Injection__File_81"),
    ("Helper", "Helper"),
])
def test_juliet_case_id_joins_the_files_of_one_case(stem, case):
    assert es.juliet_case_id(stem) == case


def test_juliet_each_case_is_one_vulnerable_and_one_safe_unit():
    d = "CWE89_SQL_Injection"
    files = ["s01/CWE89_X_01.java", "s01/CWE89_X_54a.java", "s01/CWE89_X_54b.java", "s02/CWE89_Y_02.java"]
    sides = {("s01/CWE89_X_01.java", 10): "bad", ("s01/CWE89_X_01.java", 40): "good",
             ("s01/CWE89_X_54b.java", 7): "bad", ("s02/CWE89_Y_02.java", 3): None}
    findings = {d: [_f("arbiter/java.sql", "s01/CWE89_X_01.java", ["CWE-89"], 10),
                    _f("arbiter/java.sql", "s01/CWE89_X_01.java", ["CWE-89"], 40),
                    _f("arbiter/java.sql", "s01/CWE89_X_54b.java", ["CWE-564"], 7),
                    _f("arbiter/java.sql", "s02/CWE89_Y_02.java", ["CWE-89"], 3),
                    _f("arbiter/java.other", "s02/CWE89_Y_02.java", ["CWE-117"], 3)]}
    sc = es.juliet_score({d: files}, findings, lambda f: sides[(f["path"], f["line"])], {"CWE-89"})
    assert len(sc.units) == 6, "three cases (01, 54, 02), two units each"
    assert es.confusion(sc.units) == {"tp": 2, "fn": 1, "fp": 1, "tn": 2}
    assert sc.unassessed == {"finding CWE not the directory's CWE": 1, "outside any bad/good method": 1}
    assert sc.findings == 5 and sc.strata[d].cwe == "CWE-89" and sc.strata[d].in_scope


# --- CVE fix pairs ---------------------------------------------------------------

PAIR = {"repo": "o/r", "language": "python", "cwes": ["CWE-78"], "selected_for": "CWE-78"}
OLD = ["a", "b", "run(cmd)", "d", "e", "f", "g", "h"]
NEW = ["a", "b", "run(shlex.quote(cmd))", "d", "e", "f", "g", "h"]
TEXTS = {"m.py": (OLD, NEW)}


def test_cve_vulnerable_side_hit_only_is_tp_and_tn():
    v, s, skipped = es.cve_pair_units(PAIR, [_f("arbiter/python.cmd", "m.py", ["CWE-78"], 3)], [],
                                      TEXTS, {"CWE-78"})
    assert (v.vulnerable, v.flagged, s.vulnerable, s.flagged) == (True, True, False, False)
    assert v.in_scope and v.cluster == "o/r" and not skipped


def test_cve_finding_that_survives_the_fix_is_tp_and_fp():
    f = _f("arbiter/python.cmd", "m.py", ["CWE-77"], 3)  # alias of CWE-78
    v, s, _ = es.cve_pair_units(PAIR, [f], [f], TEXTS, {"CWE-78"})
    assert v.flagged and s.flagged


def test_cve_ignores_project_rules_other_cwes_and_far_lines():
    vuln = [_f("arbiter/supply.unpinned-action", "m.py", ["CWE-78"], 3),
            _f("arbiter/python.other", "m.py", ["CWE-117"], 3),
            _f("arbiter/python.cmd", "m.py", ["CWE-78"], 8)]   # 5 lines from the hunk
    v, s, skipped = es.cve_pair_units(PAIR, vuln, [], TEXTS, {"CWE-78"})
    assert not v.flagged and not s.flagged
    assert skipped == {"project-level rule": 1, "finding CWE not the advisory's CWE": 1,
                       "away from the hunks the fix changed": 1}


def test_cve_pure_insertion_hunk_uses_the_same_window_on_both_sides():
    """A fix that only adds a guard leaves the sink line unchanged: the empty
    old-side hunk still gets the NEAR window, so the sink can match."""
    old = ["a", "b", "run(cmd)", "d"]
    new = ["a", "b", "if bad(cmd): return", "run(cmd)", "d"]
    texts = {"m.py": (old, new)}
    hit = [_f("arbiter/python.cmd", "m.py", ["CWE-78"], 3)]
    v, _, _ = es.cve_pair_units(PAIR, hit, [], texts, {"CWE-78"})
    assert v.flagged


def test_cve_strata_and_scope_are_per_language():
    pairs = [PAIR, {**PAIR, "language": "go", "repo": "o/g"}]
    st = es.cve_truth(pairs, {"python": {"CWE-78"}, "go": set()})
    assert st["CWE-78"].in_scope and {"CWE-77", "CWE-78", "CWE-88"} <= st["CWE-78"].truth
    v_go, _, _ = es.cve_pair_units(pairs[1], [], [], TEXTS, set())
    assert v_go.in_scope is False


# --- statistics ------------------------------------------------------------------

def test_metrics_use_arbiter_wilson_and_none_on_empty_denominators():
    m = es.metrics({"tp": 9, "fn": 1, "fp": 0, "tn": 0})
    lo, hi = wilson(9, 9)
    assert m["precision"]["value"] == 1.0 and m["precision"]["wilson_95"] == [round(lo, 4), round(hi, 4)]
    assert m["recall"] == {"numerator": 9, "denominator": 10, "value": 0.9,
                           "wilson_95": [round(x, 4) for x in wilson(9, 10)]}
    assert m["safe_case_false_positive_rate"] == {"numerator": 0, "denominator": 0, "value": None,
                                                  "wilson_95": None}


def test_cluster_bootstrap_is_seeded_and_resamples_whole_clusters():
    clusters = [{"tp": 1, "fn": 0, "fp": 0, "tn": 1}, {"tp": 0, "fn": 1, "fp": 1, "tn": 0},
                {"tp": 3, "fn": 0, "fp": 0, "tn": 3}]
    a = es.cluster_bootstrap(clusters, 500, 7)
    assert a == es.cluster_bootstrap(clusters, 500, 7)
    assert a["clusters"] == 3 and a["method"].startswith("repository-cluster bootstrap")
    lo, hi = a["recall_interval"]
    assert 0 <= lo <= hi <= 1
    one = es.cluster_bootstrap([{"tp": 2, "fn": 2, "fp": 0, "tn": 4}], 200, 0)
    assert one["recall_interval"] == [0.5, 0.5], "one cluster: no spread to resample"


def test_rule_recall_denominator_is_the_strata_it_claims_in_its_language():
    U = es.Unit
    strata = {"CWE-89": es.Stratum("CWE-89", frozenset({"CWE-89"}), True),
              "CWE-78": es.Stratum("CWE-78", frozenset({"CWE-78"}), True)}
    units = [U("CWE-89", True, frozenset({"arbiter/python.sql"}), "a", "python"),
             U("CWE-89", True, frozenset(), "b", "python"),
             U("CWE-89", False, frozenset(), "c", "python"),
             U("CWE-89", True, frozenset(), "d", "go"),         # other language: not this rule's
             U("CWE-78", True, frozenset({"arbiter/python.sql"}), "e", "python"),  # fired off-claim
             U("CWE-78", True, frozenset(), "f", "python")]
    rows = {r["name"]: r for r in es.rule_rows(units, strata, {"arbiter/python.sql": {"CWE-89"},
                                                                 "arbiter/python.unused": {"CWE-22"}})}
    r = rows["arbiter/python.sql"]
    assert (r["tp"], r["fn"], r["fp"], r["tn"]) == (2, 2, 0, 1)
    assert r["strata"] == ["CWE-78", "CWE-89"]
    assert "arbiter/python.unused" not in rows, "a rule claiming no benchmark CWE has no row"


def test_weak_spots_rank_by_distance_from_the_bar():
    per_cwe = [es.row("CWE-89", [es.Unit("CWE-89", True, frozenset({"r"}))] * 400, in_scope=True),
               es.row("CWE-78", [es.Unit("CWE-78", True, frozenset())] * 10, in_scope=True),
               es.row("CWE-22", [es.Unit("CWE-22", True, frozenset())] * 10, in_scope=False)]
    spots = es.weak_spots("b", per_cwe, [])
    assert [w["name"] for w in spots] == ["CWE-89", "CWE-78"], "out-of-scope CWEs are coverage, not rank"
    w78 = next(w for w in spots if w["name"] == "CWE-78")
    assert w78["gap_to_bar"] == 0.99 and w78["limiting"] == "recall", "nothing flagged: recall limits"
    assert next(w for w in spots if w["name"] == "CWE-89")["gap_to_bar"] < 0.01


# --- run record and output ---------------------------------------------------------

def _card():
    expected, findings = _owasp_fixture()
    sc = es.owasp_score(expected, findings, ALIASES, TEST_DIR, {"CWE-89", "CWE-338"}, "java")
    res = es.summarise("owasp-java", sc, {"arbiter/java.sql": {"CWE-89"}, "arbiter/java.never": {"CWE-89"}},
                       multi_cluster=False,
                       replicates=10, seed=0)
    prov = {k: None for k in ("arbiter_commit", "arbiter_worktree_clean", "benchmark_manifest_digest",
                              "benchmark_snapshot_or_pin", "evaluator_commit", "configuration_digest",
                              "analyzer_and_ruleset_versions", "vulnerability_database_snapshot",
                              "operating_system_image", "architecture", "python_version", "profile",
                              "cache_policy", "started_at_utc", "completed_at_utc")}
    prov.update(arbiter_commit="0" * 40, arbiter_worktree_clean=True, profile="offline")
    res["seconds"] = 0.0
    bench = {"owasp-java": {"run_record": es.run_record(res, prov), "result": res}}
    return es.assemble(bench, "python tools/ground_truth/external_scorecard.py --aggregate-only")


def test_run_record_validates_against_the_manifest_template_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "docs" / "accuracy-benchmark-manifest.schema.json").read_text())
    sub = {**schema["properties"]["run_record_template"], "$defs": schema["$defs"]}
    rr = _card()["benchmarks"]["owasp-java"]["run_record"]
    jsonschema.validate(rr, sub)
    assert rr["counts"]["clusters"] == 1 and rr["metrics"]["effective_sample_size"] is None
    assert rr["counts"]["known_defects"] == 4 and rr["counts"]["not_assessed_strata"] == 1


def test_single_repository_benchmark_says_its_interval_is_case_level_only():
    res = _card()["benchmarks"]["owasp-java"]["result"]
    assert res["clusters"] == 1 and "case-level only" in res["uncertainty_note"]
    assert "cluster_bootstrap" not in res
    na = next(c for c in res["per_cwe"] if c["name"] == "CWE-643")
    assert na["not_assessed_reason"]


def test_output_is_aggregate_only():
    card = _card()
    text = json.dumps(card) + es.render_markdown(card)
    assert card["general_99_percent_claim"] is False and card["aggregate_only"] is True
    for pat in (r"T00\d", r"BenchmarkTest\d", r"GHSA-", r"\.java\b", r"src/testcode"):
        assert not re.search(pat, text), pat


def test_markdown_separates_rules_that_fire_from_rules_that_flag_nothing():
    md = es.render_markdown(_card())
    fires, silent = md.split("### Fires, but short of the bar")[1].split("### Claims the CWE, flags nothing")
    assert "`arbiter/java.sql`" in fires and "`CWE-89`" in fires
    silent = silent.split("## owasp-java")[0]
    assert "`arbiter/java.never`" in silent and "`arbiter/java.never`" not in fires
    assert "`arbiter/java.sql`" not in silent


def test_aggregate_only_flag_is_required(capsys):
    with pytest.raises(SystemExit):
        es.main(["--only", "owasp-java"])
    assert "--aggregate-only is required" in capsys.readouterr().err
