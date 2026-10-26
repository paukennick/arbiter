"""ARB-112 analysis script on synthetic labels: no model calls, no cohort data."""
from __future__ import annotations

import importlib.util
import sys

from helpers import ROOT

_spec = importlib.util.spec_from_file_location("prereg_b_analysis", ROOT / "tools" / "prereg_b_analysis.py")
pb = importlib.util.module_from_spec(_spec)
sys.modules["prereg_b_analysis"] = pb
_spec.loader.exec_module(pb)


def _rec(rule, repo, label):
    return {"rule_id": rule, "repo": repo, "label": label}


def _cal(label, truth, n=1):
    return [{"label": label, "truth": truth, "source": "calibration:owasp-python",
             "votes": {"prosecutor": {"label": label}, "defender": {"label": label}}}
            for _ in range(n)]


def test_unsure_is_never_tp_or_fp():
    t = pb.tally([_rec("r", "a", "tp")] * 6 + [_rec("r", "a", "fp")] * 3 + [_rec("r", "a", "unsure")] * 3)
    assert (t["tp"], t["fp"], t["unsure"]) == (6, 3, 3)
    assert t["precision"] == round(6 / 9, 3)
    assert t["unsure_rate"] == 0.25


def test_small_rules_show_counts_only():
    t = pb.tally([_rec("r", "a", "tp")] * 4)
    assert t["precision"] == 1.0 and t["wilson95"] is None


def test_bootstrap_is_seeded_and_resamples_repositories():
    recs = [_rec("r", "a", "tp")] * 5 + [_rec("r", "b", "fp")] * 5 + [_rec("r", "c", "tp")] * 5
    one = pb.cluster_bootstrap(recs, n_boot=500)
    assert one == pb.cluster_bootstrap(recs, n_boot=500)
    lo, hi = one["interval95"]
    assert 0 <= lo <= hi <= 1 and one["repositories_with_findings"] == 3
    assert pb.cluster_bootstrap([_rec("r", "a", "tp")])["interval95"] is None


def test_calibration_below_threshold_withholds_every_rate():
    cohort = [_rec("r", "a", "tp")] * 12
    low = _cal("tp", "tp", 3) + _cal("tp", "fp", 7)
    res = pb.analyse(cohort, low)
    assert res["low_reliability"] and res["overall"]["precision"] is None
    assert res["by_rule"]["r"]["wilson95"] is None and res["cluster"]["interval95"] is None
    assert res["overall"]["tp"] == 12
    assert "Low reliability" in pb.render(res)


def test_reliable_calibration_publishes_rates():
    cohort = [_rec("r", "a", "tp")] * 9 + [_rec("r", "b", "fp")] * 3
    ok = _cal("tp", "tp", 9) + _cal("fp", "fp", 9) + _cal("tp", "fp", 2)
    res = pb.analyse(cohort, ok)
    assert not res.get("low_reliability") and res["overall"]["precision"] == 0.75
    assert res["calibration"]["agreement_with_truth"] >= pb.RELIABILITY
    assert "convenience cohort" in pb.render(res)
