from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from helpers import ROOT

spec = importlib.util.spec_from_file_location("triage_baseline", ROOT / "tools" / "triage_baseline.py")
tb = importlib.util.module_from_spec(spec)
sys.modules["triage_baseline"] = tb
spec.loader.exec_module(tb)


def _write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def test_family_groups_ai_corpus_app_across_languages():
    assert tb._family("ai-corpus/python/job-queue") == "ai-corpus:job-queue"
    assert tb._family("ai-corpus/typescript/job-queue") == "ai-corpus:job-queue"


def test_load_records_excludes_unsure_heldout_and_arb109(tmp_path: Path):
    p = _write_jsonl(tmp_path / "labels.jsonl", [
        {"repo": "a", "rule_id": "r", "label": "tp", "source": "gold-model", "held_out": False},
        {"repo": "b", "rule_id": "r", "label": "unsure", "source": "gold-model", "held_out": False},
        {"repo": "c", "rule_id": "r", "label": "fp", "source": "gold-model", "held_out": True},
        {"repo": "d", "rule_id": "r", "label": "tp", "source": "arb109-model", "held_out": False},
    ])
    rows = tb.load_records([p])
    assert len(rows) == 1 and rows[0]["repo"] == "a"


def test_split_is_repository_family_disjoint():
    rows = []
    for i in range(20):
        rows.append({"repo": f"r{i}", "family": f"f{i}", "rule_id": "x", "language": "python", "confidence": "", "severity": "", "y": i % 2})
    s = tb.build_split(rows, seed=113, valid_ratio=0.3)
    assert set(s["train_families"]).isdisjoint(set(s["valid_families"]))
    assert s["valid_stats"]["n"] > 0 and s["train_stats"]["n"] > 0


def test_eval_metrics_smoke():
    rows = []
    for i in range(30):
        rows.append({
            "repo": f"r{i}",
            "family": f"f{i}",
            "rule_id": "rule-a" if i < 20 else "rule-b",
            "language": "python",
            "confidence": "high" if i % 3 == 0 else "low",
            "severity": "",
            "y": 1 if i % 2 == 0 else 0,
        })
    s = tb.build_split(rows, seed=113, valid_ratio=0.25)
    res = tb.evaluate(rows, s)
    m = res["metrics"]
    assert 0 <= m["base_rate_valid"] <= 1
    assert 0 <= m["precision_at_10"] <= 1
    assert 0 <= m["precision_at_20"] <= 1


def test_cv_smoke():
    rows = []
    for i in range(40):
        rows.append({
            "repo": f"r{i}",
            "family": f"f{i}",
            "rule_id": "rule-a" if i < 25 else "rule-b",
            "language": "python",
            "confidence": "medium",
            "severity": "",
            "y": 1 if i % 3 else 0,
        })
    folds = tb.build_folds(rows, k=4, seed=113)
    assert len(folds) == 4
    res = tb.evaluate_cv(rows, folds)
    assert res["overall"]["rows"] == 40
    assert 0 <= res["overall"]["precision_at_20"] <= 1
