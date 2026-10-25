"""A scan that read nothing a probe reads carries no grade and passes no
gate (ARB-149, FAIL-126).

An empty directory, a docs-only tree and a directory holding one binary
each scored 100.0 at 95% coverage with the gate passed: every applicable
probe ran, over nothing, and found nothing. A mistyped path or a checkout
without its submodules therefore produced a perfect score in CI.
"""
from __future__ import annotations

import pytest
from helpers import CLEAN_PY

from arbiter.engine import run_scan
from arbiter.policy import load_config
from arbiter.report import render_console, render_markdown
from arbiter import ast as _ts


def _scan(root):
    return run_scan([str(root)], load_config(None), use_adapters=False, use_cache=False)


@pytest.mark.parametrize("files", [
    {},
    {"README.md": "# Only docs\n", "docs/guide.md": "read me\n"},
    {"blob.bin": b"\x00\x01\x02\x03" * 64},
    {"notes.txt": "plain text nobody assesses\n"},
], ids=["empty", "docs-only", "binary-only", "data-only"])
def test_a_scan_of_nothing_assessable_withholds_the_grade_and_fails_the_gate(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content) if isinstance(content, bytes) else p.write_text(content, encoding="utf-8")
    rep = _scan(tmp_path)
    sc = rep.scorecard
    assert sc.withheld and sc.overall is None
    assert sc.withheld_by == "nothing_read"
    assert "no file this scan could assess was read" in sc.withheld_reason
    assert rep.gate["passed"] is False
    assert any("grade withheld (nothing_read)" in r for r in rep.gate["reasons"])
    assert "grade withheld" in render_console(rep, color=False)
    assert "Grade withheld" in render_markdown(rep)


@pytest.mark.skipif(not _ts.available(), reason="tree-sitter not installed: rule packs cannot run, so the grade is withheld")
def test_one_source_file_is_enough_to_grade(tmp_path):
    (tmp_path / "a.py").write_text(CLEAN_PY, encoding="utf-8")
    rep = _scan(tmp_path)
    # Not graded only when the analyzers another test registered in this
    # process are switched off here (probes_selected), never for nothing read.
    assert rep.scorecard.withheld_by in ("", "probes_selected")
    assert rep.gate["passed"] is True


def test_the_reason_counts_what_was_found_and_why_it_was_not_read(tmp_path):
    (tmp_path / "a.py").write_bytes(b"import os\n# \x00\nos.system(input())\n")
    rep = _scan(tmp_path)
    reason = rep.scorecard.withheld_reason
    assert "1 file(s) found" in reason and "NUL byte" in reason
