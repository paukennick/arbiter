"""Files the walk saw and did not read are reported, counted against
coverage, and withhold the grade when they are most of the source
(ARB-150, FAIL-127).

Before this, a `.py` with a NUL byte in its first 4KB, a 2.4MB bundle, a
UTF-16 file saved without a byte-order mark, a symlinked directory and
anything under `vendor/` were absent from every section of the report
(grep of report.json for their names: 0 hits), and a tree made of them
scored 100 at 95% coverage. A file symlink pointing outside the tree was
read, and its content echoed into the evidence.
"""
from __future__ import annotations

import os
import sys

import pytest
from helpers import CLEAN_PY

from arbiter.core import RepoInfo
from arbiter.engine import run_scan
from arbiter.inventory import (
    MAX_FILE_BYTES,
    SKIP_DIR_LINK,
    SKIP_DIR_NAMED,
    SKIP_LINK_OUTSIDE,
    SKIP_NUL,
    SKIP_OVERSIZE,
    SKIP_UTF16,
    build_inventory,
)
from arbiter.lang_rules import FILES_NOT_READ_PROBE
from arbiter.policy import load_config
from arbiter.report import render_console, render_markdown
from arbiter import ast as _ts

LEAKY_WITH_NUL = b'import os\nKEY = "AKIAIOSFODNN7EXAMPLQ"\n# \x00\nos.system(input())\n'
LEAKY_UTF16 = 'import os\nKEY = "AKIAIOSFODNN7EXAMPLQ"\nos.system(input())\n'.encode("utf-16-le")


def _inv(root):
    return build_inventory([RepoInfo(id="r", path=str(root))])


def _scan(root):
    return run_scan([str(root)], load_config(None), use_adapters=False, use_cache=False)


def _by_path(inv):
    return {s["path"]: s for s in inv.skipped}


# ---------------------------------------------------------------------------
# the inventory names what it did not read, and why
# ---------------------------------------------------------------------------

def test_a_nul_in_the_first_4kb_is_recorded_not_dropped(tmp_path):
    (tmp_path / "a.py").write_bytes(LEAKY_WITH_NUL)
    (tmp_path / "ok.py").write_text(CLEAN_PY, encoding="utf-8")
    s = _by_path(_inv(tmp_path))
    assert s["a.py"]["reason"] == SKIP_NUL and s["a.py"]["source_like"] is True
    assert "ok.py" not in s


def test_an_oversize_file_is_recorded(tmp_path):
    (tmp_path / "bundle.js").write_bytes(b"x = 1;\n" * (MAX_FILE_BYTES // 7 + 1))
    s = _by_path(_inv(tmp_path))
    assert s["bundle.js"]["reason"] == SKIP_OVERSIZE and s["bundle.js"]["source_like"]


def test_utf16_without_a_mark_is_named_as_such(tmp_path):
    (tmp_path / "a.py").write_bytes(LEAKY_UTF16)
    (tmp_path / "b.py").write_bytes(LEAKY_UTF16.decode("utf-16-le").encode("utf-16-be"))
    s = _by_path(_inv(tmp_path))
    assert s["a.py"]["reason"] == SKIP_UTF16 and s["b.py"]["reason"] == SKIP_UTF16


def test_a_utf16_file_with_a_mark_is_still_read(tmp_path):
    (tmp_path / "a.py").write_bytes(b"\xff\xfe" + LEAKY_UTF16)
    inv = _inv(tmp_path)
    assert inv.skipped == [] and inv.text_files()[0].path == "a.py"


def test_a_real_binary_with_a_source_extension_is_nul_not_utf16(tmp_path):
    (tmp_path / "a.py").write_bytes(bytes(range(256)) * 20)
    assert _by_path(_inv(tmp_path))["a.py"]["reason"] == SKIP_NUL


def test_a_binary_without_a_source_extension_is_counted_but_not_source_like(tmp_path):
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    inv = _inv(tmp_path)
    assert inv.skipped[0]["source_like"] is False
    assert inv.skipped_summary()["files"] == 1
    assert inv.skipped_summary()["source_like_files"] == 0
    assert inv.skipped_summary()["entries"] == []


def test_skipped_directories_are_listed_with_a_bounded_count(tmp_path):
    (tmp_path / "app" / "vendor").mkdir(parents=True)
    (tmp_path / "app" / "vendor" / "h.py").write_text(CLEAN_PY, encoding="utf-8")
    (tmp_path / "src" / "target").mkdir(parents=True)
    (tmp_path / "src" / "target" / "a.py").write_text(CLEAN_PY, encoding="utf-8")
    (tmp_path / "main.py").write_text(CLEAN_PY, encoding="utf-8")
    inv = _inv(tmp_path)
    dirs = {d["path"]: d for d in inv.skipped_summary()["dirs"]}
    assert dirs["app/vendor"]["reason"] == SKIP_DIR_NAMED and dirs["app/vendor"]["files"] == 1
    assert dirs["src/target"]["files"] == 1
    # still not scanned: what counts as vendored did not change
    assert {f.path for f in inv.files} == {"main.py"}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_a_symlinked_directory_is_reported_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.py").write_text(CLEAN_PY, encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(real, repo / "src", target_is_directory=True)
    inv = _inv(repo)
    assert inv.files == []
    [d] = inv.skipped_summary()["dirs"]
    assert d["path"] == "src" and d["reason"] == SKIP_DIR_LINK and d["files"] == 1


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_a_file_symlink_leaving_the_tree_is_not_read(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text('TOKEN = "ghp_' + "b" * 36 + '"\n', encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(outside, repo / "a.py")
    (repo / "inside.py").write_text(CLEAN_PY, encoding="utf-8")
    os.symlink(repo / "inside.py", repo / "alias.py")
    inv = _inv(repo)
    assert _by_path(inv)["a.py"]["reason"] == SKIP_LINK_OUTSIDE
    # a link inside the tree is read: its target is part of the repository
    assert {f.path for f in inv.files} == {"inside.py", "alias.py"}
    rep = _scan(repo)
    assert not any(f.location.path == "a.py" for f in rep.findings)


# ---------------------------------------------------------------------------
# the scan says so, and the gap counts
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _ts.available(), reason="tree-sitter not installed: rule packs cannot run, so the grade is withheld")
def test_skipped_files_reach_scan_scope_the_denominator_and_the_renderings(tmp_path):
    (tmp_path / "a.py").write_bytes(LEAKY_WITH_NUL)
    for i in range(3):
        (tmp_path / f"ok{i}.py").write_text(CLEAN_PY, encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("x\n", encoding="utf-8")
    rep = _scan(tmp_path)
    sk = rep.scan_scope["skipped"]
    assert sk["files"] == 1 and sk["source_like_files"] == 1
    assert sk["by_reason"] == {SKIP_NUL: 1}
    assert sk["entries"] == [{"path": "a.py", "reason": SKIP_NUL}]
    assert [d["path"] for d in sk["dirs"]] == ["node_modules"]
    outcome = next(p for p in rep.probes if p.name == FILES_NOT_READ_PROBE)
    assert outcome.status == "skipped" and "1 source-like file(s)" in outcome.reason
    assert outcome.applicable is True and outcome.checks > 0
    # a quarter of the source skipped: not withheld for it, but not at full coverage
    assert rep.scorecard.withheld_by in ("", "probes_selected")
    assert rep.scorecard.coverage < 1.0
    console = render_console(rep, color=False)
    assert "NOT READ" in console and "1 file(s) were not read" in console
    assert "node_modules/ (1 files)" in console
    assert "1 file(s) were not read" in render_markdown(rep)


def test_coverage_is_lower_with_a_skipped_source_file_than_without(tmp_path):
    for i in range(3):
        (tmp_path / f"ok{i}.py").write_text(CLEAN_PY, encoding="utf-8")
    before = _scan(tmp_path).scorecard.coverage
    (tmp_path / "a.py").write_bytes(LEAKY_WITH_NUL)
    after = _scan(tmp_path).scorecard.coverage
    assert after < before


def test_mostly_skipped_source_withholds_the_grade_and_fails_the_gate(tmp_path):
    (tmp_path / "a.py").write_bytes(LEAKY_WITH_NUL)
    (tmp_path / "b.py").write_bytes(LEAKY_UTF16)
    (tmp_path / "ok.py").write_text(CLEAN_PY, encoding="utf-8")
    rep = _scan(tmp_path)
    sc = rep.scorecard
    assert sc.withheld and sc.withheld_by == "files_not_read"
    assert "67% of source-like files were not read" in sc.withheld_reason
    assert rep.gate["passed"] is False
    assert any("files_not_read" in r for r in rep.gate["reasons"])


def test_a_clean_tree_skips_nothing(tmp_path):
    (tmp_path / "a.py").write_text(CLEAN_PY, encoding="utf-8")
    rep = _scan(tmp_path)
    assert rep.scan_scope["skipped"]["files"] == 0
    assert not any(p.name == FILES_NOT_READ_PROBE for p in rep.probes)
    assert "NOT READ" not in render_console(rep, color=False)
