"""Under --changed, a changed file counts as read only if a probe read it,
and a change none of whose files was read does not pass quietly
(ARB-151, FAIL-128).

`narrow()` called a changed path read when it was in the inventory, so a
pull request that moved its code under `dist/` reported `files_read: 1`
and passed; one whose only changed file carried a NUL byte reported
`lines_read: 0` and passed; one that only deleted files said nothing at
all. The gate now fails when changed files exist and none was read, and a
delete-only change is named as such.
"""
from __future__ import annotations

import subprocess

from helpers import CLEAN_PY, LEAKY_PY, _git_repo

from arbiter.engine import run_scan
from arbiter.incremental import git_deleted
from arbiter.policy import load_config
from arbiter.report import render_console


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True)


def _scan(root, base):
    return run_scan([str(root)], load_config(None), changed_since=base,
                    use_adapters=False, use_cache=False)


def test_code_moved_under_dist_is_changed_but_not_read_and_fails_the_gate(tmp_path):
    base = _git_repo(tmp_path, {"a.py": CLEAN_PY, "ok.py": CLEAN_PY})
    (tmp_path / "dist").mkdir()
    (tmp_path / "a.py").rename(tmp_path / "dist" / "a.py")
    (tmp_path / "dist" / "a.py").write_text(LEAKY_PY, encoding="utf-8")
    _git(tmp_path, "add", "-A"); _git(tmp_path, "commit", "-qm", "move")
    rep = _scan(tmp_path, base)
    ss = rep.scan_scope
    assert ss["files_changed"] == 1 and ss["files_changed_read"] == 0
    assert ss["files_read"] == 0 and ss["lines_read"] == 0
    assert ss["changed_not_read"][0]["path"] == "dist/a.py"
    assert "generated" in ss["changed_not_read"][0]["reason"]
    assert rep.gate["passed"] is False
    assert any("none of the 1 changed file(s) was read" in r for r in rep.gate["reasons"])
    console = render_console(rep, color=False)
    assert "1 changed file(s) were not read (dist/a.py)" in console


def test_a_changed_file_with_a_nul_byte_is_not_read(tmp_path):
    base = _git_repo(tmp_path, {"ok.py": CLEAN_PY, "other.py": CLEAN_PY})
    (tmp_path / "ok.py").write_bytes(b'import os\n# \x00\nKEY = "AKIAIOSFODNN7EXAMPLQ"\n')
    _git(tmp_path, "add", "-A"); _git(tmp_path, "commit", "-qm", "nul")
    rep = _scan(tmp_path, base)
    assert rep.scan_scope["files_changed_read"] == 0
    assert "NUL byte" in rep.scan_scope["changed_not_read"][0]["reason"]
    assert rep.gate["passed"] is False


def test_a_delete_only_change_is_named_and_passes(tmp_path):
    base = _git_repo(tmp_path, {"a.py": CLEAN_PY, "b.py": CLEAN_PY})
    _git(tmp_path, "rm", "-q", "a.py"); _git(tmp_path, "commit", "-qm", "del")
    assert git_deleted(str(tmp_path), base) == {"a.py"}
    rep = _scan(tmp_path, base)
    ss = rep.scan_scope
    assert ss["files_changed"] == 0 and ss["files_changed_deleted"] == 1
    assert ss["files_changed_not_read"] == 0
    assert rep.gate["passed"] is True, "a deletion has nothing to read and nothing to fail on"
    assert "Delete-only change: 1 changed path(s)" in render_console(rep, color=False)


def test_a_change_under_a_skipped_directory_names_the_directory(tmp_path):
    base = _git_repo(tmp_path, {"ok.py": CLEAN_PY})
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text(LEAKY_PY, encoding="utf-8")
    _git(tmp_path, "add", "-A"); _git(tmp_path, "commit", "-qm", "vendor")
    rep = _scan(tmp_path, base)
    ss = rep.scan_scope
    assert ss["files_changed_not_read"] == 1
    assert ss["changed_not_read"] == [{"path": "vendor/lib.py",
                                       "reason": "under vendor/: vendored, build or tool "
                                                 "directory by name (never walked)"}]
    assert rep.gate["passed"] is False


def test_an_ordinary_change_is_read_and_still_passes(tmp_path):
    base = _git_repo(tmp_path, {"a.py": CLEAN_PY}, second={"b.py": CLEAN_PY})
    rep = _scan(tmp_path, base)
    ss = rep.scan_scope
    assert ss["files_changed"] == 1 and ss["files_changed_read"] == 1
    assert ss["files_changed_not_read"] == 0 and ss["files_changed_deleted"] == 0
    assert rep.scorecard.withheld and rep.scorecard.withheld_by == "partial"
    assert rep.gate["passed"] is True
    assert "NOT READ" not in render_console(rep, color=False)


def test_one_read_file_beside_an_unread_one_is_a_pass_with_a_note(tmp_path):
    base = _git_repo(tmp_path, {"a.py": CLEAN_PY})
    (tmp_path / "b.py").write_text(CLEAN_PY, encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "c.py").write_text(LEAKY_PY, encoding="utf-8")
    _git(tmp_path, "add", "-A"); _git(tmp_path, "commit", "-qm", "two")
    rep = _scan(tmp_path, base)
    assert rep.scan_scope["files_changed_read"] == 1
    assert rep.scan_scope["files_changed_not_read"] == 1
    assert rep.gate["passed"] is True
    assert "1 changed file(s) were not read (dist/c.py)" in render_console(rep, color=False)
