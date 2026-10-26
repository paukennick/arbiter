"""`--only-files` names files; a name that matches nothing is an error, not
an empty scan (ARB-145, FAIL-122).

Before this, `--only-files .husky/pre-commit` went through `lstrip("./")`,
which strips characters rather than a prefix, and came out `husky/pre-commit`;
it matched nothing, the scan read zero files and the gate passed. A
nonexistent path did the same. docs/ci.md promised the opposite.
"""
from __future__ import annotations

import pytest
from helpers import LEAKY_PY

from arbiter.engine import _requested_path, run_scan
from arbiter.policy import load_config


def _repo(tmp_path):
    (tmp_path / ".husky").mkdir()
    (tmp_path / ".husky" / "pre-commit").write_text(LEAKY_PY, encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "src" / "leak.py").write_text(LEAKY_PY.replace("b" * 36, "d" * 36), encoding="utf-8")
    return tmp_path


def test_a_literal_leading_dot_slash_is_stripped_and_nothing_else():
    assert _requested_path("./src/a.py", []) == "src/a.py"
    assert _requested_path("././src/a.py", []) == "src/a.py"
    assert _requested_path(".husky/pre-commit", []) == ".husky/pre-commit"
    assert _requested_path(".github/workflows/ci.yml", []) == ".github/workflows/ci.yml"
    assert _requested_path("src\\a.py", []) == "src/a.py"


def test_a_dotfile_is_read_when_asked_for(tmp_path):
    root = _repo(tmp_path)
    rep = run_scan([str(root)], load_config(None), use_adapters=False,
                   only_files=[".husky/pre-commit"])
    assert rep.scan_scope["files_changed"] == 1
    paths = {f.location.path for f in rep.active() if f.probe == "secrets"}
    assert paths == {".husky/pre-commit"}, paths


def test_a_dot_slash_prefix_names_the_same_file(tmp_path):
    root = _repo(tmp_path)
    rep = run_scan([str(root)], load_config(None), use_adapters=False,
                   only_files=["./src/leak.py"])
    assert rep.scan_scope["files_changed"] == 1
    assert {f.location.path for f in rep.active() if f.probe == "secrets"} == {"src/leak.py"}


def test_an_absolute_path_under_the_target_is_made_relative(tmp_path):
    root = _repo(tmp_path)
    rep = run_scan([str(root)], load_config(None), use_adapters=False,
                   only_files=[str(root / "src" / "leak.py")])
    assert rep.scan_scope["files_changed"] == 1


def test_a_path_that_matches_nothing_is_an_error_not_a_pass(tmp_path):
    root = _repo(tmp_path)
    with pytest.raises(RuntimeError, match="not files this scan can read.*nope.py"):
        run_scan([str(root)], load_config(None), use_adapters=False, only_files=["nope.py"])
    # one bad name among good ones is still a refusal: the caller asked for
    # a file this report would silently say nothing about
    with pytest.raises(RuntimeError, match="src/missing.py"):
        run_scan([str(root)], load_config(None), use_adapters=False,
                 only_files=["src/ok.py", "src/missing.py"])


def test_a_path_the_inventory_skips_is_named_as_unreadable(tmp_path):
    root = _repo(tmp_path)
    (root / "node_modules").mkdir()
    (root / "node_modules" / "x.js").write_text("var a = 1;\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="node_modules/x.js"):
        run_scan([str(root)], load_config(None), use_adapters=False,
                 only_files=["node_modules/x.js"])
