"""House-rule globs are globstar paths, case-sensitive on every OS
(ARB-147, FAIL-124).

Before this they went through `fnmatch`, whose `*` crosses `/` and whose
`**/` demands a slash: `**/*` missed every root file and `src/**/*.py`
missed `src/a.py`, so a forbid policy written either way was false-clean
on the files it named. `fnmatch.fnmatch` also folds case on Windows, so a
rule matched different files on a developer's machine and in CI.
"""
from __future__ import annotations

import pytest

from arbiter.globs import any_match, match


@pytest.mark.parametrize("path, pattern, expected", [
    # the two reproducers
    ("root.py", "**/*", True),
    ("src/a.py", "src/**/*.py", True),
    # globstar
    ("src/x/y/b.py", "src/**/*.py", True),
    ("src/a.py", "**/*.py", True),
    ("a.py", "**/*.py", True),
    ("a/b/c", "a/**/c", True),
    ("a/c", "a/**/c", True),
    ("a/b", "a/**", True),
    ("a/b/c/d", "a/**", True),
    ("a", "a/**", False),
    ("anything/at/all", "**", True),
    # one segment
    ("src/a.py", "*.py", False),
    ("a.py", "*.py", True),
    ("src/a.py", "src/*.py", True),
    ("src/x/a.py", "src/*.py", False),
    ("src/a.py", "src/?.py", True),
    ("src/ab.py", "src/?.py", False),
    ("src/a.py", "src/[ab].py", True),
    ("src/c.py", "src/[ab].py", False),
    ("src/c.py", "src/[!ab].py", True),
    # leading ./ on either side
    ("./src/a.py", "src/a.py", True),
    ("src/a.py", "./src/a.py", True),
    # literal dots and other regex characters stay literal
    ("srcXa.py", "src.a.py", False),
    ("a+b.py", "a+b.py", True),
    # README.md is not README.MD
    ("README.MD", "README.md", False),
    ("Src/a.py", "src/**/*.py", False),
])
def test_globstar_semantics(path, pattern, expected):
    assert match(path, pattern) is expected


def test_any_match():
    assert any_match("src/a.py", ["docs/**", "src/**/*.py"])
    assert not any_match("src/a.py", ["docs/**", "*.py"])


def test_a_forbid_rule_with_the_default_glob_reaches_root_files(tmp_path):
    from arbiter.engine import run_scan
    from arbiter.policy import load_config
    (tmp_path / "root.py").write_text("# TODO_FORBIDDEN\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("# TODO_FORBIDDEN\n", encoding="utf-8")
    (tmp_path / "src" / "x").mkdir()
    (tmp_path / "src" / "x" / "b.py").write_text("# TODO_FORBIDDEN\n", encoding="utf-8")
    cfg = dict(load_config(None))
    cfg["rules"] = [
        {"id": "forbid-default", "type": "content_match", "pattern": "TODO_FORBIDDEN"},
        {"id": "forbid-doc-glob", "type": "content_match", "files": "src/**/*.py", "pattern": "TODO_FORBIDDEN"},
        {"id": "no-root-py", "type": "file_absent", "paths": ["*.py"]},
        {"id": "needs-readme", "type": "file_exists", "paths": ["**/README.md"]},
    ]
    rep = run_scan([str(tmp_path)], cfg, only=["house_rules"], use_adapters=False)
    hits = sorted((f.rule_id, f.location.path) for f in rep.active())
    assert ("house/forbid-default", "root.py") in hits
    assert ("house/forbid-doc-glob", "src/a.py") in hits
    assert ("house/forbid-doc-glob", "src/x/b.py") in hits
    assert ("house/no-root-py", "root.py") in hits
    assert ("house/no-root-py", "src/a.py") not in hits, "*.py is the root only"
    assert ("house/needs-readme", "**/README.md") in hits
