"""Source in a language no rule pack reads is not assessed, and the report
says so (ARB-144, FAIL-121).

Before this, a Kotlin/Scala/Swift repository scored 99.4/100 at 94%
coverage with the gate passed: every `lang_*` probe was inapplicable (no
Python, no Go...), left the denominator, and nothing in the report named
the 2,000 lines nobody had read.
"""
from __future__ import annotations

import pytest

from arbiter.engine import UNASSESSED_SOURCE_LIMIT, run_scan
from arbiter.core import RepoInfo
from arbiter.inventory import build_inventory
from arbiter.lang_rules import (
    UNASSESSED_PROBE,
    not_assessed_outcome,
    pack_languages,
    unassessed_languages,
)
from arbiter.policy import load_config
from arbiter.report import render_console

KOTLIN = '''package app

import java.sql.DriverManager

fun lookup(user: String) {
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    // ruleid: sqli
    conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '" + user + "'")
}
'''
SWIFT = '''import WebKit

func load(_ view: WKWebView, _ html: String) {
    // ruleid: webview-js-window
    view.configuration.preferences.javaScriptEnabled = true
    view.loadHTMLString(html, baseURL: nil)
}
'''
SCALA = '''object Main {
  def run(cmd: String): Unit = {
    // ruleid: command-injection
    sys.process.Process(Seq("sh", "-c", cmd)).!
  }
}
'''


def _inv(root):
    return build_inventory([RepoInfo(id="r", path=str(root))])


def _repo(tmp_path, with_python: int = 0):
    for i in range(6):
        (tmp_path / f"k{i}.kt").write_text(KOTLIN, encoding="utf-8")
    (tmp_path / "a.swift").write_text(SWIFT, encoding="utf-8")
    (tmp_path / "b.scala").write_text(SCALA, encoding="utf-8")
    (tmp_path / "build.gradle.kts").write_text('plugins { kotlin("jvm") }\n', encoding="utf-8")
    for i in range(with_python):
        (tmp_path / f"p{i}.py").write_text("def f(x):\n    return x\n" * 20, encoding="utf-8")
    return tmp_path


def test_the_inventory_recognises_the_languages_it_cannot_assess(tmp_path):
    inv = _inv(_repo(tmp_path))
    langs = {f.language for f in inv.files}
    assert {"kotlin", "swift", "scala"} <= langs
    assert "unknown" not in {f.language for f in inv.files if f.path.endswith((".kt", ".kts", ".swift", ".scala"))}


def test_unassessed_languages_are_counted_with_their_share(tmp_path):
    inv = _inv(_repo(tmp_path))
    found = unassessed_languages(inv)
    assert set(found) == {"kotlin", "swift", "scala"}
    assert found["kotlin"]["files"] == 7  # six sources and the .kts build script
    assert abs(sum(c["share"] for c in found.values()) - 1.0) < 0.01
    assert list(found)[0] == "kotlin", "largest first"
    assert not (set(found) & pack_languages())


def test_a_repo_in_pack_languages_only_has_nothing_unassessed(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# hi\n", encoding="utf-8")
    (tmp_path / "cfg.yaml").write_text("a: 1\n", encoding="utf-8")
    inv = _inv(tmp_path)
    assert unassessed_languages(inv) == {}
    assert not_assessed_outcome(inv) is None


def test_the_outcome_is_skipped_applicable_and_sized_like_a_pack(tmp_path):
    inv = _inv(_repo(tmp_path))
    oc = not_assessed_outcome(inv)
    assert oc.name == UNASSESSED_PROBE and oc.status == "skipped" and oc.applicable is True
    assert oc.checks >= 3 * 10, "three missing packs must weigh like three packs, not one check"
    assert "kotlin" in oc.reason and "swift" in oc.reason and "not assessed" in oc.reason


def test_an_unsupported_only_repo_has_its_grade_withheld_and_names_the_languages(tmp_path):
    rep = run_scan([str(_repo(tmp_path))], load_config(None), use_adapters=False)
    sc = rep.scorecard
    assert sc.withheld is True and sc.overall is None
    assert sc.coverage < 0.6, sc.coverage
    probe = next(p for p in rep.probes if p.name == UNASSESSED_PROBE)
    assert probe.status == "skipped"
    langs = rep.scan_scope["languages_not_assessed"]
    assert set(langs) == {"kotlin", "swift", "scala"}
    console = render_console(rep, color=False)
    assert "kotlin" in console and UNASSESSED_PROBE in console


def test_a_mostly_unsupported_repo_is_withheld_even_when_coverage_clears_the_threshold(tmp_path):
    """The withholding reads the share of source, not only the probe count:
    a repository with one Python file beside two thousand Kotlin lines is
    not graded on the Python file."""
    root = _repo(tmp_path, with_python=1)
    cfg = dict(load_config(None))
    cfg["score"] = {**cfg["score"], "coverage_threshold": 0.0}
    rep = run_scan([str(root)], cfg, use_adapters=False)
    share = sum(c["share"] for c in rep.scan_scope["languages_not_assessed"].values())
    assert share > UNASSESSED_SOURCE_LIMIT
    assert rep.scorecard.withheld is True and rep.scorecard.overall is None
    assert "languages no rule pack reads" in rep.scorecard.withheld_reason
    assert "kotlin" in rep.scorecard.withheld_reason


def test_a_repo_with_a_little_unsupported_source_keeps_its_grade_and_the_note(tmp_path):
    root = tmp_path
    for i in range(30):
        (root / f"p{i}.py").write_text("def f(x):\n    return x\n" * 20, encoding="utf-8")
    (root / "one.swift").write_text(SWIFT, encoding="utf-8")
    rep = run_scan([str(root)], load_config(None), use_adapters=False)
    langs = rep.scan_scope["languages_not_assessed"]
    assert set(langs) == {"swift"} and langs["swift"]["share"] < 0.05
    assert "swift" in next(p for p in rep.probes if p.name == UNASSESSED_PROBE).reason
    # the one Swift file is a note and a coverage loss, not a reason to withhold on its own
    if rep.scorecard.withheld:
        assert "languages no rule pack reads" not in rep.scorecard.withheld_reason


@pytest.mark.parametrize("ext", [".kt", ".kts", ".swift", ".scala", ".cs", ".rs", ".php", ".dart"])
def test_every_recognised_programming_language_without_a_pack_is_unassessed(tmp_path, ext):
    (tmp_path / f"a{ext}").write_text("x = 1\n", encoding="utf-8")
    inv = _inv(tmp_path)
    assert len(unassessed_languages(inv)) == 1
