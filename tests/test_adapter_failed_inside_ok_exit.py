"""An analyzer that fails inside its `ok_exit` codes is an error, never
"ran, found nothing" (ARB-146, FAIL-123).

gitleaks exits 1 both for "leaks found" and for a fatal config error
(`[extend` in `.gitleaks.toml`); ruff `--exit-zero` still exits 1 and prints
nothing when its own config is bad; semgrep can exit 0 with an empty body;
a newer tool can rename its results key; bandit lists the files it could not
parse under `errors[]` and still exits 0. Each of these parsed as an empty
list and was recorded `ran`, 0 findings, and counted toward coverage.

Every tool here is a Python script started through `sys.executable`, never
a real analyzer: nothing on the network, nothing that depends on what is
installed.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from arbiter import adapters as A
from arbiter.core import RepoInfo
from arbiter.engine import run_scan
from arbiter.inventory import build_inventory
from arbiter.policy import load_config
from arbiter.probes import REGISTRY, ProbeContext

# `mode` is the first argument; the script prints and exits accordingly.
SCRIPT = r'''import json, sys
mode = sys.argv[1]
if mode == "gitleaks_fatal":           # bad .gitleaks.toml: FTL to stderr, exit 1, no report
    sys.stderr.write("12:00AM FTL Failed to load config error=toml: ...\n"); sys.exit(1)
if mode == "ruff_noout":               # bad ruff config: nothing on stdout, exit 1
    sys.stderr.write("error: Failed to parse ruff.toml\n"); sys.exit(1)
if mode == "empty_exit0":
    sys.exit(0)
if mode == "garbage_exit0":
    print("semgrep: something went wrong, see the log"); sys.exit(0)
if mode == "renamed_key":
    print(json.dumps({"findings": [{"check_id": "x"}], "errors": []})); sys.exit(0)
if mode == "banner_then_json":
    print("Banner line"); print(json.dumps({"results": [], "errors": []})); sys.exit(0)
if mode == "bandit_errors":
    print(json.dumps({"errors": [{"filename": "app.py", "reason": "syntax error while parsing AST from file"}],
                      "results": [{"test_id": "B102", "issue_text": "exec", "filename": "ok.py",
                                   "line_number": 1, "issue_severity": "HIGH"}]})); sys.exit(0)
if mode == "semgrep_errors_exit1":
    print(json.dumps({"results": [], "errors": [{"level": "error", "message": "Syntax error", "path": "a.py"}]})); sys.exit(1)
if mode == "semgrep_warn_only":
    print(json.dumps({"results": [], "errors": [{"level": "warn", "message": "timeout on rule x"}]})); sys.exit(0)
if mode == "clean":
    print(json.dumps({"results": [], "errors": []})); sys.exit(0)
if mode == "clean_list":
    print("[]"); sys.exit(0)
if mode == "leaks_exit1":
    print(json.dumps([{"RuleID": "aws-access-token", "Description": "AWS", "File": "ok.py", "StartLine": 1}])); sys.exit(1)
'''

RESULTS_MANIFEST = '''name = "{name}"
dimensions = ["security"]
checks = 5
scope = "repo"

[requires]
binaries = []
network = false
timeout = 60

[invoke]
argv = {argv}
parse = "json"
ok_exit = [0, 1]

[map]
findings = "$.results[*]"
errors = "$.errors[*]"
rule_id = "test_id"
title = "issue_text"
path = "filename"
line = "line_number"
severity_const = "high"
dimension = "security"
'''

LIST_MANIFEST = '''name = "{name}"
dimensions = ["security"]
checks = 5
scope = "repo"

[requires]
binaries = []
network = false
timeout = 60

[invoke]
argv = {argv}
parse = "json"
ok_exit = [0, 1]

[map]
findings = "$"
rule_id = "RuleID"
title = "Description"
path = "File"
line = "StartLine"
severity_const = "critical"
dimension = "security"
'''


def _adapter(tmp_path: Path, mode: str, manifest: str = RESULTS_MANIFEST, name: str = "fake_tool") -> A.Adapter:
    script = tmp_path / "tool.py"
    script.write_text(SCRIPT, encoding="utf-8")
    argv = json.dumps([sys.executable, str(script), mode, "{workdir}"])
    p = tmp_path / f"{name}.adapter.toml"
    p.write_text(manifest.format(name=name, argv=argv), encoding="utf-8")
    return A.load_adapter(p)


def _ctx(tmp_path: Path) -> ProbeContext:
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (root / "app.py").write_text("def f(:\n", encoding="utf-8")
    repos = [RepoInfo(id=root.name, path=str(root))]
    return ProbeContext(repos=repos, inventory=build_inventory(repos))


# ---------------------------------------------------------------------------
# Adapter.run: unreadable output is an error whatever the exit code
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode, manifest, expect", [
    ("gitleaks_fatal", LIST_MANIFEST, "no output"),
    ("ruff_noout", LIST_MANIFEST, "no output"),
    ("empty_exit0", RESULTS_MANIFEST, "no output"),
    ("garbage_exit0", RESULTS_MANIFEST, "not JSON"),
    ("renamed_key", RESULTS_MANIFEST, "no `results` key"),
])
def test_unreadable_output_inside_ok_exit_is_an_error(tmp_path, mode, manifest, expect):
    adapter = _adapter(tmp_path, mode, manifest)
    with pytest.raises(RuntimeError, match=expect):
        adapter.run(_ctx(tmp_path))


def test_the_tools_stderr_is_quoted_so_the_reader_knows_why(tmp_path):
    adapter = _adapter(tmp_path, "gitleaks_fatal", LIST_MANIFEST)
    with pytest.raises(RuntimeError, match="FTL Failed to load config"):
        adapter.run(_ctx(tmp_path))


def test_a_tool_that_reports_its_own_errors_is_an_error_that_names_what_it_set_aside(tmp_path):
    adapter = _adapter(tmp_path, "bandit_errors")
    with pytest.raises(A.AnalyzerErrors) as info:
        adapter.run(_ctx(tmp_path))
    assert "app.py" in str(info.value) and "syntax error" in str(info.value)
    assert "1 finding(s)" in str(info.value) and "set aside" in str(info.value)
    assert [f.location.path for f in info.value.findings] == ["ok.py"]


def test_semgrep_style_errors_with_exit_1_are_an_error(tmp_path):
    adapter = _adapter(tmp_path, "semgrep_errors_exit1")
    with pytest.raises(A.AnalyzerErrors, match="a.py: Syntax error"):
        adapter.run(_ctx(tmp_path))


def test_warnings_in_the_errors_list_do_not_fail_the_run(tmp_path):
    assert _adapter(tmp_path, "semgrep_warn_only").run(_ctx(tmp_path)) == []


@pytest.mark.parametrize("mode, manifest", [
    ("clean", RESULTS_MANIFEST), ("clean_list", LIST_MANIFEST), ("banner_then_json", RESULTS_MANIFEST),
])
def test_a_clean_answer_is_still_a_clean_answer(tmp_path, mode, manifest):
    assert _adapter(tmp_path, mode, manifest).run(_ctx(tmp_path)) == []


def test_findings_with_exit_1_are_findings(tmp_path):
    out = _adapter(tmp_path, "leaks_exit1", LIST_MANIFEST).run(_ctx(tmp_path))
    assert [f.rule_id for f in out] == ["fake_tool/aws-access-token"]


def test_parse_output_still_answers_the_old_question_for_readable_output():
    adapter = A.Adapter(name="t", mapping={"findings": "$.results[*]"})
    assert adapter.parse_output('{"results": [{"a": 1}]}') == [{"a": 1}]
    with pytest.raises(A.AdapterOutputError):
        adapter.parse_output("")


# ---------------------------------------------------------------------------
# engine: the outcome is `error`, the findings stay, nothing is memoised
# ---------------------------------------------------------------------------

@pytest.fixture
def registered(tmp_path):
    home = tmp_path / "fakes"
    home.mkdir()
    before = len(REGISTRY)
    yield home, before
    del REGISTRY[before:]
    for p in home.glob("*.adapter.toml"):
        A._REGISTERED.discard(p.name.split(".")[0])


def _register(home: Path, mode: str, name: str, manifest: str = RESULTS_MANIFEST) -> None:
    script = home / f"{name}.py"
    script.write_text(SCRIPT, encoding="utf-8")
    argv = json.dumps([sys.executable, str(script), mode, "{workdir}"])
    (home / f"{name}.adapter.toml").write_text(manifest.format(name=name, argv=argv), encoding="utf-8")


def test_a_tool_that_could_not_read_part_of_the_tree_is_recorded_as_an_error(tmp_path, registered):
    home, before = registered
    _register(home, "bandit_errors", "fake_bandit")
    _register(home, "gitleaks_fatal", "fake_gitleaks", LIST_MANIFEST)
    A.register_adapters([str(home)])
    assert {"fake_bandit", "fake_gitleaks"} <= {p.name for p in REGISTRY[before:]}
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (root / "app.py").write_text("def f(:\n", encoding="utf-8")
    cfg = copy.deepcopy(load_config(None))
    cfg["cache"] = {"enabled": False}
    rep = run_scan([str(root)], cfg, only=["fake_bandit", "fake_gitleaks"], use_adapters=False,
                   use_cache=False)
    by = {p.name: p for p in rep.probes}
    bandit, gitleaks = by["fake_bandit"], by["fake_gitleaks"]
    assert bandit.status == "error" and "app.py" in bandit.reason
    # CI-7: an errored probe reports no findings; the reason says how many
    # were set aside so the reader knows the tool did see something
    assert bandit.finding_count == 0 and "1 finding(s)" in bandit.reason
    assert [f for f in rep.findings if f.probe == "fake_bandit"] == []
    assert gitleaks.status == "error" and "no output" in gitleaks.reason
    assert gitleaks.finding_count == 0
    # neither counts as checked: coverage must carry both as gaps
    assert rep.scorecard.coverage == 0.0
    from arbiter.claims import verify
    assert verify(rep, cfg) == []
