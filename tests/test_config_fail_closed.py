"""Configuration mistakes fail closed (ARB-152, FAIL-129).

Three ways a repository with criticals passed its gate without anyone
asking it to:

* `gate.fail_on.severity: Critical` (or `crtical`): `sev_at_least` matched
  nothing for an unknown threshold, so the gate had no reason to fail. A
  known name in any case is now normalised; an unknown name is a config
  error (exit 2), like a misspelt `tier_mode` always was.
* a `suppress` entry without `expires` or without a selector: the
  docstring said expiry was mandatory and enforced; nothing enforced it,
  and an entry with only a reason matched every finding forever. Both are
  now config errors, and `apply_suppressions` ignores such an entry when
  the config was built in code.
* `coverage_below` off by default meant a withheld grade (probes disabled
  in the target's own config, coverage 3%) coexisted with gate PASS. A
  withheld grade now fails the gate unless the withholding is the
  operator's own partial scan; only `--config` may switch that off.
"""
from __future__ import annotations

import pytest
from helpers import CLEAN_PY, LEAKY_PY, _finding, _git_repo

from arbiter.cli import main
from arbiter.engine import run_scan
from arbiter.policy import (
    DEFAULTS,
    apply_suppressions,
    check_gate_config,
    load_config,
    normalise_severity,
    restrict_target_config,
    suppression_problems,
)

LEAKY = 'import os\nAWS = "AKIAIOSFODNN7EXAMPLQ"\nos.system(input())\n'


def _target(tmp_path, config: str, code: str = LEAKY):
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    (tmp_path / "arbiter.yaml").write_text(config, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# gate severities
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spelling", ["Critical", "CRITICAL", " critical "])
def test_a_known_severity_in_any_case_is_normalised(tmp_path, spelling):
    assert normalise_severity(spelling) == "critical"
    cfg = {"gate": {"fail_on": {"severity": spelling, "new": "High"}}}
    check_gate_config(cfg)
    assert cfg["gate"]["fail_on"] == {"severity": "critical", "new": "high"}
    out, notes = restrict_target_config({"gate": {"fail_on": {"severity": spelling}}})
    assert out["gate"]["fail_on"]["severity"] == "critical" and notes == []


@pytest.mark.parametrize("key, value", [("severity", "crtical"), ("new", "hgih"),
                                        ("severity", "nothing"), ("severity", 3)])
def test_an_unknown_gate_severity_is_a_config_error(tmp_path, key, value):
    with pytest.raises(RuntimeError, match=f"gate.fail_on.{key}"):
        check_gate_config({"gate": {"fail_on": {key: value}}}, "here")


def test_a_misspelt_severity_in_the_target_root_is_an_error_not_a_quiet_pass(tmp_path):
    """The reproducer: `severity: crtical` with `tier_mode: legacy` passed a
    repository holding a critical. Now the scan refuses to start."""
    root = _target(tmp_path, "gate:\n  tier_mode: legacy\n  fail_on:\n    severity: crtical\n")
    with pytest.raises(RuntimeError, match="crtical"):
        load_config(None, str(root))


def test_a_capitalised_severity_in_the_target_root_gates_as_written(tmp_path):
    root = _target(tmp_path, "gate:\n  tier_mode: legacy\n  fail_on:\n    severity: Critical\n")
    cfg = load_config(None, str(root))
    assert cfg["gate"]["fail_on"]["severity"] == "critical"
    assert cfg["config_source"]["ignored"] == []
    rep = run_scan([str(root)], cfg, use_adapters=False, use_cache=False)
    assert rep.gate["passed"] is False
    assert any("at or above critical" in r for r in rep.gate["reasons"])


def test_the_cli_exits_2_on_a_gate_severity_typo(tmp_path, capsys):
    root = _target(tmp_path, "gate:\n  fail_on:\n    severity: crtical\n", CLEAN_PY)
    code = main(["gate", str(root), "--no-adapters", "--no-cache", "--no-history",
                 "--out", str(tmp_path / "out"), "--format", "json"])
    assert code == 2
    assert "crtical" in capsys.readouterr().err


def test_an_explicit_config_with_a_typo_is_an_error_too(tmp_path):
    (tmp_path / "cfg.yaml").write_text("gate:\n  fail_on:\n    new: hgih\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="hgih"):
        load_config(str(tmp_path / "cfg.yaml"))


def test_coverage_below_and_withheld_grade_are_type_checked():
    with pytest.raises(RuntimeError, match="coverage_below"):
        check_gate_config({"gate": {"fail_on": {"coverage_below": "half"}}})
    with pytest.raises(RuntimeError, match="withheld_grade"):
        check_gate_config({"gate": {"fail_on": {"withheld_grade": "no"}}})


# ---------------------------------------------------------------------------
# suppressions
# ---------------------------------------------------------------------------

def test_suppression_problems_name_each_missing_part():
    problems = suppression_problems([{"reason": "temporary"}])
    assert any("`expires`" in p for p in problems)
    assert any("needs at least one of" in p for p in problems)
    assert suppression_problems([{"rule": "x/*", "reason": "r", "expires": "2099-01-01"}]) == []
    assert suppression_problems([{"rule": "x", "expires": "2099-01-01"}]) == ["suppress[0]: `reason` is mandatory"]
    assert suppression_problems([{"rule": "x", "reason": "r", "expires": "soon"}]) == \
        ["suppress[0]: `expires` is not a date: 'soon'"]
    assert suppression_problems("not a list") == ["suppress must be a list of entries"]


def test_a_suppression_without_an_expiry_is_a_config_error(tmp_path):
    (tmp_path / "cfg.yaml").write_text(
        'suppress:\n  - rule: "arbiter/*"\n    reason: "forever"\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="`expires`"):
        load_config(str(tmp_path / "cfg.yaml"))


def test_a_suppression_without_a_selector_is_a_config_error(tmp_path):
    (tmp_path / "cfg.yaml").write_text(
        'suppress:\n  - reason: "temporary"\n    expires: 2099-01-01\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="match every finding"):
        load_config(str(tmp_path / "cfg.yaml"))


def test_apply_suppressions_ignores_an_invalid_entry_as_a_backstop():
    found = [_finding("arbiter/x"), _finding("arbiter/y")]
    n = apply_suppressions(found, {"suppress": [{"reason": "blanket"},
                                                {"rule": "arbiter/x", "reason": "no end"}]})
    assert n == 0 and not any(f.suppressed for f in found)
    n = apply_suppressions(found, {"suppress": [{"rule": "arbiter/x", "reason": "ok",
                                                 "expires": "2099-01-01"}]})
    assert n == 1 and found[0].suppressed and not found[1].suppressed


def test_a_yaml_date_expiry_still_parses(tmp_path):
    import datetime as dt
    found = [_finding("arbiter/x")]
    assert apply_suppressions(found, {"suppress": [{"rule": "arbiter/x", "reason": "r",
                                                    "expires": dt.date(2099, 1, 1)}]}) == 1


# ---------------------------------------------------------------------------
# a withheld grade fails the gate
# ---------------------------------------------------------------------------

def test_probes_disabled_in_the_target_config_cannot_yield_a_passing_gate(tmp_path):
    """The reproducer: `probes: {disable: [secrets, lang_python]}` in the
    target root, coverage 49%, grade withheld, gate PASS, 0 findings."""
    root = _target(tmp_path, "probes:\n  disable: [secrets, lang_python]\n")
    rep = run_scan([str(root)], load_config(None, str(root)), use_adapters=False, use_cache=False)
    assert rep.scorecard.withheld and rep.scorecard.withheld_by == "coverage"
    assert rep.gate["passed"] is False
    assert any(r.startswith("grade withheld (coverage)") for r in rep.gate["reasons"])


def test_withheld_grade_default_is_on_and_a_target_may_not_switch_it_off():
    assert DEFAULTS["gate"]["fail_on"]["withheld_grade"] is True
    out, notes = restrict_target_config({"gate": {"fail_on": {"withheld_grade": False}}})
    assert "withheld_grade" not in out["gate"].get("fail_on", {})
    assert any(n.startswith("gate.fail_on.withheld_grade") for n in notes)
    out, notes = restrict_target_config({"gate": {"fail_on": {"withheld_grade": True}}})
    assert out["gate"]["fail_on"]["withheld_grade"] is True and notes == []


def test_an_explicit_config_may_let_a_withheld_grade_pass(tmp_path):
    (tmp_path / "app.py").write_text(CLEAN_PY, encoding="utf-8")
    (tmp_path / "cfg.yaml").write_text(
        "probes:\n  disable: [secrets, lang_python]\ngate:\n  fail_on:\n    withheld_grade: false\n",
        encoding="utf-8")
    rep = run_scan([str(tmp_path)], load_config(str(tmp_path / "cfg.yaml")),
                   use_adapters=False, use_cache=False)
    assert rep.scorecard.withheld
    assert rep.gate["passed"] is True


def test_a_partial_scan_still_passes_while_its_grade_is_withheld(tmp_path):
    base = _git_repo(tmp_path, {"a.py": CLEAN_PY}, second={"b.py": CLEAN_PY})
    rep = run_scan([str(tmp_path)], load_config(None), changed_since=base,
                   use_adapters=False, use_cache=False)
    assert rep.scorecard.withheld and rep.scorecard.withheld_by == "partial"
    assert rep.gate["passed"] is True


def test_the_withheld_token_survives_a_round_trip():
    from arbiter.core import Report
    rep = Report()
    rep.scorecard.withheld = True
    rep.scorecard.withheld_by = "nothing_read"
    again = Report.from_dict(rep.to_dict())
    assert again.scorecard.withheld_by == "nothing_read"


def test_a_leaky_repo_fails_for_the_finding_not_only_for_coverage(tmp_path):
    (tmp_path / "a.py").write_text(LEAKY_PY, encoding="utf-8")
    (tmp_path / "arbiter.yaml").write_text("gate:\n  tier_mode: legacy\n  fail_on:\n    severity: high\n",
                                           encoding="utf-8")
    rep = run_scan([str(tmp_path)], load_config(None, str(tmp_path)), use_adapters=False, use_cache=False)
    assert rep.gate["passed"] is False
    assert any("at or above high" in r for r in rep.gate["reasons"])
