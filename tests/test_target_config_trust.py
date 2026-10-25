"""A scanned repository's own arbiter.yaml may not grade itself (ARB-143,
FAIL-120).

Before this, a target could ship `precision: {ledger: ..., verified_rules:
["*"]}` with a ledger whose bar was 0.0, and every one of its findings came
out `verified ... measured at least 99% precise`; or it could set
`gate.fail_on.severity: null` and the gate could never fail. The config
found in the target root is the target's: it may tighten the gate and
suppress, never set the precision keys or loosen the gate. A config the
operator names with `--config` is trusted in full.
"""
from __future__ import annotations

import json

import pytest
from helpers import CLEAN_PY

from arbiter.core import Report
from arbiter.engine import run_scan
from arbiter.policy import DEFAULTS, config_notes, load_config, restrict_target_config
from arbiter.precision import DEFAULT_BAR, effective_bar, load_ledger
from arbiter.report import render_console, render_markdown

LAX_LEDGER = {"version": 1,
              "bar": {"rule_lower": 0.0, "rule_min_n": 0, "offline_lower": 0.0},
              "rules": {"arbiter/quality.todo-density": {"tp": 1, "fp": 0}}}

TODO_PY = "import os\n" + "".join(f"# TODO {i}\n" for i in range(12)) + "x = 1\n"


def _target(tmp_path, config: str):
    (tmp_path / "app.py").write_text(TODO_PY, encoding="utf-8")
    (tmp_path / "ledger.json").write_text(json.dumps(LAX_LEDGER), encoding="utf-8")
    (tmp_path / "arbiter.yaml").write_text(config, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# precision keys
# ---------------------------------------------------------------------------

def test_a_target_root_config_cannot_set_precision_keys(tmp_path):
    root = _target(tmp_path, 'precision:\n  ledger: ledger.json\n  verified_rules: ["*"]\n')
    cfg = load_config(None, str(root))
    assert cfg["precision"] == DEFAULTS["precision"]
    assert config_notes(cfg) == ["precision: a target's own config may not set it"]
    assert cfg["config_source"]["explicit"] is False


def test_a_target_root_config_cannot_set_the_verify_pass(tmp_path):
    root = _target(tmp_path, "verify:\n  enabled: false\n")
    cfg = load_config(None, str(root))
    assert cfg["verify"] == DEFAULTS["verify"]
    assert any(n.startswith("verify:") for n in config_notes(cfg))


def test_an_explicit_config_is_trusted_in_full(tmp_path):
    root = _target(tmp_path, 'precision:\n  ledger: ledger.json\n  verified_rules: ["*"]\n')
    cfg = load_config(str(root / "arbiter.yaml"))
    assert cfg["precision"]["verified_rules"] == ["*"]
    assert cfg["precision"]["ledger"] == str((root / "ledger.json").resolve())
    assert config_notes(cfg) == []
    assert cfg["config_source"]["explicit"] is True


def test_a_scan_of_a_self_verifying_target_yields_no_verified_finding_and_says_why(tmp_path):
    """The reproducer: a lax ledger and `verified_rules: ["*"]` in the
    target root made every finding verified. Now none is, and the report
    says the block was ignored."""
    root = _target(tmp_path, 'precision:\n  ledger: ledger.json\n  verified_rules: ["*"]\n')
    rep = run_scan([str(root)], load_config(None, str(root)), use_adapters=False)
    active = rep.active()
    assert active, "the fixture must produce findings for the tier claim to matter"
    assert {f.tier for f in active} == {"advisory"}
    assert rep.scan_scope["tiers"]["counts"]["verified"] == 0
    assert rep.scan_scope["config"]["ignored"] == ["precision: a target's own config may not set it"]
    console = render_console(rep, color=False)
    assert "may not set them" in console and "precision" in console
    assert "may not set them" in render_markdown(rep)


# ---------------------------------------------------------------------------
# ledger paths and bar
# ---------------------------------------------------------------------------

def test_ledger_paths_resolve_relative_to_the_config_file(tmp_path):
    root = _target(tmp_path, "precision:\n  ledger: ledger.json\n")
    cfg = load_config(str(root / "arbiter.yaml"))
    assert cfg["precision"]["ledger"] == str((root / "ledger.json").resolve())


def test_a_ledger_path_that_escapes_the_config_directory_is_refused(tmp_path):
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps(LAX_LEDGER), encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    _target(root, "precision:\n  ledger: ../elsewhere.json\n")
    with pytest.raises(RuntimeError, match="outside the config"):
        load_config(str(root / "arbiter.yaml"))
    _target(root, f"precision:\n  ledger: {outside}\n")
    with pytest.raises(RuntimeError, match="outside the config"):
        load_config(str(root / "arbiter.yaml"))


def test_a_ledger_can_never_lower_the_default_bar(tmp_path):
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps(LAX_LEDGER), encoding="utf-8")
    ledger = load_ledger(p)
    assert ledger["bar"]["rule_lower"] == DEFAULT_BAR["rule_lower"]
    assert ledger["bar"]["rule_min_n"] == DEFAULT_BAR["rule_min_n"]
    assert ledger["bar"]["offline_lower"] == DEFAULT_BAR["offline_lower"]
    assert isinstance(ledger["bar"]["rule_min_n"], int)
    # a stricter bar is honoured; an unknown key passes through
    assert effective_bar({"rule_lower": 0.995, "note": "x"})["rule_lower"] == 0.995
    assert effective_bar({"note": "x"})["note"] == "x"


# ---------------------------------------------------------------------------
# gate: tighten allowed, loosen dropped
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("gate, kept", [
    ({"fail_on": {"severity": "high"}}, {"fail_on": {"severity": "high"}}),
    ({"fail_on": {"new": "medium"}}, {"fail_on": {"new": "medium"}}),
    ({"fail_on": {"coverage_below": 0.8}}, {"fail_on": {"coverage_below": 0.8}}),
    ({"gate_on_inferred": True}, {"gate_on_inferred": True}),
    ({"fail_on_probe_error": True}, {"fail_on_probe_error": True}),
    ({"tier_mode": "legacy"}, {"tier_mode": "legacy"}),
    ({"tiers": ["verified", "advisory"]}, {"tiers": ["verified", "advisory"]}),
])
def test_a_target_may_tighten_its_gate(gate, kept):
    out, notes = restrict_target_config({"gate": gate})
    assert out["gate"] == kept and notes == []


@pytest.mark.parametrize("gate, note", [
    ({"fail_on": {"severity": None}}, "gate.fail_on.severity"),
    ({"fail_on": {"severity": 2}}, "gate.fail_on.severity"),
    ({"fail_on": {"coverage_below": None}}, "gate.fail_on.coverage_below"),
    ({"gate_on_inferred": False, "fail_on_probe_error": None}, "gate.fail_on_probe_error"),
    ({"tiers": ["advisory"]}, "gate.tiers"),
    ({"tiers": []}, "gate.tiers"),
])
def test_a_target_may_not_loosen_its_gate(gate, note):
    out, notes = restrict_target_config({"gate": gate})
    merged = {**DEFAULTS["gate"], **out["gate"]}
    assert merged["fail_on"].get("severity", "critical") == "critical" or note != "gate.fail_on.severity"
    assert any(n.startswith(note) for n in notes), notes
    # the dropped key took the default, not the file's value
    for k in ("tiers", "fail_on_probe_error"):
        if k in gate and any(n.startswith(f"gate.{k}") for n in notes):
            assert k not in out["gate"]


def test_a_target_that_switches_its_gate_off_still_fails_on_a_critical(tmp_path):
    (tmp_path / "creds.py").write_text(
        'AWS = "AKIAIOSFODNN7EXAMPLE"\nSECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
        encoding="utf-8")
    (tmp_path / "arbiter.yaml").write_text(
        "gate:\n  tier_mode: legacy\n  fail_on:\n    severity: null\n", encoding="utf-8")
    cfg = load_config(None, str(tmp_path))
    assert cfg["gate"]["fail_on"]["severity"] == "critical"
    assert cfg["gate"]["tier_mode"] == "legacy"
    rep = run_scan([str(tmp_path)], cfg, use_adapters=False)
    assert any(f.severity == "critical" for f in rep.active()), "fixture must plant a critical"
    assert rep.gate["passed"] is False
    assert "gate.fail_on.severity" in " ".join(rep.scan_scope["config"]["ignored"])


def test_a_misspelt_gate_value_in_a_target_config_is_still_an_error(tmp_path):
    (tmp_path / "arbiter.yaml").write_text("gate:\n  tiers: [verifed]\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="gate.tiers"):
        load_config(None, str(tmp_path))


def test_a_report_without_a_config_block_prints_no_note():
    from arbiter.report import config_ignored_line
    assert config_ignored_line(Report()) == ""
