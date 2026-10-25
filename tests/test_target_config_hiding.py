"""A scanned repository's own arbiter.yaml may not hide or downgrade its
findings (ARB-148, FAIL-125).

ARB-143 stopped a target-root config from setting the precision keys or
loosening the gate, and left `suppress`, `probes.severity_overrides` and
`score` alone as "features the target is meant to use". Two of them are a
second way to pass one's own gate: a selector-less `suppress` entry matched
every finding (the repository scored 100 with two criticals set aside), and
`severity_overrides: {"*": info}` took every finding out of every threshold.
Both are now dropped from a target-root config and listed under
`scan_scope.config.ignored`; `--config` is trusted in full. A
`score.coverage_threshold` below the default is dropped the same way.
"""
from __future__ import annotations

from arbiter.engine import run_scan
from arbiter.policy import DEFAULTS, config_notes, load_config, restrict_target_config
from arbiter.report import render_console, render_markdown

LEAKY = 'import os\nAWS = "AKIAIOSFODNN7EXAMPLQ"\nos.system(input())\n'


def _target(tmp_path, config: str):
    (tmp_path / "app.py").write_text(LEAKY, encoding="utf-8")
    (tmp_path / "arbiter.yaml").write_text(config, encoding="utf-8")
    return tmp_path


def test_a_target_root_suppress_block_is_dropped_and_noted():
    out, notes = restrict_target_config(
        {"suppress": [{"rule": "*", "reason": "x", "expires": "2099-01-01"}]})
    assert "suppress" not in out
    assert notes == ["suppress: a target's own config may not set it"]


def test_a_target_root_severity_override_is_dropped_but_other_probe_keys_stay():
    out, notes = restrict_target_config(
        {"probes": {"disable": ["judgement"], "severity_overrides": {"*": "info"}}})
    assert out["probes"] == {"disable": ["judgement"]}
    assert notes == ["probes.severity_overrides: a target's own config may not set it"]


def test_a_target_may_raise_the_coverage_bar_but_not_lower_it():
    floor = DEFAULTS["score"]["coverage_threshold"]
    out, notes = restrict_target_config({"score": {"coverage_threshold": 0.9}})
    assert out["score"]["coverage_threshold"] == 0.9 and notes == []
    out, notes = restrict_target_config({"score": {"coverage_threshold": 0.0, "weights": {"quality": 1}}})
    assert "coverage_threshold" not in out["score"]
    assert out["score"]["weights"] == {"quality": 1}
    assert notes and notes[0].startswith("score.coverage_threshold") and str(floor) in notes[0]


def test_a_selector_less_suppression_in_the_target_root_hides_nothing(tmp_path):
    """The reproducer: `suppress: [{reason: temporary}]` set every finding
    aside and the target graded 100. Now the findings stand, the gate reads
    them, and the report says the block was ignored."""
    root = _target(tmp_path, 'suppress:\n  - reason: "temporary, see ticket"\n')
    cfg = load_config(None, str(root))
    assert cfg["suppress"] == []
    rep = run_scan([str(root)], cfg, use_adapters=False, use_cache=False)
    assert rep.active(), "the fixture must produce findings"
    assert not any(f.suppressed for f in rep.findings)
    assert rep.scan_scope["config"]["ignored"] == ["suppress: a target's own config may not set it"]
    console = render_console(rep, color=False)
    assert "may not set them" in console and "suppress" in console
    assert "suppress" in render_markdown(rep)


def test_a_target_root_override_to_info_does_not_downgrade(tmp_path):
    root = _target(tmp_path, 'probes:\n  severity_overrides:\n    "*": info\n')
    cfg = load_config(None, str(root))
    assert cfg["probes"]["severity_overrides"] == {}
    rep = run_scan([str(root)], cfg, use_adapters=False, use_cache=False)
    assert any(f.severity == "critical" for f in rep.active())
    assert "probes.severity_overrides" in " ".join(config_notes(cfg))


def test_the_same_file_passed_with_config_is_honoured_in_full(tmp_path):
    root = _target(tmp_path, 'suppress:\n  - rule: "arbiter/*"\n    reason: accepted\n'
                             '    expires: 2099-01-01\nprobes:\n  severity_overrides:\n'
                             '    "arbiter/secrets.*": low\nscore:\n  coverage_threshold: 0.1\n')
    cfg = load_config(str(root / "arbiter.yaml"))
    assert len(cfg["suppress"]) == 1
    assert cfg["probes"]["severity_overrides"] == {"arbiter/secrets.*": "low"}
    assert cfg["score"]["coverage_threshold"] == 0.1
    assert config_notes(cfg) == []
    rep = run_scan([str(root)], cfg, use_adapters=False, use_cache=False)
    assert rep.findings and all(f.suppressed for f in rep.findings)
