"""Advisory bar and default-off rules (ARB-174), and the public precision
sentence (ARB-175).

A rule the ledger measured on at least 30 labels with a lower bound under
0.85, or on at least 10 labels at an observed precision under 0.5, is off
by default: its findings are not reported unless the run enables the rule,
and even then they never fail the gate. The decision is computed from the
ledger's counts at scan time. The suite runs every rule (conftest.py);
these tests set `enable_rules: []` to see the default.
"""
from __future__ import annotations

import copy
import json

import pytest
from helpers import ROOT

from arbiter import precision as P
from arbiter.core import Finding, Location, Report
from arbiter.diff import render_pr_comment
from arbiter.engine import run_scan
from arbiter.policy import DEFAULTS, evaluate_gate
from arbiter.report import render_console, render_markdown

# The scans below run the Python pack, which needs tree-sitter.
_needs_ts = pytest.mark.skipif(
    not __import__("arbiter.ast", fromlist=["available"]).available(),
    reason="tree-sitter not installed")

RULE = "arbiter/python.insecure-random-for-secret"
CODE = ("import random\n\n"
        "def token():\n"
        "    return str(random.random())\n")


def _bar() -> dict:
    return dict(P.DEFAULT_BAR)


def _entry(tp: int, fp: int, **kw) -> dict:
    return {"tp": tp, "fp": fp, "unsure": 0, **kw}


def _cfg(enable=(), ledger: str | None = None, **gate) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    cfg["enable_rules"] = list(enable)
    cfg["cache"] = {"enabled": False}
    cfg["gate"].update(gate)
    if ledger:
        cfg["precision"]["ledger"] = ledger
    return cfg


def _f(rule: str = RULE, severity: str = "critical") -> Finding:
    return Finding(rule_id=rule, title="t", severity=severity,
                   location=Location(path="a.py", start_line=3), evidence=rule)


# ---------------------------------------------------------------------------
# The bar
# ---------------------------------------------------------------------------

def test_the_advisory_bar_sits_beside_the_unchanged_admit_and_claim_bars():
    bar = P.DEFAULT_BAR
    assert bar["advisory_lower"] == 0.85 and bar["advisory_min_n"] == 30
    assert bar["off_precision"] == 0.5 and bar["off_min_n"] == 10
    assert bar["rule_lower"] == 0.97 and bar["tier_lower"] == 0.99


def test_a_ledger_cannot_loosen_the_advisory_bar():
    bar = P.effective_bar({"advisory_lower": 0.5, "advisory_min_n": 1000, "off_min_n": 500,
                           "off_precision": 0.1})
    assert bar["advisory_lower"] == 0.85 and bar["off_precision"] == 0.5
    assert bar["advisory_min_n"] == 30 and bar["off_min_n"] == 10
    tighter = P.effective_bar({"advisory_lower": 0.9, "advisory_min_n": 20})
    assert tighter["advisory_lower"] == 0.9 and tighter["advisory_min_n"] == 20


def _lower(tp, n):
    return P.wilson(tp, n)[0]


def test_lower_bound_boundary_at_thirty_labels():
    # 30/30 has lower bound 0.886 (on); 29/30 0.833 (off).
    assert _lower(30, 30) >= 0.85 > _lower(29, 30)
    assert P.default_state(_entry(30, 0), _bar())[0] == "on"
    assert P.default_state(_entry(29, 1), _bar())[0] == "off"
    # 29 labels: too few to measure, shown, however many are wrong (if p >= 0.5).
    assert P.default_state(_entry(15, 14), _bar())[0] == "on"
    assert P.default_state(_entry(15, 15), _bar())[0] == "off"   # 30 labels, lower bound 0.33


def test_the_lower_bound_comparison_is_inclusive():
    bar = _bar()
    lo = _lower(40, 40)
    bar["advisory_lower"] = lo
    assert P.default_state(_entry(40, 0), bar)[0] == "on"
    bar["advisory_lower"] = lo + 1e-9
    assert P.default_state(_entry(40, 0), bar)[0] == "off"


def test_observed_precision_boundary_at_ten_labels():
    assert P.default_state(_entry(4, 5), _bar())[0] == "on"        # 9 labels: not enough
    assert P.default_state(_entry(0, 9), _bar())[0] == "on"
    assert P.default_state(_entry(4, 6), _bar())[0] == "off"       # 10 labels, 0.4
    assert P.default_state(_entry(0, 10), _bar())[0] == "off"
    assert P.default_state(_entry(5, 5), _bar())[0] == "on"        # exactly 0.5 is not below
    state, why = P.default_state(_entry(1, 12), _bar())
    assert state == "off" and "1/13" in why


def test_no_or_few_labels_keeps_the_rule_on_as_advisory():
    assert P.default_state(None, _bar())[0] == "on"
    assert P.default_state(_entry(0, 0), _bar())[0] == "on"
    assert P.default_state(_entry(3, 2), _bar())[0] == "on"


def test_unsure_labels_do_not_count():
    assert P.default_state({"tp": 4, "fp": 5, "unsure": 50}, _bar())[0] == "on"


def test_the_shipped_ledger_records_the_runtime_decision_for_every_rule():
    led = P.load_ledger()
    for rule, e in led["rules"].items():
        state, why = P.default_state(e, led["bar"])
        assert e.get("default") == state, rule
        assert e.get("default_reason") == why, rule


def test_todays_noisiest_python_rules_are_off():
    off = P.default_off_rules(P.load_ledger())
    for rule in ("swallowed-error-in-worker-loop", "jwt-unverified-decode",
                 "ssrf-check-then-connect", "retry-loop-no-backoff", "sql-injection"):
        assert f"arbiter/python.{rule}" in off, rule
    assert "arbiter/java.sql-string-built" in off
    assert "arbiter/supply.unpinned-action" not in off
    assert "arbiter/python.http-no-timeout" not in off


# ---------------------------------------------------------------------------
# Selection, opt-in, gate
# ---------------------------------------------------------------------------

def test_enabled_by_user_takes_ids_globs_and_star():
    assert P.enabled_by_user(RULE, {"enable_rules": [RULE]})
    assert P.enabled_by_user(RULE, {"enable_rules": ["arbiter/python.*"]})
    assert P.enabled_by_user(RULE, {"enable_rules": "*"})
    assert not P.enabled_by_user(RULE, {"enable_rules": ["arbiter/java.*"]})
    assert not P.enabled_by_user(RULE, {})


def _seeded(tmp_path, tp, fp) -> str:
    led = P.empty_ledger()
    led["rules"][RULE] = _entry(tp, fp)
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps(led))
    return str(p)


def _scan(tmp_path, cfg):
    code = tmp_path / "code"
    code.mkdir(exist_ok=True)
    (code / "app.py").write_text(CODE)
    return run_scan([str(code)], cfg, only=["lang_python"], use_cache=False, use_adapters=False)


@_needs_ts
def test_a_default_off_rule_is_not_reported_and_the_report_says_how_many(tmp_path):
    ledger = _seeded(tmp_path, 10, 40)
    rep = _scan(tmp_path, _cfg(ledger=ledger))
    assert not [f for f in rep.findings if f.rule_id == RULE]
    block = rep.scan_scope["default_off"]
    assert block["findings"] == 1 and block["rules"] == {RULE: 1}
    assert "--all-rules" in block["how_to_enable"]
    for text in (render_console(rep, color=False), render_markdown(rep), render_pr_comment(rep)):
        assert "1 finding from 1 noisy rule not reported" in text
        assert "enable_rules" in text and "--all-rules" in text


@_needs_ts
def test_the_same_rule_measured_well_is_reported(tmp_path):
    rep = _scan(tmp_path, _cfg(ledger=_seeded(tmp_path, 200, 0)))
    assert [f for f in rep.findings if f.rule_id == RULE]
    assert rep.scan_scope["default_off"]["findings"] == 0


@_needs_ts
def test_enabling_the_rule_reports_it_tagged_and_it_never_gates(tmp_path):
    ledger = _seeded(tmp_path, 10, 40)
    for enable in ([RULE], ["arbiter/python.*"], ["*"]):
        for gate in ({"tier_mode": "legacy"},
                     {"tier_mode": "tiered", "tiers": ["verified", "advisory"]}):
            cfg = _cfg(enable=enable, ledger=ledger, **gate)
            cfg["gate"]["fail_on"] = {"severity": "info"}
            rep = _scan(tmp_path, cfg)
            hits = [f for f in rep.findings if f.rule_id == RULE]
            assert hits and all(P.DEFAULT_OFF_TAG in f.tags for f in hits)
            assert not set(rep.gate["failing_ids"]) & {f.id for f in hits}
            assert rep.scan_scope["default_off"]["enabled"] == {RULE: len(hits)}
            assert rep.scan_scope["default_off"]["findings"] == 0


def test_the_gate_skips_default_off_findings_even_when_verified():
    f = _f()
    f.tier = "verified"
    f.tags.append(P.DEFAULT_OFF_TAG)
    for mode in ("tiered", "legacy"):
        cfg = copy.deepcopy(DEFAULTS)
        cfg["gate"]["tier_mode"] = mode
        r = Report()
        r.findings = [f]
        g = evaluate_gate(r, cfg)
        assert g["passed"] and g["considered"] == 0
    g2 = _f()
    g2.tier = "verified"
    r = Report()
    r.findings = [g2]
    assert not evaluate_gate(r, copy.deepcopy(DEFAULTS))["passed"]


def test_rules_outside_the_ledger_are_never_switched_off():
    kept, block = P.apply_default_off([_f("semgrep/some.rule"), _f("arbiter/not.in-ledger")], {})
    assert len(kept) == 2 and block["findings"] == 0


def test_all_rules_flag_enables_everything():
    from arbiter.cli import build_parser
    args = build_parser().parse_args(["scan", "x", "--all-rules"])
    assert args.all_rules


def test_default_off_line_is_empty_when_nothing_was_left_out():
    assert P.default_off_line(None) == ""
    assert P.default_off_line({"findings": 0}) == ""
    assert P.default_off_line({"findings": 3, "rules": {"a": 2, "b": 1}}).startswith(
        "3 findings from 2 noisy rules not reported")


# ---------------------------------------------------------------------------
# The public sentence
# ---------------------------------------------------------------------------

V = "arbiter/supply.unpinned-action"
A = "arbiter/python.http-no-timeout"


def _claim_ledger(v_ho=(524, 0), v_all=(690, 0)) -> dict:
    led = P.empty_ledger()
    led["rules"][V] = _entry(*v_all, held_out={"tp": v_ho[0], "fp": v_ho[1], "unsure": 0},
                             cwe=["CWE-1357", "CWE-494"])
    led["rules"][A] = _entry(10, 40)
    return led


def test_the_sentence_fills_x_and_n_from_the_ledger():
    c = P.public_claim(_claim_ledger(), {}, rules=[V, A, "arbiter/x.y"])
    assert c["qualifying"] == [V] and c["rules_total"] == 3
    assert "1 of 3 rules qualify" in c["sentence"]
    assert c["sentence"].startswith("Findings that can fail your build come only from verified rules")
    assert "≥ 85%" in c["sentence"] and "model-labelled" in c["sentence"]
    assert c["default_off"] == [A]
    assert "2 of 3 rules have enough labels" in c["coverage"] and "1 rule is off by default" in c["coverage"]
    c0 = P.public_claim(_claim_ledger(v_ho=(100, 0), v_all=(100, 0)), {}, rules=[V, A])
    # 100/100 is not admitted (lower 0.963 < 0.97): it cannot gate, so X is 0.
    assert "0 of 2 rules qualify" in c0["sentence"] and c0["below_claim"] == []


def test_an_admitted_rule_below_99_is_never_counted_as_99():
    # 300/300 held-out: lower 0.987, admitted (>= 0.97) but under 0.99.
    led = _claim_ledger(v_ho=(300, 0), v_all=(300, 0))
    assert P.admission(led["rules"][V], led["bar"])[0]
    c = P.public_claim(led, {}, rules=[V, A])
    assert c["qualifying"] == [] and c["below_claim"] == [V]
    assert "0 of 2 rules are measured at ≥ 99%" in c["sentence"]
    assert "1 more at ≥ 97%" in c["sentence"]


def test_x_uses_the_held_out_bound_not_the_pooled_one():
    led = _claim_ledger(v_ho=(100, 0), v_all=(900, 0))
    assert P.public_claim(led, {}, rules=[V])["qualifying"] == []


def test_caveats_say_plainly_how_each_qualifying_rule_was_checked():
    c = P.public_claim(_claim_ledger(), {}, rules=[V, A])
    assert c["caveats"] and "model-labelled" in c["caveats"][0] and "700 of 700" in c["caveats"][0]
    assert P.calibration_caveat("arbiter/x.inj", {"cwe": ["CWE-89"]}) == ""
    assert "0.824" in P.calibration_caveat("arbiter/x.sup", {"cwe": ["CWE-494"]})
    assert "not calibrated" in P.calibration_caveat("arbiter/x.other", {"cwe": ["CWE-400"]})


@_needs_ts
def test_the_scan_carries_the_sentence_and_the_renderings_print_it(tmp_path):
    rep = _scan(tmp_path, _cfg())
    claim = rep.scan_scope["precision_claim"]
    assert claim["sentence"] == P.public_claim()["sentence"]
    md = render_markdown(rep)
    assert claim["sentence"] in md and claim["coverage"] in md
    assert claim["sentence"] in render_console(rep, color=False)
    assert claim["sentence"] in render_pr_comment(rep)


def test_no_output_says_99_without_its_qualifiers():
    for text in (P.TIER_MEANING["verified"], P.tier_note("verified", ["verified"])):
        assert "99%" not in text
    s = P.public_claim()["sentence"]
    assert "95% lower bound" in s and "held-out" in s and "model-labelled" in s


def test_readme_states_the_generated_sentence_shape():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Findings that can fail your build come only from verified rules" in text
    assert "99% accurate" not in text
