"""Sequential labelling (ARB-170, accuracy plan D1): synthetic rules of known
precision, the prefix property of a sequential run, pre-registration, and
the ledger report section. No network, no model calls."""
from __future__ import annotations

import importlib.util
import json
import math
import random
import sys

import pytest
from helpers import ROOT

from arbiter import sequential as S


def _load(name: str, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sys.path.insert(0, str(ROOT / "tools" / "ground_truth"))
lm = _load("label_models", ROOT / "tools" / "label_models.py")
CFG = S.validate({})


# --- the statistics ----------------------------------------------------------

def test_label_count_table_matches_the_fixed_design_it_is_compared_with():
    rows = {(r["bar"], r["fp"]): r for r in S.label_count_table()}
    # the fixed 97.5%-one-sided Wilson numbers the docs quote
    assert [rows[(0.99, f)]["wilson_975"] for f in (0, 1, 2)] == [381, 563, 726]
    assert [rows[(0.97, f)]["wilson_975"] for f in (0, 1, 2)] == [125, 185, 239]
    assert [rows[(0.99, f)]["seq_05"] for f in (0, 1, 2)] == [370, 623, 844]
    assert [rows[(0.97, f)]["seq_05"] for f in (0, 1, 2)] == [122, 206, 279]
    for r in rows.values():
        assert r["seq_05_batched"] % 25 == 0 and r["seq_05_batched"] >= r["seq_05"]
        assert r["seq_025"] > r["seq_05"]


def test_pass_needs_exactly_tp_needed_and_more_fps_need_more_tps():
    for bar in S.BARS:
        prev = 0
        for fp in range(6):
            t = S.tp_needed(fp, bar, 0.05)
            assert S.rejects(t, fp, bar, 0.05) and not S.rejects(t - 1, fp, bar, 0.05)
            assert t > prev
            prev = t


def test_reported_lower_bound_agrees_with_the_pass_decision():
    # "pass-0.99" never sits beside a bound under 0.99, and the bound falls
    # as a false positive is added
    for fp in range(4):
        t = S.tp_needed(fp, 0.99, 0.05)
        assert S.lower_bound(t, fp, 0.05) >= 0.99 > S.lower_bound(t - 1, fp, 0.05)
        d = S.decide(t, fp, CFG)
        assert d["state"] == "pass-0.99" and d["lower"] >= 0.99
    assert S.lower_bound(500, 1, 0.05) < S.lower_bound(500, 0, 0.05)


def test_statistic_falls_as_the_candidate_precision_rises():
    # the confidence sequence is an interval [lower, 1]: no grid gap above it
    for tp, fp in ((400, 0), (700, 2), (130, 0), (60, 3)):
        vals = [S.log_mixture(tp, fp, i / 1000) for i in range(500, 1000)]
        assert all(a >= b for a, b in zip(vals, vals[1:]))


def test_sprt_fails_a_bad_rule_and_never_a_clean_one():
    assert S.decide(5, 5, CFG)["state"] == "fail"
    assert S.decide(5, 5, CFG)["basis"] == "measured"
    assert S.decide(1000, 0, CFG)["state"] == "pass-0.99"
    assert all(not S.sprt_fails(tp, 0, CFG) for tp in range(0, 2000, 50))


def test_futility_fails_only_what_the_remaining_plan_cannot_lift():
    d = S.decide(10, 0, CFG, remaining=5)
    assert d["state"] == "fail" and d["basis"] == "budget" and d["stop"]
    assert S.decide(10, 0, CFG, remaining=500)["state"] == "continue"
    assert S.decide(10, 0, CFG)["state"] == "continue"           # unbounded plan
    # 0.97 passed but 0.99 out of reach of the plan: final
    d = S.decide(S.tp_needed(0, 0.97, 0.05), 0, CFG, remaining=10)
    assert d["state"] == "pass-0.97" and d["stop"]
    d = S.decide(S.tp_needed(0, 0.97, 0.05), 0, CFG, remaining=1000)
    assert d["state"] == "pass-0.97" and not d["stop"]


def test_validate_rejects_bad_parameters():
    for bad in ({"alpha": 0}, {"p0": 0.99, "p1": 0.97}, {"method": "wilson-peek"}, {"batch": 0},
                {"gamma": 1}):
        with pytest.raises(ValueError):
            S.validate(bad)


# --- simulation with known precision -------------------------------------------

def test_false_pass_rate_just_below_the_bar_is_at_most_alpha():
    # a rule on or just below 0.99, checked after every batch
    for p in (0.985, 0.99):
        r = S.simulate(p, 400, 11, max_labels=3000)
        assert r["pass-0.99"] / r["runs"] <= CFG["alpha"]
    r = S.simulate(0.965, 400, 12, max_labels=1500)
    assert (r["pass-0.97"] + r["pass-0.99"]) / r["runs"] <= CFG["alpha"]


def test_peeking_at_a_fixed_wilson_bound_would_break_the_same_check():
    # the reason for all of this: stopping when the Wilson bound first crosses
    # 0.99 passes a rule at 0.99 far more often than its nominal 2.5% (and
    # than alpha), where the sequential test above stays under alpha
    from arbiter.precision import wilson
    rng = random.Random(3)
    passed = 0
    for _ in range(300):
        tp = n = 0
        while n < 3000:
            for _ in range(25):
                tp += rng.random() < 0.99
                n += 1
            if wilson(tp, n)[0] >= 0.99:
                passed += 1
                break
    assert passed / 300 > 0.06


def test_false_fail_rate_for_an_admissible_rule_is_at_most_beta():
    for p in (0.97, 0.975):
        r = S.simulate(p, 400, 13, max_labels=2000)
        assert r["fail"] / r["runs"] <= CFG["beta"]


def test_a_good_rule_passes_with_fewer_labels_than_the_fixed_plan():
    r = S.simulate(0.999, 300, 14, max_labels=2000)
    assert r["pass-0.99"] / r["runs"] >= 0.95
    assert r["mean_labels"] < 600
    bad = S.simulate(0.9, 300, 15, max_labels=2000)
    assert bad["fail"] == bad["runs"] and bad["mean_labels"] < 150


def test_without_replacement_from_a_finite_population_stays_valid():
    r = S.simulate(0.985, 300, 16, population=1500)
    assert r["pass-0.99"] / r["runs"] <= CFG["alpha"]


def test_simulation_is_deterministic():
    assert S.simulate(0.995, 50, 7) == S.simulate(0.995, 50, 7)


# --- the labelling tool --------------------------------------------------------

def _items(rules: dict[str, int], held=True):
    out = []
    for rule, n in rules.items():
        for i in range(n):
            out.append({"rule": rule, "finding_id": f"{rule}#{i}", "excerpt_sha256": "x",
                        "held_out": held, "finding": {"rule": rule}})
    random.Random(1).shuffle(out)
    return out


class FakeLabeller:
    """Labels from a fixed truth table; counts calls."""
    def __init__(self, truth):
        self.truth, self.calls = truth, []
        self.budget = lm.Budget(1000)

    def label(self, it):
        self.calls.append(it["finding_id"])
        return {"finding_id": it["finding_id"], "excerpt_sha256": it["excerpt_sha256"],
                "rule_id": it["rule"], "label": self.truth(it), "held_out": it["held_out"]}


def _truth(it):
    rule, i = it["finding_id"].split("#")
    i = int(i)
    if rule == "r/bad":
        return "fp" if i % 3 == 0 else "tp"
    return "fp" if rule == "r/mixed" and i % 60 == 5 else "tp"


def test_sequential_run_labels_a_prefix_of_each_rules_plan_and_stops(tmp_path):
    items = _items({"r/good": 900, "r/bad": 300, "r/mixed": 200})
    out = tmp_path / "labels.jsonl"
    lab = FakeLabeller(_truth)
    dec = lm.run_sequential(items, lab, out, 1, CFG, log=lambda m: None)
    assert dec["r/good"]["state"] == "pass-0.99" and dec["r/good"]["labelled"] == 375
    assert dec["r/bad"]["state"] == "fail" and dec["r/bad"]["labelled"] == 25
    # two FPs early in a 200-finding plan: even 100 more tps cannot show 0.97
    assert (dec["r/mixed"]["state"], dec["r/mixed"]["basis"]) == ("fail", "budget")
    assert dec["r/mixed"]["labelled"] < 200
    queues = lm.rule_queues(items)
    labelled = set(lab.calls)
    for rule, q in queues.items():
        ids = [it["finding_id"] for it in q]
        m = dec[rule]["labelled"]
        assert set(ids[:m]) <= labelled and not (set(ids[m:]) & labelled)   # a prefix, nothing past it
    assert len(lab.calls) == len(labelled) == sum(d["labelled"] for d in dec.values())


def test_a_rerun_replays_the_same_decisions_and_labels_nothing_new(tmp_path):
    items = _items({"r/good": 900, "r/bad": 300})
    out = tmp_path / "labels.jsonl"
    first = lm.run_sequential(items, FakeLabeller(_truth), out, 1, CFG, log=lambda m: None)
    again = FakeLabeller(_truth)
    second = lm.run_sequential(items, again, out, 1, CFG, log=lambda m: None)
    assert first == second and again.calls == []


def test_only_held_out_labels_count_toward_a_decision(tmp_path):
    items = _items({"r/good": 900}, held=False)
    dec = lm.run_sequential(items, FakeLabeller(_truth), tmp_path / "l.jsonl", 1, CFG, log=lambda m: None)
    assert dec["r/good"]["n"] == 0 and dec["r/good"]["state"] == "fail" and dec["r/good"]["basis"] == "budget"


def test_the_plan_must_pre_register_sequential_parameters(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"*": 0, "r/a": 100}))
    with pytest.raises(SystemExit):
        lm.read_plan(plan, sequential=True)
    assert lm.read_plan(plan, sequential=False) == ({"*": 0, "r/a": 100}, None)
    plan.write_text(json.dumps({"*": 0, "r/a": 100, "sequential": {"method": S.METHOD, "alpha": 0.05,
                                                                   "beta": 0.05, "p0": 0.93, "p1": 0.97,
                                                                   "batch": 25}}))
    with pytest.raises(SystemExit):
        lm.read_plan(plan, sequential=False)
    want, cfg = lm.read_plan(plan, sequential=True)
    assert want == {"*": 0, "r/a": 100} and cfg == CFG


def test_sequential_stops_at_the_same_prefix_as_the_full_plan_order():
    # per_rule_sample keeps a stable per-rule order for a fixed plan, so a
    # sequential run's labels are the first items of what the fixed run labels
    fs = [{"rule": "r/a", "language": "go", "repo": "x", "path": f"a{i}.go", "line": i} for i in range(80)] + \
         [{"rule": "r/b", "language": "go", "repo": "x", "path": f"b{i}.go", "line": i} for i in range(40)]
    plan = {"r/a": 60, "r/b": 30}
    full = lm.per_rule_sample(fs, plan, 9)
    again = lm.per_rule_sample(fs, plan, 9)
    qa = [f["path"] for f in full if f["rule"] == "r/a"]
    assert qa == [f["path"] for f in again if f["rule"] == "r/a"] and len(qa) == 60


# --- the ledger report ----------------------------------------------------------

def test_ledger_status_reads_held_out_counts_only_and_marks_budget_fails():
    rules = {"a": {"held_out": {"tp": 400, "fp": 0, "unsure": 0}, "held_out_population": 900,
                   "tp": 9999, "fp": 0, "admitted": True},
             "b": {"held_out": {"tp": 20, "fp": 0, "unsure": 0}, "held_out_population": 20},
             "c": {"held_out": {"tp": 0, "fp": 0, "unsure": 0}, "tp": 50},
             "d": {"held_out": {"tp": 30, "fp": 9, "unsure": 1}, "held_out_population": 500}}
    st = S.ledger_status(rules)
    assert set(st) == {"a", "b", "d"}
    assert st["a"]["state"] == "pass-0.99" and st["a"]["remaining"] == 500
    assert (st["b"]["state"], st["b"]["basis"]) == ("fail", "budget")
    assert (st["d"]["state"], st["d"]["basis"]) == ("fail", "measured")
    text = S.render_status(st)
    assert "pass-0.99" in text and "1 of the fails only because" in text


def test_report_prints_the_sequential_section(tmp_path, capsys):
    pl = _load("precision_ledger", ROOT / "tools" / "precision_ledger.py")
    ledger = tmp_path / "p.json"
    ledger.write_text(json.dumps({"version": 1, "rules": {
        "arbiter/python.x": {"held_out": {"tp": 400, "fp": 0, "unsure": 0}, "held_out_population": 900,
                             "tp": 400, "fp": 0, "n": 400, "strata": []}}}))
    assert pl.main(["report", "--ledger", str(ledger)]) == 0
    out = capsys.readouterr().out
    assert "Sequential status" in out and "arbiter/python.x" in out and "pass-0.99" in out


def test_thresholds_are_cached_and_integer():
    assert isinstance(S.tp_needed(0, 0.99, 0.05), int)
    assert math.isclose(S.sprt_llr(1, 0, 0.93, 0.97), math.log(0.97 / 0.93))
