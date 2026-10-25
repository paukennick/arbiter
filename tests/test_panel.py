"""The labelling panel (ARB-122): fake providers and fake CLI runners only --
no network, no model calls, no CLI started."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import ROOT

from arbiter import precision as P


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sys.path.insert(0, str(ROOT / "tools" / "panel"))
pv = _load("providers", ROOT / "tools" / "panel" / "providers.py")
panel = _load("panel", ROOT / "tools" / "panel" / "panel.py")
PL = sys.modules["precision_ledger"]

RULE = "arbiter/python.sql-injection"


def _item(i: int, truth: str | None = None, rule: str = RULE) -> dict:
    f = {"id": f"f:{i:04d}", "rule": rule, "path": f"app/m{i}.py", "line": 3, "language": "python",
         "repo": "r"}
    it = {"finding": f, "finding_id": f["id"], "rule": rule, "category": "injection",
          "claim": "data reaches SQL", "shown_path": f["path"], "excerpt": f">> 3 q = 'x' + v{i}",
          "facts": "", "source": "calibration:owasp-python" if truth else "gold-model",
          "held_out": True, "stratum_size": 10, "stratum_held_out_size": 10, "rule_population": 10,
          "rule_held_out_population": 10, "sampling": "stratified"}
    it["excerpt_sha256"] = f"sha{i}"
    if truth:
        it["truth"] = truth
    return it


def _answer(label: str, reason: str = "the value is built into the SQL string") -> str:
    return json.dumps({"label": label, "reason": reason})


def _fake(seat: str, model: str, label="tp", **kw):
    fn = label if callable(label) else (lambda _p: _answer(label))
    return pv.FakeProvider(seat, model, fn, sleep=lambda _s: None, **kw)


def _panel(*provs, **kw) -> "panel.Panel":
    return panel.Panel(list(provs), None, today="2026-10-24", **kw)


# --- strict answers -------------------------------------------------------------

def test_strict_parse_accepts_one_object_fenced_or_not():
    assert pv.parse_strict(' {"label": "TP", "reason": "x  y"} ') == {"label": "tp", "reason": "x y"}
    assert pv.parse_strict('```json\n{"label": "fp", "reason": "constant"}\n```')["label"] == "fp"


@pytest.mark.parametrize("text", [
    'Sure! {"label": "tp", "reason": "x"}',                 # prose around the object
    '{"label": "tp", "reason": "x", "confidence": 0.9}',    # an extra key
    '{"label": "maybe", "reason": "x"}',                    # not a label
    '{"label": "tp", "reason": "  "}',                      # no reason
    '["tp", "x"]', "", "tp"])
def test_strict_parse_refuses_anything_else(text):
    with pytest.raises(pv.ParseError):
        pv.parse_strict(text)


def test_a_reason_is_masked_like_the_excerpt():
    out = pv.parse_strict(_answer("tp", "connects with postgres://admin:hunter2pass@db/x"))
    assert "hunter2pass" not in out["reason"]


def test_clean_env_passes_no_tokens_keys_or_proxy(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "OPENAI_API_KEY", "GITHUB_TOKEN",
              "CLAUDE_CODE_MESSAGING_TOKEN", "GH_TOKEN"):
        monkeypatch.setenv(k, "secret")
    monkeypatch.setenv("HOME", "/home/x")
    env = pv.clean_env()
    assert env["HOME"] == "/home/x" and "PATH" in env
    assert not any(v == "secret" for v in env.values())


# --- vendors --------------------------------------------------------------------

@pytest.mark.parametrize("model,vendor", [
    ("claude-opus-5-5", "anthropic"), ("gpt-6-astra", "openai"), ("o3-mini", "openai"),
    ("gemini-4-argon", "google"), ("mai-code-1.1-flash", "microsoft"), ("kimi-k3", "moonshot"),
    ("auto", ""), ("maimai", "")])
def test_model_vendor(model, vendor):
    assert pv.model_vendor(model) == vendor


def test_labeller_vendor_reads_the_seat_prefix_and_keeps_people_distinct():
    assert PL.labeller_vendor("copilot-gemini-4-argon:panel/v1") == "google"
    assert PL.labeller_vendor("codex-gpt-6-astra:panel/v1") == "openai"
    assert PL.labeller_vendor("claude-opus-5-5:prosecutor+defender/v3") == "anthropic"
    assert PL.labeller_vendor("alice") != PL.labeller_vendor("bob")


# --- the panel ------------------------------------------------------------------

def test_one_record_per_model_with_distinct_labellers(tmp_path):
    p = _panel(_fake("claude", "claude-opus-5-5"), _fake("codex", "gpt-6-astra", "fp"),
               _fake("copilot", "gemini-4-argon"))
    out = tmp_path / "panel-gold-model.jsonl"
    recs = p.run([_item(1), _item(2)], out)
    assert len(recs) == 6
    names = {r["labeller"] for r in recs}
    assert names == {"claude-opus-5-5:panel/v1", "codex-gpt-6-astra:panel/v1",
                     "copilot-gemini-4-argon:panel/v1"}
    r = next(r for r in recs if r["panel_seat"] == "codex")
    assert r["label"] == "fp" and r["vendor"] == "openai" and r["model"] == "gpt-6-astra"
    assert r["stratum_size"] == 10 and r["source"] == "gold-model" and r["held_out"] is True
    # The ledger reads every record the panel writes.
    assert len(PL.read_jsonl(out)) == 6


def test_a_rerun_resumes_and_a_cached_answer_costs_no_call(tmp_path):
    out = tmp_path / "o.jsonl"
    cache = panel.lm.Cache(tmp_path / "cache.jsonl")
    a = _fake("claude", "claude-opus-5-5")
    panel.Panel([a], cache, today="d").run([_item(1)], out)
    assert a.calls == 1
    b = _fake("claude", "claude-opus-5-5")
    panel.Panel([b], cache, today="d").run([_item(1), _item(2)], out)
    assert b.calls == 1                                     # item 1 already in the file
    out2 = tmp_path / "o2.jsonl"
    c = _fake("claude", "claude-opus-5-5")
    recs = panel.Panel([c], cache, today="d").run([_item(1)], out2)
    assert c.calls == 0 and recs[0]["cost"] == {}           # from the cache


def test_two_seats_of_one_vendor_are_refused():
    p = _panel(_fake("codex", "gpt-6-astra"), _fake("copilot", "gpt-6-luna"))
    p.resolve()
    assert [s.name for s in p.seats] == ["codex"]
    assert "openai" in p.refused["copilot"]


def test_a_seat_of_unknown_vendor_is_refused():
    p = _panel(_fake("copilot", "auto"))
    p.resolve()
    assert not p.seats and "unknown" in p.refused["copilot"]


def test_a_seat_not_logged_in_is_skipped_not_failed(tmp_path):
    p = _panel(_fake("claude", "claude-opus-5-5"), _fake("codex", "gpt-6-astra", available=False))
    recs = p.run([_item(1)], tmp_path / "o.jsonl")
    assert len(recs) == 1 and "codex" in p.skipped and p.report()["skipped"]["codex"]


def test_a_usage_limit_stops_that_seat_only(tmp_path):
    lim = _fake("codex", "gpt-6-astra", lambda _p: pv.UsageLimit("You've hit your usage limit"))
    p = _panel(_fake("claude", "claude-opus-5-5"), lim, jobs_per_seat=1)
    recs = p.run([_item(i) for i in range(4)], tmp_path / "o.jsonl")
    assert {r["panel_seat"] for r in recs} == {"claude"} and len(recs) == 4
    codex = next(s for s in p.seats if s.name == "codex")
    assert codex.stopped.startswith("usage limit") and lim.calls == 1


def test_an_answer_from_another_vendor_is_discarded_and_stops_the_seat(tmp_path):
    sw = _fake("copilot", "mai-code-1.1-flash", lambda _p: (_answer("tp"), "claude-haiku-4.5"))
    p = _panel(_fake("claude", "claude-opus-5-5"), sw, jobs_per_seat=1)
    recs = p.run([_item(1), _item(2)], tmp_path / "o.jsonl")
    assert all(r["panel_seat"] == "claude" for r in recs)
    assert next(s for s in p.seats if s.name == "copilot").stopped.startswith("refused")


def test_a_seat_alone_that_switches_vendor_is_still_refused(tmp_path):
    models = iter(["mai-code-1.1-flash", "gpt-6-luna", "gpt-6-luna"])
    sw = _fake("copilot", "mai-code-1.1-flash", lambda _p: (_answer("tp"), next(models)))
    p = _panel(sw, jobs_per_seat=1)
    recs = p.run([_item(1), _item(2), _item(3)], tmp_path / "o.jsonl")
    assert [r["model"] for r in recs] == ["mai-code-1.1-flash"]
    assert p.seats[0].stopped.startswith("refused") and p.seats[0].vendor == "microsoft"


def test_a_throttle_is_retried_with_delays():
    calls = []

    def flaky(_p):
        calls.append(1)
        return pv.ProviderError("server overloaded, retry after 5s") if len(calls) < 3 else _answer("fp")
    slept = []
    f = pv.FakeProvider("claude", "claude-opus-5-5", flaky, sleep=slept.append)
    assert f.label("s", "p")["label"] == "fp"
    assert slept == list(pv.RETRY_DELAYS[:2])


def test_an_unparseable_reply_is_asked_again_then_gives_no_label(tmp_path):
    replies = iter(["I think it is a tp", _answer("tp")])
    f = pv.FakeProvider("claude", "claude-opus-5-5", lambda _p: next(replies))
    assert f.label("s", "p")["label"] == "tp"
    bad = _fake("claude", "claude-opus-5-5", lambda _p: "tp, clearly")
    p = _panel(bad)
    assert p.run([_item(1)], tmp_path / "o.jsonl") == []
    assert bad.calls == 2 and p.seats[0].unparseable == 1


def test_a_call_cap_stops_a_seat(tmp_path):
    f = _fake("codex", "gpt-6-astra")
    p = _panel(f, max_calls={"codex": 2}, jobs_per_seat=1)
    recs = p.run([_item(i) for i in range(5)], tmp_path / "o.jsonl")
    assert len(recs) == 2 and f.calls == 2 and "cap" in p.seats[0].stopped


def test_a_usd_budget_stops_claude(tmp_path):
    f = _fake("claude", "claude-opus-5-5", cost={"usd": 0.4})
    p = _panel(f, budget_usd={"claude": 1.0}, jobs_per_seat=1)
    p.run([_item(i) for i in range(6)], tmp_path / "o.jsonl")
    assert f.calls == 2 and "budget" in p.seats[0].stopped


# --- the CLIs, through fake runners ---------------------------------------------

@pytest.fixture(autouse=True)
def _clis_on_path(monkeypatch):
    """Every provider is driven by a fake runner, so the real CLIs need not
    be installed (CI has none of them)."""
    monkeypatch.setattr(pv.shutil, "which", lambda name: f"/usr/bin/{name}")


def _proc(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


def test_codex_runs_read_only_ephemeral_with_tools_off_and_prompt_on_stdin(tmp_path):
    seen = {}

    def runner(cmd, cwd, timeout, input_text=None, env=None):
        if cmd[1:3] == ["login", "status"]:
            return _proc("Logged in using ChatGPT")
        if cmd[1:3] == ["features", "list"]:
            return _proc("shell_tool  stable  true\nplugins  stable  true\nfast_mode stable true\n")
        seen.update(cmd=cmd, cwd=cwd, input=input_text)
        Path(cmd[cmd.index("-o") + 1]).write_text(_answer("fp", "constant"), encoding="utf-8")
        assert list(Path(cwd).iterdir()) == []              # an empty working directory
        return _proc('{"type":"turn.completed","usage":{"input_tokens":900,"output_tokens":12}}\n')
    c = pv.CodexProvider("gpt-6-astra", runner=runner)
    assert c.available() == (True, "")
    ans = c.label("SYSTEM TEXT", "PACKET")
    cmd = seen["cmd"]
    for flag in ("--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check"):
        assert flag in cmd
    assert cmd[cmd.index("--sandbox") + 1] == "read-only" and cmd[-1] == "-"
    disabled = {cmd[i + 1] for i, x in enumerate(cmd) if x == "--disable"}
    assert disabled == {"shell_tool", "plugins"}            # only features this CLI lists
    assert "PACKET" not in " ".join(cmd) and "PACKET" in seen["input"] and "SYSTEM TEXT" in seen["input"]
    assert ans == {"label": "fp", "reason": "constant", "model": "gpt-6-astra",
                   "cost": {"input_tokens": 900, "output_tokens": 12}}


def test_codex_not_logged_in_is_unavailable():
    c = pv.CodexProvider(runner=lambda cmd, *a, **k: _proc("", "Not logged in", 1))
    ok, why = c.available()
    assert not ok and "not logged in" in why


def test_codex_401_is_unavailable_and_a_tool_use_is_refused(tmp_path):
    c = pv.CodexProvider(runner=lambda cmd, cwd, *a, **k: _proc("", "error: 401 Unauthorized", 1))
    with pytest.raises(pv.Unavailable):
        c.label("s", "p")

    def tool(cmd, cwd, *a, **k):
        Path(cmd[cmd.index("-o") + 1]).write_text(_answer("tp"), encoding="utf-8")
        return _proc('{"type":"item.completed","item":{"type":"command_execution","command":"cat x"}}\n')
    with pytest.raises(pv.ProviderError, match="tool"):
        pv.CodexProvider(runner=tool).label("s", "p")

    def spawn(cmd, cwd, *a, **k):              # an item type nobody listed is refused too
        Path(cmd[cmd.index("-o") + 1]).write_text(_answer("tp"), encoding="utf-8")
        return _proc('{"type":"item.completed","item":{"type":"collab_tool_call"}}\n')
    with pytest.raises(pv.ProviderError, match="collab_tool_call"):
        pv.CodexProvider(runner=spawn).label("s", "p")


def _copilot_events(model: str, content: str, tools=None) -> str:
    ev = [{"type": "session.auto_mode_resolved", "data": {"chosenModel": model}},
          {"type": "assistant.message", "data": {"model": model, "content": content,
                                                 "toolRequests": tools or []}},
          {"type": "result", "exitCode": 0, "usage": {"premiumRequests": 1}},
          {"type": "session.usage_checkpoint", "data": {"totalNanoAiu": 1000}}]
    return "\n".join(json.dumps(e) for e in ev) + "\n"


def _copilot_runner(by_model: dict, log: list):
    def runner(cmd, cwd, timeout, input_text=None, env=None):
        m = cmd[cmd.index("--model") + 1]
        log.append(cmd)
        out = by_model.get(m)
        if out is None:
            return _proc("", f'Error: Model "{m}" from --model flag is not available.', 1)
        return _proc(_copilot_events(out[0], out[1], out[2] if len(out) > 2 else None))
    return runner


def test_copilot_pins_the_first_model_of_a_vendor_not_yet_seated():
    log: list = []
    runner = _copilot_runner({"auto": ("mai-code-1.1-flash", _answer("unsure", "probe"))}, log)
    c = pv.CopilotProvider(("gemini-4-argon", "kimi-k3", "auto"), runner=runner)
    assert c.available() == (True, "")
    assert c.pinned == "auto" and c.model == "mai-code-1.1-flash" and c.vendor == "microsoft"
    cmd = log[-1]
    assert "--available-tools=" + pv.NO_TOOL in cmd and "--disable-builtin-mcps" in cmd
    assert "--no-custom-instructions" in cmd and cmd[cmd.index("--deny-url") + 1] == "*"
    assert "--allow-all-tools" not in cmd and "--yolo" not in cmd


def test_copilot_never_seats_an_anthropic_or_already_seated_vendor():
    runner = _copilot_runner({"auto": ("claude-haiku-4.5", _answer("unsure", "probe")),
                              "gpt-6-luna": ("gpt-6-luna", _answer("unsure", "probe"))}, [])
    c = pv.CopilotProvider(("gpt-6-luna", "auto"), runner=runner, forbid=frozenset({"anthropic", "openai"}))
    ok, why = c.available()
    assert not ok and "anthropic" in why and "openai" in why


def test_copilot_refuses_an_answer_that_asked_for_a_tool():
    runner = _copilot_runner({"auto": ("mai-code-1.1-flash", _answer("tp"), [{"name": "view"}])}, [])
    c = pv.CopilotProvider(("auto",), runner=runner)
    c.pinned, c.model = "auto", "mai-code-1.1-flash"
    with pytest.raises(pv.ProviderError, match="tool"):
        c.label("s", "p")


def test_copilot_rerouted_to_another_vendor_is_a_conflict():
    runner = _copilot_runner({"auto": ("gpt-6-luna", _answer("tp"))}, [])
    c = pv.CopilotProvider(("auto",), runner=runner)
    c.pinned, c.model = "auto", "mai-code-1.1-flash"
    with pytest.raises(pv.VendorConflict):
        c.label("s", "p")


def test_the_claude_seat_reuses_call_cli_with_a_clean_env(monkeypatch):
    seen = {}

    def fake_call(system, prompt, model, timeout=240, env=None):
        seen.update(system=system, model=model, env=env)
        return _answer("tp"), 0.02, "claude-opus-5-5"
    monkeypatch.setattr(panel.lm, "call_cli", fake_call)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:8787")
    c = pv.ClaudeProvider("opus")
    ans = c.label("SYS", "p")
    assert ans["model"] == "claude-opus-5-5" and ans["cost"] == {"usd": 0.02}
    assert seen["system"] == "SYS" and "ANTHROPIC_BASE_URL" not in seen["env"]
    assert c.labeller() == "claude-opus-5-5"


# --- calibration ----------------------------------------------------------------

def test_calibration_scores_each_model_and_the_unanimous_panel(tmp_path):
    truths = ["tp", "tp", "fp", "fp"]
    a = {0: "tp", 1: "tp", 2: "fp", 3: "tp"}       # one false tp
    b = {0: "tp", 1: "fp", 2: "fp", 3: "unsure"}   # one missed tp, one unsure
    pa = _fake("claude", "claude-opus-5-5", lambda p: _answer(a[int(p.split("v")[-1][0])]))
    pb = _fake("copilot", "gemini-4-argon", lambda p: _answer(b[int(p.split("v")[-1][0])]))
    items = [_item(i, truth=t) for i, t in enumerate(truths)]
    recs = _panel(pa, pb).run(items, tmp_path / "cal.jsonl")
    cal = panel.calibration(recs)
    ma = cal["models"]["claude-opus-5-5:panel/v1"]
    assert (ma["decided"], ma["correct"], ma["false_tp"], ma["tp_calls"]) == (4, 3, 1, 3)
    assert ma["accuracy_wilson"] == [round(x, 3) for x in P.wilson(3, 4)]
    mb = cal["models"]["copilot-gemini-4-argon:panel/v1"]
    assert (mb["decided"], mb["unsure"], mb["missed_tp"]) == (3, 1, 1)
    # panel: item0 tp/tp -> tp; item1 tp/fp -> unsure; item2 fp/fp -> fp; item3 tp/unsure -> tp (wrong)
    pn = cal["panel"]
    assert (pn["n"], pn["decided"], pn["correct"], pn["false_tp"]) == (4, 3, 2, 1)
    assert cal["pairwise"]["claude-opus-5-5:panel/v1 | copilot-gemini-4-argon:panel/v1"]["n"] == 3
    md = panel.render_calibration(cal)
    assert "panel (unanimous of 2)" in md and "injection / claude-opus-5-5:panel/v1" in md


def test_calibrate_from_label_files_makes_no_calls(tmp_path, capsys):
    rec = {"finding_id": "x", "rule_id": RULE, "label": "tp", "labeller": "claude-opus-5-5:panel/v1",
           "source": "calibration:owasp-java", "held_out": True, "truth": "tp", "panel_seat": "claude"}
    f = tmp_path / "c.jsonl"
    f.write_text(json.dumps(rec) + "\n")
    assert panel.main(["calibrate", "--labels", str(f), "--json", str(tmp_path / "c.json")]) == 0
    assert json.loads((tmp_path / "c.json").read_text())["calibration"]["models"]


# --- prioritising ---------------------------------------------------------------

def test_labels_needed_is_the_least_all_tp_count_reaching_the_bar():
    n = panel.labels_needed(0, 0)
    assert P.wilson(n, n)[0] >= 0.99 > P.wilson(n - 1, n - 1)[0]
    assert panel.labels_needed(690, 0) == 0
    k = panel.labels_needed(445, 3)
    assert P.wilson(445 + k, 448 + k)[0] >= 0.99 > P.wilson(444 + k, 447 + k)[0]
    assert panel.labels_needed(10, 10, cap=1000) is None


def test_prioritise_puts_the_rules_nearest_the_bar_first():
    ledger = {"rules": {"arbiter/a.x": {"tp": 5, "fp": 0}, "arbiter/b.y": {"tp": 300, "fp": 0},
                        "arbiter/c.z": {"tp": 3, "fp": 3}, "arbiter/d.w": {"tp": 999, "fp": 0}}}
    rows = panel.prioritise(ledger)
    assert [r["rule"] for r in rows] == ["arbiter/d.w", "arbiter/b.y", "arbiter/a.x", "arbiter/c.z"]
    assert rows[0]["needed"] == 0


def test_prioritise_writes_a_per_rule_file_label_reads(tmp_path):
    led = tmp_path / "l.json"
    led.write_text(json.dumps({"version": 1, "rules": {RULE: {"tp": 30, "fp": 0}}}))
    out = tmp_path / "want.json"
    assert panel.main(["prioritise", "--ledger", str(led), "--per-rule-out", str(out),
                       "--max-per-rule", "50"]) == 0
    assert json.loads(out.read_text()) == {RULE: 50}


# --- gemini ---------------------------------------------------------------------

def _gemini_home(tmp_path, kind="oauth-personal", creds=True):
    (tmp_path / ".gemini").mkdir(exist_ok=True)
    (tmp_path / ".gemini" / "settings.json").write_text(json.dumps({"security": {"auth": {"selectedType": kind}}}))
    if creds:
        (tmp_path / ".gemini" / "oauth_creds.json").write_text("{}")
    return tmp_path


def _gemini_events(text: str, models=None, tools=False) -> str:
    ev = [{"type": "init", "model": "auto-gemini-3"},
          {"type": "message", "role": "user", "content": "x"}]
    ev += [{"type": "message", "role": "assistant", "content": c, "delta": True}
           for c in (text[:10], text[10:])]
    if tools:
        ev.append({"type": "tool_use", "tool_name": "read_file", "parameters": {"path": "x"}})
    ev.append({"type": "result", "status": "success",
               "stats": {"input_tokens": 800, "output_tokens": 30, "tool_calls": 1 if tools else 0,
                         "models": models or {"gemini-3.1-flash-lite": {"output_tokens": 2},
                                              "gemini-3-pro-preview": {"output_tokens": 28}}}})
    return "\n".join(json.dumps(e) for e in ev) + "\n"


def test_gemini_not_logged_in_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(pv.shutil, "which", lambda _n: "/bin/gemini")
    assert not pv.GeminiProvider(home=tmp_path).available()[0]
    ok, why = pv.GeminiProvider(home=_gemini_home(tmp_path, creds=False)).available()
    assert not ok and "no credentials" in why
    assert pv.GeminiProvider(home=_gemini_home(tmp_path), probe=False).available() == (True, "")
    served = pv.GeminiProvider(home=tmp_path, runner=lambda *a, **k: _proc(_gemini_events(_answer("fp", "probe"))))
    assert served.available() == (True, "") and served.model == "gemini-3-pro-preview"
    tier = "An unexpected critical error occurred:IneligibleTierError: This client is no longer supported for X"
    refused = pv.GeminiProvider(home=tmp_path, runner=lambda *a, **k: _proc("", tier, 1))
    ok, why = refused.available()
    assert not ok and "refused this account" in why


def test_gemini_denies_every_tool_reads_stdin_and_resolves_the_answering_model(tmp_path):
    seen = {}

    def runner(cmd, cwd, timeout, input_text=None, env=None):
        pol = Path(cmd[cmd.index("--admin-policy") + 1]).read_text()
        seen.update(cmd=cmd, input=input_text, env=env, policy=pol,
                    system=Path(env["GEMINI_SYSTEM_MD"]).read_text(), empty=list(Path(cwd).iterdir()))
        return _proc(_gemini_events(_answer("fp", "constant")))
    g = pv.GeminiProvider(auth="oauth-personal", runner=runner)
    ans = g.label("SYSTEM TEXT", "PACKET")
    cmd = seen["cmd"]
    assert 'toolName = "*"' in seen["policy"] and 'decision = "deny"' in seen["policy"]
    assert cmd[cmd.index("--extensions") + 1] == "none" and "--yolo" not in cmd
    assert "PACKET" not in " ".join(cmd) and "PACKET" in seen["input"] and seen["empty"] == []
    assert seen["system"] == "SYSTEM TEXT" and "ANTHROPIC_API_KEY" not in seen["env"]
    assert ans["label"] == "fp" and ans["model"] == "gemini-3-pro-preview"
    assert g.labeller() == "gemini-3-pro-preview" and g.vendor == "google"


def test_gemini_refuses_tool_use_a_foreign_model_and_reports_no_login():
    with pytest.raises(pv.ProviderError, match="tool"):
        pv.GeminiProvider(auth="oauth-personal", runner=lambda *a, **k: _proc(_gemini_events(_answer("tp"), tools=True))).label("s", "p")
    with pytest.raises(pv.VendorConflict):
        pv.GeminiProvider(auth="oauth-personal", runner=lambda *a, **k: _proc(_gemini_events(
            _answer("tp"), models={"gpt-6-luna": {"output_tokens": 9}}))).label("s", "p")
    err = json.dumps({"type": "Error", "message": "Please set an Auth method in settings.json", "code": 41})
    with pytest.raises(pv.Unavailable):
        pv.GeminiProvider(auth="oauth-personal", runner=lambda *a, **k: _proc(err, "", 41)).label("s", "p")


def test_four_seats_one_record_each_and_gemini_names_itself(tmp_path):
    p = _panel(_fake("claude", "claude-opus-5-5"), _fake("codex", "gpt-6-astra"),
               _fake("gemini", "gemini-3-pro-preview"), _fake("copilot", "mai-code-1.1-flash"))
    recs = p.run([_item(1)], tmp_path / "o.jsonl")
    assert sorted(r["labeller"] for r in recs) == [
        "claude-opus-5-5:panel/v1", "codex-gpt-6-astra:panel/v1",
        "copilot-mai-code-1.1-flash:panel/v1", "gemini-3-pro-preview:panel/v1"]
    assert len({PL.labeller_vendor(r["labeller"]) for r in recs}) == 4


def test_gemini_api_key_comes_from_its_file_and_reaches_only_the_child_env(tmp_path, monkeypatch):
    monkeypatch.setattr(pv.shutil, "which", lambda _n: "/bin/gemini")
    home = _gemini_home(tmp_path, kind="gemini-api-key", creds=False)
    key_file = home / ".config" / "arbiter" / "gemini.key"
    ok, why = pv.GeminiProvider(home=home, probe=False).available()
    assert not ok and "missing or empty" in why
    key_file.parent.mkdir(parents=True)
    key_file.write_text("\n")
    assert not pv.GeminiProvider(home=home, probe=False).available()[0]
    key = "AIzaSyTESTKEY0123456789abcdefghijklmn"
    key_file.write_text(key + "\n")
    seen = {}

    def runner(cmd, cwd, timeout, input_text=None, env=None):
        seen.update(cmd=cmd, env=dict(env), input=input_text)
        return _proc(_gemini_events(_answer("tp")))
    g = pv.GeminiProvider(home=home, probe=False, runner=runner)
    assert g.available() == (True, "")
    ans = g.label("s", "p")
    assert seen["env"]["GEMINI_API_KEY"] == key
    assert key not in " ".join(seen["cmd"]) and key not in seen["input"] and key not in json.dumps(ans)
    assert not any(key in str(v) for v in vars(g).values())          # never kept on the object

    def leaky(cmd, cwd, timeout, input_text=None, env=None):
        return _proc("", f"Error: API key {key} not valid. Please pass a valid API key.", 1)
    with pytest.raises(pv.ProviderError) as exc:
        pv.GeminiProvider(home=home, probe=False, runner=leaky).label("s", "p")
    assert key not in str(exc.value)


def test_a_public_only_seat_never_receives_private_code(tmp_path):
    gem = _fake("gemini", "gemini-3-pro-preview")
    gem.public_only = True
    claude = _fake("claude", "claude-opus-5-5")
    gold = Path("~/wt/corpus-gold").expanduser()
    items = [{**_item(1), "source": "gold-model", "corpus_root": str(gold)},
             {**_item(2), "source": "heldout-r6-model", "corpus_root": str(gold / "go-caddy")},
             {**_item(3), "source": "calibration:owasp-java"},
             {**_item(4), "source": "calibration:cve-fix"},
             {**_item(5), "source": "gold-model", "corpus_root": str(tmp_path / "my-private-repo")},
             {**_item(6), "source": "gold-model"},                      # no corpus root: not public
             {**_item(7), "source": "calibration:planted-tests"},
             {**_item(8), "source": "ai-corpus-model"},
             {**_item(9), "source": "my-company-model", "corpus_root": str(gold)}]
    p = _panel(claude, gem)
    recs = p.run(items, tmp_path / "o.jsonl")
    sent = sorted(r["finding_id"] for r in recs if r["panel_seat"] == "gemini")
    assert sent == ["f:0001", "f:0002", "f:0003", "f:0004"]
    assert gem.calls == 4 and claude.calls == 9
    assert next(s for s in p.seats if s.name == "gemini").withheld == 5
    assert pv.GeminiProvider.public_only is True
