"""What Arbiter shows, and what can block (ARB-100, ARB-103).

Showing and blocking are separate decisions. By default (`report.show:
all`) the console, markdown, PR comment, SARIF, HTML and GitHub annotations
list every finding: verified first, then advisory, then inferred, each
section labelled with whether it can block the gate, and one line of counts
(`2 verified (can block the gate) · 71 advisory (shown, not gating) · 0
inferred`). The gate's default is `tiered`, so only verified findings can
fail it; `legacy` is an explicit opt-in (tests/test_precision_tiers.py).

`report.show: verified` (or `--verified-only`) is an opt-in: verified
findings (plus whatever failed the gate) and one line on what was left out,
which never reads as a clean report. report.json always carries every
finding with its tier.

ARB-100 made the verified view the default and, with one verified rule, hid
nearly everything Arbiter found (FAIL-071); the tests that pinned that
behaviour now set `show: verified` explicitly.
"""
from __future__ import annotations

import copy
import json
from html import escape as e
from pathlib import Path

import pytest

from arbiter.core import Finding, Location, Report
from arbiter.diff import diff_reports, render_pr_comment
from arbiter.engine import run_scan, write_baseline
from arbiter.policy import DEFAULTS, evaluate_gate, load_config, show_mode
from arbiter.precision import set_view, view_block
from arbiter.report import (
    render_annotations,
    render_console,
    render_html,
    render_markdown,
    view_summary,
    write_sarif,
)

STRIPE = 'STRIPE_KEY = "sk_live_51H8xQ2LkdIwHu7ix' + "Z" * 20 + '"\n'
GITHUB = 'GH_TOKEN = "ghp_' + "a" * 36 + '"\n'
BASE_KEYS = {
    "schema_version", "arbiter_version", "system", "profile", "started_at", "duration_s",
    "stacks", "scan_scope", "loc_by_language", "loc_by_role", "controls", "repos", "probes",
    "scorecard", "gate", "claims", "integrity", "learning", "fingerprint", "rules", "findings",
}


def _secrets_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "billing.py").write_text(STRIPE, encoding="utf-8")
    return repo


def _scan(repo: Path, config: dict | None = None, **kw) -> Report:
    cfg = config if config is not None else load_config(None)
    return run_scan([str(repo)], cfg, only=["secrets"], use_adapters=False, use_cache=False, **kw)


def _verified_only() -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    cfg["report"] = {"show": "verified"}
    return cfg


def _f(rule: str, tier: str, severity: str = "high", title: str | None = None, **kw) -> Finding:
    f = Finding(rule_id=rule, title=title or f"{tier} finding of {rule}", severity=severity,
                location=Location(path=f"{rule.split('/')[-1]}.py", start_line=2),
                evidence=rule, **kw)
    f.tier, f.tier_reason = tier, f"test: {tier}"
    return f


def _three() -> tuple[Report, Finding, Finding, Finding]:
    v = _f("arbiter/v.rule", "verified", "critical", title="Verified critical")
    a = _f("arbiter/a.rule", "advisory", "high", title="Advisory high")
    i = _f("arbiter/i.rule", "inferred", "medium", title="Inferred medium", provenance="inferred")
    rep = Report(findings=[v, a, i])
    rep.gate = evaluate_gate(rep, copy.deepcopy(DEFAULTS))
    return rep, v, a, i


# ---------------------------------------------------------------------------
# A real scan, by default: every finding shown, labelled by tier
# ---------------------------------------------------------------------------

def test_a_default_scan_shows_every_finding_labelled_by_tier(tmp_path):
    """The default view hides nothing: every rendering lists the advisory
    finding and says it cannot block the gate, and the gate still passes
    because nothing verified fired."""
    rep = _scan(_secrets_repo(tmp_path))
    n = len(rep.active())
    assert n >= 1, "fixture produced nothing, so this proves nothing"
    assert all(f.tier == "advisory" for f in rep.active()), "this fixture has no finding of a rule declared verified"
    assert rep.tiers == {"shown": "all",
                         "counts": {"verified": 0, "advisory": n, "inferred": 0},
                         "shown_count": n, "not_shown": {}}
    assert rep.gate["passed"] is True, "showing an advisory finding must not make it block"
    title = rep.active()[0].title
    line = f"0 verified · {n} advisory (shown, not gating) · 0 inferred"

    console = render_console(rep, color=False)
    assert line in console and title in console
    assert "FINDINGS (advisory) — not confirmed; shown, cannot block the gate" in console
    assert "not shown" not in console

    md = render_markdown(rep)
    assert f"**Shown:** {line}" in md and title in md
    assert f"## Findings (advisory, {n}) — not confirmed; shown, cannot block the gate" in md

    pr = render_pr_comment(rep)
    assert line in pr and "No findings." not in pr

    html = render_html(rep)
    assert e(line) in html and e(title) in html and "Findings (advisory" in html

    ann = render_annotations(rep)
    assert ann.count("::warning ") == n and "[advisory: not gating] " in ann and "::error" not in ann

    write_sarif(rep, str(tmp_path / "r.sarif"))
    run = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))["runs"][0]
    assert len(run["results"]) == n
    assert {r["properties"]["tier"] for r in run["results"]} == {"advisory"}
    assert "error" not in {r["level"] for r in run["results"]}, "an error the gate ignores"
    props = run["invocations"][0]["properties"]
    assert props["shown"] == "all" and props["not_shown"] == {} and props["summary"] == line


# ---------------------------------------------------------------------------
# A real scan under the verified-only opt-in: nothing verified, and every
# rendering says so
# ---------------------------------------------------------------------------

def test_verified_only_with_nothing_verified_says_so_and_never_reads_clean(tmp_path):
    rep = _scan(_secrets_repo(tmp_path), _verified_only())
    n = len(rep.active())
    assert n >= 1, "fixture produced nothing, so this proves nothing"
    assert all(f.tier == "advisory" for f in rep.active()), "this fixture has no finding of a rule declared verified"
    assert rep.tiers == {"shown": "verified",
                         "counts": {"verified": 0, "advisory": n, "inferred": 0},
                         "shown_count": 0, "not_shown": {"advisory": n}}
    title = rep.active()[0].title

    expect = f"no verified findings; {n} advisory findings not shown (run with --advisory to include them)"
    console = render_console(rep, color=False)
    assert expect in console
    assert "FINDINGS (" not in console and title not in console
    assert "no findings" not in console, "a report with hidden findings must not read as clean"

    md = render_markdown(rep)
    assert ("**Shown:** no verified findings; " f"{n} advisory findings not shown "
            "(run with --advisory, or set report.show: all, to include them)") in md
    assert "## Findings" not in md and title not in md
    assert "> - No verified findings" in md, "the Read-first block carries it"

    pr = render_pr_comment(rep)
    assert "no verified findings" in pr and title not in pr and "No findings." not in pr

    html = render_html(rep)
    assert "no verified findings" in html and title not in html

    assert render_annotations(rep) == ""

    write_sarif(rep, str(tmp_path / "r.sarif"))
    run = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))["runs"][0]
    assert run["results"] == []
    props = run["invocations"][0]["properties"]
    assert props["shown"] == "verified" and props["not_shown"] == {"advisory": n}
    assert props["summary"].startswith("no verified findings")


def test_the_json_report_keeps_every_finding_and_every_key(tmp_path):
    """Machine consumers (omni gate reads `findings`, `gate.passed`, `status`,
    `severity`, `suppressed`) see the whole set, whatever the view."""
    rep = _scan(_secrets_repo(tmp_path), _verified_only())
    d = json.loads(json.dumps(rep.to_dict()))
    assert d["schema_version"] == "1.0"
    assert BASE_KEYS <= set(d)
    assert len(d["findings"]) == len(rep.findings) >= 1
    for f in d["findings"]:
        assert f["tier"] in ("verified", "advisory", "inferred") and f["tier_reason"]
        assert f["status"] in ("new", "existing") and f["severity"] and "suppressed" in f
    assert d["tiers"]["shown"] == "verified" and d["tiers"]["not_shown"]["advisory"] == len(d["findings"])
    assert d["gate"]["passed"] is True and d["gate"]["tier_mode"] == "tiered"
    assert d["gate"]["excluded_by_tier"] == {"advisory": len(rep.active())}
    back = Report.from_dict(d)
    assert back.tiers == rep.tiers and len(back.findings) == len(rep.findings)
    # A report written before views recorded none: it renders every finding,
    # because no view was ever decided for it.
    d.pop("tiers")
    old = Report.from_dict(d)
    assert old.tiers == {} and rep.active()[0].title in render_console(old, color=False)


# ---------------------------------------------------------------------------
# Under verified-only a verified finding is shown and the rest counted; the
# default shows every tier in labelled sections, verified first
# ---------------------------------------------------------------------------

def test_the_verified_view_lists_verified_findings_and_counts_the_rest(tmp_path):
    rep, v, a, i = _three()
    set_view(rep, "verified")
    assert rep.tiers["shown_count"] == 1 and rep.tiers["not_shown"] == {"advisory": 1, "inferred": 1}
    assert view_summary(rep) == ("1 verified finding shown; 1 advisory and 1 inferred findings "
                                 "not shown (run with --advisory to include them)")
    console = render_console(rep, color=False)
    assert "FINDINGS (verified)" in console and v.title in console
    assert a.title not in console and i.title not in console
    assert "1 critical" in console and "1 high" not in console
    md = render_markdown(rep)
    assert "## Findings (verified, 1)" in md and "## Findings (advisory" not in md
    assert v.title in md and a.title not in md
    write_sarif(rep, str(tmp_path / "r.sarif"))
    results = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == [v.rule_id]
    assert render_annotations(rep).count("::") == 2 and v.rule_id in render_annotations(rep)


def test_all_shows_every_tier_verified_first_sectioned_and_labelled(tmp_path):
    rep, v, a, i = _three()
    # Report order puts the verified finding last, so every rendering below
    # has to sort it to the top rather than inherit the order it was given.
    rep.findings = [i, a, v]
    set_view(rep, "all")
    assert rep.tiers["not_shown"] == {} and rep.tiers["shown_count"] == 3
    line = "1 verified (can block the gate) · 1 advisory (shown, not gating) · 1 inferred (shown, not gating)"
    assert view_summary(rep) == line
    console = render_console(rep, color=False)
    assert line in console
    assert "FINDINGS (verified) — measured at least 99% precise; can block the gate" in console
    assert "FINDINGS (advisory) — not confirmed; shown, cannot block the gate" in console
    assert "FINDINGS (inferred) — found by a model, not confirmed; shown, cannot block the gate" in console
    assert console.index(v.title) < console.index(a.title) < console.index(i.title)
    assert "[advisory] test: advisory" in console
    md = render_markdown(rep)
    for section in ("verified", "advisory", "inferred"):
        assert f"## Findings ({section}, 1)" in md
    assert md.index("## Findings (verified") < md.index("## Findings (advisory") < md.index("## Findings (inferred")
    assert "not confirmed; shown, cannot block the gate" in md
    html = render_html(rep)
    assert "Findings (advisory, 1)" in html and a.title in html
    assert html.index("Findings (verified") < html.index("Findings (advisory") < html.index("Findings (inferred")
    write_sarif(rep, str(tmp_path / "r.sarif"))
    results = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == [v.rule_id, a.rule_id, i.rule_id], "verified first"
    assert {r["ruleId"]: r["properties"]["tier"] for r in results} == {
        v.rule_id: "verified", a.rule_id: "advisory", i.rule_id: "inferred"}
    # Under the tiered gate an unverified high is a warning: shown, never an
    # error the gate ignores (ARB-065), never buried as a note (ARB-103).
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels == {v.rule_id: "error", a.rule_id: "warning", i.rule_id: "warning"}
    ann = render_annotations(rep).splitlines()
    assert [v.rule_id in ann[0], a.rule_id in ann[1], i.rule_id in ann[2]] == [True, True, True]
    assert "[advisory: not gating] Advisory high" in ann[1]
    assert "[inferred: not gating] Inferred medium" in ann[2]
    assert "not gating" not in ann[0]


def test_a_console_cut_at_its_limit_keeps_the_verified_findings():
    """`--limit` cuts the list; the cut falls on advisory findings, never on
    a verified one listed after them in report order."""
    many = [_f(f"arbiter/a{n}.rule", "advisory", "high", title=f"Advisory {n}") for n in range(5)]
    v = _f("arbiter/v.rule", "verified", "low", title="Verified low")
    rep = Report(findings=[*many, v])
    rep.gate = evaluate_gate(rep, copy.deepcopy(DEFAULTS))
    set_view(rep, "all")
    console = render_console(rep, color=False, limit=2)
    assert v.title in console and "… 4 more" in console
    # The comment's severity counts stay in severity order, not tier order.
    assert "`5` high · `1` low" in render_pr_comment(rep)


def test_a_legacy_gate_says_advisory_findings_can_block():
    """The labels follow the gate: under `legacy` an advisory finding can
    fail the build, and the console must not tell the reader otherwise."""
    rep, *_ = _three()
    cfg = copy.deepcopy(DEFAULTS)
    cfg["gate"]["tier_mode"] = "legacy"
    rep.gate = evaluate_gate(rep, cfg)
    set_view(rep, "all")
    assert view_summary(rep) == ("1 verified (can block the gate) · 1 advisory (can block the gate)"
                                 " · 1 inferred (shown, not gating)")
    assert "FINDINGS (advisory) — not confirmed; can block the gate" in render_console(rep, color=False)


def test_a_finding_that_failed_a_legacy_gate_is_shown_whatever_its_tier():
    """A FAIL whose cause the reader cannot see would be worse than an
    advisory line. Under the default tiered gate only verified findings
    fail, so this only matters for the legacy opt-in."""
    crit = _f("arbiter/c.rule", "advisory", "critical", title="Advisory critical")
    low = _f("arbiter/l.rule", "advisory", "low", title="Advisory low")
    rep = Report(findings=[crit, low])
    cfg = copy.deepcopy(DEFAULTS)
    cfg["gate"]["tier_mode"] = "legacy"
    rep.gate = evaluate_gate(rep, cfg)
    assert rep.gate["failing_ids"] == [crit.id]
    set_view(rep, "verified")
    assert rep.tiers["not_shown"] == {"advisory": 1}
    console = render_console(rep, color=False)
    assert crit.title in console and low.title not in console
    assert ("no verified findings, plus 1 that failed the gate; 1 advisory findings not shown"
            in console)
    assert "FINDINGS (verified, and gate failures)" in console
    assert "::error" in render_annotations(rep) and low.rule_id not in render_annotations(rep)


# ---------------------------------------------------------------------------
# Configuration and the command line
# ---------------------------------------------------------------------------

def test_the_default_is_all_and_report_show_verified_in_arbiter_yaml_opts_in(tmp_path):
    assert show_mode(DEFAULTS) == "all" and show_mode({}) == "all"
    assert DEFAULTS["gate"]["tier_mode"] == "tiered", "showing everything did not change the gate"
    repo = _secrets_repo(tmp_path)
    (repo / "arbiter.yaml").write_text("report:\n  show: verified\n", encoding="utf-8")
    cfg = load_config(None, str(repo))
    assert show_mode(cfg) == "verified"
    rep = _scan(repo, cfg)
    assert rep.tiers["shown"] == "verified"
    console = render_console(rep, color=False)
    assert "no verified findings" in console and rep.active()[0].title not in console
    (repo / "arbiter.yaml").write_text("report:\n  show: all\n", encoding="utf-8")
    rep = _scan(repo, load_config(None, str(repo)))
    console = render_console(rep, color=False)
    assert rep.tiers["shown"] == "all" and rep.active()[0].title in console
    assert "FINDINGS (advisory)" in console


def test_a_misspelt_report_show_is_an_error(tmp_path):
    (tmp_path / "arbiter.yaml").write_text("report:\n  show: everything\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="report.show"):
        load_config(None, str(tmp_path))


def test_the_view_flags_and_the_json_is_the_same_either_way(tmp_path, capsys):
    """No flag shows every tier; `--verified-only` is the verified view for
    one run; `--advisory` is accepted and, under the default, changes
    nothing. report.json holds the same findings every time."""
    from arbiter.cli import main
    repo = _secrets_repo(tmp_path)
    out = tmp_path / "out"
    common = [str(repo), "--out", str(out), "--format", "json,console", "--only", "secrets",
              "--no-adapters", "--no-cache", "--no-history", "--no-open"]
    assert main(["scan", *common]) == 0
    plain = capsys.readouterr().out
    first = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "advisory (shown, not gating)" in plain and "FINDINGS (advisory)" in plain
    assert first["tiers"]["shown"] == "all" and len(first["findings"]) >= 1

    assert main(["scan", *common, "--verified-only"]) == 0
    quiet = capsys.readouterr().out
    second = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "no verified findings" in quiet and "FINDINGS (" not in quiet
    assert "(run with --advisory to include them)" in quiet
    assert second["tiers"]["shown"] == "verified"

    assert main(["scan", *common, "--advisory"]) == 0
    loud = capsys.readouterr().out
    third = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "FINDINGS (advisory)" in loud and "not shown" not in loud
    assert third["tiers"]["shown"] == "all"
    ids = [f["id"] for f in first["findings"]]
    assert [f["id"] for f in second["findings"]] == ids == [f["id"] for f in third["findings"]]
    # The flags exist on scan, gate, diff and remote scan, and exclude each other.
    from arbiter.cli import build_parser
    for argv in (["scan", "x"], ["gate", "x"], ["diff", "a", "b"], ["remote", "scan", "x"]):
        assert build_parser().parse_args([*argv, "--advisory"]).show_all is True
        assert build_parser().parse_args([*argv, "--verified-only"]).verified_only is True
        with pytest.raises(SystemExit):
            build_parser().parse_args([*argv, "--advisory", "--verified-only"])
    capsys.readouterr()


# ---------------------------------------------------------------------------
# The pull-request comment and the baseline
# ---------------------------------------------------------------------------

def test_the_pr_comment_lists_every_new_finding_verified_first_by_default():
    rep, v, a, i = _three()
    for f in (v, a, i):
        f.status = "new"
    rep.findings = [a, i, v]
    set_view(rep, "all")
    d = diff_reports(Report(), rep)
    text = render_pr_comment(rep, d)
    assert "not listed" not in text and "| Tier |" in text
    assert text.index(v.title) < text.index(a.title) < text.index(i.title)
    assert "| advisory (not gating) |" in text and "| verified |" in text
    assert "1 verified (can block the gate) · 1 advisory (shown, not gating)" in text


def test_the_pr_comment_under_verified_only_counts_the_hidden_new_ones():
    rep, v, a, i = _three()
    for f in (v, a, i):
        f.status = "new"
    set_view(rep, "verified")
    d = diff_reports(Report(), rep)
    assert len(d.new) == 3, "the comparison itself runs over every finding"
    text = render_pr_comment(rep, d)
    assert "`3` new" in text
    assert "`2` of the new findings are advisory or inferred and not listed" in text
    assert v.title in text and a.title not in text and i.title not in text
    assert "1 verified finding shown; 1 advisory and 1 inferred findings not shown" in text
    set_view(rep, "all")
    loud = render_pr_comment(rep, d)
    assert a.title in loud and "| Tier |" in loud and "not listed" not in loud


def test_baseline_status_is_decided_over_every_finding_not_the_shown_ones(tmp_path):
    repo = _secrets_repo(tmp_path)
    first = _scan(repo, _verified_only())
    assert first.tiers["shown_count"] == 0, "nothing verified: the whole set is hidden"
    bl = tmp_path / "baseline.json"
    write_baseline(first, str(bl))
    (repo / "ci.py").write_text(GITHUB, encoding="utf-8")
    second = _scan(repo, _verified_only(), baseline=str(bl))
    by_path = {f.location.path: f.status for f in second.active()}
    assert by_path["billing.py"] == "existing" and by_path["ci.py"] == "new"
    assert second.tiers["not_shown"]["advisory"] == len(second.active())
    assert not render_annotations(second)


# ---------------------------------------------------------------------------
# The service and MCP answer
# ---------------------------------------------------------------------------

def test_the_service_answer_lists_every_tier_by_default_and_names_the_complete_file():
    from arbiter import mcp, service
    rep, v, a, _i = _three()
    sup = _f("arbiter/s.rule", "advisory", "low", title="Suppressed", suppressed=True)
    rep.findings.append(sup)
    full = json.loads(json.dumps(rep.to_dict()))
    full["gate"] = {**full["gate"], "failing_ids": [a.id]}   # as a legacy gate might

    seen = service._view(full, "verified")
    assert [f["id"] for f in seen["findings"]] == [v.id, a.id], "verified, plus what failed the gate"
    assert seen["tiers"] == {"shown": "verified",
                             "counts": {"verified": 1, "advisory": 1, "inferred": 1},
                             "shown_count": 2, "not_shown": {"inferred": 1}}
    assert set(full) == set(seen), "no key added or dropped from the report itself"
    assert service._summary(seen["tiers"]) == ("1 verified finding shown; 1 inferred findings not "
                                               "shown (pass show: all to include them)")
    everything = service._view(full, "all")
    assert len(everything["findings"]) == 4 and everything["tiers"]["not_shown"] == {}
    with pytest.raises(service.ServiceError, match="show is one of"):
        service._view(full, "verified-ish")

    set_view(rep, "all")
    assert service._summary(everything["tiers"], full["gate"]) == view_summary(rep) == (
        "1 verified (can block the gate) · 1 advisory (shown, not gating) · 1 inferred (shown, not gating)"
    ), "the MCP line is the console's line; the suppressed finding is in neither"

    scan_tool = next(t for t in mcp.TOOLS if t["name"] == "arbiter_scan")
    assert scan_tool["inputSchema"]["properties"]["show"]["enum"] == ["verified", "all"]
    assert scan_tool["inputSchema"]["properties"]["show"]["default"] == "all"
    import inspect
    assert inspect.signature(service.scan).parameters["show"].default == "all"


def test_the_hosted_api_sends_the_report_as_written_and_the_client_renders_the_view(tmp_path):
    """`/v1/scan` is a machine surface: every finding travels with the view the
    scan recorded, so `arbiter remote scan` renders what the local console
    would (every tier, by default) and `--verified-only` can narrow it
    without another upload."""
    import tarfile

    from arbiter import api, client
    repo = _secrets_repo(tmp_path)
    archive = tmp_path / "repo.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(repo / "billing.py", arcname="repo/billing.py")

    result = api.handle_scan(archive.read_bytes(), only="secrets")
    report = result["report"]
    n = len(report["findings"])
    assert n >= 1 and result["finding_count"] == n, "fixture produced nothing, so this proves nothing"
    assert report["tiers"]["shown"] == "all" and report["tiers"]["not_shown"] == {}

    rep = client.report_from(result)
    console = render_console(rep, color=False)
    assert "FINDINGS (advisory)" in console
    set_view(rep, "verified")
    console = render_console(rep, color=False)
    assert "no verified findings" in console and "FINDINGS (" not in console


def test_view_block_counts_only_active_findings():
    v = _f("arbiter/v.rule", "verified")
    s = _f("arbiter/s.rule", "verified", suppressed=True)
    a = _f("arbiter/a.rule", "advisory")
    block = view_block([v, s, a], "verified")
    assert block == {"shown": "verified", "counts": {"verified": 1, "advisory": 1, "inferred": 0},
                     "shown_count": 1, "not_shown": {"advisory": 1}}
    assert view_block([v, s, a], "verified", failing={a.id})["not_shown"] == {}
