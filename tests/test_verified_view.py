"""The verified view (ARB-091): what Arbiter shows by default is the
verified tier, and it says what it left out.

report.json always carries every finding with its tier. The console,
markdown, PR comment, SARIF, HTML and GitHub annotations list verified
findings (plus whatever failed the gate) unless `--advisory` or
`report.show: all` asks for every tier, sectioned by tier. The gate's
default is `tiered`, so only verified findings can fail it; `legacy` is an
explicit opt-in (tests/test_precision_tiers.py).
"""
from __future__ import annotations

import copy
import json
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
# A real scan: nothing verified, and every rendering says so
# ---------------------------------------------------------------------------

def test_a_scan_records_the_verified_view_and_shows_no_unverified_finding(tmp_path):
    rep = _scan(_secrets_repo(tmp_path))
    n = len(rep.active())
    assert n >= 1, "fixture produced nothing, so this proves nothing"
    assert all(f.tier == "advisory" for f in rep.active()), "no rule is declared verified yet"
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
    rep = _scan(_secrets_repo(tmp_path))
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
# A verified finding is shown; --advisory shows every tier in sections
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


def test_all_shows_every_tier_sectioned_and_labelled(tmp_path):
    rep, v, a, i = _three()
    set_view(rep, "all")
    assert rep.tiers["not_shown"] == {} and rep.tiers["shown_count"] == 3
    console = render_console(rep, color=False)
    assert "all tiers shown: 1 verified · 1 advisory · 1 inferred" in console
    for section in ("verified", "advisory", "inferred"):
        assert f"FINDINGS ({section})" in console
    assert console.index(v.title) < console.index(a.title) < console.index(i.title)
    assert "[advisory] test: advisory" in console
    md = render_markdown(rep)
    for section in ("verified", "advisory", "inferred"):
        assert f"## Findings ({section}, 1)" in md
    html = render_html(rep)
    assert "Findings (advisory, 1)" in html and a.title in html
    write_sarif(rep, str(tmp_path / "r.sarif"))
    results = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))["runs"][0]["results"]
    assert {r["ruleId"]: r["properties"]["tier"] for r in results} == {
        v.rule_id: "verified", a.rule_id: "advisory", i.rule_id: "inferred"}
    # Under the tiered gate the unverified results are notes, not errors.
    assert {r["ruleId"]: r["level"] for r in results}[a.rule_id] == "note"


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

def test_report_show_all_in_arbiter_yaml(tmp_path):
    repo = _secrets_repo(tmp_path)
    (repo / "arbiter.yaml").write_text("report:\n  show: all\n", encoding="utf-8")
    cfg = load_config(None, str(repo))
    assert show_mode(cfg) == "all" and show_mode(DEFAULTS) == "verified"
    rep = _scan(repo, cfg)
    assert rep.tiers["shown"] == "all"
    console = render_console(rep, color=False)
    assert "all tiers shown" in console and rep.active()[0].title in console
    assert "FINDINGS (advisory)" in console


def test_a_misspelt_report_show_is_an_error(tmp_path):
    (tmp_path / "arbiter.yaml").write_text("report:\n  show: everything\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="report.show"):
        load_config(None, str(tmp_path))


def test_the_advisory_flag_shows_every_tier_and_the_json_is_the_same_either_way(tmp_path, capsys):
    from arbiter.cli import main
    repo = _secrets_repo(tmp_path)
    out = tmp_path / "out"
    common = [str(repo), "--out", str(out), "--format", "json,console", "--only", "secrets",
              "--no-adapters", "--no-cache", "--no-history", "--no-open"]
    assert main(["scan", *common]) == 0
    plain = capsys.readouterr().out
    first = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "no verified findings" in plain and "FINDINGS (" not in plain
    assert first["tiers"]["shown"] == "verified" and len(first["findings"]) >= 1

    assert main(["scan", *common, "--advisory"]) == 0
    loud = capsys.readouterr().out
    second = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "all tiers shown" in loud and "FINDINGS (advisory)" in loud
    assert second["tiers"]["shown"] == "all"
    assert [f["id"] for f in second["findings"]] == [f["id"] for f in first["findings"]]
    # The flag exists on both scan and gate.
    from arbiter.cli import build_parser
    for cmd in ("scan", "gate"):
        assert build_parser().parse_args([cmd, "x", "--advisory"]).show_all is True


# ---------------------------------------------------------------------------
# The pull-request comment and the baseline
# ---------------------------------------------------------------------------

def test_the_pr_comment_lists_new_verified_findings_and_counts_the_hidden_new_ones():
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
    first = _scan(repo)
    assert first.tiers["shown_count"] == 0, "nothing verified: the whole set is hidden"
    bl = tmp_path / "baseline.json"
    write_baseline(first, str(bl))
    (repo / "ci.py").write_text(GITHUB, encoding="utf-8")
    second = _scan(repo, baseline=str(bl))
    by_path = {f.location.path: f.status for f in second.active()}
    assert by_path["billing.py"] == "existing" and by_path["ci.py"] == "new"
    assert second.tiers["not_shown"]["advisory"] == len(second.active())
    assert not render_annotations(second)


# ---------------------------------------------------------------------------
# The service and MCP answer
# ---------------------------------------------------------------------------

def test_the_service_answer_lists_the_verified_tier_and_names_the_complete_file():
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

    scan_tool = next(t for t in mcp.TOOLS if t["name"] == "arbiter_scan")
    assert scan_tool["inputSchema"]["properties"]["show"]["enum"] == ["verified", "all"]
    assert scan_tool["inputSchema"]["properties"]["show"]["default"] == "verified"


def test_the_hosted_api_sends_the_report_as_written_and_the_client_renders_the_view(tmp_path):
    """`/v1/scan` is a machine surface: every finding travels with the view the
    scan recorded, so `arbiter remote scan` renders the verified tier by
    default and `--advisory` can bring the rest back without another upload.
    A copy whose `tiers.shown` said `all` would make the remote console louder
    than the local one for the same repository."""
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
    assert report["tiers"]["shown"] == "verified" and report["tiers"]["not_shown"] == {"advisory": n}

    rep = client.report_from(result)
    console = render_console(rep, color=False)
    assert "no verified findings" in console and "FINDINGS (" not in console
    set_view(rep, "all")
    assert "FINDINGS (advisory)" in render_console(rep, color=False)


def test_view_block_counts_only_active_findings():
    v = _f("arbiter/v.rule", "verified")
    s = _f("arbiter/s.rule", "verified", suppressed=True)
    a = _f("arbiter/a.rule", "advisory")
    block = view_block([v, s, a], "verified")
    assert block == {"shown": "verified", "counts": {"verified": 1, "advisory": 1, "inferred": 0},
                     "shown_count": 1, "not_shown": {"advisory": 1}}
    assert view_block([v, s, a], "verified", failing={a.id})["not_shown"] == {}
