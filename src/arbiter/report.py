"""Reporters.

JSON is canonical and is written first; every other format is a rendering of
the same object, so a stale HTML report next to a fresh JSON one is not a
thing that can happen.
"""
from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path

from .core import SARIF_LEVEL, Finding, Report

SEV_ORDER = ["critical", "high", "medium", "low", "info"]

ANSI = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[2m", "reset": "\033[0m",
    "bold": "\033[1m", "dim": "\033[2m", "green": "\033[32m",
}


def _color(enabled: bool, key: str, text: str) -> str:
    if not enabled:
        return text
    return f"{ANSI.get(key, '')}{text}{ANSI['reset']}"


def counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEV_ORDER}
    for f in findings:
        if f.severity in out:
            out[f.severity] += 1
    return out


# ---------------------------------------------------------------------------

def write_json(report: Report, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


def write_sarif(report: Report, path: str) -> None:
    rules: dict[str, dict] = {}
    results = []
    for f in report.active():
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("/", "."),
                "shortDescription": {"text": f.title[:200]},
                "fullDescription": {"text": (f.description or f.title)[:1000]},
                "properties": {
                    "dimension": f.dimension,
                    "provenance": f.provenance,
                    "tags": f.tags + f.controls,
                },
            }
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.location.path or "."},
                "region": {"startLine": max(1, f.location.start_line or 1)},
            }
        }
        if f.location.logical:
            loc["logicalLocations"] = [{"fullyQualifiedName": f.location.logical}]
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.title},
            "locations": [loc],
            "fingerprints": {"arbiter/v1": f.id},
            "properties": {
                "severity": f.severity,
                "confidence": f.confidence,
                "repo": f.repo_id,
                "status": f.status,
            },
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "arbiter",
                "version": report.arbiter_version,
                "informationUri": "https://example.invalid/arbiter",
                "rules": list(rules.values()),
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "profile": report.profile,
                    "coverage": report.scorecard.coverage,
                    "skipped_probes": [
                        {"name": p.name, "reason": p.reason}
                        for p in report.probes if p.status != "ran"
                    ],
                },
            }],
        }],
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------

def render_console(report: Report, color: bool | None = None, limit: int = 40) -> str:
    if color is None:
        color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    L: list[str] = []
    sc = report.scorecard
    active = report.active()
    counts = counts_by_severity(active)

    L.append("")
    L.append(_color(color, "bold", f"  arbiter {report.arbiter_version}  ·  {report.system}  ·  profile={report.profile}"))
    repo_line = ", ".join(f"{r.id}({r.loc} loc)" for r in report.repos)
    L.append(_color(color, "dim", f"  {len(report.repos)} repo(s): {repo_line}"))
    if report.stacks:
        L.append(_color(color, "dim", f"  stacks: {', '.join(report.stacks)}"))
    ss = report.scan_scope or {}
    if ss.get("mode") == "partial":
        # Loud, and above the findings. Somebody scrolling to the counts must
        # not be able to reach them without passing this line.
        L.append("")
        L.append(_color(color, "high", "  PARTIAL SCAN — this is not a report about the repository"))
        L.append(_color(color, "dim",
                        f"  read {ss.get('files_read', 0)} of {ss.get('files_total', 0)} file(s) "
                        f"({ss.get('fraction_read', 0):.0%} of lines) — {ss.get('basis', '')}"))
        L.append(_color(color, "dim",
                        "  checks that read across files were not run; see NOT ASSESSED"))
        outside = sum(1 for f in active if "outside-this-change" in f.tags)
        if outside:
            L.append(_color(color, "dim",
                            f"  {outside} finding(s) are in context files this change did "
                            "not touch (tagged outside-this-change)"))
    L.append("")

    head = "  " + "  ".join(
        _color(color, s, f"{counts[s]} {s}") for s in SEV_ORDER if counts[s]
    )
    L.append(head.rstrip() or _color(color, "green", "  no findings"))

    if sc.withheld:
        L.append("  " + _color(color, "medium", f"grade withheld — {sc.withheld_reason}"))
    elif sc.overall is not None:
        L.append(f"  overall {sc.overall}/100   coverage {sc.coverage:.0%}")
    L.append("")

    if sc.dimensions:
        # In a partial scan a dimension can reach 100% check coverage -- every
        # probe carrying it ran -- while having read a third of the files.
        # The claim ledger already scopes those claims partial; the console
        # must not read more confidently than the ledger does.
        mark = "*" if (report.scan_scope or {}).get("mode") == "partial" else " "
        L.append(_color(color, "bold", "  DIMENSION        SCORE   COVERAGE   FINDINGS"))
        for name, d in sorted(sc.dimensions.items()):
            L.append(f"  {name:<15}  {d.score:>5.1f}   {d.coverage:>6.0%}{mark}   {d.findings:>8}")
        if mark == "*":
            L.append(_color(color, "dim",
                            "  * share of CHECKS that ran, not of the repository: "
                            "these checks read only the changed files"))
        L.append("")

    shown = [f for f in active][:limit]
    if shown:
        L.append(_color(color, "bold", "  FINDINGS"))
        for f in shown:
            tag = _color(color, f.severity, f"{f.severity:<8}")
            conf = "" if f.confidence == "high" else _color(color, "dim", f" [{f.confidence} confidence]")
            # short() already carries the repo on cross-repo findings
            prefix = "" if (f.location.repo_id or len(report.repos) == 1) else f"{f.repo_id}:"
            where = prefix + f.location.short()
            L.append(f"  {tag} {where}  {f.title}{conf}")
            L.append(_color(color, "dim", f"           {f.rule_id}  {f.id}"))
        if len(active) > limit:
            L.append(_color(color, "dim", f"  … {len(active) - limit} more (see the JSON report)"))
        L.append("")

    skipped = [p for p in report.probes if p.status != "ran"]
    if skipped:
        L.append(_color(color, "bold", "  NOT ASSESSED"))
        for p in skipped:
            mark = "error" if p.status == "error" else "skip "
            L.append(f"  {mark}  {p.name:<18} {p.reason}")
        L.append("")

    suppressed = [f for f in report.findings if f.suppressed]
    if suppressed:
        L.append(_color(color, "dim", f"  {len(suppressed)} finding(s) suppressed by policy"))

    gate = report.gate or {}
    if gate:
        if gate.get("passed"):
            L.append("  " + _color(color, "green", "gate PASS"))
        else:
            L.append("  " + _color(color, "critical", "gate FAIL") + " — " + "; ".join(gate.get("reasons", [])))
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------

def render_markdown(report: Report) -> str:
    sc = report.scorecard
    active = report.active()
    counts = counts_by_severity(active)
    L: list[str] = []
    L.append(f"# Arbiter report — {report.system}")
    L.append("")
    verdict = "**PASS**" if (report.gate or {}).get("passed") else "**FAIL**"
    L.append(f"{verdict} · profile `{report.profile}` · {len(report.repos)} repo(s) · "
             f"{sum(r.loc for r in report.repos):,} lines · {report.duration_s:.1f}s")
    L.append("")
    if sc.withheld:
        L.append(f"> **Grade withheld.** {sc.withheld_reason}")
    else:
        L.append(f"**Overall {sc.overall}/100** at {sc.coverage:.0%} coverage")
    L.append("")
    L.append("| " + " | ".join(s.capitalize() for s in SEV_ORDER) + " |")
    L.append("|" + "---|" * len(SEV_ORDER))
    L.append("| " + " | ".join(str(counts[s]) for s in SEV_ORDER) + " |")
    L.append("")

    if sc.dimensions:
        L.append("## Dimensions")
        L.append("")
        L.append("| Dimension | Score | Coverage | Findings |")
        L.append("|---|---|---|---|")
        for name, d in sorted(sc.dimensions.items()):
            L.append(f"| {name} | {d.score} | {d.coverage:.0%} | {d.findings} |")
        L.append("")

    if active:
        L.append("## Findings")
        L.append("")
        for sev in SEV_ORDER:
            group = [f for f in active if f.severity == sev]
            if not group:
                continue
            L.append(f"### {sev.capitalize()} ({len(group)})")
            L.append("")
            for f in group:
                repo = f"`{f.repo_id}` " if len(report.repos) > 1 else ""
                L.append(f"- {repo}**{f.title}**  \n  `{f.location.short()}` · `{f.rule_id}` · {f.id}")
                if f.description:
                    L.append(f"  \n  {f.description}")
            L.append("")

    skipped = [p for p in report.probes if p.status != "ran"]
    if skipped:
        L.append("## Not assessed")
        L.append("")
        for p in skipped:
            L.append(f"- `{p.name}` — {p.reason}")
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------

_HTML_CSS = """
:root{--bg:#f3f5f8;--sf:#fff;--ink:#161a21;--ink2:#3d4654;--mut:#66717f;--rule:#d7dde5;
--acc:#1f5b6e;--crit:#9c2118;--high:#a45a05;--med:#6f6410;--low:#24614a;--info:#4c5a6b;--code:#eef1f6}
@media(prefers-color-scheme:dark){:root{--bg:#101318;--sf:#171b22;--ink:#e6eaf0;--ink2:#c2cad6;
--mut:#8d97a6;--rule:#2a313b;--acc:#62a8bd;--crit:#e8776b;--high:#dc9b45;--med:#c2b04a;--low:#6fbd9b;
--info:#93a2b5;--code:#1b2029}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1060px;margin:0 auto;padding:32px 20px 72px}
h1{font-size:26px;letter-spacing:-.02em;margin:0 0 4px}
h2{font-size:16px;letter-spacing:.02em;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--rule)}
.sub{color:var(--mut);font-size:13px;margin:0 0 24px;font-variant-numeric:tabular-nums}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:8px}
.card{background:var(--sf);border:1px solid var(--rule);border-radius:5px;padding:12px 14px}
.card .n{font-size:24px;font-weight:600;font-variant-numeric:tabular-nums;line-height:1.1}
.card .l{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--mut);margin-top:2px}
.banner{border-left:3px solid var(--acc);background:var(--sf);padding:12px 14px;border-radius:0 5px 5px 0;margin:16px 0}
.pass{border-left-color:var(--low)}.fail{border-left-color:var(--crit)}
table{width:100%;border-collapse:collapse;font-size:13.5px;background:var(--sf);
border:1px solid var(--rule);border-radius:5px;overflow:hidden}
th{text-align:left;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);
padding:9px 12px;border-bottom:1px solid var(--rule);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid var(--rule);vertical-align:top;color:var(--ink2)}
tr:last-child td{border-bottom:none}
.tw{overflow-x:auto}
.pill{display:inline-block;font-size:10px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;
padding:2px 6px;border-radius:3px;border:1px solid currentColor;white-space:nowrap}
.s-critical{color:var(--crit)}.s-high{color:var(--high)}.s-medium{color:var(--med)}
.s-low{color:var(--low)}.s-info{color:var(--info)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
code{background:var(--code);padding:1px 5px;border-radius:3px}
.bar{height:6px;background:var(--code);border-radius:3px;overflow:hidden;min-width:70px}
.bar i{display:block;height:100%;background:var(--acc)}
.muted{color:var(--mut)}
"""


def render_html(report: Report) -> str:
    sc = report.scorecard
    active = report.active()
    counts = counts_by_severity(active)
    e = html.escape

    def rows_findings() -> str:
        out = []
        for f in active:
            related = ""
            if f.related:
                related = "<br><span class='muted mono'>also: " + e(
                    ", ".join(r.short() for r in f.related)
                ) + "</span>"
            out.append(
                f"<tr><td><span class='pill s-{f.severity}'>{f.severity}</span></td>"
                f"<td>{e(f.title)}<br><span class='muted mono'>{e(f.rule_id)} · {e(f.id)}"
                f"{'' if f.confidence == 'high' else ' · ' + f.confidence + ' confidence'}</span></td>"
                f"<td class='mono'>{e(f.repo_id)}</td>"
                f"<td class='mono'>{e(f.location.short())}{related}</td>"
                f"<td class='mono'>{e(f.dimension)}</td></tr>"
            )
        return "\n".join(out) or "<tr><td colspan='5' class='muted'>No active findings.</td></tr>"

    def rows_dims() -> str:
        out = []
        for name, d in sorted(sc.dimensions.items()):
            out.append(
                f"<tr><td>{e(name)}</td><td class='mono'>{d.score}</td>"
                f"<td><div class='bar'><i style='width:{d.coverage*100:.0f}%'></i></div>"
                f"<span class='mono muted'>{d.coverage:.0%}</span></td>"
                f"<td class='mono'>{d.checks_run}/{d.checks_applicable}</td>"
                f"<td class='mono'>{d.findings}</td></tr>"
            )
        return "\n".join(out)

    def rows_probes() -> str:
        out = []
        for p in report.probes:
            mark = {"ran": "ran", "skipped": "skipped", "error": "error"}[p.status]
            cls = "s-low" if p.status == "ran" else ("s-high" if p.status == "error" else "s-info")
            out.append(
                f"<tr><td><span class='pill {cls}'>{mark}</span></td>"
                f"<td class='mono'>{e(p.name)}</td>"
                f"<td class='mono'>{p.finding_count if p.status == 'ran' else '—'}</td>"
                f"<td class='mono'>{p.duration_s:.2f}s</td>"
                f"<td class='muted'>{e(p.reason)}</td></tr>"
            )
        return "\n".join(out)

    gate = report.gate or {}
    gate_cls = "pass" if gate.get("passed") else "fail"
    gate_txt = "Gate passed" if gate.get("passed") else "Gate failed — " + e("; ".join(gate.get("reasons", [])))
    grade = (
        f"<div class='banner'><b>Grade withheld.</b> {e(sc.withheld_reason)}</div>"
        if sc.withheld else
        f"<div class='banner'><b>Overall {sc.overall}/100</b> at {sc.coverage:.0%} assessment coverage</div>"
    )
    cards = "".join(
        f"<div class='card'><div class='n s-{s}'>{counts[s]}</div><div class='l'>{s}</div></div>"
        for s in SEV_ORDER
    )
    repos = ", ".join(f"{e(r.id)} ({r.loc:,} loc{', ' + e(r.commit) if r.commit else ''})" for r in report.repos)

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Arbiter — {e(report.system)}</title><style>{_HTML_CSS}</style></head><body><div class="wrap">
<h1>Arbiter — {e(report.system)}</h1>
<p class="sub">profile <code>{e(report.profile)}</code> · {len(report.repos)} repo(s): {repos}
 · stacks: {e(', '.join(report.stacks) or 'none detected')} · {report.duration_s:.1f}s · {e(report.started_at)}</p>
<div class="banner {gate_cls}"><b>{gate_txt}</b></div>
{grade}
<div class="cards">{cards}</div>
<h2>Dimensions</h2><div class="tw"><table>
<thead><tr><th>Dimension</th><th>Score</th><th>Coverage</th><th>Checks</th><th>Findings</th></tr></thead>
<tbody>{rows_dims()}</tbody></table></div>
<h2>Findings ({len(active)})</h2><div class="tw"><table>
<thead><tr><th>Severity</th><th>Finding</th><th>Repo</th><th>Location</th><th>Dimension</th></tr></thead>
<tbody>{rows_findings()}</tbody></table></div>
<h2>Probe outcomes</h2><div class="tw"><table>
<thead><tr><th>Status</th><th>Probe</th><th>Findings</th><th>Time</th><th>Reason</th></tr></thead>
<tbody>{rows_probes()}</tbody></table></div>
<p class="sub" style="margin-top:28px">Absence of findings from a skipped probe is not a pass.
Coverage above counts only checks that actually ran.</p>
</div></body></html>"""


def write_all(report: Report, outdir: str, formats: list[str]) -> dict[str, str]:
    Path(outdir).mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    if "json" in formats:
        p = str(Path(outdir) / "report.json"); write_json(report, p); written["json"] = p
    if "sarif" in formats:
        p = str(Path(outdir) / "report.sarif"); write_sarif(report, p); written["sarif"] = p
    if "html" in formats:
        p = str(Path(outdir) / "report.html")
        Path(p).write_text(render_html(report), encoding="utf-8"); written["html"] = p
    if "markdown" in formats or "md" in formats:
        p = str(Path(outdir) / "REPORT.md")
        Path(p).write_text(render_markdown(report), encoding="utf-8"); written["markdown"] = p
    if "pr-comment" in formats:
        from .diff import render_pr_comment
        p = str(Path(outdir) / "pr-comment.md")
        Path(p).write_text(render_pr_comment(report), encoding="utf-8"); written["pr-comment"] = p
    return written
