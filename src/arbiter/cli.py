"""Command line interface.

The CLI is the engine. The CI gate, the Claude skill and any dashboard are
consumers of the JSON it writes — none of them re-implement analysis.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .ab import (
    Arm, arm_from_dict, load_ab_spec, render_ab_console, render_ab_html, run_ab,
)
from .adapters import register_adapters
from .core import Report
from .engine import run_scan, write_baseline
from .policy import PROFILES, load_config
from .probes import REGISTRY, ProbeContext
from .report import render_console, render_markdown, write_all

EXIT_OK, EXIT_GATE_FAIL, EXIT_ERROR = 0, 1, 2


def _parse_arm(spec: str) -> Arm:
    """`name;kind=tool;tool=checkov` or `native;only=secrets,quality`."""
    parts = [p for p in spec.split(";") if p.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("empty --arm")
    d: dict = {"name": parts[0].strip()}
    for kv in parts[1:]:
        if "=" not in kv:
            raise argparse.ArgumentTypeError(f"bad arm field '{kv}' (expected key=value)")
        k, v = kv.split("=", 1)
        k, v = k.strip(), v.strip()
        d[k] = [x for x in v.split(",") if x] if k in ("only", "skip") else v
    return arm_from_dict(d)


def _formats(value: str) -> list[str]:
    return [f.strip() for f in value.split(",") if f.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="arbiter",
        description="Evaluate a repository — or a system of repositories — and refuse to grade what it did not inspect.",
    )
    p.add_argument("--version", action="version", version=f"arbiter {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("targets", nargs="*", help="paths or git URLs")
        sp.add_argument("--system", help="arbiter-system.yaml describing several repos")
        sp.add_argument("--config", help="arbiter.yaml (defaults to one in the target)")
        sp.add_argument("--profile", choices=sorted(PROFILES), help="capability budget for this run")
        sp.add_argument("--only", default="", help="comma-separated probes to run exclusively")
        sp.add_argument("--skip", default="", help="comma-separated probes to skip")
        sp.add_argument("--baseline", help="baseline JSON for new/existing labelling")
        sp.add_argument("--no-adapters", action="store_true", help="native probes only")
        sp.add_argument("--knowledge", help="knowledge file (default .arbiter/knowledge.json)")
        sp.add_argument("--pin-knowledge", metavar="HASH",
                        help="fail unless the knowledge file is exactly this version")
        sp.add_argument("--changed", metavar="REF", default=None,
                        help="scan only files that differ from REF (plus uncommitted "
                             "work), and record every check that needs the whole "
                             "repository as not assessed. For pull-request gates.")
        sp.add_argument("--only-files", default="", metavar="PATHS",
                        help="comma-separated paths to scan; same partial-scan "
                             "accounting as --changed")
        sp.add_argument("--tfplan", action="append", default=[], metavar="[REPO=]PATH",
                        help="Terraform plan or state JSON; supersedes reading .tf source. "
                             "Repeatable, and prefix with `repo=` in a multi-repo system.")
        return sp

    sc = common(sub.add_parser("scan", help="analyze and report"))
    sc.add_argument("--out", default="arbiter-out", help="output directory")
    sc.add_argument("--format", default="json,console", help="json,sarif,html,markdown,console")
    sc.add_argument("--limit", type=int, default=40, help="findings shown on the console")

    gt = common(sub.add_parser("gate", help="analyze and exit non-zero on policy failure"))
    gt.add_argument("--out", default="arbiter-out")
    gt.add_argument("--format", default="json,console")

    ab = sub.add_parser("ab", help="run two arms over the same target and compare")
    ab.add_argument("--spec", help="A/B spec YAML")
    ab.add_argument("--target", action="append", default=[], help="target path (repeatable)")
    ab.add_argument("--system", help="arbiter-system.yaml")
    ab.add_argument("--config", help="base arbiter.yaml")
    ab.add_argument("--arm", action="append", default=[], type=_parse_arm,
                    help="arm spec, e.g. 'native;only=secrets' or 'checkov;kind=tool;tool=checkov'")
    ab.add_argument("--name", default="", help="label for the comparison")
    ab.add_argument("--out", default="arbiter-ab", help="output directory")
    ab.add_argument("--no-adapters", action="store_true")

    pr = sub.add_parser("probes", help="list probes and whether they can run here")
    pr.add_argument("target", nargs="?", default=".", help="target to assess applicability against")
    pr.add_argument("--no-adapters", action="store_true")

    bl = sub.add_parser("baseline", help="write a baseline from a report")
    bl.add_argument("report", help="path to report.json")
    bl.add_argument("--out", default=".arbiter/baseline.json")

    df = sub.add_parser("diff", help="compare two reports")
    df.add_argument("before", help="earlier report.json")
    df.add_argument("after", help="later report.json")
    df.add_argument("--format", default="console", help="console,json,markdown,pr-comment")
    df.add_argument("--out", default="", help="write the chosen formats into this directory")

    fb = sub.add_parser("feedback", help="adjudicate findings so the tool calibrates")
    fb.add_argument("finding_ids", nargs="+", help="finding ids from a report")
    fb.add_argument("--report", default="arbiter-out/report.json")
    fb.add_argument("--knowledge", help="knowledge file (default .arbiter/knowledge.json)")
    group = fb.add_mutually_exclusive_group(required=True)
    group.add_argument("--false-positive", action="store_true")
    group.add_argument("--true-positive", action="store_true")
    fb.add_argument("--note", default="")

    ln = sub.add_parser("learn", help="show what the tool has learned")
    ln.add_argument("--knowledge", help="knowledge file (default .arbiter/knowledge.json)")
    ln.add_argument("--target", type=float, default=1e-6,
                    help="error rate you want to claim, for the sample-size column")

    vf = sub.add_parser("verify", help="check a report's claims against their basis")
    vf.add_argument("report", nargs="?", default="arbiter-out/report.json")
    vf.add_argument("--config", help="arbiter.yaml, for the coverage threshold")
    vf.add_argument("--show-claims", action="store_true", help="print every claim, not just violations")

    rv = sub.add_parser("review",
                        help="adjudicate a batch of findings in one pass")
    rv.add_argument("report", nargs="?", default="arbiter-out/report.json")
    rv.add_argument("--out", default="arbiter-out/review.md",
                    help="where to write the review file")
    rv.add_argument("--limit", type=int, default=20,
                    help="how many findings to put in front of you (default 20)")
    rv.add_argument("--rule", help="only findings whose rule id contains this")
    rv.add_argument("--apply", metavar="FILE",
                    help="read a marked review file back and record the verdicts")
    rv.add_argument("--note", default="", help="note stored with each verdict")
    rv.add_argument("--knowledge", help="path to knowledge.json")
    rv.add_argument("--html", metavar="FILE", nargs="?", const="arbiter-out/review.html",
                    help="write a self-contained review page instead of markdown")
    rv.add_argument("--interactive", action="store_true",
                    help="walk the findings in the terminal, one keypress each")
    rv.add_argument("--repo", action="append", default=[],
                    help="id=path, so the review can show code context; repeatable")

    ct = sub.add_parser("controls",
                        help="control coverage per framework, including what was NOT assessed")
    ct.add_argument("report", nargs="?", default="arbiter-out/report.json")
    ct.add_argument("--framework", action="append", default=[],
                    help="limit to one framework id; repeatable")
    ct.add_argument("--packs", action="append", default=[],
                    help="extra directory of control packs; repeatable")
    ct.add_argument("--state", action="append", default=[],
                    help="show only controls in this state "
                         "(violated, not_assessed, no_coverage, satisfied, not_automatable)")
    ct.add_argument("--json", action="store_true", help="machine-readable output")
    ct.add_argument("--list", action="store_true", help="list available frameworks and exit")

    ex = sub.add_parser("explain", help="show one finding in full")
    ex.add_argument("finding_id")
    ex.add_argument("--report", default="arbiter-out/report.json")

    return p


def _load_adapters(disabled: bool) -> None:
    if not disabled:
        register_adapters()


def cmd_scan(args, gate_mode: bool = False) -> int:
    if not args.targets and not args.system:
        print("arbiter: give a target path or --system", file=sys.stderr)
        return EXIT_ERROR
    _load_adapters(args.no_adapters)
    root = args.targets[0] if args.targets else None
    config = load_config(args.config, root if root and not root.startswith("http") else None)

    report = run_scan(
        targets=args.targets,
        config=config,
        system_path=args.system,
        profile=args.profile,
        only=[s for s in args.only.split(",") if s],
        skip=[s for s in args.skip.split(",") if s],
        baseline=args.baseline,
        use_adapters=not args.no_adapters,
        plan_paths=list(getattr(args, "tfplan", []) or []),
        knowledge_path=getattr(args, "knowledge", None),
        pin_knowledge=getattr(args, "pin_knowledge", None),
        changed_since=getattr(args, "changed", None),
        only_files=[s for s in (getattr(args, "only_files", "") or "").split(",") if s],
        out_dir=args.out,
    )

    formats = _formats(args.format)
    written = write_all(report, args.out, [f for f in formats if f != "console"])
    if "console" in formats or not formats:
        print(render_console(report, limit=getattr(args, "limit", 40)))
    for kind, path in written.items():
        print(f"  wrote {kind}: {path}")
    if written:
        print()

    if gate_mode and not (report.gate or {}).get("passed"):
        return EXIT_GATE_FAIL
    return EXIT_OK


def cmd_ab(args) -> int:
    _load_adapters(args.no_adapters)
    targets = list(args.target)
    arms = list(args.arm)
    name = args.name
    system_path = args.system
    config_path = args.config

    if args.spec:
        spec = load_ab_spec(args.spec)
        base = Path(args.spec).parent
        name = name or spec.get("ab", Path(args.spec).stem)
        system_path = system_path or spec.get("system")
        config_path = config_path or spec.get("config")
        for t in spec.get("targets", []):
            cand = Path(t)
            targets.append(str(cand if cand.is_absolute() else (base / cand).resolve()))
        arms = [arm_from_dict(a) for a in spec.get("arms", [])] + arms

    if len(arms) != 2:
        print(f"arbiter ab: need exactly two arms, got {len(arms)}", file=sys.stderr)
        return EXIT_ERROR
    if not targets and not system_path:
        print("arbiter ab: give --target or --system", file=sys.stderr)
        return EXIT_ERROR

    config = load_config(config_path, targets[0] if targets else None)
    result = run_ab(name or "comparison", targets, arms[0], arms[1], config, system_path)

    print(render_ab_console(result))
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "ab.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    (outdir / "ab.html").write_text(render_ab_html(result), encoding="utf-8")
    print(f"  wrote json: {outdir / 'ab.json'}")
    print(f"  wrote html: {outdir / 'ab.html'}\n")

    if result.a.error or result.b.error:
        return EXIT_ERROR
    return EXIT_OK


def cmd_probes(args) -> int:
    _load_adapters(args.no_adapters)
    from .engine import resolve_targets
    from .graph import build_graph
    from .inventory import build_inventory
    import shutil as _sh

    name, repos, tmps, manifest = resolve_targets([args.target], None)
    try:
        inv = build_inventory(repos)
        ctx = ProbeContext(repos=repos, inventory=inv, graph=build_graph(inv), config={}, system=manifest)
        print(f"\n  stacks detected: {', '.join(sorted(inv.stacks)) or 'none'}\n")
        print(f"  {'PROBE':<18} {'CHECKS':>6}  {'DIMENSIONS':<28} STATUS")
        for probe in REGISTRY:
            ok, why = probe.applicable(ctx)
            missing = [b for b in probe.binaries if _sh.which(b) is None]
            if missing:
                status = f"skip — missing binary: {', '.join(missing)}"
            elif not ok:
                status = f"skip — {why}"
            elif probe.network:
                status = "ready (needs network profile)"
            else:
                status = "ready"
            print(f"  {probe.name:<18} {probe.checks:>6}  {','.join(probe.dimensions):<28} {status}")
        print()
    finally:
        for d in tmps:
            _sh.rmtree(d, ignore_errors=True)
    return EXIT_OK


def cmd_baseline(args) -> int:
    report = Report.from_dict(json.loads(Path(args.report).read_text(encoding="utf-8")))
    n = write_baseline(report, args.out)
    print(f"  baseline written: {args.out} ({n} finding ids)")
    return EXIT_OK


def cmd_diff(args) -> int:
    from .diff import diff_reports, render_diff_console, render_pr_comment
    before = Report.from_dict(json.loads(Path(args.before).read_text(encoding="utf-8")))
    after = Report.from_dict(json.loads(Path(args.after).read_text(encoding="utf-8")))
    d = diff_reports(before, after)
    formats = _formats(args.format)

    if "console" in formats:
        print(render_diff_console(d))
    if args.out:
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        if "json" in formats:
            (outdir / "diff.json").write_text(json.dumps(d.to_dict(), indent=2), encoding="utf-8")
            print(f"  wrote json: {outdir / 'diff.json'}")
        if "pr-comment" in formats or "markdown" in formats:
            (outdir / "pr-comment.md").write_text(render_pr_comment(after, d), encoding="utf-8")
            print(f"  wrote pr-comment: {outdir / 'pr-comment.md'}")
    elif "pr-comment" in formats or "markdown" in formats:
        print(render_pr_comment(after, d))
    return EXIT_OK


def cmd_feedback(args) -> int:
    from .learn import Knowledge, record
    report = Report.from_dict(json.loads(Path(args.report).read_text(encoding="utf-8")))
    by_id = {f.id: f for f in report.findings}
    knowledge = Knowledge.load(args.knowledge)
    verdict = "false_positive" if args.false_positive else "true_positive"

    recorded, repeated, unknown = 0, 0, []
    for fid in args.finding_ids:
        target = by_id.get(fid) or next((f for f in report.findings if f.id.endswith(fid)), None)
        if target is None:
            unknown.append(fid)
            continue
        if record(knowledge, target, verdict, args.note):
            recorded += 1
        else:
            repeated += 1

    version = knowledge.save(args.knowledge)
    print()
    print(f"  recorded {recorded} as {verdict.replace('_', ' ')}"
          + (f", {repeated} already adjudicated" if repeated else ""))
    for fid in unknown:
        print(f"  not found in the report: {fid}")
    print(f"  knowledge version now {version}")
    print("  scans pick this up on the next run; pin it with --pin-knowledge to freeze\n")
    return EXIT_OK if not unknown else EXIT_ERROR


def cmd_learn(args) -> int:
    from .claims import nines, observations_needed
    from .learn import MIN_OBSERVATIONS, Knowledge, calibrated_confidence
    knowledge = Knowledge.load(args.knowledge)
    print()
    print(f"  knowledge version {knowledge.version_hash()}"
          + (f"  (updated {knowledge.updated})" if knowledge.updated else "  (empty)"))
    print(f"  {len(knowledge.adjudicated)} finding(s) adjudicated across "
          f"{len(knowledge.rules)} rule(s)\n")

    if not knowledge.rules:
        print("  Nothing learned yet. Adjudicate findings with:")
        print("    arbiter feedback <finding-id> --false-positive --note 'why'\n")
        return EXIT_OK

    need = observations_needed(args.target)
    print(f"  {'RULE':<46}{'N':>5}{'TP':>5}{'FP':>5}{'PRECISION':>11}{'LOWER':>9}  STATUS")
    for rule_id, s in sorted(knowledge.rules.items(), key=lambda kv: -kv[1].observations):
        conf = calibrated_confidence(s)
        status = (f"calibrated -> {conf}" if conf
                  else f"unproven (needs {MIN_OBSERVATIONS - s.observations} more)")
        print(f"  {rule_id[:45]:<46}{s.observations:>5}{s.true_positives:>5}"
              f"{s.false_positives:>5}{(s.precision or 0):>11.3f}"
              f"{(s.precision_lower_bound or 0):>9.3f}  {status}")

    total = sum(s.observations for s in knowledge.rules.values())
    print(f"\n  Claiming an error rate below {args.target:g} with 95% confidence needs")
    print(f"  ~{need:,} clean observations per rule. Best rule so far: "
          f"{max((s.observations for s in knowledge.rules.values()), default=0):,}.")
    print(f"  Total adjudicated observations: {total:,}\n")
    return EXIT_OK


def cmd_verify(args) -> int:
    from .claims import INVARIANTS, build_claims, verify
    report = Report.from_dict(json.loads(Path(args.report).read_text(encoding="utf-8")))
    config = load_config(args.config) if args.config else {}
    claims = build_claims(report)
    violations = verify(report, config)

    print()
    if args.show_claims:
        print(f"  {'SCOPE':<10}{'CLAIM':<30}{'BASIS':>6}{'ABST':>6}  STATEMENT")
        for c in claims:
            print(f"  {c.scope:<10}{c.id:<30}{len(c.basis):>6}{len(c.abstained):>6}  {c.statement[:56]}")
        print()

    print(f"  {len(claims)} claim(s) checked against {len(INVARIANTS)} invariant(s)")
    if not violations:
        print("  integrity OK — no claim outruns its basis\n")
        return EXIT_OK
    print(f"  {len(violations)} VIOLATION(S)\n")
    for v in violations:
        print(f"    {v.invariant}  {v.claim_id}")
        print(f"           {INVARIANTS.get(v.invariant, '')}")
        print(f"           {v.detail}")
    print()
    return EXIT_GATE_FAIL


def cmd_review(args) -> int:
    from .learn import Knowledge, MIN_OBSERVATIONS
    from .review import apply as apply_marks, newly_proven, render, select

    path = Path(args.report)
    if not path.is_file():
        print(f"arbiter: no report at {path}. Run `arbiter scan` first.", file=sys.stderr)
        return EXIT_ERROR
    report = Report.from_dict(json.loads(path.read_text(encoding="utf-8")))
    knowledge = Knowledge.load(args.knowledge)

    if args.apply:
        marked = Path(args.apply)
        if not marked.is_file():
            print(f"arbiter: no review file at {marked}", file=sys.stderr)
            return EXIT_ERROR
        before = {r: s.observations for r, s in knowledge.rules.items()}
        res = apply_marks(marked.read_text(encoding="utf-8"), report.findings, knowledge, args.note)
        version = knowledge.save(args.knowledge)
        print()
        print(f"  {res['marked']} marked, {res['recorded']} recorded"
              + (f", {res['already_adjudicated']} already adjudicated"
                 if res["already_adjudicated"] else ""))
        for rule, counts in sorted(res["per_rule"].items()):
            print(f"    {rule:<48}{counts['true']:>3} real  {counts['false']:>3} not")
        if res["unknown"]:
            print(f"    {len(res['unknown'])} id(s) not in this report — ignored")
        proven = newly_proven(knowledge, before)
        for rule in proven:
            print(f"\n  {rule} has reached {MIN_OBSERVATIONS} adjudications "
                  "and is no longer reported as unproven.")
        if not res["recorded"]:
            print("\n  Nothing recorded. Marks go inside the brackets: [y] or [n].")
        print(f"\n  knowledge is now {version}")
        return EXIT_OK

    picked = select(report.findings, knowledge, limit=args.limit, rule=args.rule)
    if not picked:
        print("\n  Nothing left to review in this report — every finding here has "
              "already been adjudicated.")
        return EXIT_OK

    # Where to read code context from. The report records each repository's
    # path; --repo overrides it for a report produced somewhere else.
    repo_paths = {r.id: r.path for r in report.repos}
    for spec in args.repo:
        rid, _, path = spec.partition("=")
        repo_paths[rid or "root"] = path or rid

    if args.interactive:
        from .review_ui import run_terminal
        from .learn import record
        before = {r: st.observations for r, st in knowledge.rules.items()}
        marks = run_terminal(picked, knowledge, repo_paths)
        by_id = {f.id: f for f in picked}
        recorded = 0
        for fid, verdict in marks.items():
            if record(knowledge, by_id[fid], verdict, args.note):
                recorded += 1
        version = knowledge.save(args.knowledge)
        print(f"\n  {recorded} recorded of {len(marks)} marked")
        for rule in newly_proven(knowledge, before):
            print(f"  {rule} has reached {MIN_OBSERVATIONS} adjudications "
                  "and is no longer reported as unproven.")
        print(f"  knowledge is now {version}\n")
        return EXIT_OK

    if args.html:
        from .review_ui import render_html
        out = Path(args.html)
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd = f"arbiter review {args.report} --apply review.md"
        out.write_text(render_html(picked, knowledge, repo_paths, cmd), encoding="utf-8")
        rules = {f.rule_id for f in picked}
        print()
        print(f"  wrote {out}")
        print(f"  {len(picked)} findings across {len(rules)} rules. Open it in a "
              "browser — it needs no server and no network.")
        print("  Mark them, save the text it gives you as review.md, then:")
        print(f"\n      arbiter review {args.report} --apply review.md")
        return EXIT_OK

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(picked, knowledge, str(out)), encoding="utf-8")
    rules = {f.rule_id for f in picked}
    print()
    print(f"  wrote {out}")
    print(f"  {len(picked)} findings across {len(rules)} rules, chosen to move the "
          "most rules past")
    print(f"  the {MIN_OBSERVATIONS}-observation line. Mark them, then:")
    print(f"\n      arbiter review --apply {out}")
    return EXIT_OK


def cmd_controls(args) -> int:
    """Control coverage, reported so the gap is as visible as the passes.

    The ordering is deliberate and is the whole point of the command. Violated
    and not-assessed come first, because a control nothing checked is the thing
    a reader most needs to know and the thing every other compliance report
    buries. Satisfied comes last.
    """
    from .controls import (NOT_ASSESSED, NOT_AUTOMATABLE, NO_COVERAGE, SATISFIED,
                           STATES, STATE_MEANING, VIOLATED, evaluate_all,
                           load_frameworks)
    from .core import Finding

    if args.list:
        for fw in load_frameworks(args.packs):
            print(f"  {fw.id:<24}{fw.enumerated:>4} enumerated of "
                  f"{fw.declared_controls:<5} {fw.title}")
        return EXIT_OK

    path = Path(args.report)
    if not path.is_file():
        print(f"arbiter: no report at {path}. Run `arbiter scan` first.", file=sys.stderr)
        return EXIT_ERROR
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings = [Finding.from_dict(f) for f in doc.get("findings", [])]
    outcomes = [_outcome_from_dict(o) for o in doc.get("probes", [])]

    results = evaluate_all(findings, outcomes, only=args.framework, extra_dirs=args.packs)
    if not results:
        print("arbiter: no control packs matched", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(results, indent=2))
        return EXIT_OK

    wanted = {s.lower() for s in args.state}
    for res in results:
        fw, counts = res["framework"], res["counts"]
        print(f"\n  {fw['title']}")
        print(f"  {fw['id']}  baseline {fw['baseline'] or '-'}")
        print(f"  {'-' * 72}")
        for state in STATES:
            print(f"    {counts[state]:>4}  {state:<17}{STATE_MEANING[state]}")
        if res["not_enumerated"]:
            print(f"    {res['not_enumerated']:>4}  not_enumerated   "
                  "not in this pack; assess by other means")
        print(f"  {'-' * 72}")
        print(f"    {res['declared_total']:>4}  controls in this baseline "
              f"({fw['declared_source'].strip()[:60]})")
        pct = res["assessed_fraction"] * 100
        print(f"\n    {pct:.1f}% of the baseline carries evidence from this scan "
              f"({counts[SATISFIED] + counts[VIOLATED]} of {res['declared_total']}).")
        print("    Every other control is unevidenced here. That is a statement "
              "about\n    this tool's reach, not about the system's security.")

        rows = [r for r in res["controls"]
                if not wanted or r["state"] in wanted]
        order = {s: i for i, s in enumerate(STATES)}
        rows.sort(key=lambda r: (order.get(r["state"], 9), r["id"]))
        shown = [r for r in rows if r["state"] in (VIOLATED, NOT_ASSESSED, NO_COVERAGE)] \
            if not wanted else rows
        if shown:
            print()
            for r in shown:
                print(f"    [{r['state'].upper()}] {r['id']}  {r['title']}")
                if r.get("reason"):
                    print(f"        {r['reason'][:100]}")
                if r["state"] in (VIOLATED, SATISFIED) and r.get("residual"):
                    print(f"        still needs a person: {r['residual'].strip()[:100]}")
    return EXIT_OK


def _outcome_from_dict(d: dict):
    from .core import ProbeOutcome
    return ProbeOutcome(
        name=d.get("name", ""), dimensions=d.get("dimensions", []),
        checks=int(d.get("checks", 0)), status=d.get("status", "skipped"),
        reason=d.get("reason", ""), version=d.get("version", ""),
        applicable=bool(d.get("applicable", True)),
    )


def cmd_explain(args) -> int:
    report = Report.from_dict(json.loads(Path(args.report).read_text(encoding="utf-8")))
    for f in report.findings:
        if f.id == args.finding_id or f.id.endswith(args.finding_id):
            print()
            print(f"  {f.severity.upper()}  {f.title}")
            print(f"  {f.id}   {f.rule_id}   [{f.provenance}, {f.confidence} confidence]")
            print(f"  repo {f.repo_id}   {f.location.short()}"
                  + (f"   {f.location.logical}" if f.location.logical else ""))
            print()
            if f.description:
                print(f"  {f.description}\n")
            if f.remediation:
                print(f"  Fix: {f.remediation}\n")
            if f.controls:
                print(f"  Controls: {', '.join(f.controls)}\n")
            if f.evidence:
                print(f"  Evidence: {f.evidence}\n")
            if f.related:
                print("  Also at: " + ", ".join(r.short() for r in f.related) + "\n")
            return EXIT_OK
    print(f"arbiter: no finding {args.finding_id} in {args.report}", file=sys.stderr)
    return EXIT_ERROR


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "scan":
            return cmd_scan(args)
        if args.cmd == "gate":
            args.limit = 40
            return cmd_scan(args, gate_mode=True)
        if args.cmd == "ab":
            return cmd_ab(args)
        if args.cmd == "probes":
            return cmd_probes(args)
        if args.cmd == "baseline":
            return cmd_baseline(args)
        if args.cmd == "diff":
            return cmd_diff(args)
        if args.cmd == "verify":
            return cmd_verify(args)
        if args.cmd == "feedback":
            return cmd_feedback(args)
        if args.cmd == "learn":
            return cmd_learn(args)
        if args.cmd == "review":
            return cmd_review(args)
        if args.cmd == "controls":
            return cmd_controls(args)
        if args.cmd == "explain":
            return cmd_explain(args)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        print(f"arbiter: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
