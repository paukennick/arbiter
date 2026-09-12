"""Batch adjudication: making the one irreplaceable input cheap enough to give.

## Why this is the bottleneck

Calibration reads one ledger and one only: findings a person looked at and
judged right or wrong. Not the injection trials, which measure whether a rule
works mechanically against faults the tool itself generated. Not the corpus
discrimination, which measures whether a rule separates broken code from
working code. Those are both worth having and neither answers the question
calibration asks, which is whether the things this rule flags are things you
would actually act on.

No schedule can supply that. No amount of nightly running produces it. It is
the one input that has to come from a person, and at the time of writing the
ledger had exactly zero entries -- which means the calibration machinery, in a
tool built around calibration, was doing nothing at all.

The reason was not unwillingness. It was that adjudicating meant copying
fingerprints out of a report one at a time:

    arbiter feedback f:8c41d2ae9b07 --false-positive
    arbiter feedback f:9d02a11bc433 --true-positive

Twenty of those is an afternoon of clerical work, so it never happened. This
module exists to turn twenty adjudications into a few minutes of reading.

## Sampling, and why it is not random

Twenty adjudicated observations is the threshold at which a rule stops being
reported as unproven. That number is what the sampler optimizes for, not
coverage of the finding list:

  1. Rules already close to twenty come first. Getting one rule from fifteen
     to twenty is worth more than one observation each on five rules, because
     the first crosses a threshold and the second crosses nothing.
  2. Then rules with the most findings, because a rule that fires often is one
     whose precision matters most.
  3. Within a rule, findings are spread across files rather than taken in
     order, so twenty samples of the same mistake in one file do not get
     mistaken for twenty independent observations.
  4. Findings already adjudicated never reappear. One disputed finding must
     not be able to move the statistics as many times as somebody clicks.

A flat random sample would spend most of its budget on whatever rule happens
to fire most, which is usually the least interesting one.
"""
from __future__ import annotations

import datetime as _dt
import re
from collections import defaultdict
from pathlib import Path

from .core import Finding
from .learn import MIN_OBSERVATIONS, Knowledge

MARK = re.compile(r"^\s*\[([ yYnNsS?])\]\s*(f:[0-9a-f]{6,})\b")

HEADER = """\
# Findings to review

Mark each one, save the file, then run:

    arbiter review --apply {path}

    [y]  a real problem — I would act on this
    [n]  not a real problem — the rule is wrong here
    [ ]  skip; leave it blank and it is not recorded

Marking honestly matters more than marking everything. A skipped finding costs
nothing; a wrong mark is worse than no mark, because calibration reads this
ledger and nothing else.

A rule needs {min_obs} adjudications before it stops being reported as unproven.
The selection below is weighted toward rules that are close to that line.

---
"""


def _rule_gap(knowledge: Knowledge, rule_id: str) -> int:
    """How many more adjudications this rule needs to cross the threshold."""
    stats = knowledge.rules.get(rule_id)
    have = stats.observations if stats else 0
    return max(0, MIN_OBSERVATIONS - have)


def select(
    findings: list[Finding],
    knowledge: Knowledge,
    limit: int = 20,
    rule: str | None = None,
) -> list[Finding]:
    """Pick the findings whose adjudication buys the most."""
    pool = [f for f in findings
            if not f.suppressed and f.id not in knowledge.adjudicated]
    if rule:
        pool = [f for f in pool if rule in f.rule_id]
    if not pool:
        return []

    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in pool:
        by_rule[f.rule_id].append(f)

    def rule_priority(rid: str) -> tuple:
        gap = _rule_gap(knowledge, rid)
        # A rule already past the threshold is the lowest priority: more
        # observations there refine an estimate that is already reportable.
        started = 1 if (knowledge.rules.get(rid) and
                        knowledge.rules[rid].observations) else 0
        return (0 if gap else 1, -started, -len(by_rule[rid]), rid)

    # Spread within a rule across distinct files before repeating one.
    for rid, items in by_rule.items():
        seen: dict[str, int] = defaultdict(int)
        ordered = []
        for f in sorted(items, key=lambda f: (f.location.path, f.location.start_line)):
            seen[f.location.path] += 1
            ordered.append((seen[f.location.path], f.location.path, f))
        by_rule[rid] = [f for _, _, f in sorted(ordered, key=lambda t: (t[0], t[1]))]

    # Two tiers, not one ranked list. Spreading round-robin across every rule
    # would hand budget to already-proven rules on the first pass, and another
    # observation there only refines an estimate that is already reportable.
    # So rules still short of the threshold are exhausted first, and proven
    # rules get whatever is left over — usually nothing.
    needs = sorted((r for r in by_rule if _rule_gap(knowledge, r)), key=rule_priority)
    proven = sorted((r for r in by_rule if not _rule_gap(knowledge, r)), key=rule_priority)

    out: list[Finding] = []
    for tier in (needs, proven):
        idx = 0
        while len(out) < limit and any(idx < len(by_rule[r]) for r in tier):
            for rid in tier:
                if len(out) >= limit:
                    break
                if idx < len(by_rule[rid]):
                    out.append(by_rule[rid][idx])
            idx += 1
        if len(out) >= limit:
            break
    return out[:limit]


def render(findings: list[Finding], knowledge: Knowledge, path: str) -> str:
    lines = [HEADER.format(path=path, min_obs=MIN_OBSERVATIONS)]
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)

    for rid in sorted(by_rule, key=lambda r: (-len(by_rule[r]), r)):
        stats = knowledge.rules.get(rid)
        have = stats.observations if stats else 0
        gap = _rule_gap(knowledge, rid)
        status = (f"{have} reviewed so far, {gap} more to become proven"
                  if gap else f"{have} reviewed — already proven")
        lines.append(f"\n## {rid}")
        lines.append(f"_{status}_\n")
        for f in by_rule[rid]:
            lines.append(f"[ ] {f.id}  **{f.title}**")
            lines.append(f"    {f.location.short() or '-'}  ·  "
                         f"{f.severity}/{f.confidence}")
            if f.evidence:
                lines.append(f"    evidence: `{f.evidence[:110]}`")
            if f.description:
                lines.append(f"    {f.description[:220]}")
            lines.append("")
    lines.append("\n---\n")
    lines.append(f"_Generated {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')} "
                 f"· {len(findings)} findings across {len(by_rule)} rules._")
    return "\n".join(lines) + "\n"


def parse(text: str) -> dict[str, str]:
    """Read marks back. Unmarked and unrecognised lines are simply skipped."""
    out: dict[str, str] = {}
    for line in text.split("\n"):
        m = MARK.match(line)
        if not m:
            continue
        mark, fid = m.group(1).lower(), m.group(2)
        if mark == "y":
            out[fid] = "true_positive"
        elif mark == "n":
            out[fid] = "false_positive"
        # " ", "s", "?" all mean skip, and skipping is a legitimate answer
    return out


def apply(
    text: str,
    findings: list[Finding],
    knowledge: Knowledge,
    note: str = "",
) -> dict:
    """Record the marks. Returns a summary; never raises on unknown ids."""
    from .learn import record
    marks = parse(text)
    by_id = {f.id: f for f in findings}
    recorded, repeated, unknown = 0, 0, []
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"true": 0, "false": 0})
    for fid, verdict in marks.items():
        target = by_id.get(fid)
        if target is None:
            unknown.append(fid)
            continue
        if record(knowledge, target, verdict, note):
            recorded += 1
            per_rule[target.rule_id]["true" if verdict == "true_positive" else "false"] += 1
        else:
            repeated += 1
    return {
        "marked": len(marks), "recorded": recorded,
        "already_adjudicated": repeated, "unknown": unknown,
        "per_rule": {k: dict(v) for k, v in per_rule.items()},
    }


def newly_proven(knowledge: Knowledge, before: dict[str, int]) -> list[str]:
    """Rules that crossed the threshold as a result of this batch."""
    out = []
    for rid, stats in knowledge.rules.items():
        if stats.observations >= MIN_OBSERVATIONS and before.get(rid, 0) < MIN_OBSERVATIONS:
            out.append(rid)
    return sorted(out)
