"""Pull-request review comments: findings where the developer is looking (ARB-173).

## Why

A finding in a batch report is read by almost nobody; the same finding as a
review comment on the line the author just wrote gets acted on (Meta's
experience with static analysis in code review: fix rates near zero for batch
reports, above 70% in review). `arbiter gate --post-review` turns the gate's
report into one GitHub review per push.

## What gets posted

Three filters, in order, and a finding that fails any of them is not posted:

1. **Changed lines only.** The line must be one this pull request added or
   modified (a `+` line of the diff), and the workspace line at the finding's
   line number must read exactly what the diff added. The second check is
   there because a `pull_request` checkout is the merge commit, whose line
   numbers can differ from the head commit the review is anchored to.
2. **Trust.** The rule must be one the precision ledger admits (`trusted`).
   `review.min_tier: verified` stops there. `advisory` (the default) also
   accepts rules at the ledger's advisory bar when the ledger carries one
   (`ADVISORY_ENTRY_KEYS`, `ADVISORY_BAR_KEYS`), honours any default-off
   flag (`DEFAULT_OFF_KEYS`), and, when the ledger has no advisory admission
   at all, falls back to high-severity, high-confidence deterministic
   findings whose rule the ledger has not measured below
   `FALLBACK_FLOOR`.
3. **Cap.** `review.max_comments` (default 20) inline comments; the rest are
   listed in the summary comment.

## Idempotence

One summary comment, found again by `SUMMARY_MARKER` and edited in place.
Inline comments carry a hidden `arbiter-finding` marker with the finding id;
an existing comment is edited (only if its text changed), never reposted. A
comment whose finding Arbiter no longer reports is edited to say so; the REST
API cannot resolve a review thread (that is GraphQL's `resolveReviewThread`),
so the thread stays open.

## Never fails the gate

`post_review_safely` catches everything. The gate's exit code is decided
before posting starts and nothing here can change it.
"""
from __future__ import annotations

import ast
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

from .core import SEV_RANK, Finding, Report

SUMMARY_MARKER = "<!-- arbiter-review -->"
FINDING_MARKER = re.compile(
    r"<!-- arbiter-finding id=(?P<id>f:[0-9a-f]+) rule=(?P<rule>\S+)(?P<gone> state=gone)? -->")
MAX_BODY = 60_000  # GitHub's limit is 65,536 characters
FEEDBACK_LINE = ("Useful? React 👍 or 👎 on this comment; Arbiter reads the reactions back "
                 "as labels (`arbiter review-feedback collect`).")

REVIEW_DEFAULTS = {"min_tier": "advisory", "max_comments": 20, "suggestions": True}
MIN_TIERS = ("verified", "advisory")  # strictest first

# The advisory admission is being added to the ledger separately (r7-advisory);
# its field names are not settled, so every name it might use is read here and
# nowhere else.
ADVISORY_ENTRY_KEYS = ("advisory", "advisory_admitted")
ADVISORY_BAR_KEYS = ("advisory_lower",)
DEFAULT_OFF_KEYS = ("default_off",)
DEFAULT_ON_KEYS = ("default_on", "enabled_by_default")
# Without an advisory bar: a rule the ledger has measured (enough labels)
# below this lower bound does not post on severity alone.
FALLBACK_FLOOR = 0.85


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _hunk_added(lines: list[str], i: int, added: dict[int, str]) -> int:
    """Read one hunk starting at its `@@` line; record added lines into
    `added` (new-side line number -> text). Returns the index after it.
    Bounded by the header's counts (an absent count means 1), so it never
    reads into the next file's `---`/`+++` header."""
    m = _HUNK.match(lines[i])
    old_left = int(m.group(1)) if m.group(1) is not None else 1
    new_line = int(m.group(2))
    new_left = int(m.group(3)) if m.group(3) is not None else 1
    i += 1
    while i < len(lines) and (old_left > 0 or new_left > 0):
        line = lines[i]
        tag = line[:1]
        if tag == "\\":  # "\ No newline at end of file"
            i += 1
            continue
        if tag == "+":
            added[new_line] = line[1:]
            new_line += 1
            new_left -= 1
        elif tag == "-":
            old_left -= 1
        elif tag == " " or line == "":
            new_line += 1
            new_left -= 1
            old_left -= 1
        else:
            break
        i += 1
    while i < len(lines) and lines[i].startswith("\\"):
        i += 1
    return i


def _strip_prefix(p: str, prefix: str) -> str:
    p = p.strip()
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1]
    return p[len(prefix):] if p.startswith(prefix) else p


def parse_unified_diff(text: str) -> dict[str, dict[int, str]]:
    """Added lines per new-side path from `git diff` output.

    Renamed files are keyed by their new name; deleted files are absent; a
    file whose only change is deletions maps to an empty dict."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: dict[str, dict[int, str]] = {}
    path: str | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git "):
            path = None
            i += 1
            continue
        if line.startswith("rename to "):
            path = line[len("rename to "):].strip()
            out.setdefault(path, {})
        elif line.startswith("+++ "):
            target = line[4:].split("\t")[0]
            path = None if target.strip() == "/dev/null" else _strip_prefix(target, "b/")
            if path is not None:
                out.setdefault(path, {})
        elif line.startswith("@@") and _HUNK.match(line):
            if path is None:
                i = _hunk_added(lines, i, {})
            else:
                i = _hunk_added(lines, i, out[path])
            continue
        i += 1
    return out


def changed_lines_from_pr_files(files: Iterable[dict]) -> dict[str, dict[int, str]]:
    """The same map from GitHub's `GET /pulls/{n}/files` entries, whose
    `patch` holds hunks without file headers. Removed files and files with no
    patch (binary, or too large for the API) carry nothing to comment on."""
    out: dict[str, dict[int, str]] = {}
    for f in files:
        if f.get("status") == "removed":
            continue
        name = f.get("filename") or ""
        added: dict[int, str] = {}
        patch = (f.get("patch") or "").replace("\r\n", "\n").split("\n")
        i = 0
        while i < len(patch):
            if _HUNK.match(patch[i]):
                i = _hunk_added(patch, i, added)
            else:
                i += 1
        out[name] = added
    return out


def git_diff_added(repo: str, base: str) -> tuple[dict[str, dict[int, str]], str]:
    """Added lines in `base...HEAD`, or ({}, why-not). Every option that user
    configuration could change is pinned."""
    cmd = ["git", "-C", repo, "-c", "core.quotePath=false", "diff", "--no-color",
           "--no-ext-diff", "-M", "--src-prefix=a/", "--dst-prefix=b/", "--unified=0",
           f"{base}...HEAD"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=120)
    except Exception as exc:  # noqa: BLE001 - no git: posting is skipped, never the gate
        return {}, f"git diff failed: {exc}"
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip().splitlines()
        return {}, (f"could not diff {base}...HEAD ({err[-1] if err else 'no merge base'}); "
                    "a shallow checkout needs fetch-depth: 0")
    return parse_unified_diff(r.stdout.decode("utf-8", "replace")), ""


def git_prefix(path: str) -> str:
    """The scan target's path inside its git work tree (`sub/dir/` or '')."""
    try:
        r = subprocess.run(["git", "-C", path, "rev-parse", "--show-prefix"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    except Exception:  # noqa: BLE001 - not a git checkout: paths are used as they are
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------

def review_settings(config: dict | None) -> dict:
    return {**REVIEW_DEFAULTS, **((config or {}).get("review") or {})}


def _flag(entry: dict, keys: Iterable[str]) -> bool | None:
    for k in keys:
        if k in entry:
            v = entry[k]
            if isinstance(v, dict):
                v = v.get("admitted", v.get("enabled"))
            if isinstance(v, bool):
                return v
    return None


def ledger_has_advisory(ledger: dict) -> bool:
    bar = ledger.get("bar") or {}
    if any(k in bar for k in ADVISORY_BAR_KEYS):
        return True
    return any(any(k in e for k in ADVISORY_ENTRY_KEYS)
               for e in (ledger.get("rules") or {}).values() if isinstance(e, dict))


def _advisory_admits(entry: dict | None, bar: dict) -> tuple[bool, str]:
    from .precision import wilson
    if not entry:
        return False, "no ledger entry"
    flag = _flag(entry, ADVISORY_ENTRY_KEYS)
    if flag is not None:
        return flag, "ledger advisory admission" if flag else "below the ledger's advisory bar"
    lower_bar = next((bar[k] for k in ADVISORY_BAR_KEYS if k in bar), None)
    if lower_bar is None:
        return False, "no advisory admission for this rule"
    tp, fp = int(entry.get("tp", 0)), int(entry.get("fp", 0))
    if tp + fp < int(bar.get("rule_min_n", 30)):
        return False, f"{tp + fp} label(s), {bar.get('rule_min_n', 30)} needed"
    lo = wilson(tp, tp + fp)[0]
    if lo < float(lower_bar):
        return False, f"lower bound {lo:.3f} below the advisory bar {lower_bar}"
    return True, f"advisory bar: lower bound {lo:.3f} on {tp + fp} labels"


def trust(f: Finding, ledger: dict, min_tier: str = "advisory") -> tuple[bool, str]:
    """Whether a finding is trustworthy enough to post, and why."""
    from .precision import admission, wilson
    from .rule_meta import ledger_key
    if f.suppressed:
        return False, "suppressed"
    if f.provenance == "inferred":
        return False, "found by a model"
    verdict = str((f.verification or {}).get("verdict") or "")
    if verdict in ("rejected", "unsure"):
        return False, f"model {verdict}"
    bar = ledger.get("bar") or {}
    entry = (ledger.get("rules") or {}).get(ledger_key(f.rule_id))
    if entry and (_flag(entry, DEFAULT_OFF_KEYS) is True or _flag(entry, DEFAULT_ON_KEYS) is False):
        return False, "rule is off by default"
    ok, why = admission(entry, bar)
    if ok:
        return True, f"ledger-admitted ({why})"
    if min_tier == "verified":
        return False, f"ledger does not admit the rule: {why}"
    if ledger_has_advisory(ledger):
        return _advisory_admits(entry, bar)
    # No advisory admission in this ledger: severity and confidence, unless
    # the ledger has measured the rule and found it poor.
    if SEV_RANK.get(f.severity, 99) > SEV_RANK["high"] or f.confidence != "high":
        return False, f"ledger does not admit the rule ({why}) and it is not high severity, high confidence"
    if entry:
        tp, fp = int(entry.get("tp", 0)), int(entry.get("fp", 0))
        if tp + fp >= int(bar.get("rule_min_n", 30)):
            lo = wilson(tp, tp + fp)[0]
            if lo < FALLBACK_FLOOR:
                return False, f"ledger measured the rule at lower bound {lo:.3f}, below {FALLBACK_FLOOR}"
    return True, "high severity, high confidence (no advisory bar in this ledger)"


# ---------------------------------------------------------------------------
# Suggested fixes
# ---------------------------------------------------------------------------

@dataclass
class Suggestion:
    line: str          # the replacement for the finding's one line
    note: str = ""


FixFn = Callable[[Finding, str], "Suggestion | None"]
FIXES: dict[str, FixFn] = {}


def register_fix(rule_id: str) -> Callable[[FixFn], FixFn]:
    """A fix is registered per rule id. It receives the finding and the
    file's text and returns a one-line replacement, or None whenever it is
    not certain the edit is mechanical and stays inside the rule's scope."""
    def deco(fn: FixFn) -> FixFn:
        FIXES[rule_id] = fn
        return fn
    return deco


def suggest(f: Finding, source: str) -> Suggestion | None:
    fn = FIXES.get(f.rule_id)
    if fn is None or f.location.start_line <= 0:
        return None
    try:
        return fn(f, source)
    except Exception:  # noqa: BLE001 - a fix that cannot decide is no fix
        return None


TIMEOUT_SECONDS = 30
_REQUESTS_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}


def _is_requests_call(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "requests"
            and node.func.attr in _REQUESTS_METHODS)


def _without_timeout(tree: ast.AST, lineno: int) -> str:
    for node in ast.walk(tree):
        if _is_requests_call(node) and node.lineno == lineno:
            node.keywords = [k for k in node.keywords if k.arg != "timeout"]
    return ast.dump(tree, include_attributes=False)


@register_fix("arbiter/python.http-no-timeout")
def _fix_http_no_timeout(f: Finding, source: str) -> Suggestion | None:
    """`requests.<method>(...)` on one line -> the same call with
    `timeout=30` appended. Nothing else: not `urlopen` (its third positional
    argument is the timeout), not a call spanning lines, not a line with two
    such calls, not a call that splats `**kwargs` or already passes one."""
    line_no = f.location.start_line
    if f.location.end_line and f.location.end_line != line_no:
        return None
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree) if _is_requests_call(n)
             and n.lineno == line_no and n.end_lineno == line_no]
    if len(calls) != 1:
        return None
    call = calls[0]
    if any(k.arg is None or k.arg == "timeout" for k in call.keywords):
        return None
    lines = source.splitlines(keepends=True)
    raw = lines[line_no - 1]
    eol = raw[len(raw.rstrip("\r\n")):]
    data = raw.rstrip("\r\n").encode("utf-8")
    close = call.end_col_offset - 1  # byte offset of the closing parenthesis
    if data[close:close + 1] != b")":
        return None
    parts = [*call.args, *call.keywords]
    if parts:
        last_end = max(p.end_col_offset for p in parts)
        if any(p.end_lineno != line_no for p in parts):
            return None
        between = data[last_end:close]
        if between.strip() not in (b"", b","):
            return None  # a comment or anything else we do not understand
        new = data[:last_end] + b", timeout=" + str(TIMEOUT_SECONDS).encode() + data[close:]
    else:
        inner = data[call.func.end_col_offset:close]
        if inner.strip() != b"(":
            return None
        new = data[:close] + b"timeout=" + str(TIMEOUT_SECONDS).encode() + data[close:]
    new_line = new.decode("utf-8")
    # Proof of scope: the edited file must parse to the same tree except for
    # the one keyword this fix adds.
    edited = "".join(lines[:line_no - 1]) + new_line + eol + "".join(lines[line_no:])
    try:
        after = ast.parse(edited)
    except SyntaxError:
        return None
    added = [k for n in ast.walk(after) if _is_requests_call(n) and n.lineno == line_no
             for k in n.keywords if k.arg == "timeout"]
    if len(added) != 1 or _without_timeout(after, line_no) != ast.dump(tree, include_attributes=False):
        return None
    return Suggestion(new_line, f"`timeout={TIMEOUT_SECONDS}` is a starting point; "
                                f"pick the bound this call can afford.")


# ---------------------------------------------------------------------------
# Selection and rendering
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    finding: Finding
    path: str                 # repository-relative, as the diff names it
    line: int
    reason: str
    suggestion: Suggestion | None = None


@dataclass
class Plan:
    post: list[Candidate] = field(default_factory=list)
    overflow: list[Candidate] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    diff_paths: set[str] = field(default_factory=set)   # files this pull request changed


def _skip(plan: Plan, why: str) -> None:
    plan.skipped[why] = plan.skipped.get(why, 0) + 1


def plan_review(report: Report, changed: dict[str, dict[int, str]], ledger: dict,
                config: dict | None, workspace: str = ".", prefix: str = "") -> Plan:
    """Which findings to comment on, in order (severity, then path)."""
    settings = review_settings(config)
    min_tier = settings["min_tier"]
    cap = int(settings["max_comments"])
    plan = Plan(diff_paths=set(changed))
    repo_ids = [r.id for r in report.repos]
    first = repo_ids[0] if repo_ids else None
    sources: dict[str, str | None] = {}

    def text_of(rel: str) -> str | None:
        if rel not in sources:
            try:
                sources[rel] = (Path(workspace) / rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                sources[rel] = None
        return sources[rel]

    findings = sorted(report.active(), key=lambda f: (SEV_RANK.get(f.severity, 99),
                                                      f.location.path, f.location.start_line))
    for f in findings:
        if len(repo_ids) > 1 and f.repo_id != first:
            _skip(plan, "another repository of the system")
            continue
        line = f.location.start_line
        rel = f.location.path
        diff_path = prefix + rel
        added = changed.get(diff_path)
        if not added or line not in added:
            _skip(plan, "not on a changed line")
            continue
        ok, why = trust(f, ledger, min_tier)
        if not ok:
            _skip(plan, "not trusted enough to post")
            continue
        source = text_of(rel)
        if source is None:
            _skip(plan, "file unreadable")
            continue
        src_lines = source.splitlines()
        if line > len(src_lines) or src_lines[line - 1].rstrip("\r") != added[line].rstrip("\r"):
            _skip(plan, "line differs from the pull request's head")
            continue
        cand = Candidate(f, diff_path, line, why)
        if settings.get("suggestions", True):
            cand.suggestion = suggest(f, source)
        (plan.post if len(plan.post) < cap else plan.overflow).append(cand)
    return plan


def finding_marker(f: Finding, gone: bool = False) -> str:
    return f"<!-- arbiter-finding id={f.id} rule={f.rule_id}{' state=gone' if gone else ''} -->"


def render_inline(c: Candidate) -> str:
    f = c.finding
    L = [f"**Arbiter** · {f.severity} · `{f.rule_id}`", "", f"**{f.title}**"]
    if f.description:
        L += ["", f.description.strip()]
    if c.suggestion is not None:
        L += ["", "Suggested fix:", "```suggestion", c.suggestion.line, "```"]
        if c.suggestion.note:
            L.append(c.suggestion.note)
    elif f.remediation:
        L += ["", f"**Fix:** {f.remediation.strip()}"]
    L += ["", f"<sub>Posted because: {c.reason}. {FEEDBACK_LINE}</sub>", finding_marker(f)]
    return "\n".join(L)[:MAX_BODY]


def render_gone(body: str, finding_id: str, rule: str, sha: str) -> str:
    first = f"~~This finding~~ — Arbiter no longer reports `{rule}` here as of `{sha[:7]}`."
    kept = FINDING_MARKER.sub("", body).strip()
    return f"{first}\n\n<details><summary>Original comment</summary>\n\n{kept}\n\n</details>\n" \
           f"<!-- arbiter-finding id={finding_id} rule={rule} state=gone -->"


def render_summary(report: Report, plan: Plan) -> str:
    from .diff import render_pr_comment
    L = [SUMMARY_MARKER, "### Arbiter review", ""]
    n = len(plan.post)
    L.append(f"{n} finding{'s' if n != 1 else ''} commented inline on lines this pull request "
             f"changed.")
    if plan.overflow:
        L[-1] += f" {len(plan.overflow)} more findings are listed below rather than commented."
    L += ["", render_pr_comment(report), ""]
    if plan.overflow:
        L += [f"<details><summary>{len(plan.overflow)} more findings in the summary</summary>", "",
              "| Severity | Finding | Location |", "|---|---|---|"]
        for c in plan.overflow:
            L.append(f"| {c.finding.severity} | {c.finding.title} | `{c.path}:{c.line}` |")
        L += ["", "</details>", ""]
    L.append("<sub>Inline comments cover only changed lines and only rules the precision ledger "
             "trusts; the full report is in the job summary and the SARIF upload. "
             "React 👍 or 👎 on an inline comment to say whether it was useful.</sub>")
    body = "\n".join(L)
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY - 40] + "\n\n_… truncated_"
    return body


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

class GitHubError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status


class GitHub(Protocol):
    def pr_files(self, repo: str, pr: int) -> list[dict]: ...
    def review_comments(self, repo: str, pr: int) -> list[dict]: ...
    def create_review(self, repo: str, pr: int, commit: str, body: str,
                      comments: list[dict]) -> dict: ...
    def create_review_comment(self, repo: str, pr: int, commit: str, comment: dict) -> dict: ...
    def edit_review_comment(self, repo: str, comment_id: int, body: str) -> dict: ...
    def issue_comments(self, repo: str, pr: int) -> list[dict]: ...
    def create_issue_comment(self, repo: str, pr: int, body: str) -> dict: ...
    def edit_issue_comment(self, repo: str, comment_id: int, body: str) -> dict: ...
    def comment_reactions(self, repo: str, comment_id: int) -> list[dict]: ...


class GitHubClient:
    """The REST calls this feature makes, over urllib, every list paginated."""

    def __init__(self, token: str, api: str = "https://api.github.com", timeout: float = 20.0):
        self.token = token
        self.api = api.rstrip("/")
        self.timeout = timeout

    def _call(self, method: str, url: str, body: Any = None) -> tuple[Any, dict]:
        import urllib.error
        import urllib.request
        if not url.startswith("http"):
            url = self.api + url
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "arbiter-review",
            **({"Content-Type": "application/json"} if data is not None else {}),
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return (json.loads(raw) if raw else None), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise GitHubError(exc.code, detail) from None

    def _list(self, path: str) -> list[dict]:
        out: list[dict] = []
        url: str | None = path + ("&" if "?" in path else "?") + "per_page=100"
        while url:
            page, headers = self._call("GET", url)
            out.extend(page or [])
            url = None
            for part in (headers.get("Link") or headers.get("link") or "").split(","):
                if 'rel="next"' in part:
                    url = part[part.find("<") + 1:part.find(">")]
        return out

    def pr_files(self, repo, pr):
        return self._list(f"/repos/{repo}/pulls/{pr}/files")

    def review_comments(self, repo, pr):
        return self._list(f"/repos/{repo}/pulls/{pr}/comments")

    def create_review(self, repo, pr, commit, body, comments):
        return self._call("POST", f"/repos/{repo}/pulls/{pr}/reviews",
                          {"commit_id": commit, "event": "COMMENT", "body": body,
                           "comments": comments})[0]

    def create_review_comment(self, repo, pr, commit, comment):
        return self._call("POST", f"/repos/{repo}/pulls/{pr}/comments",
                          {**comment, "commit_id": commit})[0]

    def edit_review_comment(self, repo, comment_id, body):
        return self._call("PATCH", f"/repos/{repo}/pulls/comments/{comment_id}", {"body": body})[0]

    def issue_comments(self, repo, pr):
        return self._list(f"/repos/{repo}/issues/{pr}/comments")

    def create_issue_comment(self, repo, pr, body):
        return self._call("POST", f"/repos/{repo}/issues/{pr}/comments", {"body": body})[0]

    def edit_issue_comment(self, repo, comment_id, body):
        return self._call("PATCH", f"/repos/{repo}/issues/comments/{comment_id}", {"body": body})[0]

    def comment_reactions(self, repo, comment_id):
        return self._list(f"/repos/{repo}/pulls/comments/{comment_id}/reactions")


@dataclass
class PRContext:
    repo: str = ""
    pr: int = 0
    head_sha: str = ""
    fork: bool = False
    base_ref: str = ""


def context_from_env(env: dict | None = None) -> PRContext:
    """The pull request a GitHub Actions run is about, from its event file.
    The head sha comes from the payload, never GITHUB_SHA: on a
    `pull_request` event that is the merge commit, which a review cannot be
    anchored to."""
    env = os.environ if env is None else env
    ctx = PRContext(repo=env.get("GITHUB_REPOSITORY", ""), base_ref=env.get("GITHUB_BASE_REF", ""))
    path = env.get("GITHUB_EVENT_PATH")
    if path and Path(path).is_file():
        try:
            event = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            event = {}
        pr = event.get("pull_request") or {}
        if pr:
            ctx.pr = int(pr.get("number") or event.get("number") or 0)
            ctx.head_sha = ((pr.get("head") or {}).get("sha")) or ""
            head_repo = (((pr.get("head") or {}).get("repo")) or {}).get("full_name")
            base_repo = (((pr.get("base") or {}).get("repo")) or {}).get("full_name")
            ctx.fork = bool(head_repo and base_repo and head_repo != base_repo)
            ctx.base_ref = ctx.base_ref or (pr.get("base") or {}).get("ref", "")
    return ctx


@dataclass
class Outcome:
    mode: str                       # posted | dry-run | job-summary | skipped
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    gone: int = 0
    dropped: int = 0                # refused by the API one at a time
    notes: list[str] = field(default_factory=list)


def _existing_inline(comments: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for c in comments:
        m = FINDING_MARKER.search(c.get("body") or "")
        if m and m.group("id") not in out:
            out[m.group("id")] = {**c, "_rule": m.group("rule"), "_gone": bool(m.group("gone"))}
    return out


def sync_review(client: GitHub, ctx: PRContext, report: Report, plan: Plan) -> Outcome:
    """Bring the pull request's Arbiter comments in line with `plan`.
    Raises on API errors; `post_review_safely` is what callers use."""
    out = Outcome("posted")
    existing = _existing_inline(client.review_comments(ctx.repo, ctx.pr))
    new: list[dict] = []
    for c in plan.post:
        body = render_inline(c)
        prior = existing.get(c.finding.id)
        if prior is None:
            new.append({"path": c.path, "line": c.line, "side": "RIGHT", "body": body})
        elif (prior.get("body") or "") != body:
            client.edit_review_comment(ctx.repo, prior["id"], body)
            out.updated += 1
        else:
            out.unchanged += 1
    if new:
        try:
            client.create_review(ctx.repo, ctx.pr, ctx.head_sha,
                                 f"Arbiter: {len(new)} new finding(s) on changed lines.", new)
            out.created += len(new)
        except GitHubError as exc:
            if exc.status != 422:
                raise
            # One comment outside the diff fails the whole review: post them
            # one at a time and drop the ones GitHub refuses.
            for comment in new:
                try:
                    client.create_review_comment(ctx.repo, ctx.pr, ctx.head_sha, comment)
                    out.created += 1
                except GitHubError as one:
                    if one.status != 422:
                        raise
                    out.dropped += 1
    active = {f.id for f in report.active()}
    partial = (report.scan_scope or {}).get("mode") == "partial"
    for fid, prior in existing.items():
        if fid in active or prior["_gone"]:
            continue
        if partial and prior.get("path") not in plan.diff_paths:
            continue  # its file was not scanned this time: absence proves nothing
        client.edit_review_comment(ctx.repo, prior["id"],
                                   render_gone(prior.get("body") or "", fid, prior["_rule"], ctx.head_sha))
        out.gone += 1
    summary = render_summary(report, plan)
    mine = [c for c in client.issue_comments(ctx.repo, ctx.pr) if SUMMARY_MARKER in (c.get("body") or "")]
    if mine:
        if mine[0].get("body") != summary:
            client.edit_issue_comment(ctx.repo, mine[0]["id"], summary)
    else:
        client.create_issue_comment(ctx.repo, ctx.pr, summary)
    return out


def render_dry_run(report: Report, plan: Plan) -> str:
    L = ["", f"  review (dry run): would post {len(plan.post)} inline comment(s) and one summary"]
    for c in plan.post:
        L.append(f"     {c.finding.severity:<8} {c.path}:{c.line}  {c.finding.title[:60]}"
                 + ("  [suggestion]" if c.suggestion else ""))
    if plan.overflow:
        L.append(f"     … {len(plan.overflow)} more in the summary (review.max_comments)")
    for why, n in sorted(plan.skipped.items()):
        L.append(f"     not posted: {n} {why}")
    return "\n".join(L)


def post_review_safely(report: Report, config: dict | None, *, changed: dict[str, dict[int, str]] | None,
                       ctx: PRContext, client: GitHub | None, workspace: str, prefix: str = "",
                       ledger: dict | None = None, step_summary: str | None = None,
                       log: Callable[[str], None] = print, diff_note: str = "") -> Outcome:
    """Plan and deliver the review. Never raises: a review that could not be
    posted is a note in the log, and the gate's verdict stands."""
    try:
        from .precision import load_ledger
        if ledger is None:
            ledger = load_ledger(((config or {}).get("precision") or {}).get("ledger"))
        if changed is None and client is not None and ctx.repo and ctx.pr:
            changed = changed_lines_from_pr_files(client.pr_files(ctx.repo, ctx.pr))
        if changed is None:
            log(f"  review: skipped — {diff_note or 'no pull-request diff to compare against'}")
            return Outcome("skipped", notes=[diff_note])
        plan = plan_review(report, changed, ledger, config, workspace, prefix)
        if client is None or ctx.fork or not (ctx.repo and ctx.pr and ctx.head_sha):
            why = ("a fork's token cannot write to the pull request" if ctx.fork else
                   "no GITHUB_TOKEN" if client is None else "no pull request in this run")
            text = render_dry_run(report, plan)
            log(f"  review: not posting ({why}); this is what would be posted:{text}")
            if step_summary and (ctx.fork or client is not None):
                with open(step_summary, "a", encoding="utf-8") as fh:
                    fh.write("\n" + render_summary(report, plan) + "\n")
                return Outcome("job-summary", notes=[why])
            return Outcome("dry-run", notes=[why])
        try:
            out = sync_review(client, ctx, report, plan)
        except GitHubError as exc:
            if exc.status in (401, 403, 404) and step_summary:
                with open(step_summary, "a", encoding="utf-8") as fh:
                    fh.write("\n" + render_summary(report, plan) + "\n")
                log(f"  review: GitHub refused the write ({exc}); wrote the review to the job summary")
                return Outcome("job-summary", notes=[str(exc)])
            raise
        log(f"  review: {out.created} new, {out.updated} updated, {out.unchanged} unchanged, "
            f"{out.gone} marked no longer reported"
            + (f", {out.dropped} refused by GitHub" if out.dropped else ""))
        return out
    except Exception as exc:  # noqa: BLE001 - posting must never fail the gate
        log(f"  review: not posted ({type(exc).__name__}: {exc}); the gate result is unaffected")
        return Outcome("skipped", notes=[str(exc)])


# ---------------------------------------------------------------------------
# Reactions -> labels
# ---------------------------------------------------------------------------

HUMAN_LABELLER = "human:pr-reaction"
DEFAULT_LABELS = Path(".arbiter") / "labels" / "human-pr.jsonl"


def hash_login(login: str) -> str:
    return "sha256:" + hashlib.sha256(login.strip().lower().encode("utf-8")).hexdigest()[:16]


def collect_reactions(client: GitHub, repo: str, pr: int, today: str | None = None) -> tuple[list[dict], dict]:
    """One label per (finding, person) from 👍/👎 on Arbiter's inline comments.
    Bots and the comment's own author are not people giving feedback; a
    person who left both reactions has not decided, and is skipped."""
    today = today or _dt.date.today().isoformat()
    stats = {"comments": 0, "reactions": 0, "conflicting": 0, "ignored": 0}
    labels: list[dict] = []
    for c in client.review_comments(repo, pr):
        m = FINDING_MARKER.search(c.get("body") or "")
        if not m:
            continue
        stats["comments"] += 1
        author = ((c.get("user") or {}).get("login") or "").lower()
        votes: dict[str, set[str]] = {}
        for r in client.comment_reactions(repo, c["id"]):
            user = r.get("user") or {}
            login = (user.get("login") or "").lower()
            if r.get("content") not in ("+1", "-1"):
                continue
            if not login or user.get("type") == "Bot" or login == author or login.endswith("[bot]"):
                stats["ignored"] += 1
                continue
            stats["reactions"] += 1
            votes.setdefault(login, set()).add(r["content"])
        for login, contents in sorted(votes.items()):
            if len(contents) > 1:
                stats["conflicting"] += 1
                continue
            labels.append({
                "finding_id": f"pr:{repo}#{pr}:{m.group('id')}",
                "rule_id": m.group("rule"),
                "label": "tp" if "+1" in contents else "fp",
                "question": "useful",
                "labeller": HUMAN_LABELLER,
                "provenance": HUMAN_LABELLER,
                "reactor": hash_login(login),
                "source": "pr-reaction",
                "held_out": False,
                "role": "labeller",
                "date": today,
                "repo": repo,
                "pr": pr,
                "path": c.get("path", ""),
                "line": c.get("line") or c.get("original_line") or 0,
                "comment_id": c["id"],
            })
    return labels, stats


def merge_labels(path: Path, labels: list[dict]) -> tuple[int, int]:
    """Write labels into `path`, one per (finding, reactor): a new one is
    added, a changed reaction replaces the old label. Returns (added, changed)."""
    existing: dict[tuple[str, str], dict] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                rec = json.loads(line)
                existing[(rec["finding_id"], rec.get("reactor", ""))] = rec
    added = changed = 0
    for rec in labels:
        key = (rec["finding_id"], rec["reactor"])
        prior = existing.get(key)
        if prior is None:
            added += 1
        elif prior.get("label") != rec["label"]:
            changed += 1
        else:
            continue
        existing[key] = rec
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                            for _, r in sorted(existing.items())), encoding="utf-8")
    return added, changed


def token_from_env(env: dict | None = None) -> str:
    env = os.environ if env is None else env
    return env.get("GITHUB_TOKEN") or env.get("GH_TOKEN") or ""


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)
