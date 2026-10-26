"""Pull-request review comments (ARB-173): diff parsing, the changed-line and
trust filters, suggestions, idempotent sync and reaction labels. Every GitHub
call goes to an in-memory fake; nothing here reaches the network."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import urllib.request

import pytest
from helpers import ROOT

from arbiter import pr_review as pr
from arbiter.core import Finding, Location, RepoInfo, Report
from arbiter.policy import DEFAULTS, check_review_config, load_config


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    for k in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_ACTIONS", "GITHUB_EVENT_PATH",
              "GITHUB_REPOSITORY", "GITHUB_STEP_SUMMARY", "GITHUB_BASE_REF"):
        monkeypatch.delenv(k, raising=False)

    def refuse(*a, **k):
        raise AssertionError("a test tried to reach the network")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

GIT_DIFF = """\
diff --git a/app/old.py b/app/new.py
similarity index 90%
rename from app/old.py
rename to app/new.py
index 111..222 100644
--- a/app/old.py
+++ b/app/new.py
@@ -2,0 +3,2 @@ def f():
+    a = 1
+    b = 2
@@ -10 +12 @@
-    old
+    new
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-x
-y
diff --git a/only_deleted.py b/only_deleted.py
--- a/only_deleted.py
+++ b/only_deleted.py
@@ -4,2 +3,0 @@
-p
-q
diff --git a/renamed_only.py b/moved.py
similarity index 100%
rename from renamed_only.py
rename to moved.py
diff --git a/tail.py b/tail.py
--- a/tail.py
+++ b/tail.py
@@ -1,3 +1,3 @@
 keep
-before
+after
 last
\\ No newline at end of file
"""


def test_diff_parsing_renames_hunks_and_deletions():
    got = pr.parse_unified_diff(GIT_DIFF.replace("\n", "\r\n"))
    assert got["app/new.py"] == {3: "    a = 1", 4: "    b = 2", 12: "    new"}
    assert "app/old.py" not in got and "gone.py" not in got
    assert got["only_deleted.py"] == {}
    assert got["moved.py"] == {}
    assert got["tail.py"] == {2: "after"}


def test_a_hunk_never_reads_into_the_next_files_header():
    text = ("--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
            "--- a/y.py\n+++ b/y.py\n@@ -0,0 +1 @@\n+c\n")
    assert pr.parse_unified_diff(text) == {"x.py": {1: "b"}, "y.py": {1: "c"}}


def test_pr_files_patches():
    files = [
        {"filename": "src/a.py", "status": "modified",
         "patch": "@@ -1,3 +1,4 @@\n import x\n+import y\n z\n-w\n+v\n@@ -20,2 +21,2 @@ def g():\n-  q\n+  r\n   s"},
        {"filename": "img.png", "status": "added"},
        {"filename": "old.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-a"},
        {"filename": "b.py", "previous_filename": "c.py", "status": "renamed",
         "patch": "@@ -1 +1 @@\n-a\n+b"},
    ]
    got = pr.changed_lines_from_pr_files(files)
    assert got == {"src/a.py": {2: "import y", 4: "v", 21: "  r"}, "img.png": {}, "b.py": {1: "b"}}


def test_git_diff_against_a_real_repository(tmp_path):
    from helpers import _git_repo
    repo = tmp_path / "r"
    _git_repo(repo, {"m.py": "a\nb\nc\n"})
    import subprocess
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", "-b", "feature"], check=True)
    (repo / "m.py").write_text("a\nB\nc\nd\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "commit", "-qam", "x"], check=True)
    got, note = pr.git_diff_added(str(repo), "main")
    assert note == "" and got == {"m.py": {2: "B", 4: "d"}}
    none, note = pr.git_diff_added(str(repo), "no-such-ref")
    assert none == {} and "could not diff" in note


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------

ADMITTED = "arbiter/supply.unpinned-action"
NOISY = "arbiter/python.sql-injection"
TIMEOUT = "arbiter/python.http-no-timeout"


def _entry(tp, fp, **extra):
    return {"tp": tp, "fp": fp, **extra}


def _ledger(rules, **bar):
    from arbiter.precision import DEFAULT_BAR
    return {"bar": {**DEFAULT_BAR, **bar}, "rules": rules}


def _f(rule, sev="medium", conf="high", path="app.py", line=1, **kw):
    return Finding(rule_id=rule, title=f"{rule} here", severity=sev, confidence=conf,
                   evidence=f"{rule}:{path}:{line}", location=Location(path=path, start_line=line), **kw)


def test_trust_without_the_advisory_key():
    led = _ledger({ADMITTED: _entry(500, 0), NOISY: _entry(20, 200), TIMEOUT: _entry(340, 17)})
    assert pr.trust(_f(ADMITTED), led)[0]
    assert not pr.trust(_f(TIMEOUT), led)[0]                     # medium, below the bar
    assert pr.trust(_f("arbiter/new.rule", sev="high"), led)[0]  # fallback: high/high, unmeasured
    assert not pr.trust(_f("arbiter/new.rule", sev="high", conf="medium"), led)[0]
    ok, why = pr.trust(_f(NOISY, sev="critical"), led)          # measured poor: never on severity
    assert not ok and "lower bound" in why
    assert not pr.trust(_f("arbiter/new.rule", sev="high"), led, "verified")[0]
    assert not pr.trust(_f(ADMITTED, provenance="inferred"), led)[0]
    assert not pr.trust(_f(ADMITTED, verification={"verdict": "rejected"}), led)[0]
    assert not pr.trust(_f(ADMITTED, suppressed=True), led)[0]


def test_trust_with_the_advisory_key():
    led = _ledger({ADMITTED: _entry(500, 0),
                   TIMEOUT: _entry(340, 17, advisory={"admitted": True}),
                   NOISY: _entry(20, 200, advisory=False),
                   "arbiter/off.rule": _entry(400, 1, default_off=True)})
    assert pr.ledger_has_advisory(led)
    assert pr.trust(_f(TIMEOUT), led)[0]
    assert not pr.trust(_f(TIMEOUT), led, "verified")[0]
    assert not pr.trust(_f(NOISY, sev="critical"), led)[0]
    # With an advisory admission in the ledger, severity no longer substitutes for it.
    assert not pr.trust(_f("arbiter/new.rule", sev="critical"), led)[0]
    assert not pr.trust(_f("arbiter/off.rule"), led)[0]          # default-off beats admission


def test_trust_with_only_an_advisory_bar():
    led = _ledger({TIMEOUT: _entry(340, 17), NOISY: _entry(20, 200)}, advisory_lower=0.85)
    assert pr.trust(_f(TIMEOUT), led)[0]
    assert not pr.trust(_f(NOISY), led)[0]


def test_the_shipped_ledger_is_read_without_error():
    from arbiter.precision import load_ledger
    led = load_ledger()
    assert pr.trust(_f(ADMITTED), led)[0]


# ---------------------------------------------------------------------------
# Suggestions
# ---------------------------------------------------------------------------

def _suggest(src, line=1, rule=TIMEOUT):
    return pr.suggest(_f(rule, line=line), src)


def test_suggestion_inside_a_function_keeps_the_indent():
    src = "def f(u, body):\n    return requests.post(u, json=body)\n"
    assert _suggest(src, line=2).line == "    return requests.post(u, json=body, timeout=30)"


@pytest.mark.parametrize("src,want", [
    ("r = requests.get(url)\n", "r = requests.get(url, timeout=30)"),
    ("y = requests.post(u, json=body)\n", "y = requests.post(u, json=body, timeout=30)"),
    ("x = requests.get(url,)\n", "x = requests.get(url, timeout=30)"),
    ("x = requests.get()\n", "x = requests.get(timeout=30)"),
    ("x = requests.get(f(a), 'é')  # note\n", "x = requests.get(f(a), 'é', timeout=30)  # note"),
    ("x = requests.get(url)\r\n", "x = requests.get(url, timeout=30)"),
])
def test_suggestion_adds_only_the_timeout(src, want):
    s = _suggest(src)
    assert s is not None and s.line == want


@pytest.mark.parametrize("src", [
    "r = urllib.request.urlopen(url)\n",                     # positional timeout exists
    "r = requests.get(url, **kw)\n",                         # might already carry one
    "a, b = requests.get(x), requests.get(y)\n",             # two calls on one line
    "r = requests.get(\n    url)\n",                          # spans lines
    "r = requests.get(url  # why\n)\n",
    "r = session.get(url)\n",                                # not the module function
    "r = requests.get(url, timeout=5)\n",
])
def test_no_suggestion_where_the_fix_is_not_certain(src):
    assert _suggest(src) is None


def test_no_suggestion_for_rules_without_a_fix_and_on_bad_source():
    assert _suggest("r = requests.get(url)\n", rule=ADMITTED) is None
    assert _suggest("def (:\n") is None


def test_register_fix_is_the_extension_point():
    @pr.register_fix("arbiter/test.example")
    def _fix(f, source):
        return pr.Suggestion("fixed")
    try:
        assert pr.suggest(_f("arbiter/test.example"), "x\n").line == "fixed"
    finally:
        pr.FIXES.pop("arbiter/test.example")


# ---------------------------------------------------------------------------
# Planning: changed lines only, cap, line check
# ---------------------------------------------------------------------------

SRC = "import requests\n\nr = requests.get(url)\nq = requests.get(other)\nkeep = 1\n"


def _report(findings, mode="full"):
    return Report(system="t", repos=[RepoInfo(id="root")], findings=findings,
                  gate={"passed": True}, scan_scope={"mode": mode})


def _ws(tmp_path, text=SRC, name="app.py"):
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text, encoding="utf-8")
    return str(tmp_path)


LED = _ledger({TIMEOUT: _entry(340, 17, advisory=True), ADMITTED: _entry(500, 0)})


def test_only_changed_lines_are_planned(tmp_path):
    ws = _ws(tmp_path)
    findings = [_f(TIMEOUT, line=3), _f(TIMEOUT, line=4)]
    changed = {"app.py": {3: "r = requests.get(url)"}}
    plan = pr.plan_review(_report(findings), changed, LED, DEFAULTS, ws)
    assert [c.line for c in plan.post] == [3]
    assert plan.skipped == {"not on a changed line": 1}
    assert plan.post[0].suggestion.line == "r = requests.get(url, timeout=30)"


def test_a_line_that_differs_from_the_head_is_not_posted(tmp_path):
    ws = _ws(tmp_path)
    changed = {"app.py": {3: "r = requests.get(somewhere_else)"}}
    plan = pr.plan_review(_report([_f(TIMEOUT, line=3)]), changed, LED, DEFAULTS, ws)
    assert plan.post == [] and plan.skipped == {"line differs from the pull request's head": 1}


def test_a_scan_target_below_the_repository_root_maps_its_paths(tmp_path):
    ws = _ws(tmp_path)
    changed = {"svc/app.py": {3: "r = requests.get(url)"}}
    plan = pr.plan_review(_report([_f(TIMEOUT, line=3)]), changed, LED, DEFAULTS, ws, prefix="svc/")
    assert [c.path for c in plan.post] == ["svc/app.py"]


def test_the_cap_moves_the_rest_to_the_summary(tmp_path):
    lines = "".join(f"r{i} = requests.get(u{i})\n" for i in range(5))
    ws = _ws(tmp_path, lines)
    fs = [_f(TIMEOUT, line=i + 1) for i in range(5)]
    for i, f in enumerate(fs):
        f.evidence = f"e{i}"
        f.id = f.fingerprint()
    changed = {"app.py": {i + 1: f"r{i} = requests.get(u{i})" for i in range(5)}}
    cfg = {**DEFAULTS, "review": {**DEFAULTS["review"], "max_comments": 2}}
    plan = pr.plan_review(_report(fs), changed, LED, cfg, ws)
    assert len(plan.post) == 2 and len(plan.overflow) == 3
    summary = pr.render_summary(_report(fs), plan)
    assert summary.startswith(pr.SUMMARY_MARKER)
    assert "3 more findings in the summary" in summary


def test_inline_rendering(tmp_path):
    ws = _ws(tmp_path)
    plan = pr.plan_review(_report([_f(TIMEOUT, line=3)]), {"app.py": {3: "r = requests.get(url)"}},
                          LED, DEFAULTS, ws)
    body = pr.render_inline(plan.post[0])
    assert "```suggestion\nr = requests.get(url, timeout=30)\n```" in body
    assert "👍" in body and "👎" in body and "review-feedback collect" in body
    m = pr.FINDING_MARKER.search(body)
    assert m and m.group("rule") == TIMEOUT and m.group("id") == plan.post[0].finding.id


# ---------------------------------------------------------------------------
# A fake GitHub behind the real client: routing, pagination, 422s
# ---------------------------------------------------------------------------

class FakeGitHub(pr.GitHubClient):
    PAGE = 2   # small, so every list call has to follow the Link header

    def __init__(self, files=None, refuse_lines=(), fail_with=None):
        super().__init__("fake-token", api="https://api.example")
        self.files = files or []
        self.review_cs: list[dict] = []
        self.issue_cs: list[dict] = []
        self.reactions: dict[int, list[dict]] = {}
        self.calls: list[tuple[str, str]] = []
        self.refuse_lines = set(refuse_lines)
        self.fail_with = fail_with
        self._id = 100

    def _next(self):
        self._id += 1
        return self._id

    def _page(self, items, url):
        m = re.search(r"[?&]page=(\d+)", url)
        page = int(m.group(1)) if m else 1
        chunk = items[(page - 1) * self.PAGE: page * self.PAGE]
        headers = {}
        if page * self.PAGE < len(items):
            base = re.sub(r"[?&]page=\d+", "", url)
            headers["Link"] = f'<{base}&page={page + 1}>; rel="next"'
        return [dict(x) for x in chunk], headers

    def _call(self, method, url, body=None):
        path = url.replace(self.api, "")
        self.calls.append((method, path.split("?")[0]))
        if self.fail_with:
            raise self.fail_with
        if method == "GET":
            if re.search(r"/pulls/\d+/files", path):
                return self._page(self.files, url)
            if re.search(r"/pulls/\d+/comments", path):
                return self._page(self.review_cs, url)
            if re.search(r"/issues/\d+/comments", path):
                return self._page(self.issue_cs, url)
            m = re.search(r"/pulls/comments/(\d+)/reactions", path)
            if m:
                return self._page(self.reactions.get(int(m.group(1)), []), url)
        if method == "POST" and path.endswith("/reviews"):
            if any(c["line"] in self.refuse_lines for c in body["comments"]):
                raise pr.GitHubError(422, "line must be part of the diff")
            for c in body["comments"]:
                self._add_review_comment(c)
            return {"id": self._next()}, {}
        if method == "POST" and re.search(r"/pulls/\d+/comments$", path):
            if body["line"] in self.refuse_lines:
                raise pr.GitHubError(422, "line must be part of the diff")
            return self._add_review_comment(body), {}
        if method == "PATCH" and "/pulls/comments/" in path:
            cid = int(path.rsplit("/", 1)[1])
            for c in self.review_cs:
                if c["id"] == cid:
                    c["body"] = body["body"]
            return {}, {}
        if method == "POST" and re.search(r"/issues/\d+/comments$", path):
            c = {"id": self._next(), "body": body["body"], "user": {"login": "github-actions[bot]"}}
            self.issue_cs.append(c)
            return c, {}
        if method == "PATCH" and "/issues/comments/" in path:
            cid = int(path.rsplit("/", 1)[1])
            for c in self.issue_cs:
                if c["id"] == cid:
                    c["body"] = body["body"]
            return {}, {}
        raise AssertionError(f"unrouted {method} {path}")

    def _add_review_comment(self, c):
        rec = {"id": self._next(), "path": c["path"], "line": c["line"], "body": c["body"],
               "user": {"login": "github-actions[bot]", "type": "Bot"}}
        self.review_cs.append(rec)
        return rec


CTX = pr.PRContext(repo="o/r", pr=7, head_sha="abc1234def")


def _five(tmp_path):
    text = "".join(f"r{i} = requests.get(u{i})\n" for i in range(5))
    ws = _ws(tmp_path, text)
    fs = []
    for i in range(5):
        f = _f(TIMEOUT, line=i + 1)
        f.evidence = f"e{i}"
        f.id = f.fingerprint()
        fs.append(f)
    files = [{"filename": "app.py", "status": "modified",
              "patch": "@@ -0,0 +1,5 @@\n" + "".join(f"+r{i} = requests.get(u{i})\n" for i in range(5))}]
    return ws, fs, files


def test_second_run_edits_instead_of_duplicating(tmp_path):
    ws, fs, files = _five(tmp_path)
    gh = FakeGitHub(files)
    first = pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=CTX, client=gh,
                                  workspace=ws, ledger=LED, log=lambda s: None)
    assert first.mode == "posted" and first.created == 5
    assert len(gh.review_cs) == 5 and len(gh.issue_cs) == 1
    second = pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=CTX, client=gh,
                                   workspace=ws, ledger=LED, log=lambda s: None)
    assert (second.created, second.unchanged) == (0, 5)
    assert len(gh.review_cs) == 5 and len(gh.issue_cs) == 1
    # Fixed one finding: its comment says so and the others stay as they are.
    third = pr.post_review_safely(_report(fs[1:]), DEFAULTS, changed=None, ctx=CTX, client=gh,
                                  workspace=ws, ledger=LED, log=lambda s: None)
    assert (third.created, third.gone, third.unchanged) == (0, 1, 4)
    gone = [c for c in gh.review_cs if "state=gone" in c["body"]]
    assert len(gone) == 1 and "no longer reports" in gone[0]["body"]
    assert len(gh.issue_cs) == 1
    # A fourth run does not re-edit the gone comment.
    before = [c["body"] for c in gh.review_cs]
    pr.post_review_safely(_report(fs[1:]), DEFAULTS, changed=None, ctx=CTX, client=gh,
                          workspace=ws, ledger=LED, log=lambda s: None)
    assert [c["body"] for c in gh.review_cs] == before


def test_a_partial_scan_never_marks_findings_in_unscanned_files_gone(tmp_path):
    ws, fs, files = _five(tmp_path)
    gh = FakeGitHub(files)
    pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=CTX, client=gh,
                          workspace=ws, ledger=LED, log=lambda s: None)
    gh.files = [{"filename": "other.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}]
    out = pr.post_review_safely(_report([], mode="partial"), DEFAULTS, changed=None, ctx=CTX,
                                client=gh, workspace=ws, ledger=LED, log=lambda s: None)
    assert out.gone == 0


def test_a_422_falls_back_to_one_comment_at_a_time(tmp_path):
    ws, fs, files = _five(tmp_path)
    gh = FakeGitHub(files, refuse_lines={2})
    out = pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=CTX, client=gh,
                                workspace=ws, ledger=LED, log=lambda s: None)
    assert (out.created, out.dropped) == (4, 1)


@pytest.mark.parametrize("exc", [pr.GitHubError(500, "boom"), pr.GitHubError(429, "rate limited"),
                                 RuntimeError("anything"), OSError("network down")])
def test_api_errors_never_escape(tmp_path, exc):
    ws, fs, files = _five(tmp_path)
    logs: list[str] = []
    out = pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=CTX,
                                client=FakeGitHub(files, fail_with=exc), workspace=ws,
                                ledger=LED, log=logs.append)
    assert out.mode == "skipped" and "unaffected" in logs[-1]


def test_a_refused_write_goes_to_the_job_summary(tmp_path):
    ws, fs, files = _five(tmp_path)
    gh = FakeGitHub(files)
    summary = tmp_path / "summary.md"
    gh.create_review = lambda *a, **k: (_ for _ in ()).throw(pr.GitHubError(403, "forbidden"))
    out = pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=CTX, client=gh,
                                workspace=ws, ledger=LED, log=lambda s: None,
                                step_summary=str(summary))
    assert out.mode == "job-summary" and pr.SUMMARY_MARKER in summary.read_text(encoding="utf-8")


def test_a_fork_writes_the_job_summary_and_posts_nothing(tmp_path):
    ws, fs, files = _five(tmp_path)
    gh = FakeGitHub(files)
    summary = tmp_path / "summary.md"
    ctx = pr.PRContext(repo="o/r", pr=7, head_sha="abc", fork=True)
    out = pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=ctx, client=gh,
                                workspace=ws, ledger=LED, log=lambda s: None,
                                step_summary=str(summary))
    assert out.mode == "job-summary"
    assert not [c for c in gh.calls if c[0] in ("POST", "PATCH")]
    assert "### Arbiter review" in summary.read_text(encoding="utf-8")


def test_no_token_is_a_dry_run(tmp_path):
    ws, fs, _ = _five(tmp_path)
    logs: list[str] = []
    changed = {"app.py": {i + 1: f"r{i} = requests.get(u{i})" for i in range(5)}}
    out = pr.post_review_safely(_report(fs), DEFAULTS, changed=changed, ctx=pr.PRContext(),
                                client=None, workspace=ws, ledger=LED, log=logs.append)
    assert out.mode == "dry-run"
    assert "would post 5 inline comment(s)" in logs[-1] and "[suggestion]" in logs[-1]


def test_context_comes_from_the_event_payload(tmp_path):
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps({"pull_request": {
        "number": 12, "head": {"sha": "headsha", "repo": {"full_name": "fork/r"}},
        "base": {"ref": "main", "repo": {"full_name": "o/r"}}}}), encoding="utf-8")
    ctx = pr.context_from_env({"GITHUB_EVENT_PATH": str(ev), "GITHUB_REPOSITORY": "o/r",
                               "GITHUB_SHA": "mergesha"})
    assert (ctx.pr, ctx.head_sha, ctx.fork, ctx.base_ref) == (12, "headsha", True, "main")


# ---------------------------------------------------------------------------
# Reactions -> labels
# ---------------------------------------------------------------------------

def _reaction(login, content, kind="User"):
    return {"content": content, "user": {"login": login, "type": kind}}


def test_reactions_become_hashed_human_labels(tmp_path):
    ws, fs, files = _five(tmp_path)
    gh = FakeGitHub(files)
    pr.post_review_safely(_report(fs), DEFAULTS, changed=None, ctx=CTX, client=gh,
                          workspace=ws, ledger=LED, log=lambda s: None)
    a, b, c = gh.review_cs[:3]
    gh.reactions = {
        a["id"]: [_reaction("Alice", "+1"), _reaction("bob", "-1"), _reaction("dependabot[bot]", "+1", "Bot"),
                  _reaction("carol", "heart")],
        b["id"]: [_reaction("alice", "+1"), _reaction("alice", "-1")],      # undecided: skipped
        c["id"]: [_reaction("github-actions[bot]", "-1")],                 # the author itself
    }
    labels, stats = pr.collect_reactions(gh, "o/r", 7, today="2026-10-26")
    assert stats == {"comments": 5, "reactions": 4, "conflicting": 1, "ignored": 2}
    assert sorted(lab["label"] for lab in labels) == ["fp", "tp"]
    for lab in labels:
        assert lab["labeller"] == lab["provenance"] == "human:pr-reaction"
        assert lab["rule_id"] == TIMEOUT and lab["finding_id"].startswith("pr:o/r#7:f:")
        assert lab["reactor"].startswith("sha256:") and "alice" not in json.dumps(lab).lower()
    assert pr.hash_login("Alice") == pr.hash_login("alice")

    out = tmp_path / "labels" / "human-pr.jsonl"
    assert pr.merge_labels(out, labels) == (2, 0)
    assert pr.merge_labels(out, labels) == (0, 0)          # collecting twice adds nothing
    flipped = [{**labels[0], "label": "fp" if labels[0]["label"] == "tp" else "tp"}]
    assert pr.merge_labels(out, flipped) == (0, 1)
    assert len(out.read_text(encoding="utf-8").splitlines()) == 2


def _load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_reaction_labels_never_reach_admission(tmp_path, monkeypatch):
    PL = _load_tool("precision_ledger")
    monkeypatch.setattr(PL, "LEDGER", tmp_path / "none.json")
    base = [{"finding_id": f"b:f:{i:012x}", "rule_id": TIMEOUT, "label": "tp" if i % 10 else "fp",
             "labeller": "alice", "source": "gold", "held_out": True} for i in range(40)]
    human = [{"finding_id": f"pr:o/r#7:f:{i:012x}", "rule_id": TIMEOUT, "label": "tp",
              "labeller": "human:pr-reaction", "provenance": "human:pr-reaction",
              "reactor": f"sha256:{i:016x}", "source": "pr-reaction", "held_out": False}
             for i in range(200)]
    only = tmp_path / "only.jsonl"
    only.write_text("".join(json.dumps(r) + "\n" for r in base), encoding="utf-8")
    mixed = tmp_path / "human-pr.jsonl"
    mixed.write_text("".join(json.dumps(r) + "\n" for r in human), encoding="utf-8")
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert PL.main(["build", str(only), "--out", str(a), "--date", "2026-10-26"]) == 0
    assert PL.main(["build", str(only), str(mixed), "--out", str(b), "--date", "2026-10-26"]) == 0
    ra, rb = (json.loads(a.read_text(encoding="utf-8"))["rules"][TIMEOUT],
              json.loads(b.read_text(encoding="utf-8"))["rules"][TIMEOUT])
    assert (ra["tp"], ra["fp"], ra["admitted"]) == (rb["tp"], rb["fp"], rb["admitted"])


# ---------------------------------------------------------------------------
# Config and CLI
# ---------------------------------------------------------------------------

def test_review_config_is_validated(tmp_path):
    assert DEFAULTS["review"] == {"min_tier": "advisory", "max_comments": 20, "suggestions": True}
    for bad in ({"min_tier": "everything"}, {"max_comments": -1}, {"max_comments": True},
                {"suggestions": "yes"}):
        with pytest.raises(RuntimeError):
            check_review_config({"review": {**DEFAULTS["review"], **bad}})
    cfg = tmp_path / "arbiter.yaml"
    cfg.write_text("review:\n  min_tier: verified\n  max_comments: 5\n", encoding="utf-8")
    got = load_config(None, str(tmp_path))["review"]
    assert got == {"min_tier": "verified", "max_comments": 5, "suggestions": True}


@pytest.mark.parametrize("passed", [True, False])
def test_gate_post_review_never_changes_the_exit_code(tmp_path, monkeypatch, capsys, passed):
    from arbiter import cli
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "run_scan", lambda **k: Report(
        system="t", repos=[RepoInfo(id="root")], gate={"passed": passed}))
    monkeypatch.setattr(pr, "post_review_safely", lambda *a, **k:
                        (_ for _ in ()).throw(RuntimeError("boom")))
    base = ["gate", str(tmp_path), "--out", str(tmp_path / "out"), "--format", "json",
            "--no-history", "--no-github"]
    want = cli.EXIT_OK if passed else cli.EXIT_GATE_FAIL
    assert cli.main(base) == want
    assert cli.main(base + ["--post-review", "--review-base", "HEAD"]) == want
    assert "the gate result is unaffected" in capsys.readouterr().out


def test_review_feedback_collect_needs_a_token(capsys):
    from arbiter import cli
    assert cli.main(["review-feedback", "collect", "--repo", "o/r", "--pr", "1"]) == cli.EXIT_ERROR
    assert "GITHUB_TOKEN" in capsys.readouterr().err
