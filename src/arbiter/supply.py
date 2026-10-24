"""Supply-chain pinning: is what gets built what was reviewed?

Each check here answers one mechanical question about one file -- is this
reference to third-party code immutable? -- and is called from
`probes.probe_supply_chain`. Structured files are read with a parser, not a
regular expression: YAML through PyYAML's node API (which keeps line numbers),
JSON and TOML through the standard library, Maven POMs through expat, and
Terraform through graph.py's HCL subset reader. The one unpinned-action
defect that reached a verified rule (FAIL-100) was a regex reading YAML: a
quoted `uses: "actions/checkout@<sha>"` carried its closing quote into the
ref, so a pinned action was reported unpinned. A parser hands back the
scalar without its quotes.

Shell-shaped text (Dockerfile RUN lines, CI `run:` / `script:` bodies,
shell scripts) and the Ruby and Groovy DSLs have no parser here, so those
are read line by line with the commands split and tokenised.

What counts as pinned, per ecosystem:

  GitHub Actions     a full 40-hex commit SHA (a `# v4` comment is fine)
  container images   an `@sha256:<64 hex>` digest; a tag can be re-pushed
  pre-commit hooks   `rev:` a 40-hex SHA, mirroring Actions
  GitLab includes    `ref:` a 40-hex SHA (remote URLs only when they embed one)
  Python             `==` / `===` (not `==1.*`), or a VCS URL at a 40-hex commit;
                     any range is fine when a lockfile (poetry.lock, uv.lock,
                     Pipfile.lock, pdm.lock) sits beside it or above it
  npm                an exact version, or a git ref at a 40-hex commit; any
                     range is fine beside or under a lockfile
  Maven / Gradle     anything but LATEST / RELEASE / ranges / `+` / latest.*;
                     SNAPSHOT only in a SNAPSHOT build; Gradle locking credits
                     dynamic versions
  RubyGems           a bounded requirement, or any requirement under a
                     Gemfile.lock; git gems need `ref:`
  Terraform          modules at an exact version or `?ref=<sha or x.y.z>`;
                     providers declare a version (or a .terraform.lock.hcl)
  Go                 no rule: go.sum records a hash for every module, so a
                     Go build is verified against what was first resolved.
                     `go install ...@latest` in a build is covered by
                     supply.unpinned-install-in-build.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
import shlex
from typing import Any, Iterator

from .core import Finding, Location

SHA40 = re.compile(r"^[0-9a-f]{40}$")
URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

PROBE = "supply_chain"

# ---------------------------------------------------------------------------
# Repository context: lockfiles beside or above a manifest
# ---------------------------------------------------------------------------

PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock")
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
             "bun.lockb", "bun.lock")
RUBY_LOCKS = ("Gemfile.lock", "gems.locked")
TF_LOCKS = (".terraform.lock.hcl",)
GRADLE_LOCKS = ("gradle.lockfile", "buildscript-gradle.lockfile", "settings-gradle.lockfile")
_LOCK_NAMES = frozenset(PY_LOCKS + NPM_LOCKS + RUBY_LOCKS + TF_LOCKS + GRADLE_LOCKS)


def _is_lock_path(path: str) -> bool:
    return posixpath.basename(path) in _LOCK_NAMES or "/dependency-locks/" in f"/{path}"


def lock_paths(ctx) -> dict[str, set[str]]:
    """repo id -> every lockfile path in the repository.

    Read from the complete inventory, not the possibly narrowed one: whether
    a lockfile EXISTS is a fact about the repository, not about the subset a
    partial or cached scan is re-reading."""
    inv = ctx.inventory
    whole = getattr(inv, "whole", None) or inv
    out: dict[str, set[str]] = {}
    for f in whole.files:
        if _is_lock_path(f.path):
            out.setdefault(f.repo_id, set()).add(f.path)
    return out


def cache_context(ctx) -> str:
    """The cache digest for probe_supply_chain: which lockfiles exist.

    A manifest's findings depend on whether a lockfile sits beside it, so the
    set of lockfile paths is folded into the result-cache key. Only paths,
    never content: a lockfile's presence is what is read, and hashing a
    multi-megabyte package-lock.json on every scan would buy nothing."""
    h = hashlib.sha256()
    for repo, paths in sorted(lock_paths(ctx).items()):
        for p in sorted(paths):
            h.update(f"{repo}:{p}\n".encode("utf-8"))
    return h.hexdigest()


def _ancestors(path: str) -> Iterator[str]:
    d = posixpath.dirname(path)
    while True:
        yield d
        if not d:
            return
        d = posixpath.dirname(d)


def lock_near(locks: set[str], path: str, names: tuple[str, ...], climb: bool = True) -> str:
    """The lockfile covering `path`: beside it, or (with `climb`) in any
    directory above it -- a workspace root's lockfile pins its members, and
    that is how the labelled false positives of unpinned-npm-dep were all
    shaped (a root package-lock.json under a nested package.json)."""
    for d in _ancestors(path):
        for n in names:
            cand = f"{d}/{n}" if d else n
            if cand in locks:
                return cand
        if not climb:
            break
    return ""


# ---------------------------------------------------------------------------
# YAML through the node API: line numbers survive, quotes do not
# ---------------------------------------------------------------------------

def yaml_docs(text: str) -> list | None:
    """Composed YAML documents (nodes, with marks), or None when the text is
    not YAML. Nodes rather than Python values because the marks give each
    scalar's line, and a finding has to point at it."""
    import yaml
    loader = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader
    try:
        return [d for d in yaml.compose_all(text, Loader=loader) if d is not None]
    except (yaml.YAMLError, ValueError, RecursionError):
        return None


def _is_map(node) -> bool:
    import yaml
    return isinstance(node, yaml.MappingNode)


def _is_seq(node) -> bool:
    import yaml
    return isinstance(node, yaml.SequenceNode)


def _scalar(node) -> str | None:
    import yaml
    return node.value if isinstance(node, yaml.ScalarNode) else None


def _line(node) -> int:
    return node.start_mark.line + 1


def _pairs(node) -> list[tuple[str, Any, Any]]:
    """(key text, key node, value node) of a mapping; [] for anything else."""
    if not _is_map(node):
        return []
    out = []
    for k, v in node.value:
        key = _scalar(k)
        if key is not None:
            out.append((key, k, v))
    return out


def _get(node, key: str):
    for k, _, v in _pairs(node):
        if k == key:
            return v
    return None


def _items(node) -> list:
    return list(node.value) if _is_seq(node) else []


def walk_pairs(root) -> Iterator[tuple[str, Any, Any, tuple[str, ...]]]:
    """Every mapping entry under `root`: (key, key node, value node, path of
    keys above it). Iterative and alias-safe: an anchor reused twice is the
    same node object, visited once."""
    seen: set[int] = set()
    stack: list[tuple[Any, tuple[str, ...]]] = [(root, ())]
    while stack:
        node, path = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if _is_map(node):
            for key, knode, vnode in reversed(_pairs(node)):
                yield key, knode, vnode, path
                stack.append((vnode, path + (key,)))
        elif _is_seq(node):
            for item in reversed(node.value):
                stack.append((item, path))


def scalar_lines(node, lines: list[str]) -> list[tuple[int, str]]:
    """The source lines a scalar spans, as (1-based line, text).

    Read from the source, not the parsed value: a `|` block scalar's value
    has lost its indentation and a `>` one its line breaks, and a finding
    has to point at the line the command is on. The first line is cut at
    the scalar's own column so `run: curl ... | sh` scans `curl ... | sh`."""
    start, end = node.start_mark, node.end_mark
    out = []
    last = min(end.line, len(lines) - 1)
    for ln in range(start.line, last + 1):
        text = lines[ln]
        if ln == start.line:
            text = text[start.column:]
        if ln == end.line and end.line != start.line:
            text = text[:end.column]
        out.append((ln + 1, text))
    return out


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def finding(rule: str, title: str, f, line: int, *, severity: str, confidence: str,
             description: str, remediation: str, evidence: str, controls: list[str],
             tags: list[str], logical: str = "", dimension: str = "supply_chain") -> Finding:
    return Finding(
        rule_id=rule, title=title, dimension=dimension, severity=severity,
        confidence=confidence, repo_id=f.repo_id, probe=PROBE,
        location=Location(path=f.path, start_line=line, repo_id=f.repo_id, logical=logical),
        description=description, remediation=remediation, evidence=evidence[:200],
        controls=controls, tags=tags,
    )


# ---------------------------------------------------------------------------
# GitHub Actions (supply.unpinned-action) -- the verified rule
# ---------------------------------------------------------------------------

# Fallback for a CI file that is not YAML (a Jenkinsfile) or does not parse.
# `[ \t]`, not `\s`: with re.M, `^\s*` also matched from a blank line above
# and swallowed its newline, so the finding was reported on the blank line
# (round 4: all 3 `v3` FP labels of supply.unpinned-action). The optional
# quote is captured and required again at the end, and neither group may
# contain one (FAIL-100: `[^\s#]+` ran over a closing quote, so a quoted SHA
# pin read as `<sha>"` and was reported as unpinned).
_USES_LINE = re.compile(r"""^[ \t]*-?[ \t]*uses:[ \t]*(["']?)([^\s"'#]+)\1""", re.M)


def uses_refs(text: str, docs: list | None) -> list[tuple[int, str]]:
    """(line, value) of every `uses:` in a workflow or action file."""
    if docs is None:
        return [(text.count("\n", 0, m.start(2)) + 1, m.group(2)) for m in _USES_LINE.finditer(text)]
    out = []
    for doc in docs:
        for key, knode, vnode, _ in walk_pairs(doc):
            if key == "uses":
                v = _scalar(vnode)
                if v:
                    out.append((_line(knode), v.strip()))
    return sorted(out)


def check_actions(f, text: str, docs: list | None) -> list[Finding]:
    out = []
    for line, value in uses_refs(text, docs):
        if value.startswith("./") or value.startswith("docker://") or "@" not in value:
            # Local actions are part of the repository; `docker://` names a
            # container image, judged by supply.unpinned-container-image.
            continue
        action, ref = value.split("@", 1)
        if SHA40.match(ref):
            continue
        out.append(finding(
            "arbiter/supply.unpinned-action",
            f"Action `{action}` pinned to a mutable ref (`{ref}`)", f, line,
            # Stays at "low": unlike the package-manager rules, this one
            # discriminates -- 4.3x on Node, 219x on CloudFormation.
            severity="low", confidence="high",
            description="Tags and branches can be repointed, so the workflow can execute "
                        "different code tomorrow.",
            remediation="Pin the action to a full commit SHA.",
            evidence=f"{action}@{ref}",
            controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-7"],
            tags=["ci", "supply-chain"],
        ))
    return out


def is_composite_action(path: str, docs: list | None) -> bool:
    """An `action.yml` / `action.yaml` that is a GitHub action definition
    (it has a top-level `runs:`)."""
    if posixpath.basename(path) not in ("action.yml", "action.yaml") or not docs:
        return False
    return any(_get(d, "runs") is not None for d in docs)


# ---------------------------------------------------------------------------
# Container images (supply.unpinned-container-image)
# ---------------------------------------------------------------------------

def image_issue(ref: str) -> str:
    """'' when `ref` is digest-pinned or cannot be judged; else 'tag',
    'latest' or 'untagged'."""
    r = ref.strip().strip("\"'")
    if not r or "$" in r or "{{" in r or "${{" in r or r.lower() == "scratch":
        return ""
    if r.startswith("docker://"):
        r = r[len("docker://"):]
    name, _, digest = r.partition("@")
    if digest:
        return "" if _DIGEST.match(digest) else "tag"
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
        return "latest" if tag.lower() == "latest" else "tag"
    return "untagged"


def _image_finding(f, line: int, ref: str, issue: str, where: str) -> Finding:
    ref = ref.strip().strip("\"'")
    if issue == "tag":
        title = f"Container image `{ref}` pinned to a mutable tag"
        desc = ("A tag can be re-pushed, so the same reference can pull a different image "
                "tomorrow.")
    else:
        title = f"Container image `{ref}` has no version (`latest`)"
        desc = ("With no tag, or `latest`, the reference pulls whatever was pushed last, "
                "so every build or restart can run a different image.")
    sev, conf = IMAGE_SEVERITY[issue]
    return finding(
        "arbiter/supply.unpinned-container-image", title, f, line,
        severity=sev, confidence=conf, description=desc,
        remediation="Pin the image by digest (`image:tag@sha256:...`) and let a bot "
                    "propose digest updates.",
        evidence=f"{where}:{ref}",
        controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-2"],
        tags=["containers", "supply-chain"],
    )


DOCKERFILE_NAMES = re.compile(r"^(Dockerfile|Containerfile)(\..+)?$|.+\.(dockerfile|Dockerfile)$")


def is_dockerfile(path: str) -> bool:
    return bool(DOCKERFILE_NAMES.match(posixpath.basename(path)))


def logical_lines(text: str, escape: str = "\\") -> list[tuple[int, str]]:
    """Dockerfile / shell lines with backslash continuations joined:
    (first line number, joined text). Comment lines inside a continued
    Dockerfile instruction are dropped, as the builder drops them."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if buf and line.lstrip().startswith("#"):
            continue
        if not buf:
            start = i
        stripped = line.rstrip()
        if stripped.endswith(escape) and not stripped.endswith(escape * 2):
            buf.append(stripped[:-1])
            continue
        buf.append(line)
        out.append((start, " ".join(s.strip() for s in buf)))
        buf = []
    if buf:
        out.append((start, " ".join(s.strip() for s in buf)))
    return out


_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))")


def substitute(value: str, args: dict[str, str | None]) -> str | None:
    """Expand $VAR / ${VAR} / ${VAR:-default} / ${VAR:+alt} from ARG
    defaults. None when a variable has no default here: its value comes from
    `--build-arg` at build time and cannot be judged from the file."""
    failed = False

    def rep(m: re.Match) -> str:
        nonlocal failed
        name = m.group(1) or m.group(4)
        op, word = m.group(2), m.group(3)
        val = args.get(name)
        if op in (":-", "-"):
            return val if val else (word or "")
        if op in (":+", "+"):
            return (word or "") if val else ""
        if val is None:
            failed = True
            return ""
        return val

    out = _VAR.sub(rep, value)
    return None if failed or "$" in out else out


def _dockerfile_escape(text: str) -> str:
    for line in text.split("\n")[:10]:
        m = re.match(r"^\s*#\s*escape\s*=\s*(\S)\s*$", line, re.I)
        if m:
            return m.group(1)
        if line.strip() and not line.lstrip().startswith("#"):
            break
    return "\\"


def _arg_defaults(rest: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    try:
        toks = shlex.split(rest, comments=True)
    except ValueError:
        toks = rest.split()
    for t in toks:
        if "=" in t:
            k, v = t.split("=", 1)
            out[k] = v
        else:
            out[t] = None
    return out


def dockerfile_images(text: str) -> list[tuple[int, str, str]]:
    """(line, image as written, instruction) for every image a Dockerfile
    pulls: FROM, and COPY/ADD `--from=` naming an image rather than a stage.
    Build stages, `scratch`, and references whose ARG has no default here
    are left out: none of them is a pull this file decides."""
    esc = _dockerfile_escape(text)
    global_args: dict[str, str | None] = {}
    stages: set[str] = set()
    seen_from = False
    out = []
    for line, logical in logical_lines(text, esc):
        s = logical.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        instr = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        if instr == "ARG" and not seen_from:
            global_args.update(_arg_defaults(rest))
            continue
        if instr == "FROM":
            seen_from = True
            toks = [t for t in rest.split() if not t.startswith("--")]
            # A trailing `# ...` on an instruction is not a Dockerfile
            # comment, but nothing after it can be part of the image.
            toks = toks[:next((i for i, t in enumerate(toks) if t.startswith("#")), len(toks))]
            if not toks:
                continue
            raw = toks[0]
            resolved = substitute(raw, global_args)
            earlier_stage = resolved is not None and resolved.lower() in stages
            if len(toks) >= 3 and toks[1].lower() == "as":
                stages.add(toks[2].lower())
            if resolved is None or earlier_stage:
                continue
            out.append((line, resolved, "FROM"))
        elif instr in ("COPY", "ADD"):
            m = re.search(r"--from=(\S+)", rest)
            if not m:
                continue
            ref = m.group(1).strip("\"'")
            if ref.isdigit() or ref.lower() in stages:
                continue
            resolved = substitute(ref, global_args)
            # A bare word is a stage name defined later or in another file;
            # an image reference names a registry path or a tag.
            if resolved is None or not re.search(r"[/:@]", resolved):
                continue
            out.append((line, resolved, f"{instr} --from"))
    return out


COMPOSE_NAMES = re.compile(r"^(docker-)?compose(\.[\w.-]+)?\.ya?ml$")


def compose_images(docs: list) -> list[tuple[int, str]]:
    out = []
    for doc in docs:
        services = _get(doc, "services")
        if services is None:
            # Compose file format v1: services at the top level.
            services = doc
        built: set[str] = set()
        refs = []
        for _, _, svc in _pairs(services):
            img = _get(svc, "image")
            v = _scalar(img) if img is not None else None
            if not v:
                continue
            if _get(svc, "build") is not None:
                # With `build:`, `image:` names the tag the build produces,
                # not an image pulled from a registry -- and so does every
                # other service here that runs that same tag (netty's
                # compose files build one image and run it as six services).
                built.add(v.strip())
                continue
            refs.append((_line(img), v))
        out += [(ln, v) for ln, v in refs if v.strip() not in built]
    return out


_K8S_CONTAINERS = ("containers", "initContainers", "ephemeralContainers")


def k8s_images(docs: list) -> list[tuple[int, str]]:
    """`image:` of every container in Kubernetes manifests (documents with
    apiVersion and kind). Helm templates do not parse as YAML until they
    are rendered, so they never reach here: their values are not knowable
    from the file."""
    out = []
    for doc in docs:
        if _get(doc, "apiVersion") is None or _get(doc, "kind") is None:
            continue
        for key, _, vnode, path in walk_pairs(doc):
            if key == "image" and any(p in _K8S_CONTAINERS for p in path):
                v = _scalar(vnode)
                if v:
                    out.append((_line(vnode), v))
    return out


def _image_value(node) -> tuple[int, str] | None:
    """A CI `image:` / service entry: a string, or a mapping with `name:`
    (GitLab) or `image:` (GitHub services)."""
    v = _scalar(node)
    if v:
        return _line(node), v
    for key in ("name", "image"):
        sub = _get(node, key)
        if sub is not None and _scalar(sub):
            return _line(sub), _scalar(sub)
    return None


def gitlab_images(docs: list) -> list[tuple[int, str]]:
    out = []
    for doc in docs:
        scopes = [doc] + [v for _, _, v in _pairs(doc) if _is_map(v)]
        for scope in scopes:
            img = _get(scope, "image")
            if img is not None:
                got = _image_value(img)
                if got:
                    out.append(got)
            for item in _items(_get(scope, "services")):
                got = _image_value(item)
                if got:
                    out.append(got)
    return sorted(set(out))


def workflow_images(docs: list) -> list[tuple[int, str]]:
    """GitHub workflow `jobs.<id>.container` and `jobs.<id>.services.<id>`."""
    out = []
    for doc in docs:
        for _, _, job in _pairs(_get(doc, "jobs")):
            cont = _get(job, "container")
            if cont is not None:
                got = _image_value(cont)
                if got:
                    out.append(got)
            for _, _, svc in _pairs(_get(job, "services")):
                got = _image_value(svc)
                if got:
                    out.append(got)
    return out


def docker_uses(text: str, docs: list | None) -> list[tuple[int, str]]:
    out = [(ln, v) for ln, v in uses_refs(text, docs) if v.startswith("docker://")]
    for doc in docs or []:
        runs = _get(doc, "runs")
        img = _get(runs, "image") if runs is not None else None
        v = _scalar(img) if img is not None else None
        if v and v.startswith("docker://"):
            out.append((_line(img), v))
    return out


def check_images(f, refs: list[tuple[int, str]], where: str) -> list[Finding]:
    out = []
    for line, ref in refs:
        issue = image_issue(ref)
        if issue:
            out.append(_image_finding(f, line, ref, issue, where))
    return out


# ---------------------------------------------------------------------------
# pre-commit (supply.unpinned-precommit)
# ---------------------------------------------------------------------------

def check_precommit(f, docs: list) -> list[Finding]:
    out = []
    for doc in docs:
        for repo in _items(_get(doc, "repos")):
            url = _scalar(_get(repo, "repo")) or ""
            if url in ("local", "meta") or not url:
                continue
            rev_node = _get(repo, "rev")
            rev = (_scalar(rev_node) or "").strip() if rev_node is not None else ""
            if SHA40.match(rev):
                continue
            line = _line(rev_node) if rev_node is not None else _line(_get(repo, "repo"))
            out.append(finding(
                "arbiter/supply.unpinned-precommit",
                f"pre-commit hook `{url.rstrip('/').rsplit('/', 1)[-1]}` pinned to a mutable "
                f"ref (`{rev or 'none'}`)", f, line,
                severity=PRECOMMIT_SEVERITY[0], confidence=PRECOMMIT_SEVERITY[1],
                description="A tag can be repointed, so the hook code every contributor runs "
                            "can change without a change to this file.",
                remediation="Pin `rev:` to a full commit SHA (`pre-commit autoupdate "
                            "--freeze` writes one, with the tag as a comment).",
                evidence=f"{url}@{rev}",
                controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-7"],
                tags=["ci", "supply-chain"],
            ))
    return out


# ---------------------------------------------------------------------------
# GitLab CI include (supply.unpinned-ci-include)
# ---------------------------------------------------------------------------

def check_gitlab_include(f, docs: list) -> list[Finding]:
    out = []

    def flag(line: int, what: str, ref: str, evidence: str) -> None:
        out.append(finding(
            "arbiter/supply.unpinned-ci-include",
            f"CI include `{what}` pinned to a mutable ref (`{ref or 'none'}`)", f, line,
            severity=INCLUDE_SEVERITY[0], confidence=INCLUDE_SEVERITY[1],
            description="The included pipeline runs with this project's CI variables and "
                        "secrets; a branch, tag or URL can serve different jobs tomorrow.",
            remediation="Include a project at `ref: <commit SHA>`; vendor remote files or "
                        "pin components to a SHA.",
            evidence=evidence,
            controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-7"],
            tags=["ci", "supply-chain"],
        ))

    for doc in docs:
        inc = _get(doc, "include")
        if inc is None:
            continue
        entries = _items(inc) if _is_seq(inc) else [inc]
        for e in entries:
            s = _scalar(e)
            if s is not None:
                if URL.match(s) and not re.search(r"(^|/)[0-9a-f]{40}(/|$)", s):
                    flag(_line(e), s, "", f"remote:{s}")
                continue
            remote = _scalar(_get(e, "remote"))
            if remote:
                if not re.search(r"(^|/)[0-9a-f]{40}(/|$)", remote):
                    flag(_line(_get(e, "remote")), remote, "", f"remote:{remote}")
                continue
            project = _scalar(_get(e, "project"))
            if project:
                ref = (_scalar(_get(e, "ref")) or "").strip()
                if not SHA40.match(ref) and "$" not in ref:
                    flag(_line(_get(e, "project")), project, ref, f"project:{project}@{ref}")
                continue
            comp = _scalar(_get(e, "component"))
            if comp and "@" in comp:
                ref = comp.rsplit("@", 1)[1]
                if not SHA40.match(ref) and "$" not in ref:
                    flag(_line(_get(e, "component")), comp.rsplit("@", 1)[0], ref,
                         f"component:{comp}")
    return out


# ---------------------------------------------------------------------------
# Shell text: Dockerfile RUN lines, CI step bodies, shell scripts
# ---------------------------------------------------------------------------

_CI_SHELL_KEYS = {"run", "script", "before_script", "after_script", "bash", "pwsh",
                  "powershell", "inlineScript", "sh"}


def ci_shell_lines(docs: list, lines: list[str]) -> list[tuple[int, str]]:
    """(line, text) of every line of every CI step body: GitHub `run:`,
    GitLab `script:` / `before_script:` / `after_script:`, Azure `script:` /
    `bash:` / `pwsh:`. Each is a scalar or a list of scalars."""
    out: list[tuple[int, str]] = []
    for doc in docs:
        for key, _, vnode, _ in walk_pairs(doc):
            if key not in _CI_SHELL_KEYS:
                continue
            nodes = [vnode] if _scalar(vnode) is not None else _items(vnode)
            for n in nodes:
                if _scalar(n) is not None:
                    out.extend(join_continuations(scalar_lines(n, lines)))
    return sorted(set(out))


def join_continuations(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Shell lines ending in a backslash joined to the next, on the first
    line's number: `pip install \\` / `  requests` is one command."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for ln, text in lines:
        if not buf:
            start = ln
        t = text.rstrip()
        if t.endswith("\\"):
            buf.append(t[:-1].strip())
            continue
        buf.append(t.strip())
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def dockerfile_run_lines(text: str) -> list[tuple[int, str]]:
    out = []
    for line, logical in logical_lines(text, _dockerfile_escape(text)):
        s = logical.strip()
        if s[:4].upper() == "RUN " or s.upper() == "RUN":
            body = s[4:]
            body = re.sub(r"^(--\S+\s+)+", "", body)   # --mount=..., --network=...
            out.append((line, body))
    return out


def shell_script_lines(text: str) -> list[tuple[int, str]]:
    return [(ln, s) for ln, s in logical_lines(text) if not s.lstrip().startswith("#")]


_FETCH = r"\b(?:curl|wget)\b"
_INTERP = r"(?:sh|bash|zsh|dash|ksh|python[0-9.]*|perl|ruby|node)\b"
_PIPED = re.compile(
    _FETCH + r"(?:(?!&&|\|\||;)[^|\n])*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?"
    + _INTERP)
_SUBSTITUTED = re.compile(
    r"\b(?:sh|bash|zsh)\b(?:\s+-\S+)*\s+(?:-c\s+)?[\"']?(?:\$\(|<\()\s*" + _FETCH)
_PS_IEX = re.compile(
    r"(?i)\b(?:iex|invoke-expression)\b[\s(]*(?:\(\s*)?(?:iwr|irm|invoke-webrequest|"
    r"invoke-restmethod|new-object\s+(?:system\.)?net\.webclient)\b"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b[^|\n]*\|\s*"
    r"(?:iex|invoke-expression)\b")


def piped_script(text: str) -> str:
    """The matched download-and-execute, or ''."""
    for pat in (_PIPED, _SUBSTITUTED, _PS_IEX):
        m = pat.search(text)
        if m:
            return m.group(0)
    return ""


def check_piped(f, snippets: list[tuple[int, str]], where: str) -> list[Finding]:
    out = []
    for line, text in snippets:
        hit = piped_script(text)
        if not hit:
            continue
        out.append(finding(
            "arbiter/supply.remote-script-piped",
            "Remote script piped straight into an interpreter", f, line,
            dimension="security",
            severity=PIPED_SEVERITY[0], confidence=PIPED_SEVERITY[1],
            description="The script is executed as it is downloaded, with nothing checking "
                        "what arrived: whoever controls that URL (or the network path to "
                        "it) runs code here.",
            remediation="Download to a file, verify a pinned checksum or signature, then run "
                        "it; or install a pinned package instead.",
            evidence=f"{where}:{hit.strip()[:160]}",
            controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-7"],
            tags=["supply-chain", "ci" if where == "ci" else "build"],
        ))
    return out


# --- unpinned installs in a build ------------------------------------------

_SPLIT_CMDS = re.compile(r"&&|\|\||;|\||\n")
_PIP_VALUE_OPTS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t",
                   "--target", "--prefix", "--root", "--src", "--python", "--platform",
                   "--python-version", "--implementation", "--abi", "--progress-bar",
                   "--trusted-host", "--cache-dir", "--log", "--timeout", "--retries",
                   "--report", "-C", "--config-settings", "--global-option",
                   "--no-binary", "--only-binary", "--upgrade-strategy",
                   "--root-user-action", "--proxy", "--cert", "--client-cert",
                   "--exists-action", "--keyring-provider", "--extra-index"}
_PIP_SKIP = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
             "--require-hashes", "--no-deps"}
# The installer's own toolchain (`pip install --upgrade pip wheel`), not
# anything the project imports or ships.
_PIP_BOOTSTRAP = {"pip", "setuptools", "wheel"}
_NPM_VALUE_OPTS = {"--registry", "--prefix", "--cache", "--tag", "--loglevel", "--userconfig"}


# A GitHub/GitLab/Azure expression is one opaque value, and it can hold
# spaces: `npm@${{ env.NPM_VERSION }}` must stay one token, and a token
# holding `$` is not judged.
_CI_EXPR = re.compile(r"\$\{\{.*?\}\}|\$\(\(.*?\)\)|\$\[\[.*?\]\]")


def _tokens(cmd: str) -> list[str]:
    cmd = _CI_EXPR.sub("$EXPR", cmd)
    try:
        toks = shlex.split(cmd, comments=True)
    except ValueError:
        toks = cmd.split()
    while toks and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0])
                    or toks[0] in ("sudo", "exec", "time", "command")):
        toks = toks[1:]
    if "--" in toks:
        # Everything after `--` belongs to a build step (`gem install x --
        # --with-openssl-dir=...`), not to the installer.
        toks = toks[:toks.index("--")]
    return toks


def _positional(args: list[str], value_opts: set[str]) -> list[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in value_opts:
                skip = True
            continue
        out.append(a)
    return out


def _pip_args(toks: list[str]) -> list[str] | None:
    """The arguments after `install` when `toks` is a pip install."""
    if not toks:
        return None
    head = posixpath.basename(toks[0])
    i = None
    if re.fullmatch(r"pip[0-9.]*", head):
        i = 1
    elif re.fullmatch(r"python[0-9.]*|py", head) and toks[1:3] == ["-m", "pip"]:
        i = 3
    elif head == "uv" and toks[1:2] == ["pip"]:
        i = 2
    if i is None or toks[i:i + 1] != ["install"]:
        return None
    return toks[i + 1:]


def install_issues(cmd: str) -> list[tuple[str, str]]:
    """(manager, package) for every package `cmd` installs without a version."""
    toks = _tokens(cmd)
    if not toks:
        return []
    args = _pip_args(toks)
    if args is not None:
        if any(a in _PIP_SKIP or a.split("=", 1)[0] in _PIP_SKIP for a in args):
            return []
        if "--no-index" in args:
            return []   # installs only from a local --find-links directory
        out = []
        for p in _positional(args, _PIP_VALUE_OPTS):
            if p.split("[", 1)[0].lower() in _PIP_BOOTSTRAP:
                continue
            if "$" in p or p.startswith((".", "/", "~")) or "/" in p or "://" in p \
                    or p.endswith((".whl", ".tar.gz", ".zip")):
                continue
            spec = re.sub(r"\[[^\]]*\]", "", p.split(";", 1)[0])
            if re.search(r"===?[^,*]+$", spec) and not re.search(r"[<>~!]|==.*\*", spec):
                continue
            out.append(("pip", p))
        return out
    head = posixpath.basename(toks[0])
    if head in ("npm", "pnpm") and len(toks) > 1 and toks[1] in ("install", "i", "add") and \
            any(a in ("-g", "--global", "--location=global") for a in toks[2:]):
        return [("npm", p) for p in _positional(toks[2:], _NPM_VALUE_OPTS)
                if "$" not in p and _npm_install_unpinned(p)]
    if head == "yarn" and toks[1:3] == ["global", "add"]:
        return [("npm", p) for p in _positional(toks[3:], _NPM_VALUE_OPTS)
                if "$" not in p and _npm_install_unpinned(p)]
    if head == "gem" and toks[1:2] == ["install"]:
        rest = toks[2:]
        if any(a in ("-v", "--version") or a.startswith("--version=") for a in rest) or \
                any(a in ("-g", "--file") for a in rest):
            return []
        return [("gem", p) for p in _positional(rest, {"-i", "--install-dir", "-n",
                                                       "--bindir", "--source", "-s",
                                                       "--platform"})
                if "$" not in p and not re.search(r":\d", p) and not p.endswith(".gem")]
    if head == "go" and toks[1:2] == ["install"]:
        out = []
        for p in _positional(toks[2:], {"-ldflags", "-tags", "-gcflags", "-o"}):
            if "@" in p and p.rsplit("@", 1)[1] in ("latest", "master", "main", "HEAD"):
                out.append(("go", p))
        return out
    return []


def _npm_install_unpinned(p: str) -> bool:
    if p.startswith((".", "/", "file:")) or "://" in p:
        return False
    at = p.rfind("@")
    if at <= 0:            # no version (or a bare `@scope/name`)
        return True
    from .supply_deps import npm_spec_issue
    return bool(npm_spec_issue(p[at + 1:]))


def check_installs(f, snippets: list[tuple[int, str]], where: str) -> list[Finding]:
    out = []
    for line, text in snippets:
        bad: list[tuple[str, str]] = []
        for cmd in _SPLIT_CMDS.split(text):
            bad += install_issues(cmd)
        if not bad:
            continue
        pkgs = ", ".join(p for _, p in bad)
        mgrs = "/".join(sorted({m for m, _ in bad}))
        out.append(finding(
            "arbiter/supply.unpinned-install-in-build",
            f"Build installs `{pkgs[:80]}` ({mgrs}) without a version", f, line,
            severity=INSTALL_SEVERITY[0], confidence=INSTALL_SEVERITY[1],
            description="The build installs whatever release is current when it runs, so the "
                        "same commit can produce a different image or test environment.",
            remediation="Pin the version (`pkg==1.2.3`, `pkg@1.2.3`, `gem install pkg -v "
                        "1.2.3`, `go install mod@v1.2.3`), or install from a lockfile "
                        "(`pip install -r`, `npm ci`).",
            evidence=f"{where}:{text.strip()[:160]}",
            controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-2"],
            tags=["dependencies", "ci" if where == "ci" else "build"],
        ))
    return out


# ---------------------------------------------------------------------------
# Severities, set from measured fire rates (ARB-130; docs/supply-chain.md)
#
# Measured 2026-10-24 over the development tuning corpora only (held-out
# gold repositories, corpus-r5 and the ground-truth sets never scanned):
# 11,283 KLOC of well-maintained code (49 repositories) against 443 KLOC
# deliberately vulnerable (govwa, go-test-bench, WebGoat, railsgoat,
# juice-shop, nodegoat, nodejs-goof). Same bar as the rules before them:
# vulnerable/maintained above 3x carries a severity, below it is "info"
# (reported, scores zero). Rates per KLOC of the whole repository, then
# per KLOC of the languages the rule can fire on:
#
#   unpinned-container-image  142 vs 22  0.013 vs 0.050  (3.95x); 0.60 vs 2.42 (4.07x) -> low
#   unpinned-install-in-build  62 vs 6   0.005 vs 0.014  (2.47x); 0.26 vs 0.66 (2.54x) -> info
#   unpinned-precommit         36 vs 3   0.003 vs 0.007  (2.12x); 0.15 vs 0.34 (2.23x) -> info
#   remote-script-piped        21 vs 1   0.002 vs 0.002  (1.21x); 0.08 vs 0.11 (1.27x) -> info
#   unpinned-ruby-dep          14 vs 0   fires only on maintained code             -> info
#   unpinned-java-dep           0 vs 0   no evidence either way                     -> info
#   unpinned-terraform          0 vs 0   no Terraform in the development corpora    -> info
#   unpinned-ci-include         0 vs 0   no GitLab CI in the development corpora    -> info
#
# Every one is advisory (rule metadata tier): none is gate-eligible until
# the precision ledger admits it on labels.
# ---------------------------------------------------------------------------

IMAGE_SEVERITY = {"tag": ("low", "high"), "latest": ("low", "high"), "untagged": ("low", "high")}
PRECOMMIT_SEVERITY = ("info", "high")
INCLUDE_SEVERITY = ("info", "high")
PIPED_SEVERITY = ("info", "high")
# "medium" confidence: the command line is tokenised, not executed, so a
# wrapper script or a variable holding the version can hide a pin.
INSTALL_SEVERITY = ("info", "medium")


# ---------------------------------------------------------------------------
# Dispatch: one file in, its findings out
# ---------------------------------------------------------------------------

def is_shell_script(f) -> bool:
    return f.language == "shell" or f.path.endswith((".sh", ".bash"))


def check_file(f, text: str, locks: set[str]) -> list[Finding]:
    """Every pinning finding for one file (pull_request_target excepted,
    which probes.py keeps beside the probe it was written for)."""
    path = f.path
    base = posixpath.basename(path)
    lower = base.lower()
    out: list[Finding] = []
    is_yaml = lower.endswith((".yml", ".yaml"))
    docs = None
    if is_yaml and (f.role == "ci" or lower in ("action.yml", "action.yaml",
                                                 ".pre-commit-config.yaml",
                                                 ".pre-commit-config.yml")
                    or COMPOSE_NAMES.match(lower)
                    or (re.search(r"^\s*-?\s*image:", text, re.M)
                        and re.search(r"^kind:", text, re.M))):
        docs = yaml_docs(text)

    if f.role == "ci":
        out += check_actions(f, text, docs if is_yaml else None)
        if docs:
            lines = text.split("\n")
            out += check_images(f, docker_uses(text, docs), "uses")
            if base.startswith(".gitlab-ci"):
                out += check_images(f, gitlab_images(docs), "gitlab-ci")
                out += check_gitlab_include(f, docs)
            else:
                out += check_images(f, workflow_images(docs), "workflow")
            shell = ci_shell_lines(docs, lines)
            out += check_piped(f, shell, "ci")
            out += check_installs(f, shell, "ci")
        elif not is_yaml:
            shell = shell_script_lines(text)
            out += check_piped(f, shell, "ci")
            out += check_installs(f, shell, "ci")
        return out

    if is_composite_action(path, docs):
        out += check_actions(f, text, docs)
        out += check_images(f, docker_uses(text, docs), "uses")
        shell = ci_shell_lines(docs, text.split("\n"))
        out += check_piped(f, shell, "ci")
        out += check_installs(f, shell, "ci")
        return out

    if is_dockerfile(path):
        out += check_images(f, [(ln, ref) for ln, ref, _ in dockerfile_images(text)],
                            "dockerfile")
        runs = dockerfile_run_lines(text)
        out += check_piped(f, runs, "dockerfile")
        out += check_installs(f, runs, "dockerfile")
        return out

    if lower in (".pre-commit-config.yaml", ".pre-commit-config.yml"):
        return check_precommit(f, docs or [])
    if is_yaml and COMPOSE_NAMES.match(lower):
        return check_images(f, compose_images(docs or []), "compose")
    if is_yaml and docs:
        # An explicit `:latest` in a Kubernetes manifest is already reported
        # by resource.k8s-mutable-image-tag; this rule adds the rest (other
        # tags, and images with no tag at all) without reporting it twice.
        return [x for x in check_images(f, k8s_images(docs), "k8s")
                if not x.evidence.lower().endswith(":latest")]

    from . import supply_deps as deps
    if deps.is_python_requirements(path):
        return deps.check_python_requirements(f, text, locks)
    if base == "package.json":
        return deps.check_package_json(f, text, locks)
    if base == "pom.xml":
        return deps.check_pom(f, text)
    if deps.is_gradle(path):
        return deps.check_gradle(f, text, locks)
    if lower.endswith(".versions.toml"):
        return deps.check_version_catalog(f, text, locks)
    if base in ("Gemfile", "gems.rb"):
        return deps.check_gemfile(f, text, locks)
    if lower.endswith(".tf"):
        return deps.check_terraform(f, text, locks)
    if is_shell_script(f) or lower.endswith(".ps1"):
        return check_piped(f, shell_script_lines(text), "script")
    return out

