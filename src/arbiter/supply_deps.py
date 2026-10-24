"""Package-manifest pinning: Python, npm, Maven/Gradle, RubyGems, Terraform.

The ecosystem half of src/arbiter/supply.py (which holds the shared helpers,
the CI and container checks, and the dispatch). What counts as pinned in
each ecosystem is listed in that module's docstring. Every structured file
is read with a parser: json for package.json, expat for a POM, tomllib for a
version catalog, graph.py's HCL subset reader for Terraform. A requirements
file, a Gemfile and a Gradle build script have no parser here (pip's format
is line-based; Ruby and Groovy/Kotlin are programs), so those are read line
by line.
"""
from __future__ import annotations

import json
import posixpath
import re
from typing import Any, Iterator

from .core import Finding
from .supply import (
    GRADLE_LOCKS,
    NPM_LOCKS,
    PY_LOCKS,
    RUBY_LOCKS,
    SHA40,
    TF_LOCKS,
    URL,
    finding,
    lock_near,
    logical_lines,
)

_VCS = re.compile(r"^(git|hg|svn|bzr)\+", re.I)


# ---------------------------------------------------------------------------
# Python (supply.unpinned-python-dep)
# ---------------------------------------------------------------------------

_PY_REQ_NAME = re.compile(r"^(requirements|constraints)([-_.][\w.-]*)?\.txt$", re.I)


def is_python_requirements(path: str) -> bool:
    base = posixpath.basename(path)
    if _PY_REQ_NAME.match(base):
        return True
    parent = posixpath.basename(posixpath.dirname(path)).lower()
    return parent == "requirements" and base.lower().endswith(".txt")


_PIP_OPTION_LINE = re.compile(
    r"^(-r|--requirement|-c|--constraint|-i|--index-url|--extra-index-url|-f|--find-links|"
    r"--trusted-host|--no-binary|--only-binary|--pre|--prefer-binary|--require-hashes|"
    r"--use-feature|--no-index|--hash|-Z|--always-unzip)\b")


def _requirement_lines(text: str) -> list[tuple[int, str]]:
    out = []
    for line, logical in logical_lines(text):
        s = re.sub(r"(^|\s)#.*$", "", logical).strip()
        if s:
            out.append((line, s))
    return out


def _vcs_issue(url: str) -> str:
    """'' when a VCS URL names a 40-hex commit, else why it does not."""
    body = url.split("#", 1)[0]
    tail = body.rsplit("/", 1)[-1]
    if "@" not in tail:
        return "a VCS reference with no commit"
    ref = tail.rsplit("@", 1)[1]
    return "" if SHA40.match(ref) else f"a VCS reference at `{ref}`, not a commit SHA"


def python_requirement_issue(s: str) -> tuple[str, str] | None:
    """(package, why) when a requirements line does not pin, else None."""
    if _PIP_OPTION_LINE.match(s):
        return None
    if "--hash" in s:
        # Hash-checking mode: pip installs exactly the artifact hashed here.
        return None
    m = re.match(r"^(-e|--editable)(=|\s+)(.+)$", s)
    if m:
        target = m.group(3).strip()
        if _VCS.match(target):
            why = _vcs_issue(target)
            egg = re.search(r"#egg=([\w.-]+)", target)
            return ((egg.group(1) if egg else target[:60]), why) if why else None
        return None   # a local path: the repository's own code
    if s.startswith("-"):
        return None
    req = s.split(" --", 1)[0].strip()          # per-requirement options
    if _VCS.match(req):
        why = _vcs_issue(req)
        egg = re.search(r"#egg=([\w.-]+)", req)
        return ((egg.group(1) if egg else req[:60]), why) if why else None
    if URL.match(req) or req.startswith((".", "/", "~", "file:")):
        return None   # an archive URL or a local path: a fixed artifact
    req = req.split(";", 1)[0].strip()          # environment marker
    if " @ " in req or re.match(r"^[\w.\-\[\], ]+@\s*\S", req):
        name, _, url = req.partition("@")
        url = url.strip()
        if _VCS.match(url):
            why = _vcs_issue(url)
            return (name.strip(), why) if why else None
        return None   # a direct archive reference
    pkg = re.split(r"[<>=!~\[ (]", req, maxsplit=1)[0].strip()
    if not pkg:
        return None
    spec = req[len(pkg):]
    spec = re.sub(r"^\s*\[[^\]]*\]", "", spec).strip().strip("()")
    exact = re.fullmatch(r"\s*===?\s*([^,*\s]+)\s*", spec)
    if exact:
        return None
    if not spec:
        return pkg, "no version"
    return pkg, f"the range `{spec}`"


_REQ_SHAPE = re.compile(
    r"^(-{1,2}[a-z][\w-]*([ =]\S.*)?"                  # an option line
    r"|[a-z][a-z]*\+?[a-z]*://\S+.*|(git|hg|svn|bzr)\+\S+.*"   # a URL / VCS reference
    r"|[.~/]\S*.*"                                      # a local path
    r"|[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*"      # a name, extras,
    r"((===?|~=|!=|<=|>=|<|>)\s*[\w.*+!-]+\s*(,\s*(===?|~=|!=|<=|>=|<|>)\s*[\w.*+!-]+\s*)*)?"
    r"(@\s*\S+)?\s*(;.*)?(\s+--hash[= ]\S+)*)$", re.I)  # specifiers, URL, marker, hashes


def looks_like_requirements(lines: list[tuple[int, str]]) -> bool:
    """Whether a file named like a requirements file holds requirements.

    The name alone is not enough: Django's documentation keeps prose in
    `docs/ref/models/constraints.txt`, and reading that as pip input
    reported 296 "unpinned dependencies" that were English sentences."""
    if not lines:
        return False
    ok = sum(1 for _, s in lines if _REQ_SHAPE.match(s))
    return ok >= 0.9 * len(lines)


def check_python_requirements(f, text: str, locks: set[str]) -> list[Finding]:
    # Beside it only: a poetry.lock or uv.lock pins its own project's
    # pyproject, not a requirements file in some other directory.
    lock = lock_near(locks, f.path, PY_LOCKS, climb=False)
    if lock:
        return []
    reqs = _requirement_lines(text)
    if not looks_like_requirements(reqs):
        return []
    out = []
    for line, s in reqs:
        got = python_requirement_issue(s)
        if not got:
            continue
        pkg, why = got
        out.append(finding(
            "arbiter/supply.unpinned-python-dep", f"Unpinned dependency `{pkg}`", f, line,
            # Severity "info": measured on the corpus, this fires at 0.0x on
            # deliberately vulnerable Python relative to well-maintained
            # Python. It does not discriminate, so it is reported for
            # completeness and scores zero.
            severity="info", confidence="high",
            description="An unpinned requirement makes builds non-reproducible. Note that "
                        "libraries are expected to declare ranges; this matters for "
                        f"applications and deployment manifests. Here: {why}, and no "
                        "lockfile (poetry.lock, uv.lock, Pipfile.lock, pdm.lock) beside it.",
            remediation="Pin with == (and --hash for a deployment), or commit a lockfile.",
            evidence=s[:80],
            controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-2"],
            tags=["dependencies"],
        ))
    return out


# ---------------------------------------------------------------------------
# npm (supply.unpinned-npm-dep)
# ---------------------------------------------------------------------------

_SEMVER_EXACT = re.compile(r"^=?v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
_GIT_SPEC = re.compile(r"^(git(\+[a-z]+)?://|git\+|github:|gitlab:|bitbucket:|gist:|"
                       r"[\w.-]+/[\w.-]+(#.*)?$)", re.I)


def npm_spec_issue(spec: Any) -> str:
    """'' when an npm dependency spec is pinned (or not a registry/git
    reference), else a short description of why it floats."""
    if not isinstance(spec, str):
        return ""
    s = spec.strip()
    if s.startswith(("file:", "link:", "workspace:", "portal:", "patch:", "exec:")):
        return ""
    if s.startswith("npm:"):
        inner = s[4:]
        at = inner.rfind("@")
        return npm_spec_issue(inner[at + 1:]) if at > 0 else "an alias with no version"
    if _GIT_SPEC.match(s) or (s.startswith(("http://", "https://")) and ".git" in s):
        ref = s.split("#", 1)[1] if "#" in s else ""
        ref = ref.split("::", 1)[0]
        if ref.startswith("commit="):
            ref = ref[len("commit="):]
        return "" if SHA40.match(ref) else "a git reference without a commit SHA"
    if s.startswith(("http://", "https://")):
        return ""   # a tarball URL: a fixed artifact
    if _SEMVER_EXACT.match(s):
        return ""
    if s in ("", "*", "x", "X", "latest"):
        return "any version"
    if "||" in s:
        return "a `||` range"
    if s[:1] in ("^", "~"):
        return "a caret or tilde range"
    if s[:1] in (">", "<"):
        return "an open comparator range"
    if re.search(r"\s-\s", s):
        return "a hyphen range"
    if re.fullmatch(r"=?v?\d+(\.(\d+|[xX*]))?(\.[xX*])?", s):
        return "a partial version (any matching release)"
    if re.fullmatch(r"[A-Za-z][\w.-]*", s):
        return "a dist-tag"
    return ""


_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def check_package_json(f, text: str, locks: set[str]) -> list[Finding]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    lock = lock_near(locks, f.path, NPM_LOCKS)
    out = []
    for section in _NPM_SECTIONS:
        deps = doc.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            why = npm_spec_issue(spec)
            if not why or lock:
                # A lockfile beside or above this manifest pins every one of
                # these, git references included: the build is reproducible
                # (the six FP labels of this rule were all that shape).
                continue
            out.append(finding(
                "arbiter/supply.unpinned-npm-dep",
                f"Floating version range on `{name}` ({spec})", f, 0,
                # Severity "info": 0.68/kloc on well-maintained Node vs
                # 0.73/kloc on deliberately vulnerable Node -- a ratio of
                # 1.1x, which is no signal at all. Re-measured with lockfiles
                # credited (ARB-131): 138 vs 170 findings, but all 170 come
                # from one vulnerable repository (juice-shop), and one
                # repository is not a population. Still "info".
                severity="info", confidence="high",
                description=f"`{spec}` is {why}: it resolves differently over time, and no "
                            "lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock, "
                            "pnpm-lock.yaml) sits beside or above this manifest.",
                remediation="Commit a lockfile, or pin exact versions and let a bot propose "
                            "upgrades.",
                evidence=f"{name}@{spec}",
                controls=["NIST-800-218:PW.4"],
                tags=["dependencies"],
                logical=f"{section}.{name}",
            ))
    return out


# ---------------------------------------------------------------------------
# Java (supply.unpinned-java-dep)
# ---------------------------------------------------------------------------

def _java_version_issue(v: str, snapshot_ok: bool) -> str:
    s = v.strip()
    if not s or "${" in s or "$" in s:
        return ""
    if s.upper() in ("LATEST", "RELEASE"):
        return f"the dynamic version `{s}`"
    if s.startswith("latest."):
        return f"the dynamic version `{s}`"
    if "+" in s and re.fullmatch(r"[\w.\-]*\+", s):
        return f"the dynamic version `{s}`"
    if s[:1] in "[(" and s[-1:] in "])" or ("," in s and s[:1] in "[("):
        return f"the version range `{s}`"
    if s.upper().endswith("-SNAPSHOT") and not snapshot_ok:
        return f"the snapshot `{s}` in a release build"
    return ""


class _Elem:
    __slots__ = ("tag", "line", "text", "children", "parent")

    def __init__(self, tag: str, line: int, parent: "_Elem | None"):
        self.tag, self.line, self.parent = tag, line, parent
        self.text = ""
        self.children: list[_Elem] = []

    def child(self, tag: str) -> "_Elem | None":
        return next((c for c in self.children if c.tag == tag), None)

    def child_text(self, tag: str) -> str:
        c = self.child(tag)
        return c.text.strip() if c else ""


def parse_xml(text: str) -> _Elem | None:
    """A small element tree with line numbers (ElementTree keeps none).
    expat never fetches external entities, and its billion-laughs limits
    apply."""
    import xml.parsers.expat as expat
    root = _Elem("#doc", 0, None)
    cur = [root]
    p = expat.ParserCreate()

    def start(name, _attrs):
        e = _Elem(name.split("}")[-1].split(":")[-1], p.CurrentLineNumber, cur[-1])
        cur[-1].children.append(e)
        cur.append(e)

    def end(_name):
        cur.pop()

    def chars(data):
        cur[-1].text += data

    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, chars
    try:
        p.Parse(text.encode("utf-8"), True)
    except expat.ExpatError:
        return None
    return root.children[0] if root.children else None


def _iter(e: _Elem) -> Iterator[_Elem]:
    stack = [e]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def check_pom(f, text: str) -> list[Finding]:
    project = parse_xml(text)
    if project is None or project.tag != "project":
        return []
    props: dict[str, str] = {}
    pe = project.child("properties")
    for c in (pe.children if pe else []):
        props[c.tag] = c.text.strip()
    own = project.child_text("version")
    parent = project.child("parent")
    parent_version = parent.child_text("version") if parent else ""
    build_version = own or parent_version
    props.setdefault("project.version", build_version)
    props.setdefault("version", build_version)
    props.setdefault("project.parent.version", parent_version)

    def resolve(v: str) -> str:
        for _ in range(5):
            m = re.search(r"\$\{([^}]+)\}", v)
            if not m or m.group(1) not in props:
                break
            v = v.replace(m.group(0), props[m.group(1)])
        return v

    # A SNAPSHOT dependency is only a defect in a release build. A version
    # this file cannot resolve (`${revision}` set in .mvn/maven.config) is
    # not judged.
    bv = resolve(build_version)
    snapshot_ok = not bv or "$" in bv or bv.upper().endswith("-SNAPSHOT")
    own_group = project.child_text("groupId") or (parent.child_text("groupId") if parent else "")

    out = []
    for e in _iter(project):
        if e.tag not in ("dependency", "plugin", "extension"):
            continue
        ver = e.child("version")
        if ver is None:
            continue
        raw = ver.text.strip()
        group = resolve(e.child_text("groupId"))
        # A SNAPSHOT of this project's own group is a sibling module built
        # from this same tree (tomcat's modules/*/pom.xml at 1.0 depending on
        # tomcat 12.0.0-SNAPSHOT), not a moving artifact from a repository.
        sibling = bool(own_group) and (group == own_group or group.startswith(own_group + "."))
        why = _java_version_issue(resolve(raw), snapshot_ok or sibling)
        if not why:
            continue
        coord = f"{e.child_text('groupId')}:{e.child_text('artifactId')}".strip(":")
        out.append(_java_finding(f, ver.line, coord, raw, why))
    return out


def _java_finding(f, line: int, coord: str, raw: str, why: str) -> Finding:
    return finding(
        "arbiter/supply.unpinned-java-dep",
        f"Dependency `{coord}` resolves {why}", f, line,
        severity="info", confidence="high",
        description="A dynamic version, a range or a snapshot resolves to whatever the "
                    "repository holds at build time, so two builds of one commit can ship "
                    "different code.",
        remediation="Declare an exact release version (a BOM or version catalog keeps them "
                    "in one place), or enable Gradle dependency locking.",
        evidence=f"{coord}:{raw}",
        controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-2"],
        tags=["dependencies", "java"],
    )


_GRADLE_COORD = re.compile(r"""["']([\w.\-]+):([\w.\-]+):([^"':@\s]+)(?:[:@][^"']*)?["']""")
_GRADLE_MAP_VERSION = re.compile(r"""\bversion\s*[:=]\s*["']([^"']+)["']""")
_GRADLE_PLUGIN = re.compile(r"""\bid\s*\(?\s*["']([\w.\-]+)["']\s*\)?\s+version\s*\(?\s*["']([^"']+)["']""")
_GRADLE_PROJECT_VERSION = re.compile(r"""^\s*(?:project\.)?version\s*=\s*["']([^"']+)["']""", re.M)


def is_gradle(path: str) -> bool:
    base = posixpath.basename(path)
    return base.endswith((".gradle", ".gradle.kts"))


def _gradle_locks_in(d: str, locks: set[str]) -> bool:
    """A Gradle lockfile for the build in directory `d`: `gradle.lockfile`
    beside the build file, or the older `gradle/dependency-locks/` folder."""
    legacy = f"{d}/gradle/dependency-locks/" if d else "gradle/dependency-locks/"
    return any((posixpath.dirname(p) == d and posixpath.basename(p) in GRADLE_LOCKS)
               or p.startswith(legacy) for p in locks)


def gradle_locked(f, text: str, locks: set[str]) -> bool:
    return "dependencyLocking" in text or _gradle_locks_in(posixpath.dirname(f.path), locks)


def check_gradle(f, text: str, locks: set[str]) -> list[Finding]:
    locked = gradle_locked(f, text, locks)
    pv = _GRADLE_PROJECT_VERSION.search(text)
    # A SNAPSHOT dependency matters only in a release build, and a Gradle
    # build's version is often set elsewhere (gradle.properties): unknown
    # here means not judged.
    snapshot_ok = not pv or pv.group(1).upper().endswith("-SNAPSHOT")
    out = []
    for i, line in enumerate(text.split("\n"), 1):
        code = re.sub(r"(^|\s)//.*$", "", line)
        if not code.strip():
            continue
        cands = [(m.group(1) + ":" + m.group(2), m.group(3)) for m in _GRADLE_COORD.finditer(code)]
        cands += [(m.group(1), m.group(2)) for m in _GRADLE_PLUGIN.finditer(code)]
        if not cands and re.search(r"\b(group|name)\s*[:=]", code):
            m = _GRADLE_MAP_VERSION.search(code)
            if m:
                name = re.search(r"""\bname\s*[:=]\s*["']([^"']+)["']""", code)
                cands.append((name.group(1) if name else "?", m.group(1)))
        for coord, ver in cands:
            why = _java_version_issue(ver, snapshot_ok)
            if not why or (locked and "snapshot" not in why):
                continue
            out.append(_java_finding(f, i, coord, ver, why))
    return out


def check_version_catalog(f, text: str, locks: set[str]) -> list[Finding]:
    try:
        import tomllib
    except ImportError:   # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        doc = tomllib.loads(text)
    except ValueError:   # tomllib.TOMLDecodeError
        return []
    # gradle/libs.versions.toml -> the build root is the directory above.
    root = posixpath.dirname(posixpath.dirname(f.path))
    locked = _gradle_locks_in(root, locks)
    lines = text.split("\n")

    def line_of(key: str) -> int:
        pat = re.compile(rf"""^\s*["']?{re.escape(key)}["']?\s*=""")
        return next((i for i, ln in enumerate(lines, 1) if pat.match(ln)), 0)

    out = []

    def judge(key: str, coord: str, ver: Any) -> None:
        vals = []
        if isinstance(ver, str):
            vals = [ver]
        elif isinstance(ver, dict):
            vals = [v for k, v in ver.items() if k in ("strictly", "require", "prefer")
                    and isinstance(v, str)]
        for v in vals:
            why = _java_version_issue(v, True)
            if why and not locked:
                out.append(_java_finding(f, line_of(key), coord, v, why))

    for key, ver in (doc.get("versions") or {}).items():
        judge(key, f"versions.{key}", ver)
    for table in ("libraries", "plugins"):
        for key, entry in (doc.get(table) or {}).items():
            if isinstance(entry, str):
                parts = entry.split(":")
                if len(parts) >= 3:
                    judge(key, ":".join(parts[:2]), parts[2])
            elif isinstance(entry, dict) and isinstance(entry.get("version"), (str, dict)):
                v = entry["version"]
                if isinstance(v, dict) and "ref" in v:
                    continue
                coord = entry.get("module") or entry.get("id") or key
                judge(key, str(coord), v)
    return out


# ---------------------------------------------------------------------------
# Ruby (supply.unpinned-ruby-dep)
# ---------------------------------------------------------------------------

_GEM = re.compile(r"""^\s*gem\s*\(?\s*["']([^"']+)["']\s*(.*)$""")
_OPT = re.compile(r"""(?::(\w+)\s*=>|\b(\w+):(?!:))\s*""")


def _gem_logical_lines(text: str) -> list[tuple[int, str]]:
    """Gemfile lines with trailing-comma continuations joined."""
    out, buf, start = [], [], 0
    for i, line in enumerate(text.split("\n"), 1):
        code = re.sub(r"\s#.*$|^\s*#.*$", "", line).rstrip()
        if not buf:
            start = i
        buf.append(code.strip())
        if code.endswith(","):
            continue
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def gem_issue(rest: str) -> str:
    """'' when a `gem` line's arguments pin it (or it is a local path)."""
    opts = {m.group(1) or m.group(2) for m in _OPT.finditer(rest)}
    if "path" in opts:
        return ""
    if opts & {"git", "github", "gitlab", "bitbucket"}:
        return "" if "ref" in opts else "a git source with no `ref:`"
    first_opt = _OPT.search(rest)
    positional = rest[:first_opt.start()] if first_opt else rest
    if re.search(r"""(^|,)\s*[A-Za-z_@$][\w.:@$]*(\[[^\]]*\])?\s*(,|$)""", positional.strip()) \
            or "(" in positional:
        # A version held in a constant or variable (`gem "rails",
        # RAILS_VERSION`): its value is not in this line, so not judged.
        return ""
    reqs = re.findall(r"""["']([^"']*)["']""", positional)
    reqs = [r.strip() for r in reqs if re.match(r"^\s*(~>|>=|<=|!=|=|>|<)?\s*\d", r)]
    if not reqs:
        return "no version requirement"
    if all(re.match(r"^(>=|>|!=)", r) for r in reqs):
        return f"only the open requirement `{', '.join(reqs)}`"
    return ""


def check_gemfile(f, text: str, locks: set[str]) -> list[Finding]:
    if lock_near(locks, f.path, RUBY_LOCKS, climb=False):
        return []
    if re.search(r"^\s*gemspec\b", text, re.M):
        # A gem's Gemfile: its dependencies are declared as ranges in the
        # .gemspec for its consumers, and gems conventionally do not commit
        # a Gemfile.lock. The same reasoning as pyproject ranges in a
        # library.
        return []
    out = []
    for line, logical in _gem_logical_lines(text):
        m = _GEM.match(logical)
        if not m:
            continue
        why = gem_issue(m.group(2))
        if not why:
            continue
        out.append(finding(
            "arbiter/supply.unpinned-ruby-dep", f"Gem `{m.group(1)}` has {why}", f, line,
            severity="info", confidence="high",
            description="With no Gemfile.lock beside this Gemfile, `bundle install` resolves "
                        "whatever release satisfies the requirement today.",
            remediation="Commit Gemfile.lock, or bound the requirement (`~> x.y`); give git "
                        "gems a `ref:`.",
            evidence=logical.strip()[:120],
            controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-2"],
            tags=["dependencies", "ruby"],
        ))
    return out


# ---------------------------------------------------------------------------
# Terraform (supply.unpinned-terraform)
# ---------------------------------------------------------------------------

# `[ \t]*`, not `\s*`: under re.M, `^\s*` starts on a blank line above and
# the reported line is the blank one (the bug unpinned-action had in round 4).
_TF_MODULE = re.compile(r'^[ \t]*module[ \t]+"([^"]+)"\s*\{', re.M)
_TF_TERRAFORM = re.compile(r"^[ \t]*terraform\s*\{", re.M)
_TF_REGISTRY = re.compile(r"^(?:[\w.-]+\.[a-z]{2,}/)?[\w-]+/[\w-]+/[\w-]+(//.*)?$")
_TF_EXACT = re.compile(r"^=?\s*v?\d+\.\d+\.\d+(-[\w.]+)?$")
_TF_GIT = re.compile(r"^(git::|github\.com/|bitbucket\.org/|git@)")


def _hcl_str(v: Any) -> Any:
    """An HCL string value without a trailing comment. graph.py's subset
    reader returns `"x" # note` verbatim when a comment follows the value."""
    if isinstance(v, str):
        m = re.match(r'^\s*"((?:[^"\\]|\\.)*)"\s*(#.*|//.*)?$', v)
        if m:
            return m.group(1)
    return v


def tf_module_issue(source: str, version: Any) -> str:
    s = source.strip()
    if not s or s.startswith(("./", "../")) or "${" in s or s.startswith("var."):
        return ""
    if _TF_GIT.match(s):
        m = re.search(r"[?&]ref=([^&]+)", s)
        if not m:
            return "a git source with no `?ref=`"
        ref = m.group(1)
        if SHA40.match(ref) or _TF_EXACT.match(ref):
            return ""
        return f"a git source at `{ref}`, not a commit SHA or exact tag"
    if _TF_REGISTRY.match(s) and "::" not in s:
        if version is None or version == "":
            return "a registry source with no `version`"
        if not isinstance(version, str) or "var." in version:
            return ""
        if _TF_EXACT.match(version.strip()):
            return ""
        return f"the version constraint `{version}`"
    return ""


def check_terraform(f, text: str, locks: set[str]) -> list[Finding]:
    from .graph import _match_brace, _parse_hcl_body
    out = []

    def tf_finding(line: int, title: str, why: str, evidence: str, remediation: str) -> Finding:
        return finding(
            "arbiter/supply.unpinned-terraform", title, f, line,
            severity="info", confidence="high",
            description=f"{why}: `terraform init` resolves whatever the source holds at that "
                        "moment, so two applies of one commit can run different code.",
            remediation=remediation, evidence=evidence,
            controls=["NIST-800-218:PW.4", "NIST-800-53r5:CM-2"],
            tags=["dependencies", "terraform"],
        )

    for m in _TF_MODULE.finditer(text):
        open_idx = text.index("{", m.end() - 1)
        body = text[open_idx + 1:_match_brace(text, open_idx) - 1]
        props = _parse_hcl_body(body)
        source = _hcl_str(props.get("source"))
        if not isinstance(source, str):
            continue
        why = tf_module_issue(source, _hcl_str(props.get("version")))
        if why:
            out.append(tf_finding(text.count("\n", 0, m.start()) + 1,
                                  f"Module `{m.group(1)}` uses {why}",
                                  f"Module `{m.group(1)}` uses {why}",
                                  f"module.{m.group(1)}:{source}",
                                  "Pin registry modules to an exact `version` and git sources "
                                  "to `?ref=<commit SHA>`."))
    lock = lock_near(locks, f.path, TF_LOCKS, climb=False)
    for m in _TF_TERRAFORM.finditer(text):
        open_idx = text.index("{", m.end() - 1)
        end = _match_brace(text, open_idx)
        block = text[open_idx + 1:end - 1]
        rp = re.search(r"^\s*required_providers\s*\{", block, re.M)
        if not rp:
            continue
        rp_open = open_idx + 1 + block.index("{", rp.start())
        rp_body = text[rp_open + 1:_match_brace(text, rp_open) - 1]
        for name, spec in _parse_hcl_body(rp_body).items():
            if isinstance(spec, str) and spec.strip().startswith("{"):
                # A one-line object, `aws = { source = "...", version = "..." }`:
                # the subset reader hands it back as text (with any comment).
                obj = spec.strip()
                spec = _parse_hcl_body(obj[1:_match_brace(obj, 0) - 1])
            if isinstance(spec, dict):
                spec = {k: _hcl_str(v) for k, v in spec.items()}
            if not isinstance(spec, dict) or spec.get("version") or lock:
                continue
            km = re.compile(rf"^[ \t]*{re.escape(name)}\s*=", re.M).search(text, rp_open)
            idx = km.start() if km else rp_open
            out.append(tf_finding(text.count("\n", 0, idx) + 1,
                                  f"Provider `{name}` has no version constraint",
                                  f"Provider `{name}` declares no `version` and no "
                                  ".terraform.lock.hcl sits beside it",
                                  f"required_providers.{name}:{spec.get('source', '')}",
                                  "Add a `version` constraint and commit .terraform.lock.hcl."))
    return out
