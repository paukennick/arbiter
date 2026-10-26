"""Acquire targets and classify what is in them.

Acquire turns a target (local path, git URL, or a multi-repo system manifest)
into read-only workspaces. Inventory classifies every file by language and
role, and detects which stacks are present so the planner knows which probes
are even applicable.
"""
from __future__ import annotations

import codecs
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .core import RepoInfo

# Directories never worth walking. cdk.out is deliberately NOT here: synthesized
# templates are ground truth and we want them.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".terraform", ".tox",
    "site-packages", ".next", ".nuxt", ".gradle", ".idea", ".vscode",
    "vendor", "target", ".arbiter",
}

LANG_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".php": "php",
    ".r": "r", ".R": "r",
    # Recognised so that a repository written in one of these is reported as
    # source no rule pack reads, not as a tree with nothing to assess
    # (ARB-144). No probe reads them beyond the language-neutral ones.
    ".swift": "swift", ".scala": "scala", ".sc": "scala", ".dart": "dart",
    ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".hs": "haskell",
    ".lua": "lua", ".pl": "perl", ".pm": "perl", ".clj": "clojure", ".cljs": "clojure",
    ".groovy": "groovy", ".fs": "fsharp", ".vb": "vb", ".jl": "julia", ".zig": "zig",
    ".nim": "nim", ".elm": "elm", ".ml": "ocaml", ".mli": "ocaml",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ps1": "powershell",
    ".tf": "terraform", ".tfvars": "terraform", ".hcl": "hcl",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".ini": "ini", ".cfg": "ini",
    ".md": "markdown", ".markdown": "markdown", ".rst": "rst",
    ".sql": "sql",
    ".html": "html", ".css": "css", ".scss": "css",
    ".env": "dotenv",
}

TEST_HINTS = re.compile(r"(^|/)(tests?|spec|__tests__)(/|$)|(^|/)test_[^/]+$|_test\.[a-z]+$"
                        r"|\.(spec|test)\.[a-z]+$|_spec\.rb$|(^|/)src/test/"
                        # Gradle/Maven test source sets: integration tests, JMH
                        # benchmarks, test fixtures, and `src/<name>Test/` suites.
                        r"|(^|/)src/(it|jmh|testFixtures|[A-Za-z0-9]+Test)/"
                        # A directory named exactly `_test`: the go tool ignores
                        # `_`-prefixed dirs, and yaegi keeps its interpreter's
                        # input programs there. Not `foo_test/` or `_testdata/`.
                        r"|(^|/)_test/"
                        # tsd-style type-level test directories (`test-d/`,
                        # jose) and suites kept in `integration-tests/`
                        # (opentelemetry-js). Whole directory names only.
                        r"|(^|/)(test-d|integration-tests)/")
DOC_HINTS = re.compile(r"(^|/)(docs?|\.ai)(/|$)|\.(md|rst|adoc)$", re.IGNORECASE)
# `cdk\.out[^/]*` rather than `cdk\.out`: CDK_OUTDIR lets a project redirect
# synth output to a renamed directory (`cdk.out.chk`, seen on a real system),
# and the un-suffixed pattern silently stopped matching anything under it --
# a Lambda asset bundle's vendored dependencies then read as first-party
# source, which is how a third-party library's own PEM-parsing code and test
# fixtures were reported as secrets committed to the repository.
GENERATED_HINTS = re.compile(r"(^|/)(cdk\.out[^/]*|dist|build|out|coverage|\.next)(/|$)|\.min\.(js|css)$|lock\.json$|\.lock$")
IAC_HINTS = re.compile(r"\.tf$|\.tfvars$|template\.(ya?ml|json)$")
CI_HINTS = re.compile(r"(^|/)\.github/workflows/.*\.ya?ml$|(^|/)\.gitlab-ci\.ya?ml$|(^|/)Jenkinsfile$|(^|/)azure-pipelines\.ya?ml$")

MAX_FILE_BYTES = 2_000_000


@dataclass
class FileInfo:
    path: str          # relative to repo root
    abspath: str
    repo_id: str
    language: str = "unknown"
    role: str = "source"   # source | test | docs | config | iac | ci | generated | data
    size: int = 0
    lines: int = 0
    binary: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("abspath", None)
        return d


# Roles a probe reads. A file in any other role (docs, data, generated) may
# be opened by a probe or two, but no rule pack or quality check assesses it,
# so a tree holding only such files has had nothing assessed (ARB-149).
ASSESSABLE_ROLES = ("source", "test", "config", "iac", "ci")

# How many files are counted under a directory the walk never enters, so the
# report can say "vendor/: 500+ files" without walking node_modules in full.
SKIPPED_DIR_COUNT_CAP = 500
# How many skipped files report.json names individually; the counts by
# reason are always complete.
SKIPPED_ENTRIES_CAP = 200

# Reasons a file or directory was not read (ARB-150). Fixed strings so
# scan_scope.skipped.by_reason groups cleanly and tests can name them.
SKIP_NUL = "NUL byte in the first 4KB (binary, or text with a stray NUL)"
SKIP_OVERSIZE = f"larger than {MAX_FILE_BYTES:,} bytes"
SKIP_UTF16 = "UTF-16 without a byte-order mark (save as UTF-8, or with a BOM)"
SKIP_UNREADABLE = "unreadable"
SKIP_LINK_OUTSIDE = "symbolic link to a file outside the repository (not followed)"
SKIP_GITIGNORED = "ignored by .gitignore"
SKIP_DIR_NAMED = "vendored, build or tool directory by name (never walked)"
SKIP_DIR_LINK = "symbolic link to a directory (not followed)"
SKIP_DIR_GITIGNORED = "directory ignored by .gitignore"


def source_like(rel: str, language: str) -> bool:
    """Whether a file Arbiter did not read looks like one it would have
    assessed: a known text extension in a role a probe reads. A skipped
    `.png` is not a coverage gap; a skipped `.py` is."""
    return language != "unknown" and classify(rel, language) in ASSESSABLE_ROLES


@dataclass
class Inventory:
    files: list[FileInfo] = field(default_factory=list)
    stacks: set[str] = field(default_factory=set)
    by_repo: dict[str, list[FileInfo]] = field(default_factory=dict)
    # Every file and directory the walk saw and did not read, each with a
    # reason (ARB-150): {"path", "repo_id", "reason", "kind": "file"|"dir",
    # "source_like": bool, "files": int (dirs only)}. Before this, a file
    # skipped for a NUL byte or its size vanished from every section of the
    # report, and a tree of such files scored 100.
    skipped: list[dict] = field(default_factory=list)
    # The complete inventory this one was narrowed from (a partial scan, or
    # the result cache showing a probe only the files it must re-read), or
    # None for a complete inventory. A probe that asks which paths EXIST in
    # the repository -- not what they contain -- answers from here, so that
    # the answer is a fact about the repository rather than about the subset.
    whole: "Inventory | None" = None

    def text_files(self, repo_id: str | None = None) -> list[FileInfo]:
        src = self.files if repo_id is None else self.by_repo.get(repo_id, [])
        return [f for f in src if not f.binary]

    def with_ext(self, *exts: str, repo_id: str | None = None) -> list[FileInfo]:
        exts_l = tuple(e.lower() for e in exts)
        return [f for f in self.text_files(repo_id) if f.path.lower().endswith(exts_l)]

    def languages(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.files:
            if f.binary or f.role == "generated":
                continue
            out[f.language] = out.get(f.language, 0) + f.lines
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def summary(self) -> dict:
        return {
            "files": len(self.files),
            "lines": sum(f.lines for f in self.files),
            "languages": self.languages(),
            "stacks": sorted(self.stacks),
        }

    def assessable_files(self, repo_id: str | None = None) -> list[FileInfo]:
        """Text files in a role a probe reads (ARB-149)."""
        return [f for f in self.text_files(repo_id) if f.role in ASSESSABLE_ROLES]

    def skipped_source_like(self) -> list[dict]:
        return [s for s in self.skipped if s["kind"] == "file" and s.get("source_like")]

    def skipped_source_share(self) -> float:
        """Share of source-like files the walk saw that it did not read:
        skipped over skipped plus assessable text files read. 0.0 when
        nothing was skipped; 1.0 when every source-like file was."""
        skipped = len(self.skipped_source_like())
        if not skipped:
            return 0.0
        read = len(self.assessable_files())
        return round(skipped / (skipped + read), 4)

    def skipped_summary(self) -> dict:
        """The `scan_scope.skipped` block: counts by reason for every skipped
        file, the source-like ones named (capped), and every directory the
        walk did not enter with a bounded file count."""
        files = [s for s in self.skipped if s["kind"] == "file"]
        dirs = [s for s in self.skipped if s["kind"] == "dir"]
        by_reason: dict[str, int] = {}
        for s in files:
            by_reason[s["reason"]] = by_reason.get(s["reason"], 0) + 1
        named = [s for s in files if s.get("source_like")]
        return {
            "files": len(files),
            "source_like_files": len(named),
            "source_like_share": self.skipped_source_share(),
            "by_reason": dict(sorted(by_reason.items(), key=lambda kv: (-kv[1], kv[0]))),
            "entries": [{"path": s["path"], "reason": s["reason"]}
                        for s in named[:SKIPPED_ENTRIES_CAP]],
            "entries_omitted": max(0, len(named) - SKIPPED_ENTRIES_CAP),
            "dirs": [{"path": s["path"], "reason": s["reason"], "files": s.get("files", 0)}
                     for s in dirs],
        }


# Byte-order marks that declare a text file, longest first so UTF-32-LE is not
# read as UTF-16-LE (its mark starts with the same two bytes).
_TEXT_BOMS = (
    codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE,
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE,
)


def _is_binary(sample: bytes) -> bool:
    """A NUL means binary, unless the file opens by declaring it is not.

    UTF-16 puts a NUL between every ASCII character, so the bare NUL test
    called every UTF-16 file binary -- and binary files are never read. A
    credential in a file an editor saved as "Unicode" was therefore never
    looked at. That is a coverage gap rather than a wrong answer, since the
    file is recorded as unassessed data, but it is invisible in exactly the
    place a Windows-authored config is most likely to be.

    Only a declared mark overrides the NUL test. Sniffing headerless UTF-16
    would mean guessing, and guessing wrong turns a real binary into
    thousands of lines of mojibake to scan.
    """
    if sample.startswith(_TEXT_BOMS):
        return False
    return b"\x00" in sample


def _looks_utf16_without_bom(sample: bytes) -> bool:
    """Whether a NUL-bearing sample has UTF-16's stride: a NUL at (nearly)
    every odd offset and none at even offsets, or the mirror image.

    Detection only. Every probe reads bytes or UTF-8 through its own path
    (tree-sitter parses the raw bytes), so decoding here would make one
    reader right and the rest wrong; the file is reported as not read, with
    a reason that says how to fix it, instead of vanishing as binary.
    """
    n = len(sample) - (len(sample) % 2)
    if n < 16:
        return False
    odd = sum(1 for i in range(1, n, 2) if sample[i] == 0)
    even = sum(1 for i in range(0, n, 2) if sample[i] == 0)
    half = n // 2
    return (odd >= half * 0.5 and even == 0) or (even >= half * 0.5 and odd == 0)


def _count_files_under(path: Path, cap: int = SKIPPED_DIR_COUNT_CAP) -> int:
    """How many files sit under a directory the walk skipped, stopping at
    `cap` so node_modules costs a few directory reads, not a full walk."""
    n = 0
    try:
        for _, _, names in os.walk(path):
            n += len(names)
            if n >= cap:
                return cap
    except OSError:
        pass
    return n


def _skip(skipped: list[dict] | None, **entry) -> None:
    if skipped is not None:
        skipped.append(entry)


def classify(rel: str, language: str) -> str:
    # IAC_HINTS before GENERATED_HINTS: a CDK stack's own `*.template.json` is
    # the synthesized ground truth this scanner deliberately reads (SKIP_DIRS
    # above), sitting in the same `cdk.out*/` directory as everything else
    # CDK writes. Checking GENERATED_HINTS first would classify the template
    # itself as generated -- true of the tree, not of that one file -- and
    # nothing downstream treats "iac" as exempt from a probe the way
    # "generated" is, so this ordering costs nothing for files that only ever
    # matched GENERATED_HINTS to begin with.
    if IAC_HINTS.search(rel):
        return "iac"
    if GENERATED_HINTS.search(rel):
        return "generated"
    if CI_HINTS.search(rel):
        return "ci"
    if TEST_HINTS.search(rel):
        return "test"
    if DOC_HINTS.search(rel):
        return "docs"
    if language in ("yaml", "json", "toml", "ini", "dotenv"):
        return "config"
    if language in ("markdown", "rst"):
        return "docs"
    if language == "unknown":
        return "data"
    return "source"


def _gitignored(root: Path) -> tuple[set[str], set[str]]:
    """Paths git itself calls both untracked and ignored, split dirs from files.

    Only untracked-and-ignored: a file force-added despite matching a later
    pattern is still tracked, so git omits it here and this still scans it as
    a deliberate exception. Same plumbing incremental.py already calls for
    changed-file detection -- this is git answering "is this actually part of
    the project" rather than Arbiter guessing from directory names, and it is
    what a static SKIP_DIRS list can never cover: a fresh `arbiter-out/` from
    an uncleaned previous run, under whatever name `--out` was given that
    time, is untracked and `.gitignore`-matched without ever being named here.
    `--directory` reports a fully-ignored directory as one trailing-slash
    entry instead of walking every file inside it; a directory with a mix of
    tracked and ignored content can't collapse that way, so its ignored files
    still come back individually and are handled at the file-name check below.
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--others", "--ignored",
             "--exclude-standard", "--directory", "-z"],
            capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return set(), set()
    if r.returncode != 0:
        return set(), set()
    dirs: set[str] = set()
    files: set[str] = set()
    for entry in r.stdout.decode("utf-8", errors="replace").split("\0"):
        if not entry:
            continue
        if entry.endswith("/"):
            dirs.add(str((root / entry[:-1]).resolve()))
        else:
            files.add(entry)
    return dirs, files


def walk_repo(root: Path, repo_id: str, exclude: set[str] | None = None,
              skipped: list[dict] | None = None) -> list[FileInfo]:
    """Every file under `root`, classified. What the walk does not read --
    a directory it never enters, a file it calls binary or too large, a
    link it will not follow -- is appended to `skipped` with a reason
    (ARB-150), except Arbiter's own output, which is excluded, not skipped.
    """
    out: list[FileInfo] = []
    root = root.resolve()
    # Resolved, because the caller passes the output directory as it was typed
    # and `arbiter-out` is relative to the working directory, not to the root.
    excluded = {str(Path(p).resolve()) for p in (exclude or ())}
    ignored_dirs, ignored_files = _gitignored(root)

    def relpath(p: Path) -> str:
        return str(p.relative_to(root)).replace(os.sep, "/")

    for dirpath, dirnames, filenames in os.walk(root):
        # .git is skipped; .github is emphatically not — CI config is a target.
        kept_dirs: list[str] = []
        for d in dirnames:
            dp = Path(dirpath) / d
            resolved = str(dp.resolve())
            if resolved in excluded:
                continue
            reason = ""
            if d in SKIP_DIRS:
                reason = SKIP_DIR_NAMED
            elif dp.is_symlink():
                # os.walk(followlinks=False) lists the link and never enters
                # it. A monorepo's shared tree behind a link was therefore
                # silently absent; now it is absent and said so.
                reason = SKIP_DIR_LINK
            elif resolved in ignored_dirs:
                reason = SKIP_DIR_GITIGNORED
            if reason:
                if d != ".git":
                    _skip(skipped, path=relpath(dp), repo_id=repo_id, kind="dir",
                          reason=reason, files=_count_files_under(dp))
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs
        for name in filenames:
            ap = Path(dirpath) / name
            if str(ap) in excluded:
                # A file Arbiter writes (the result cache) rather than a
                # directory; `root` is resolved, so `ap` already is.
                continue
            rel = relpath(ap)
            ext = ap.suffix
            language = LANG_BY_EXT.get(ext, LANG_BY_EXT.get(ext.lower(), "unknown"))
            if name in ("Dockerfile", "Containerfile") or name.startswith("Dockerfile."):
                language = "dockerfile"
            if name in ("Makefile", "Jenkinsfile"):
                language = name.lower()
            src_like = source_like(rel, language)

            def skip_file(reason: str, rel: str = rel, src_like: bool = src_like) -> None:
                _skip(skipped, path=rel, repo_id=repo_id, kind="file", reason=reason,
                      source_like=src_like)

            if ap.is_symlink():
                # A link whose target is outside the tree would be read and
                # its contents echoed into the evidence (a hostile pull
                # request pointing at the runner's files). Inside the tree
                # the target is walked under its own name.
                try:
                    ap.resolve(strict=True).relative_to(root)
                except (OSError, ValueError):
                    skip_file(SKIP_LINK_OUTSIDE)
                    continue
            try:
                st = ap.stat()
            except OSError as exc:
                skip_file(f"{SKIP_UNREADABLE}: {exc.strerror or exc}")
                continue
            if rel in ignored_files:
                skip_file(SKIP_GITIGNORED)
                continue
            fi = FileInfo(path=rel, abspath=str(ap), repo_id=repo_id, language=language, size=st.st_size)
            if st.st_size > MAX_FILE_BYTES:
                fi.binary = True
                fi.role = "data"
                out.append(fi)
                skip_file(SKIP_OVERSIZE)
                continue
            try:
                raw = ap.read_bytes()
            except OSError as exc:
                skip_file(f"{SKIP_UNREADABLE}: {exc.strerror or exc}")
                continue
            sample = raw[:4096]
            if _is_binary(sample):
                fi.binary = True
                fi.role = "data"
                skip_file(SKIP_UTF16 if language != "unknown" and _looks_utf16_without_bom(sample)
                          else SKIP_NUL)
            else:
                fi.lines = raw.count(b"\n") + (0 if raw.endswith(b"\n") or not raw else 1)
                fi.role = classify(rel, language)
            out.append(fi)
    return out


def detect_stacks(files: list[FileInfo]) -> set[str]:
    paths = {f.path for f in files}
    names = {os.path.basename(p) for p in paths}
    stacks: set[str] = set()

    if any(p.endswith(".tf") for p in paths):
        stacks.add("terraform")
    if "cdk.json" in names or any("/cdk.out/" in p or p.startswith("cdk.out/") for p in paths):
        stacks.add("aws_cdk")
    if any(p.endswith(".template.json") for p in paths):
        stacks.add("cloudformation")
    if "package.json" in names:
        stacks.add("node")
    if any(f.language in ("typescript",) for f in files):
        stacks.add("typescript")
    if {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile"} & names or any(
        f.language == "python" and f.role != "generated" for f in files
    ):
        stacks.add("python")
    if any(f.language == "javascript" for f in files):
        stacks.add("javascript")
    if any(f.language == "dockerfile" for f in files):
        stacks.add("docker")
    if any(p.startswith(".github/workflows/") or "/.github/workflows/" in p for p in paths):
        stacks.add("github_actions")
    if ".gitlab-ci.yml" in names or ".gitlab-ci.yaml" in names:
        stacks.add("gitlab_ci")
    if "go.mod" in names or any(f.language == "go" for f in files):
        stacks.add("go")
    if {"pom.xml", "build.gradle", "build.gradle.kts"} & names or any(
            f.language == "java" for f in files):
        stacks.add("java")
    if {"Gemfile", "Rakefile"} & names or any(f.language == "ruby" for f in files):
        stacks.add("ruby")
    if {"CMakeLists.txt"} & names or any(f.language == "cpp" for f in files):
        stacks.add("cpp")
    if any(f.language == "r" for f in files):
        stacks.add("r")

    # Kubernetes: a yaml with both apiVersion and kind at top level
    for f in files:
        if f.language == "yaml" and not f.binary and f.size < 200_000:
            try:
                head = Path(f.abspath).read_text(encoding="utf-8", errors="replace")[:2000]
            except OSError:
                continue
            if re.search(r"^apiVersion:", head, re.M) and re.search(r"^kind:", head, re.M):
                stacks.add("kubernetes")
                break
    return stacks


# --------------------------------------------------------------------------
# Acquire
# --------------------------------------------------------------------------

@dataclass
class Acquired:
    repos: list[RepoInfo] = field(default_factory=list)
    tempdirs: list[str] = field(default_factory=list)


def _git_commit(path: Path) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def acquire_one(source: str, repo_id: str = "root", role: str = "", ref: str = "") -> tuple[RepoInfo, str | None]:
    """Return (RepoInfo, tempdir_or_None). Clones only for remote URLs."""
    if source.startswith(("http://", "https://", "git@", "ssh://")):
        tmp = tempfile.mkdtemp(prefix="arbiter-ws-")
        cmd = ["git", "clone", "--depth", "1"]
        if ref:
            cmd += ["--branch", ref]
        cmd += [source, tmp]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f"clone failed for {source}: {r.stderr.strip()[:400]}")
        p = Path(tmp)
        return RepoInfo(id=repo_id, path=str(p), source=source, role=role, commit=_git_commit(p)), tmp

    p = Path(source).expanduser().resolve()
    if not p.is_dir():
        raise RuntimeError(f"not a directory: {source}")
    return RepoInfo(id=repo_id, path=str(p), source=str(p), role=role, commit=_git_commit(p)), None


def build_inventory(repos: list[RepoInfo], exclude: set[str] | None = None) -> Inventory:
    inv = Inventory()
    for r in repos:
        files = walk_repo(Path(r.path), r.id, exclude, inv.skipped)
        inv.by_repo[r.id] = files
        inv.files.extend(files)
        r.files = len(files)
        r.loc = sum(f.lines for f in files)
    inv.stacks = detect_stacks(inv.files)
    return inv
