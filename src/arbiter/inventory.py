"""Acquire targets and classify what is in them.

Acquire turns a target (local path, git URL, or a multi-repo system manifest)
into read-only workspaces. Inventory classifies every file by language and
role, and detects which stacks are present so the planner knows which probes
are even applicable.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
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
    ".java": "java", ".kt": "kotlin",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".php": "php",
    ".r": "r", ".R": "r",
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

TEST_HINTS = re.compile(r"(^|/)(tests?|spec|__tests__)(/|$)|(^|/)test_[^/]+$|_test\.[a-z]+$|\.spec\.[a-z]+$")
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


@dataclass
class Inventory:
    files: list[FileInfo] = field(default_factory=list)
    stacks: set[str] = field(default_factory=set)
    by_repo: dict[str, list[FileInfo]] = field(default_factory=dict)

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


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


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


def walk_repo(root: Path, repo_id: str, exclude: set[str] | None = None) -> list[FileInfo]:
    out: list[FileInfo] = []
    root = root.resolve()
    # Resolved, because the caller passes the output directory as it was typed
    # and `arbiter-out` is relative to the working directory, not to the root.
    excluded = {str(Path(p).resolve()) for p in (exclude or ())}
    for dirpath, dirnames, filenames in os.walk(root):
        # .git is skipped; .github is emphatically not — CI config is a target.
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS
            and str((Path(dirpath) / d).resolve()) not in excluded
        ]
        for name in filenames:
            ap = Path(dirpath) / name
            try:
                st = ap.stat()
            except OSError:
                continue
            rel = str(ap.relative_to(root)).replace(os.sep, "/")
            ext = ap.suffix
            language = LANG_BY_EXT.get(ext, LANG_BY_EXT.get(ext.lower(), "unknown"))
            if name in ("Dockerfile", "Containerfile") or name.startswith("Dockerfile."):
                language = "dockerfile"
            if name in ("Makefile", "Jenkinsfile"):
                language = name.lower()
            fi = FileInfo(path=rel, abspath=str(ap), repo_id=repo_id, language=language, size=st.st_size)
            if st.st_size > MAX_FILE_BYTES:
                fi.binary = True
                fi.role = "data"
                out.append(fi)
                continue
            try:
                raw = ap.read_bytes()
            except OSError:
                continue
            if _is_binary(raw[:4096]):
                fi.binary = True
                fi.role = "data"
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
    if "go.mod" in names:
        stacks.add("go")
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
    except Exception:
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
        files = walk_repo(Path(r.path), r.id, exclude)
        inv.by_repo[r.id] = files
        inv.files.extend(files)
        r.files = len(files)
        r.loc = sum(f.lines for f in files)
    inv.stacks = detect_stacks(inv.files)
    return inv
