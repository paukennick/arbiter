"""Plan and verify the external tools Arbiter can use."""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from . import ast
from .adapters import cache_dir as adapter_cache_dir
from .inventory import LANG_BY_EXT, SKIP_DIRS

_CATALOG_PATH = Path(__file__).with_name("tooling.json")
_VERSION = re.compile(r"\bv?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)\b")
_LOCK_SCHEMA_VERSION = 1


def load_catalog() -> dict[str, Any]:
    """Read the packaged tool catalog."""
    catalog = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    if catalog.get("schema_version") != 1:
        raise ValueError("unsupported tooling catalog schema_version")
    return catalog


def detect_languages(target: str | Path) -> set[str]:
    """Detect source/config languages without descending into generated or dependency trees."""
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"tool plan target is not a directory: {root}")

    languages: set[str] = set()

    def raise_walk_error(error: OSError) -> None:
        raise error

    for current, dirs, files in os.walk(root, onerror=raise_walk_error):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
        for filename in files:
            language = LANG_BY_EXT.get(Path(filename).suffix.lower())
            if language:
                languages.add(language)
    return languages


def _inspect_binary(
    tool: dict[str, Any],
    expected: str | None = None,
    executable: str | Path | None = None,
) -> dict[str, Any]:
    binary = tool["binary"]
    expected_version = expected or tool["version"]
    resolved = str(executable) if executable is not None else shutil.which(binary)
    if resolved is None or (executable is not None and not Path(resolved).is_file()):
        return {
            "name": tool["name"],
            "expected": expected_version,
            "actual": None,
            "status": "missing",
            "detail": f"{binary} is not available" if executable is not None
            else f"{binary} is not on PATH",
        }

    try:
        result = subprocess.run(
            [resolved, *tool["version_args"]],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "name": tool["name"],
            "expected": expected_version,
            "actual": None,
            "status": "error",
            "detail": f"could not read version: {exc}",
        }

    output = f"{result.stdout}\n{result.stderr}".strip()
    match = _VERSION.search(output)
    if result.returncode != 0 or match is None:
        detail = f"version command exited {result.returncode}"
        if output:
            detail += f": {output.splitlines()[0]}"
        return {
            "name": tool["name"],
            "expected": expected_version,
            "actual": None,
            "status": "error",
            "detail": detail,
        }

    actual = match.group(1)
    status = "ready" if actual == expected_version else "mismatch"
    detail = f"version {actual}" if status == "ready" else f"expected {expected_version}, found {actual}"
    return {
        "name": tool["name"],
        "expected": expected_version,
        "actual": actual,
        "status": status,
        "detail": detail,
    }


def _cached_semgrep_rules(cache_dir: str | Path | None = None) -> str | None:
    root = Path(cache_dir).expanduser() if cache_dir else adapter_cache_dir()
    marker = root / "semgrep-rules" / ".arbiter-ref"
    return marker.read_text(encoding="utf-8").strip() if marker.is_file() else None


def _grammar_status(grammar: str, cached: set[str]) -> dict[str, Any]:
    available = ast.available()
    if not available:
        return {
            "name": grammar,
            "expected": "cached grammar",
            "actual": None,
            "status": "missing",
            "detail": "tree-sitter-language-pack is not installed",
        }
    if grammar not in cached:
        return {
            "name": grammar,
            "expected": "cached grammar",
            "actual": None,
            "status": "missing",
            "detail": "grammar is not cached",
        }
    return {
        "name": grammar,
        "expected": "cached grammar",
        "actual": grammar,
        "status": "ready",
        "detail": "grammar is cached",
    }


def build_plan(target: str | Path, cache_dir: str | Path | None = None) -> dict[str, Any]:
    """Build a read-only plan for tools relevant to a repository."""
    catalog = load_catalog()
    languages = detect_languages(target)
    analyzers = []
    for tool in catalog["analyzers"]:
        relevant = "*" in tool["languages"] or bool(languages.intersection(tool["languages"]))
        if relevant:
            analyzers.append(_inspect_binary(tool))

    tree_sitter = catalog["tree_sitter"]
    grammar_names = sorted({
        grammar
        for language in languages
        for grammar in tree_sitter["grammars"].get(language, [])
    })
    cached = ast.cached_grammars()
    grammars = [_grammar_status(name, cached) for name in grammar_names]

    semgrep_rules = None
    if any(tool["name"] == "semgrep" for tool in analyzers):
        expected = catalog["semgrep_rules_ref"]
        actual = _cached_semgrep_rules(cache_dir)
        semgrep_rules = {
            "name": "semgrep-rules",
            "expected": expected,
            "actual": actual,
            "status": "ready" if actual == expected else ("missing" if actual is None else "mismatch"),
            "detail": "pinned rules are cached" if actual == expected else (
                "pinned rules are not cached" if actual is None
                else f"expected {expected}, found {actual}"
            ),
        }

    return {
        "target": str(Path(target).expanduser().resolve()),
        "languages": sorted(languages),
        "analyzers": analyzers,
        "grammars": grammars,
        "semgrep_rules": semgrep_rules,
        "lock": make_lock(analyzers, grammars, semgrep_rules),
    }


def _catalog_digest() -> str:
    return hashlib.sha256(_CATALOG_PATH.read_bytes()).hexdigest()


def make_lock(
    analyzers: list[dict[str, Any]],
    grammars: list[dict[str, Any]],
    semgrep_rules: dict[str, Any] | None,
) -> dict[str, Any]:
    """Create a lock record containing the applicable recommended capabilities."""
    lock = {
        "schema_version": _LOCK_SCHEMA_VERSION,
        "catalog_sha256": _catalog_digest(),
        "tools": [
            {"name": result["name"], "version": result["expected"], "required": True}
            for result in analyzers
        ],
        "grammars": [
            {"name": result["name"], "required": True}
            for result in grammars
        ],
    }
    if semgrep_rules is not None:
        lock["semgrep_rules"] = {
            "ref": semgrep_rules["expected"],
            "required": True,
        }
    return lock


def write_lock(lock: dict[str, Any], destination: str | Path) -> Path:
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_lock(path: str | Path) -> dict[str, Any]:
    lock_path = Path(path).expanduser()
    document = json.loads(lock_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != _LOCK_SCHEMA_VERSION:
        raise ValueError(f"unsupported tooling lock schema in {lock_path}")
    if not isinstance(document.get("tools"), list) or not isinstance(document.get("grammars"), list):
        raise TypeError(f"tooling lock must contain tools and grammars lists: {lock_path}")
    return document


def verify_lock(
    lock: dict[str, Any],
    cache_dir: str | Path | None = None,
    tool_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Check a lock against installed binaries and cached grammars; never installs anything."""
    catalog = load_catalog()
    catalog_tools = {tool["name"]: tool for tool in catalog["analyzers"]}
    known_grammars = {
        grammar
        for names in catalog["tree_sitter"]["grammars"].values()
        for grammar in names
    }
    results: list[dict[str, Any]] = []
    locked_catalog_digest = lock.get("catalog_sha256")
    if not isinstance(locked_catalog_digest, str):
        raise TypeError("tooling lock must contain a catalog_sha256 string")
    current_catalog_digest = _catalog_digest()
    results.append({
        "name": "tooling-catalog",
        "expected": locked_catalog_digest,
        "actual": current_catalog_digest,
        "status": "ready" if locked_catalog_digest == current_catalog_digest else "mismatch",
        "detail": "catalog matches lock" if locked_catalog_digest == current_catalog_digest
        else "catalog changed; regenerate the tooling lock",
        "required": True,
    })

    trivy_entry = next(
        (entry for entry in lock["tools"]
         if isinstance(entry, dict) and entry.get("name") == "trivy"),
        None,
    )
    for entry in lock["tools"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise TypeError("each tooling lock tool entry must name a tool")
        tool = catalog_tools.get(entry["name"])
        if tool is None:
            raise ValueError(f"tooling lock names unknown analyzer: {entry['name']}")
        expected = entry.get("version")
        required = entry.get("required", True)
        if not isinstance(expected, str) or not isinstance(required, bool):
            raise TypeError(f"invalid tooling lock entry for analyzer: {entry['name']}")
        if tool_root is None:
            result = _inspect_binary(tool, expected)
        else:
            executable = _tool_executable_path(Path(tool_root), tool)
            result = _inspect_binary(tool, expected, executable=executable)
        result["required"] = required
        results.append(result)

    if trivy_entry is not None:
        if tool_root is not None:
            trivy_cache_root = Path(tool_root).expanduser()
        else:
            base_cache = Path(cache_dir).expanduser() if cache_dir is not None else Path(
                os.environ.get("ARBITER_CACHE_DIR") or Path.home() / ".cache" / "arbiter"
            ).expanduser()
            trivy_cache_root = base_cache
        database = trivy_cache_root / "trivy-cache" / "db" / "trivy.db"
        database_ready = database.is_file()
        results.append({
            "name": "trivy-database",
            "expected": "present",
            "actual": "present" if database_ready else None,
            "status": "ready" if database_ready else "missing",
            "detail": "Trivy vulnerability database is cached" if database_ready
            else "Trivy vulnerability database is not cached; run arbiter tools install",
            "required": trivy_entry.get("required", True),
        })

    cached = ast.cached_grammars()
    for entry in lock["grammars"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise TypeError("each tooling lock grammar entry must name a grammar")
        required = entry.get("required", True)
        if not isinstance(required, bool):
            raise TypeError(f"invalid required flag for grammar: {entry['name']}")
        if entry["name"] not in known_grammars:
            raise ValueError(f"tooling lock names unknown tree-sitter grammar: {entry['name']}")
        result = _grammar_status(entry["name"], cached)
        result["required"] = required
        results.append(result)

    if "semgrep_rules" in lock:
        rules_entry = lock["semgrep_rules"]
        if not isinstance(rules_entry, dict) or not isinstance(rules_entry.get("ref"), str):
            raise TypeError("semgrep_rules in tooling lock must contain a ref string")
        expected = rules_entry["ref"]
        required = rules_entry.get("required", True)
        if not isinstance(required, bool):
            raise TypeError("semgrep_rules required flag must be a boolean")
        rules_cache = tool_root if tool_root is not None else cache_dir
        actual = _cached_semgrep_rules(rules_cache)
        results.append({
            "name": "semgrep-rules",
            "expected": expected,
            "actual": actual,
            "status": "ready" if actual == expected else ("missing" if actual is None else "mismatch"),
            "detail": "pinned rules are cached" if actual == expected else (
                "pinned rules are not cached" if actual is None
                else f"expected {expected}, found {actual}"
            ),
            "required": required,
        })
    return results


_TOOL_CACHE_ENV = "ARBITER_TOOL_CACHE"


def _tool_executable_path(root: Path, tool: dict[str, Any]) -> Path:
    binary = tool["binary"]
    if tool["install_method"] == "pip":
        scripts = "Scripts" if os.name == "nt" else "bin"
        suffix = ".exe" if os.name == "nt" else ""
        return root / "python" / tool["name"] / scripts / f"{binary}{suffix}"
    suffix = ".exe" if os.name == "nt" else ""
    return root / "bin" / f"{binary}{suffix}"


def tool_cache_root(
    target: str | Path,
    lock_path: str | Path | None = None,
    cache_dir: str | Path | None = None,
) -> Path:
    repo = Path(target).expanduser().resolve()
    lock_file = Path(lock_path).expanduser() if lock_path else repo / ".arbiter" / "tooling.lock.json"
    if not lock_file.is_absolute():
        target_relative_lock = repo / lock_file
        lock_file = target_relative_lock if target_relative_lock.is_file() else lock_file.resolve()
    content = lock_file.read_bytes()
    configured_base = os.environ.get(_TOOL_CACHE_ENV)
    if configured_base is not None and not configured_base.strip() and cache_dir is None:
        raise ValueError(f"{_TOOL_CACHE_ENV} must not be empty")
    base = Path(cache_dir).expanduser() if cache_dir else Path(
        configured_base or Path.home() / ".cache" / "arbiter" / "toolchains"
    ).expanduser()
    key = hashlib.sha256(str(repo).encode("utf-8") + b"\0" + content).hexdigest()
    return base / key


def resolve_locked_binary(target: str | Path, binary: str) -> tuple[bool, str | None]:
    """Return whether the lock owns this binary and its verified cached path."""
    repo = Path(target).expanduser().resolve()
    lock_path = repo / ".arbiter" / "tooling.lock.json"
    if not lock_path.is_file():
        return False, None

    lock = load_lock(lock_path)
    catalog_tools = {tool["name"]: tool for tool in load_catalog()["analyzers"]}
    tool = next((item for item in catalog_tools.values() if item["binary"] == binary), None)
    if tool is None:
        return False, None
    entry = next((item for item in lock["tools"] if item.get("name") == tool["name"]), None)
    if entry is None:
        return False, None
    expected = entry.get("version")
    if not isinstance(expected, str):
        raise TypeError(f"invalid tooling lock version for analyzer: {tool['name']}")
    executable = _tool_executable_path(tool_cache_root(repo, lock_path), tool)
    status = _inspect_binary(tool, expected, executable=executable)
    return True, str(executable) if status["status"] == "ready" else None


def locked_cache_dir(target: str | Path) -> Path | None:
    repo = Path(target).expanduser().resolve()
    lock_path = repo / ".arbiter" / "tooling.lock.json"
    if not lock_path.is_file():
        return None
    lock = load_lock(lock_path)
    needs_cached_data = "semgrep_rules" in lock or any(
        isinstance(entry, dict) and entry.get("name") == "trivy"
        for entry in lock.get("tools", [])
    )
    return tool_cache_root(repo, lock_path) if needs_cached_data else None


def _install_python_tool(tool: dict[str, Any], expected: str, root: Path) -> None:
    environment = root / "python" / tool["name"]
    subprocess.run(
        [sys.executable, "-m", "venv", str(environment)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    package = tool.get("install_package")
    if not isinstance(package, str) or not package:
        raise ValueError(f"tool catalog has no install package for {tool['name']}")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
         f"{package}=={expected}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=1800,
    )


def _gitleaks_asset(version: str) -> tuple[str, str, str]:
    system = platform.system().lower()
    os_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system)
    machine = platform.machine().lower()
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if os_name is None or arch is None:
        raise ValueError(f"no gitleaks release build for {system}/{machine}")
    suffix = "zip" if os_name == "windows" else "tar.gz"
    filename = f"gitleaks_{version}_{os_name}_{arch}.{suffix}"
    return filename, f"gitleaks_{version}_checksums.txt", "gitleaks.exe" if os_name == "windows" else "gitleaks"


def _release_asset(tool: dict[str, Any], version: str) -> tuple[str, str, str]:
    release = tool.get("release")
    if not isinstance(release, dict):
        if tool.get("name") == "gitleaks":
            filename, checksum, binary = _gitleaks_asset(version)
            return filename, checksum, binary
        raise ValueError(f"tool catalog has no release metadata for {tool.get('name')}")

    systems = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    system = systems.get(platform.system().lower())
    machines = {
        "amd64": "x86_64",
        "i386": "i386",
        "i686": "i386",
        "x86_64": "x86_64",
        "arm64": "arm64",
        "aarch64": "aarch64",
        "armv7l": "armv7l",
        "ppc64le": "ppc64le",
        "s390x": "s390x",
    }
    machine = machines.get(platform.machine().lower())
    key = f"{system}-{machine}" if system and machine else ""
    assets = release.get("assets")
    template = assets.get(key) if isinstance(assets, dict) else None
    if not isinstance(template, str):
        raise ValueError(
            f"no {tool.get('name')} release for {platform.system()}/{platform.machine()}"
        )
    checksum_template = release.get("checksums")
    binary = release.get("binary")
    if not isinstance(checksum_template, str) or not isinstance(binary, str):
        raise ValueError(f"invalid release metadata for {tool.get('name')}")
    # Windows archives hold `trivy.exe`, not `trivy` (FAIL-135).
    if system == "windows" and not binary.endswith(".exe"):
        binary += ".exe"
    return template.format(version=version), checksum_template.format(version=version), binary


def _install_release_tool(tool: dict[str, Any], expected: str, root: Path) -> None:
    filename, checksums_name, binary = _release_asset(tool, expected)
    release = tool.get("release")
    repository = release.get("repository") if isinstance(release, dict) else "gitleaks/gitleaks"
    if not isinstance(repository, str) or not repository:
        raise ValueError(f"invalid release repository for {tool['name']}")
    base = f"https://github.com/{repository}/releases/download/v{expected}"
    with urllib.request.urlopen(f"{base}/{checksums_name}", timeout=60) as response:
        checksums_text = response.read().decode("utf-8")
    expected_digest = next(
        (parts[0] for line in checksums_text.splitlines()
         if len(parts := line.split()) >= 2 and Path(parts[-1].lstrip("*")).name == filename),
        None,
    )
    if expected_digest is None or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_digest):
        raise ValueError(f"release checksums do not list {filename}")
    with urllib.request.urlopen(f"{base}/{filename}", timeout=120) as response:
        archive = response.read()
    actual_digest = hashlib.sha256(archive).hexdigest()
    if actual_digest.lower() != expected_digest.lower():
        raise ValueError(f"checksum mismatch for {filename}")

    if filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            content = bundle.read(binary)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            member = next((item for item in bundle.getmembers()
                           if item.name == binary and item.isfile()), None)
            if member is None:
                raise ValueError(f"release archive does not contain {binary}")
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise ValueError(f"could not read {binary} from release archive")
            content = extracted.read()

    destination = _tool_executable_path(root, tool)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    if os.name != "nt":
        destination.chmod(0o755)


def _install_trivy_database(tool: dict[str, Any], root: Path) -> None:
    executable = _tool_executable_path(root, tool)
    cache = root / "trivy-cache"
    database = cache / "db" / "trivy.db"
    if database.is_file():
        return
    subprocess.run(
        [str(executable), "--cache-dir", str(cache), "image", "--download-db-only"],
        check=True,
        capture_output=True,
        text=True,
        timeout=900,
    )
    if not database.is_file():
        raise ValueError("Trivy completed database download but trivy.db is missing")


def _fetch_semgrep_rules(ref: str, root: Path) -> None:
    source = root / ".semgrep-rules-source"
    destination = root / "semgrep-rules"
    for path in (source, destination):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)
    source.mkdir()
    try:
        subprocess.run(["git", "-C", str(source), "init", "--quiet"], check=True,
                       capture_output=True, text=True, timeout=30)
        subprocess.run(["git", "-C", str(source), "remote", "add", "origin",
                        "https://github.com/semgrep/semgrep-rules.git"], check=True,
                       capture_output=True, text=True, timeout=30)
        subprocess.run(["git", "-C", str(source), "fetch", "--quiet", "--depth", "1", "origin", ref],
                       check=True, capture_output=True, text=True, timeout=600)
        subprocess.run(["git", "-C", str(source), "checkout", "--quiet", "FETCH_HEAD"],
                       check=True, capture_output=True, text=True, timeout=60)
        actual = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], check=True,
                                capture_output=True, text=True, timeout=30).stdout.strip()
        if actual != ref:
            raise ValueError(f"expected Semgrep rules {ref}, fetched {actual}")
        shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git"))
        (destination / ".arbiter-ref").write_text(ref + "\n", encoding="utf-8")
    finally:
        if source.exists():
            shutil.rmtree(source)



def _install_error(exc: Exception) -> str:
    detail = str(exc)
    output = getattr(exc, "stderr", None) or getattr(exc, "stdout", None)
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    if isinstance(output, str) and output.strip():
        detail = f"{detail}: {output.strip().splitlines()[-1][:300]}"
    return detail


def install_lock(
    target: str | Path,
    lock_path: str | Path | None = None,
    cache_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Install a repository's locked analyzers into its user cache, never its checkout."""
    repo = Path(target).expanduser().resolve()
    lock_file = Path(lock_path).expanduser() if lock_path else repo / ".arbiter" / "tooling.lock.json"
    if not lock_file.is_absolute():
        target_relative_lock = repo / lock_file
        lock_file = target_relative_lock if target_relative_lock.is_file() else lock_file.resolve()
    lock = load_lock(lock_file)
    current_digest = _catalog_digest()
    if lock.get("catalog_sha256") != current_digest:
        return [{
            "name": "tooling-catalog", "expected": lock.get("catalog_sha256"),
            "actual": current_digest, "status": "mismatch",
            "detail": "catalog changed; regenerate the tooling lock", "required": True,
        }]

    catalog = load_catalog()
    catalog_tools = {tool["name"]: tool for tool in catalog["analyzers"]}
    for entry in lock["tools"]:
        if not isinstance(entry, dict) or entry.get("name") not in catalog_tools:
            raise ValueError(f"tooling lock names unknown analyzer: {entry.get('name') if isinstance(entry, dict) else entry}")
        if not isinstance(entry.get("version"), str) or not isinstance(entry.get("required", True), bool):
            raise TypeError(f"invalid tooling lock entry for analyzer: {entry['name']}")
    if lock.get("semgrep_rules") is not None:
        rules = lock["semgrep_rules"]
        if not isinstance(rules, dict) or not isinstance(rules.get("ref"), str):
            raise TypeError("semgrep_rules in tooling lock must contain a ref string")

    cache_root = tool_cache_root(repo, lock_file, cache_dir)
    cache_root.mkdir(parents=True, exist_ok=True)
    failures: dict[str, str] = {}
    for entry in lock["tools"]:
        tool = catalog_tools[entry["name"]]
        existing = _inspect_binary(
            tool, entry["version"], executable=_tool_executable_path(cache_root, tool),
        )
        if existing["status"] != "ready":
            try:
                if tool["install_method"] == "pip":
                    _install_python_tool(tool, entry["version"], cache_root)
                elif tool["install_method"] == "release":
                    _install_release_tool(tool, entry["version"], cache_root)
                else:
                    raise ValueError(f"unsupported install method for {tool['name']}: {tool['install_method']}")
            except (OSError, subprocess.SubprocessError, urllib.error.URLError, ValueError,
                    tarfile.TarError, zipfile.BadZipFile) as exc:
                failures[tool["name"]] = _install_error(exc)

        if tool["name"] == "trivy" and tool["name"] not in failures:
            try:
                _install_trivy_database(tool, cache_root)
            except (OSError, subprocess.SubprocessError, urllib.error.URLError, ValueError,
                    tarfile.TarError, zipfile.BadZipFile) as exc:
                failures["trivy-database"] = _install_error(exc)

    rules = lock.get("semgrep_rules")
    if rules is not None and _cached_semgrep_rules(cache_root) != rules["ref"]:
        try:
            _fetch_semgrep_rules(rules["ref"], cache_root)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            failures["semgrep-rules"] = _install_error(exc)

    results = verify_lock(lock, cache_dir=cache_root, tool_root=cache_root)
    for result in results:
        if result["name"] in failures:
            result["actual"] = None
            result["status"] = "error"
            result["detail"] = f"installation failed: {failures[result['name']]}"
    return results


def has_required_failures(results: list[dict[str, Any]]) -> bool:
    return any(
        result.get("required", True) and result["status"] != "ready"
        for result in results
    )
