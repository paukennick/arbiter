"""Plan and verify the external tools Arbiter can use."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
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


def _inspect_binary(tool: dict[str, Any], expected: str | None = None) -> dict[str, Any]:
    binary = tool["binary"]
    expected_version = expected or tool["version"]
    executable = shutil.which(binary)
    if executable is None:
        return {
            "name": tool["name"],
            "expected": expected_version,
            "actual": None,
            "status": "missing",
            "detail": f"{binary} is not on PATH",
        }

    try:
        result = subprocess.run(
            [executable, *tool["version_args"]],
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


def verify_lock(lock: dict[str, Any], cache_dir: str | Path | None = None) -> list[dict[str, Any]]:
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
        result = _inspect_binary(tool, expected)
        result["required"] = required
        results.append(result)

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
        actual = _cached_semgrep_rules(cache_dir)
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


def has_required_failures(results: list[dict[str, Any]]) -> bool:
    return any(
        result.get("required", True) and result["status"] != "ready"
        for result in results
    )
