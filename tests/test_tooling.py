from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from arbiter import cli, tooling


def test_detect_languages_skips_dependency_directories(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "hidden.js").write_text("", encoding="utf-8")

    assert tooling.detect_languages(tmp_path) == {"python"}


def test_build_plan_includes_only_applicable_tools_and_grammars(tmp_path: Path, monkeypatch):
    (tmp_path / "main.py").write_text("", encoding="utf-8")
    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    monkeypatch.setattr(tooling.ast, "available", lambda: True)
    monkeypatch.setattr(tooling.ast, "cached_grammars", lambda: {"python", "hcl"})
    monkeypatch.setattr(
        tooling,
        "_inspect_binary",
        lambda tool, expected=None: {
            "name": tool["name"],
            "expected": expected or tool["version"],
            "actual": expected or tool["version"],
            "status": "ready",
            "detail": "installed",
        },
    )

    plan = tooling.build_plan(tmp_path, cache_dir=tmp_path / "cache")

    assert plan["languages"] == ["python", "terraform"]
    assert {tool["name"] for tool in plan["analyzers"]} == {
        "checkov", "semgrep", "bandit", "ruff", "gitleaks",
    }
    assert [grammar["name"] for grammar in plan["grammars"]] == ["hcl", "python"]
    assert plan["semgrep_rules"]["status"] == "missing"
    assert plan["lock"]["semgrep_rules"]["ref"] == tooling.load_catalog()["semgrep_rules_ref"]


@pytest.mark.parametrize(
    ("which", "returncode", "output", "expected_status", "actual"),
    [
        ("/usr/bin/ruff", 0, "ruff 0.15.11", "ready", "0.15.11"),
        ("/usr/bin/ruff", 0, "ruff 0.15.10", "mismatch", "0.15.10"),
        (None, 0, "", "missing", None),
        ("/usr/bin/ruff", 1, "cannot start", "error", None),
    ],
)
def test_inspect_binary_reports_installed_state(
    monkeypatch, which, returncode, output, expected_status, actual,
):
    tool = tooling.load_catalog()["analyzers"][-2]
    monkeypatch.setattr(tooling.shutil, "which", lambda _binary: which)
    monkeypatch.setattr(
        tooling.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=returncode,
            stdout=output,
            stderr="",
        ),
    )

    result = tooling._inspect_binary(tool)

    assert result["status"] == expected_status
    assert result["actual"] == actual


def test_inspect_binary_reports_timeout(monkeypatch):
    tool = tooling.load_catalog()["analyzers"][-2]
    monkeypatch.setattr(tooling.shutil, "which", lambda _binary: "/usr/bin/ruff")

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("ruff", 10)

    monkeypatch.setattr(tooling.subprocess, "run", timeout)

    result = tooling._inspect_binary(tool)

    assert result["status"] == "error"
    assert "could not read version" in result["detail"]


def test_verify_lock_flags_required_missing_but_not_optional_mismatch(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        tooling,
        "_inspect_binary",
        lambda tool, expected=None: {
            "name": tool["name"],
            "expected": expected,
            "actual": None,
            "status": "missing" if tool["name"] == "ruff" else "mismatch",
            "detail": "test",
        },
    )
    monkeypatch.setattr(tooling.ast, "available", lambda: True)
    monkeypatch.setattr(tooling.ast, "cached_grammars", lambda: {"python"})

    results = tooling.verify_lock({
        "schema_version": 1,
        "catalog_sha256": tooling._catalog_digest(),
        "tools": [
            {"name": "ruff", "version": "0.15.11", "required": True},
            {"name": "bandit", "version": "1.9.4", "required": False},
        ],
        "grammars": [{"name": "python", "required": True}],
    }, cache_dir=tmp_path)

    assert [result["status"] for result in results] == [
        "ready", "missing", "mismatch", "ready",
    ]
    assert tooling.has_required_failures(results)
    results[1]["required"] = False
    assert not tooling.has_required_failures(results)


def test_verify_lock_detects_catalog_drift(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(tooling.ast, "available", lambda: True)
    monkeypatch.setattr(tooling.ast, "cached_grammars", lambda: set())

    results = tooling.verify_lock({
        "schema_version": 1,
        "catalog_sha256": "previous-catalog",
        "tools": [],
        "grammars": [],
    }, cache_dir=tmp_path)

    assert results[0]["name"] == "tooling-catalog"
    assert results[0]["status"] == "mismatch"
    assert tooling.has_required_failures(results)


def test_tool_lock_round_trips(tmp_path: Path):
    lock = {
        "schema_version": 1,
        "catalog_sha256": "abc",
        "tools": [{"name": "ruff", "version": "0.15.11", "required": True}],
        "grammars": [],
    }
    path = tooling.write_lock(lock, tmp_path / ".arbiter" / "tooling.lock.json")

    assert tooling.load_lock(path) == lock
    assert json.loads(path.read_text(encoding="utf-8"))["tools"][0]["name"] == "ruff"


def test_tools_cli_writes_plan_lock_and_verify_uses_exit_status(tmp_path: Path, monkeypatch, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    expected_lock = {
        "schema_version": 1,
        "catalog_sha256": "abc",
        "tools": [{"name": "ruff", "version": "0.15.11", "required": True}],
        "grammars": [],
    }
    fake_plan = {
        "target": str(target),
        "languages": ["python"],
        "analyzers": [{
            "name": "ruff", "expected": "0.15.11", "actual": None,
            "status": "missing", "detail": "ruff is not on PATH",
        }],
        "grammars": [],
        "semgrep_rules": None,
        "lock": expected_lock,
    }
    monkeypatch.setattr(cli.tooling, "build_plan", lambda *_args, **_kwargs: fake_plan)
    lock_path = tmp_path / ".arbiter" / "tooling.lock.json"

    assert cli.main(["tools", "plan", str(target), "--write-lock", str(lock_path)]) == 0
    assert tooling.load_lock(lock_path) == expected_lock
    assert "No lock written" not in capsys.readouterr().out

    monkeypatch.setattr(cli.tooling, "load_lock", lambda _path: expected_lock)
    monkeypatch.setattr(cli.tooling, "verify_lock", lambda *_args, **_kwargs: [{
        "name": "ruff", "expected": "0.15.11", "actual": None,
        "status": "missing", "detail": "ruff is not on PATH", "required": True,
    }])
    assert cli.main(["tools", "verify", str(lock_path)]) == cli.EXIT_GATE_FAIL
    assert "required capabilities" in capsys.readouterr().out


def test_tools_plan_defaults_lock_to_target_repository(tmp_path: Path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    lock = {"schema_version": 1, "tools": [], "grammars": []}
    monkeypatch.setattr(cli.tooling, "build_plan", lambda *_args, **_kwargs: {
        "target": str(target),
        "languages": [],
        "analyzers": [],
        "grammars": [],
        "semgrep_rules": None,
        "lock": lock,
    })

    assert cli.main(["tools", "plan", str(target), "--write-lock"]) == cli.EXIT_OK
    assert tooling.load_lock(target / ".arbiter" / "tooling.lock.json") == lock


def test_tools_cli_verify_passes_optional_missing_component(monkeypatch, capsys):
    monkeypatch.setattr(cli.tooling, "load_lock", lambda _path: {"tools": [], "grammars": []})
    monkeypatch.setattr(cli.tooling, "verify_lock", lambda *_args, **_kwargs: [{
        "name": "ruff", "expected": "0.15.11", "actual": None,
        "status": "missing", "detail": "ruff is not on PATH", "required": False,
    }])

    assert cli.main(["tools", "verify", "lock.json"]) == cli.EXIT_OK
    assert "Tool verification passed" in capsys.readouterr().out
