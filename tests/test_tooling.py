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



def _ruff_lock(target: Path) -> Path:
    lock = {
        "schema_version": 1,
        "catalog_sha256": tooling._catalog_digest(),
        "tools": [{"name": "ruff", "version": "0.15.11", "required": True}],
        "grammars": [],
    }
    return tooling.write_lock(lock, target / ".arbiter" / "tooling.lock.json")


def test_install_lock_uses_lock_keyed_user_cache_without_checkout_binaries(tmp_path: Path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    lock_path = _ruff_lock(target)
    cache_base = tmp_path / "user-cache"
    monkeypatch.setenv("ARBITER_TOOL_CACHE", str(cache_base))

    def install_fake(tool, _expected, root):
        executable = tooling._tool_executable_path(root, tool)
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text("cached analyzer", encoding="utf-8")

    monkeypatch.setattr(tooling, "_install_python_tool", install_fake)
    monkeypatch.setattr(tooling.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=0, stdout="ruff 0.15.11", stderr="",
    ))

    results = tooling.install_lock(target)

    cache_root = tooling.tool_cache_root(target, lock_path)
    assert not tooling.has_required_failures(results)
    assert (cache_root / "python" / "ruff").is_dir()
    assert list((target / ".arbiter").iterdir()) == [lock_path]
    locked, executable = tooling.resolve_locked_binary(target, "ruff")
    assert locked and executable == str(tooling._tool_executable_path(cache_root, tooling.load_catalog()["analyzers"][-2]))


def test_locked_missing_cache_does_not_fall_back_to_path(tmp_path: Path, monkeypatch):
    from arbiter.adapters import Adapter

    target = tmp_path / "repo"
    target.mkdir()
    _ruff_lock(target)
    monkeypatch.setenv("ARBITER_TOOL_CACHE", str(tmp_path / "empty-cache"))
    monkeypatch.setattr(tooling.shutil, "which", lambda _binary: "/global/bin/ruff")
    context = SimpleNamespace(repos=[SimpleNamespace(path=str(target))])

    assert Adapter(name="ruff", binaries=["ruff"]).missing_binaries(context) == ["ruff"]


def test_adapter_invokes_locked_cache_executable(tmp_path: Path, monkeypatch):
    from arbiter.adapters import Adapter

    target = tmp_path / "repo"
    target.mkdir()
    lock_path = _ruff_lock(target)
    cache_root = tooling.tool_cache_root(target, lock_path, tmp_path / "cache")
    executable = tooling._tool_executable_path(cache_root, tooling.load_catalog()["analyzers"][-2])
    executable.parent.mkdir(parents=True)
    executable.write_text("cached analyzer", encoding="utf-8")
    monkeypatch.setenv("ARBITER_TOOL_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(tooling.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=0, stdout="ruff 0.15.11", stderr="",
    ))
    calls = []

    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return "cached result", ""

    def popen(argv, **_kwargs):
        calls.append(argv)
        return Process()

    monkeypatch.setattr("arbiter.adapters.subprocess.Popen", popen)
    output, code = Adapter(name="ruff", binaries=["ruff"], argv=["ruff", "--version"]).invoke(str(target))

    assert code == 0
    assert output == "cached result"
    assert calls[0][0] == str(executable)


def test_tools_install_cli_reports_required_failure(tmp_path: Path, monkeypatch, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.setattr(cli.tooling, "install_lock", lambda *_args, **_kwargs: [{
        "name": "ruff", "expected": "0.15.11", "actual": None,
        "status": "error", "detail": "installation failed", "required": True,
    }])

    assert cli.main(["tools", "install", str(target)]) == cli.EXIT_GATE_FAIL
    assert "Tool installation failed" in capsys.readouterr().out



def test_install_lock_reports_package_failure_and_keeps_cache_unpublished(tmp_path: Path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    _ruff_lock(target)
    cache_base = tmp_path / "user-cache"
    monkeypatch.setenv("ARBITER_TOOL_CACHE", str(cache_base))

    def fail_install(_tool, _expected, _root):
        raise subprocess.CalledProcessError(1, ["pip", "install"], stderr="package unavailable")

    monkeypatch.setattr(tooling, "_install_python_tool", fail_install)
    results = tooling.install_lock(target)

    assert tooling.has_required_failures(results)
    ruff = next(result for result in results if result["name"] == "ruff")
    assert ruff["status"] == "error"
    assert "package unavailable" in ruff["detail"]
    executable = tooling._tool_executable_path(
        tooling.tool_cache_root(target), tooling.load_catalog()["analyzers"][-2],
    )
    assert not executable.exists()



def test_install_committed_lock_resolves_each_cached_analyzer(tmp_path: Path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    tooling.write_lock(
        tooling.load_lock(Path(__file__).parents[1] / ".arbiter" / "tooling.lock.json"),
        target / ".arbiter" / "tooling.lock.json",
    )
    cache_base = tmp_path / "user-cache"
    monkeypatch.setenv("ARBITER_TOOL_CACHE", str(cache_base))
    versions: dict[str, str] = {}

    def fake_install(tool, expected, root):
        executable = tooling._tool_executable_path(root, tool)
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text("cached analyzer", encoding="utf-8")
        versions[tool["binary"]] = expected

    def fake_rules(ref, root):
        rules = root / "semgrep-rules"
        rules.mkdir()
        (rules / ".arbiter-ref").write_text(ref, encoding="utf-8")

    monkeypatch.setattr(tooling, "_install_python_tool", fake_install)
    monkeypatch.setattr(tooling, "_install_release_tool", fake_install)
    monkeypatch.setattr(tooling, "_fetch_semgrep_rules", fake_rules)
    def fake_version(args, **_kwargs):
        binary = Path(args[0]).name.removesuffix(".exe")
        return SimpleNamespace(returncode=0, stdout=f"{binary} {versions[binary]}", stderr="")

    monkeypatch.setattr(tooling.subprocess, "run", fake_version)

    results = tooling.install_lock(target, cache_dir=cache_base)

    assert not tooling.has_required_failures(results)
    assert {result["name"] for result in results if result["status"] == "ready"} == {
        "tooling-catalog", "checkov", "semgrep", "bandit", "ruff", "gitleaks", "semgrep-rules",
    }
    for tool in tooling.load_catalog()["analyzers"]:
        locked, executable = tooling.resolve_locked_binary(target, tool["binary"])
        assert locked and executable is not None
        assert Path(executable).is_relative_to(cache_base)
    assert not any(path.name in {tool["binary"] for tool in tooling.load_catalog()["analyzers"]}
                   for path in target.rglob("*"))



def test_probe_diagnostics_respect_locked_cache(tmp_path: Path, monkeypatch, capsys):
    from arbiter.adapters import Adapter
    from arbiter.probes import Probe
    from arbiter import engine, graph, inventory

    target = tmp_path / "repo"
    target.mkdir()
    _ruff_lock(target)
    monkeypatch.setenv("ARBITER_TOOL_CACHE", str(tmp_path / "empty-cache"))
    monkeypatch.setattr(tooling.shutil, "which", lambda _binary: "/global/bin/ruff")
    adapter = Adapter(name="ruff", binaries=["ruff"])
    probe = Probe(
        name="ruff", dimensions=["quality"], checks=1, run=lambda _ctx: [],
        binaries=["ruff"], binary_checker=adapter.missing_binaries,
    )
    monkeypatch.setattr(cli, "_load_adapters", lambda _no_adapters: None)
    monkeypatch.setattr(cli, "REGISTRY", [probe])
    repo = SimpleNamespace(path=str(target), id="repo")
    inv = SimpleNamespace(stacks=set())
    monkeypatch.setattr(engine, "resolve_targets", lambda *_args, **_kwargs: ("repo", [repo], [], {}))
    monkeypatch.setattr(inventory, "build_inventory", lambda _repos: inv)
    monkeypatch.setattr(graph, "build_graph", lambda _inventory: [])

    assert cli.cmd_probes(SimpleNamespace(no_adapters=False, target=str(target))) == cli.EXIT_OK
    assert "skip — missing binary: ruff" in capsys.readouterr().out


def test_ab_tool_preflight_respects_locked_cache(tmp_path: Path, monkeypatch):
    from arbiter import adapters, engine, inventory
    from arbiter.ab import Arm, run_arm
    from arbiter.adapters import Adapter

    target = tmp_path / "repo"
    target.mkdir()
    _ruff_lock(target)
    monkeypatch.setenv("ARBITER_TOOL_CACHE", str(tmp_path / "empty-cache"))
    monkeypatch.setattr(tooling.shutil, "which", lambda _binary: "/global/bin/ruff")
    adapter = Adapter(name="ruff", binaries=["ruff"])
    repo = SimpleNamespace(path=str(target), id="repo")
    monkeypatch.setattr(adapters, "load_all", lambda: [adapter])
    monkeypatch.setattr(engine, "resolve_targets", lambda *_args, **_kwargs: ("repo", [repo], [], {}))
    monkeypatch.setattr(inventory, "build_inventory", lambda _repos: SimpleNamespace(stacks=set(), by_repo={}))

    result = run_arm(Arm(name="locked", kind="tool", tool="ruff"), [str(target)], None, {})

    assert result.error == "missing binary: ruff"
