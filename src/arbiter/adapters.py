"""Declarative adapters for external analyzers.

An adapter is a TOML manifest: how to invoke a tool, how to parse it, and how
to map its output onto Finding. No Python is written per tool, which is what
keeps the long tail of languages tractable.

A tool that is not installed is not a failure. The adapter reports `skipped`
with the missing binary named, and the coverage figure drops accordingly.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import Finding, Location
from .probes import Probe, ProbeContext, register

PACKS = Path(__file__).parent / "packs" / "adapters"


# ---------------------------------------------------------------------------
# Minimal selector: $, $.a.b, $.a[0].b, trailing [*] to fan out
# ---------------------------------------------------------------------------

def select(doc: Any, expr: str) -> list[Any]:
    if not expr or expr == "$":
        return doc if isinstance(doc, list) else [doc]
    e = expr[2:] if expr.startswith("$.") else (expr[1:] if expr.startswith("$") else expr)
    cur: Any = doc
    fan = e.endswith("[*]")
    if fan:
        e = e[:-3]
    for part in [p for p in re.split(r"\.(?![^\[]*\])", e) if p]:
        m = re.fullmatch(r"([^\[]*)\[(\d+)\]", part)
        if m:
            key, idx = m.group(1), int(m.group(2))
            if key:
                cur = cur.get(key) if isinstance(cur, dict) else None
            if isinstance(cur, list) and idx < len(cur):
                cur = cur[idx]
            else:
                return []
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            # A tool (checkov, across multiple detected frameworks) can emit a
            # list of sibling result objects instead of one. Fan the key
            # lookup across them and flatten, rather than failing the whole
            # path because *a* list turned up where a dict was expected.
            nxt: list[Any] = []
            for item in cur:
                if not isinstance(item, dict):
                    continue
                v = item.get(part)
                if isinstance(v, list):
                    nxt.extend(v)
                elif v is not None:
                    nxt.append(v)
            cur = nxt
        else:
            return []
        if cur is None:
            return []
    if fan:
        return cur if isinstance(cur, list) else []
    return cur if isinstance(cur, list) else [cur]


def dig(obj: Any, path: str, default: Any = None) -> Any:
    if not path:
        return default
    cur = obj
    for part in path.split("."):
        m = re.fullmatch(r"([^\[]*)\[(\d+)\]", part)
        if m:
            key, idx = m.group(1), int(m.group(2))
            if key:
                cur = cur.get(key) if isinstance(cur, dict) else None
            if isinstance(cur, list) and idx < len(cur):
                cur = cur[idx]
            else:
                return default
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
        else:
            return default
        if cur is None:
            return default
    return cur


@dataclass
class Adapter:
    name: str
    dimensions: list[str] = field(default_factory=lambda: ["quality"])
    stacks: list[str] | None = None
    binaries: list[str] = field(default_factory=list)
    network: bool = False
    timeout: int = 300
    argv: list[str] = field(default_factory=list)
    cwd: str = "{workdir}"
    parse: str = "json"
    ok_exit: list[int] = field(default_factory=lambda: [0, 1])
    checks: int = 10
    mapping: dict = field(default_factory=dict)
    version_argv: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    # -- lifecycle ---------------------------------------------------------
    def missing_binaries(self) -> list[str]:
        return [b for b in self.binaries if shutil.which(b) is None]

    def tool_version(self) -> str:
        if not self.version_argv:
            return ""
        try:
            version_argv = list(self.version_argv)
            version_argv[0] = shutil.which(version_argv[0]) or version_argv[0]
            r = subprocess.run(version_argv, capture_output=True, text=True, timeout=20)
            return (r.stdout or r.stderr).strip().split("\n")[0][:60]
        except Exception:
            return ""

    def invoke(self, workdir: str) -> tuple[str, int]:
        """Run the tool, and make sure a timeout actually stops it.

        `subprocess.run(timeout=...)` kills the process it started and nothing
        else. Several of these analyzers fan out with multiprocessing, so a
        timeout left a pool of orphaned workers alive. Observed after checkov
        deadlocked on a one-million-line repository: the parent was killed on
        timeout, and four workers were still resident twenty minutes later,
        competing for CPU with every scan that followed.

        Starting the tool in its own process group and signalling the group is
        what makes the timeout mean what it says.
        """
        argv = [a.replace("{workdir}", workdir) for a in self.argv]
        if argv:
            # On Windows, Popen(shell=False) calls CreateProcess directly,
            # which -- unlike cmd.exe -- does not search PATHEXT for a bare
            # name. A tool whose console-script entry point is a .cmd/.bat
            # shim (checkov) resolves fine via shutil.which() in
            # missing_binaries() but then fails every invocation with
            # WinError 2. Resolving to the full, extensioned path here makes
            # invocation match the availability check.
            argv[0] = shutil.which(argv[0]) or argv[0]
        cwd = self.cwd.replace("{workdir}", workdir) if self.cwd else None
        env = dict(os.environ)
        env.setdefault("PYTHONIOENCODING", "utf-8")

        popen_kwargs: dict = {}
        if hasattr(os, "setsid"):
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=cwd, env=env, **popen_kwargs,
        )
        try:
            out, _err = proc.communicate(timeout=self.timeout)
            return out, proc.returncode
        except BaseException:
            self._kill_group(proc)
            raise

    @staticmethod
    def _kill_group(proc: "subprocess.Popen") -> None:
        """SIGTERM the whole group, then SIGKILL whatever ignored it."""
        import signal as _signal
        if not hasattr(os, "killpg"):
            Adapter._kill_tree(proc)
            return
        for sig in (_signal.SIGTERM, _signal.SIGKILL):
            try:
                os.killpg(os.getpgid(proc.pid), sig)
            except (ProcessLookupError, PermissionError, OSError):
                break
            try:
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                continue
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    @staticmethod
    def _kill_tree(proc: "subprocess.Popen") -> None:
        """Kill a process and its descendants where there is no process group.

        Windows has neither `os.killpg` nor `SIGKILL`, so the group signalling
        above has nothing to signal — reaching it there raised AttributeError
        and the analyzer outlived its own timeout. `taskkill /T` walks the child
        tree from the parent PID, which is the nearest equivalent: killing only
        the direct child leaves the fanned-out workers running, which is the
        failure this whole path exists to prevent.
        """
        taskkill = shutil.which("taskkill")
        if taskkill:
            try:
                subprocess.run(
                    [taskkill, "/T", "/F", "/PID", str(proc.pid)],
                    capture_output=True, timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                proc.kill()
        else:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    # -- normalize ---------------------------------------------------------
    def parse_output(self, out: str) -> list[Any]:
        out = out.strip()
        if not out:
            return []
        if self.parse == "jsonlines":
            rows = []
            for line in out.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
            return rows
        try:
            doc = json.loads(out)
        except Exception:
            # tools sometimes emit a banner before the JSON body
            m = re.search(r"[\[{]", out)
            if not m:
                return []
            try:
                doc = json.loads(out[m.start():])
            except Exception:
                return []
        expr = self.mapping.get("findings", "$")
        rows = select(doc, expr)
        # Some tools (checkov with several frameworks) emit a LIST of result
        # objects rather than one. Fan the selector across the elements.
        if not rows and isinstance(doc, list) and expr.startswith("$."):
            for element in doc:
                rows.extend(select(element, expr))
        return rows

    def to_findings(self, rows: list[Any], repo_id: str, workdir: str) -> list[Finding]:
        m = self.mapping
        sev_table = {str(k).lower(): v for k, v in (m.get("severity_table") or {}).items()}
        remediation_table = {str(k): v for k, v in (m.get("remediation_table") or {}).items()}
        out: list[Finding] = []
        for row in rows:
            rule = str(dig(row, m.get("rule_id", ""), "") or "unknown")
            title = str(dig(row, m.get("title", ""), "") or rule)
            path = str(dig(row, m.get("path", ""), "") or "")
            if path.startswith(workdir):
                path = os.path.relpath(path, workdir)
            # removeprefix, not lstrip: lstrip("./") eats the dot in ".github"
            while path.startswith("./"):
                path = path[2:]
            path = path.lstrip("/")
            line = dig(row, m.get("line", ""), 0)
            try:
                line = int(line or 0)
            except (TypeError, ValueError):
                line = 0
            if m.get("severity_const"):
                sev = m["severity_const"]
            else:
                raw_sev = str(dig(row, m.get("severity", ""), "") or "").lower()
                sev = sev_table.get(raw_sev, m.get("severity_default", "medium"))
            logical = str(dig(row, m.get("logical", ""), "") or "")
            desc = str(dig(row, m.get("description", ""), "") or "")
            # A curated, per-rule fix (remediation_table) beats a raw dug
            # field: "see the tool's docs" is not a fix, and a specific rule
            # id maps to one well-known mitigation, not a URL to go read.
            remediation = remediation_table.get(rule, "")
            if not remediation:
                remediation = str(dig(row, m.get("remediation", ""), "") or "").strip()
                if remediation and m.get("remediation_format"):
                    remediation = m["remediation_format"].format(value=remediation)
                elif remediation.startswith(("http://", "https://")):
                    remediation = f"See {self.name}'s guidance: {remediation}"
            if not remediation:
                remediation = (m.get("remediation_default", "") or "").format(rule_id=rule)
            out.append(Finding(
                rule_id=f"{self.name}/{rule}",
                title=title[:200],
                dimension=m.get("dimension", self.dimensions[0]),
                severity=sev,
                confidence=m.get("confidence", "high"),
                repo_id=repo_id,
                probe=self.name,
                location=Location(path=path, start_line=line, logical=logical),
                description=desc[:1000],
                remediation=remediation[:500],
                evidence=f"{rule}@{path}:{logical}" if logical else f"{rule}@{path}",
                tags=["external-tool", self.name],
            ))
        return out

    def run(self, ctx: ProbeContext) -> list[Finding]:
        findings: list[Finding] = []
        for repo in ctx.repos:
            try:
                out, code = self.invoke(repo.path)
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"{self.name} timed out after {self.timeout}s")
            if code not in self.ok_exit and not out.strip():
                raise RuntimeError(f"{self.name} exited {code}")
            findings.extend(self.to_findings(self.parse_output(out), repo.id, repo.path))
        return findings


def load_adapter(path: Path) -> Adapter:
    data = tomllib.loads(path.read_text())
    req = data.get("requires", {})
    inv = data.get("invoke", {})
    sel = data.get("selects", {})
    return Adapter(
        name=data["name"],
        dimensions=data.get("dimensions", ["quality"]),
        stacks=sel.get("stacks"),
        binaries=req.get("binaries", []),
        network=req.get("network", False),
        timeout=int(req.get("timeout", 300)),
        argv=inv.get("argv", []),
        cwd=inv.get("cwd", "{workdir}"),
        parse=inv.get("parse", "json"),
        ok_exit=inv.get("ok_exit", [0, 1]),
        version_argv=inv.get("version_argv", []),
        checks=int(data.get("checks", 10)),
        mapping=data.get("map", {}),
        raw=data,
    )


def load_all(extra_dirs: list[str] | None = None) -> list[Adapter]:
    out: list[Adapter] = []
    dirs = [PACKS] + [Path(d) for d in (extra_dirs or [])]
    for d in dirs:
        if not d.is_dir():
            continue
        # `.adapter.toml`, not `.toml`: a bare `ruff.toml` anywhere in a scanned
        # tree is picked up by ruff itself as its own configuration and breaks it.
        for p in sorted(d.glob("*.adapter.toml")):
            try:
                out.append(load_adapter(p))
            except Exception:
                continue
    return out


_REGISTERED: set[str] = set()


def register_adapters(extra_dirs: list[str] | None = None) -> list[Adapter]:
    """Idempotent: the CLI and the library API can both call this safely.

    Registration matters even for tools that are not installed — an adapter
    that never registers is an adapter that never counts against coverage,
    which would quietly flatter a thin scan.
    """
    adapters = [a for a in load_all(extra_dirs) if a.name not in _REGISTERED]
    for a in adapters:
        _REGISTERED.add(a.name)
        register(Probe(
            name=a.name,
            dimensions=a.dimensions,
            checks=a.checks,
            run=a.run,
            stacks=a.stacks,
            binaries=a.binaries,
            network=a.network,
            version=a.tool_version() or "",
        ))
    return adapters
