"""The scan pipeline: acquire → inventory → plan → execute → normalize →
correlate → score → report.

Stages are separate so each is testable on its own and so a probe failure is
contained: one probe erroring degrades to 'not assessed' for that probe and
never fails the run.
"""
from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import random
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .core import (
    FINGERPRINT_SCHEME,
    Finding,
    ProbeOutcome,
    RepoInfo,
    Report,
    assign_occurrences,
)
from .graph import build_graph
from .inventory import acquire_one, build_inventory
from .policy import (
    PROFILES,
    apply_severity_overrides,
    apply_suppressions,
    compute_scorecard,
    evaluate_gate,
)
from .probes import REGISTRY, Probe, ProbeContext
from .scope_notes import apply_scope_notes

ARBITER_VERSION = "0.1.0"

# Above this share of source lines in languages without a rule pack, the grade
# is withheld the way a partial scan's is (ARB-144); the same limit applies to
# the share of source-like files the walk did not read (ARB-150).
UNASSESSED_SOURCE_LIMIT = 0.5
# Withholding tokens a stronger cause may replace: not withheld, or withheld
# for coverage (including coverage the operator's --only/--skip explains). A
# partial scan's token stays: its gate is about the changed files (ARB-151).
_OVERRIDABLE = ("", "coverage", "probes_selected")


def _withhold(report: Report, by: str, reason: str) -> None:
    """Withhold the grade, naming why in a token the gate reads (ARB-152)."""
    report.scorecard.withheld = True
    report.scorecard.overall = None
    report.scorecard.withheld_reason = reason
    report.scorecard.withheld_by = by


def _reason_counts(skipped: dict) -> str:
    return ", ".join(f"{n} {r}" for r, n in (skipped.get("by_reason") or {}).items())


def _not_in_inventory_reason(inv, repo_id: str, path: str) -> str:
    """Why a path that exists on disk is not in the inventory: under a
    directory the walk skipped, a link it did not follow, or ignored by git."""
    whole = inv.whole or inv
    for s in whole.skipped:
        if s["repo_id"] != repo_id:
            continue
        if s["kind"] == "file" and s["path"] == path:
            return s["reason"]
        if s["kind"] == "dir" and (path == s["path"] or path.startswith(s["path"] + "/")):
            return f"under {s['path']}/: {s['reason']}"
    return "not in the inventory"


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Two tools finding the same defect is one defect.

    Exact fingerprint matches collapse. Different tools produce different
    fingerprints for the same issue, so a second pass collapses findings that
    share a repo, path, line and normalized title.
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id not in seen:
            seen[f.id] = f
            continue
        keep = seen[f.id]
        if keep.severity != f.severity:
            from .core import SEV_RANK
            if SEV_RANK.get(f.severity, 99) < SEV_RANK.get(keep.severity, 99):
                seen[f.id] = f
    out = list(seen.values())

    by_site: dict[tuple, Finding] = {}
    final: list[Finding] = []
    for f in out:
        key = (
            f.repo_id,
            f.location.path,
            f.location.start_line,
            "".join(ch for ch in f.title.lower() if ch.isalnum())[:48],
        )
        if key[1] and key[2] and key in by_site:
            existing = by_site[key]
            if existing.probe != f.probe:
                if f.probe not in existing.tags:
                    existing.tags.append(f"also:{f.probe}")
                continue
        by_site[key] = f
        final.append(f)
    return final


# Baseline formats. 1.0 ids were line-free fingerprints only, so same-evidence
# repeats in one file shared one id. 1.1 ids carry the occurrence ordinal
# (ARB-080) and the file says so with `fingerprint: "occurrence-v1"`.
BASELINE_SCHEMA = "1.1"
BASELINE_FINGERPRINT = FINGERPRINT_SCHEME


def _read_baseline(path: str | None) -> dict | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        ids = data.get("ids", [])
    except (OSError, ValueError, AttributeError, TypeError):
        return None
    if not isinstance(ids, list):
        return None
    return data


def baseline_is_legacy(data: dict) -> bool:
    """True for a baseline cut before occurrence ordinals (schema 1.0)."""
    return data.get("fingerprint") != BASELINE_FINGERPRINT


def baseline_matches(f: Finding, known: set[str], legacy: bool) -> bool:
    """Whether `f` is a finding the baseline already accepted.

    A legacy baseline recorded one id for every same-evidence repeat in a
    file, because they all collapsed into it. Each of those repeats was in
    the accepted state, so each still matches: an upgrade must not turn a
    green gate red on code nobody touched. A current baseline lists every
    occurrence, so a repeat added after it was cut is new.
    """
    return f.id in known or (legacy and f.fingerprint_base in known)


def apply_baseline(findings: list[Finding], baseline_path: str | None) -> None:
    """Label each finding new / existing against a stored baseline."""
    data = _read_baseline(baseline_path)
    if data is None:
        return
    known = {str(x) for x in data.get("ids", [])}
    legacy = baseline_is_legacy(data)
    for f in findings:
        f.status = "existing" if baseline_matches(f, known, legacy) else "new"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def write_baseline(report: Report, path: str, migrate_from: str | None = None) -> int:
    """Write the ids of `report`'s active findings as a baseline.

    With `migrate_from` (an earlier baseline, legacy or current), the result
    is that baseline carried into the current id format instead of a re-cut:
    a finding in `report` is kept when the old baseline accepted it, by the
    rule in `baseline_matches`, and everything else stays out, so whatever
    was new against the old baseline is still new against the migrated one.
    Old ids with no finding in `report` are kept too: migrating changes the
    id format, never what was accepted, so `created` keeps the old date (omni
    doctor reads it to tell whether the baseline predates a fix).
    """
    active = [f for f in report.findings if not f.suppressed]
    extra: dict = {}
    old: dict = {}
    if migrate_from:
        old = _read_baseline(migrate_from)
        if old is None:
            raise ValueError(f"{migrate_from}: not a readable baseline")
        known = {str(x) for x in old.get("ids", [])}
        legacy = baseline_is_legacy(old)
        kept = {f.id for f in active if baseline_matches(f, known, legacy)}
        matched = kept | {f.fingerprint_base for f in active if f.id in kept}
        ids = sorted(kept | (known - matched))
        extra = {"migrated_from": {"schema_version": old.get("schema_version", "1.0"),
                                   "ids": len(known), "at": _now()}}
        # Carry what omni records beside the ids (commit, config_hash).
        extra.update({k: v for k, v in old.items()
                      if k not in {"schema_version", "fingerprint", "created", "system",
                                   "ids", "migrated_from"}})
    else:
        ids = sorted({f.id for f in active})
    # A report from before ARB-080 has collapsed ids; cutting it as 1.1 would
    # make every repeat it hid read as new on the next run.
    current = report.fingerprint == FINGERPRINT_SCHEME
    if migrate_from and not current:
        raise ValueError("migrating a baseline needs a report from this version "
                         "(its findings carry occurrence ids); re-run the scan first")
    marker = {"schema_version": BASELINE_SCHEMA, "fingerprint": BASELINE_FINGERPRINT} \
        if current else {"schema_version": "1.0"}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({
        **marker,
        "created": (old.get("created") if migrate_from else None) or _now(),
        "system": report.system,
        "ids": ids,
        **extra,
    }, indent=2), encoding="utf-8")
    return len(ids)


def resolve_targets(targets: list[str], system_path: str | None) -> tuple[str, list[RepoInfo], list[str], dict]:
    """Return (system_name, repos, tempdirs, system_manifest)."""
    tempdirs: list[str] = []
    if system_path:
        from .policy import load_system
        manifest = load_system(system_path)
        repos: list[RepoInfo] = []
        base = Path(system_path).parent
        for entry in manifest.get("repos", []):
            src = entry.get("source") or entry.get("path") or ""
            if not src.startswith(("http", "git@", "ssh://")):
                cand = Path(src)
                if not cand.is_absolute():
                    src = str((base / src).resolve())
            info, tmp = acquire_one(
                src, repo_id=entry.get("id", "repo"), role=entry.get("role", ""), ref=entry.get("ref", "")
            )
            repos.append(info)
            if tmp:
                tempdirs.append(tmp)
        return manifest.get("system", "system"), repos, tempdirs, manifest

    repos = []
    for i, t in enumerate(targets):
        rid = "root" if len(targets) == 1 else Path(t.rstrip("/")).name or f"repo{i}"
        info, tmp = acquire_one(t, repo_id=rid)
        repos.append(info)
        if tmp:
            tempdirs.append(tmp)
    name = repos[0].id if len(repos) == 1 else "adhoc-system"
    return name, repos, tempdirs, {}


def _requested_path(raw: str, repos: list[RepoInfo]) -> str:
    """One `--only-files` entry as the inventory spells it: forward slashes,
    a literal leading `./` removed (never the dot of `.husky`), and an
    absolute path under a target made relative to it."""
    path = str(raw).strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if os.path.isabs(path):
        for r in repos:
            root = str(Path(r.path).resolve()).replace("\\", "/").rstrip("/") + "/"
            full = str(Path(path).resolve()).replace("\\", "/")
            if full.startswith(root):
                return full[len(root):]
    return path.rstrip("/")


def _record_probe_error(oc: ProbeOutcome, exc: Exception) -> None:
    from .judgement import Unavailable
    if isinstance(exc, Unavailable):
        # A probe that could not be configured is NOT-ASSESSED, which is a
        # coverage fact, not an error. Reporting it as an error would be
        # noisy; reporting it as a clean pass would be a lie.
        oc.status, oc.reason = "skipped", str(exc)[:300]
    else:
        oc.status = "error"
        oc.reason = f"{type(exc).__name__}: {exc}"[:300]


def adapter_workers(config: dict) -> int:
    """How many external analyzers run at once: `probes.adapters_parallel`,
    default min(4, cpu count); 1 runs them one after another."""
    raw = (config.get("probes") or {}).get("adapters_parallel")
    if raw is None:
        return min(4, os.cpu_count() or 1)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return 1


def _run_external_probes(
    deferred: list[tuple[int, Probe, ProbeOutcome]],
    ctx: ProbeContext,
    cache,
    config: dict,
    verify: bool,
    workers: int,
    findings_by_slot: dict[int, list[Finding]],
    rng: random.Random | None = None,
) -> None:
    """Run the adapters that were cleared to run, concurrently, through the
    adapter memo (ARB-047).

    The cache is consulted and written on this thread only; the pool runs
    `probe.run` and nothing else. Each adapter gets a shallow copy of the
    context: `run_with_cache` swaps `ctx.inventory` while a native probe
    runs, and an adapter filtering its findings against a narrowed
    inventory would drop real ones. Results are recorded in registry order
    whatever order the pool finished them in, so the report's bytes do not
    depend on the scheduler.
    """
    from . import cache as _cache

    to_run: list[tuple[int, Probe, ProbeOutcome, str | None, list[dict] | None]] = []
    hits: list[tuple[int, Probe, ProbeOutcome, str, list[dict]]] = []
    if cache is not None:
        inputs = _cache.adapter_inputs_digest(ctx.inventory, ctx.repos)
        for slot, probe, oc in deferred:
            k = _cache.adapter_key(probe.name, probe.version,
                                   _cache.rules_hash(config, probe), inputs)
            cached = cache.get(probe.name, k)
            if cached is None:
                to_run.append((slot, probe, oc, k, None))
                continue
            try:
                replay = [Finding.from_dict(d) for d in cached]
            except (AttributeError, KeyError, TypeError, ValueError):  # a malformed entry is a miss
                to_run.append((slot, probe, oc, k, None))
                continue
            hits.append((slot, probe, oc, k, cached))
            oc.status, oc.reason = "ran", _cache.REPLAY_REASON
            oc.finding_count = len(replay)
            findings_by_slot[slot] = replay
    else:
        to_run = [(slot, probe, oc, None, None) for slot, probe, oc in deferred]

    if verify and hits:
        # One memoised adapter per scan is re-run and compared, the way a
        # sample of file entries is; its replay is withdrawn below if the
        # fresh answer differs.
        picked = (rng or random.SystemRandom()).randrange(len(hits))
        to_run.append(hits.pop(picked))
        to_run.sort(key=lambda item: item[0])

    def work(item):
        _slot, probe, oc, _k, _cached = item
        t0 = time.time()
        try:
            produced = probe.run(copy.copy(ctx)) or []
        except Exception as exc:  # noqa: BLE001 - a probe that raises becomes an error outcome, never a silent pass
            _record_probe_error(oc, exc)
            produced = None
        oc.duration_s = round(time.time() - t0, 3)
        return produced

    if workers > 1 and len(to_run) > 1:
        with ThreadPoolExecutor(max_workers=min(workers, len(to_run))) as pool:
            results = list(pool.map(work, to_run))
    else:
        results = [work(item) for item in to_run]

    for (slot, probe, oc, k, cached), produced in zip(to_run, results):
        if produced is None:
            findings_by_slot.pop(slot, None)
            continue
        fresh = [f.to_dict() for f in produced]
        report = list(produced)
        oc.status = "ran"
        if cached is not None:
            cache.verified += 1
            if _cache._canonical(fresh) != _cache._canonical(cached):
                cache.divergent += 1
                report.append(_cache.adapter_divergence(probe.name, cached, fresh))
                oc.reason = _cache.DIVERGED_REASON
            else:
                oc.reason = _cache.VERIFIED_REASON
        if k is not None:
            cache.put(probe.name, k, fresh)
        oc.finding_count = len(report)
        findings_by_slot[slot] = report


def run_scan(
    targets: list[str],
    config: dict,
    system_path: str | None = None,
    profile: str | None = None,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    baseline: str | None = None,
    keep_workspace: bool = False,
    use_adapters: bool = True,
    plan_paths: list[str] | None = None,
    knowledge_path: str | None = None,
    pin_knowledge: str | None = None,
    changed_since: str | None = None,
    only_files: list[str] | None = None,
    out_dir: str | None = None,
    use_cache: bool = True,
    cache_path: str | None = None,
    verify_cache: bool = False,
    verify_sample: float = 0.05,
    model_verify: bool | None = None,
) -> Report:
    started = time.time()
    if use_adapters:
        # Registering is what makes an uninstalled tool count as "not assessed"
        # instead of vanishing from the coverage denominator.
        from .adapters import register_adapters
        register_adapters()
    profile_name = profile or config.get("profile") or "offline"
    caps = PROFILES.get(profile_name, PROFILES["offline"])

    # One scan, one view of the files. A previous scan's bytes must never be
    # served for this one's paths.
    from .probes import clear_read_cache
    clear_read_cache()

    system_name, repos, tempdirs, manifest = resolve_targets(targets, system_path)
    # A scan must not read the previous scan's output. The output directory
    # defaults to `arbiter-out` inside the tree being scanned, so without this
    # the second run reports on the first run's HTML -- 27% of unsuppressed
    # findings, concentrated in the suppression rules, which the rendered
    # report is naturally full of.
    # The result cache is a file Arbiter writes inside the tree it scans, so
    # it is excluded for the same reason the output directory is: a scan must
    # never read its own previous output back as evidence. See cache.py.
    from . import cache as _cache
    cache = None
    if use_cache and (config.get("cache") or {}).get("enabled", True) and repos:
        cache = _cache.ResultCache.load(
            Path(cache_path) if cache_path else _cache.default_path(repos[0].path))
    excluded = {p for p in (out_dir, str(cache.path) if cache else None) if p}
    inv = build_inventory(repos, excluded or None)
    plans = list(plan_paths or [])
    plans += [str(p) for p in ((config.get("terraform") or {}).get("plans") or [])]

    # Incremental scanning. The full walk still happens -- it costs 0.2s on a
    # 452,000-line repository, and the stack set and the line counts must be
    # facts about the repository rather than about the diff. What narrows is
    # which files the probes are shown. See incremental.py.
    scan_scope: dict = {"mode": "full"}
    source = config.get("config_source")
    if source:
        # Which config was read and what it was not allowed to set (ARB-143),
        # so a dropped `precision:` block from a target's own arbiter.yaml is
        # printed, never silently gone.
        scan_scope["config"] = dict(source)
    changed_set: dict[str, set[str]] = {}
    if changed_since or only_files:
        from .incremental import git_changed, narrow
        selected: dict[str, set[str]] = {}
        if only_files:
            want = {_requested_path(x, repos) for x in only_files}
            # A path nobody can find is a mistake in the request, not an
            # empty change: a partial scan of nothing read passes every gate
            # (FAIL-122). `.husky/pre-commit` used to arrive here as
            # `husky/pre-commit` (lstrip("./") strips characters, not a
            # prefix), was found nowhere, and the scan read zero files.
            known = {f.path for r in repos for f in inv.by_repo.get(r.id, [])}
            unknown = sorted(p for p in want if p not in known)
            if unknown:
                raise RuntimeError(
                    f"--only-files: {len(unknown)} path(s) are not files this scan can read: "
                    f"{', '.join(unknown[:5])}{', ...' if len(unknown) > 5 else ''}. "
                    "Paths are relative to the target root; a path that exists but is "
                    "ignored, generated or binary is not scanned either.")
            for r in repos:
                selected[r.id] = set(want)
        deleted: dict[str, set[str]] = {}
        if changed_since:
            from .incremental import git_deleted
            for r in repos:
                paths, note = git_changed(r.path, changed_since)
                if note:
                    # An empty diff and a failed diff look identical downstream,
                    # and one of them would produce a clean partial scan of
                    # nothing. Refuse rather than report.
                    raise RuntimeError(
                        f"cannot scan {r.id} incrementally: {note}. "
                        "Run a full scan, or give a ref that exists."
                    )
                selected.setdefault(r.id, set()).update(paths)
                deleted[r.id] = git_deleted(r.path, changed_since)
        inv, stats = narrow(inv, selected)
        if only_files and not stats["files_changed_read"]:
            raise RuntimeError("--only-files: none of the requested files was read; "
                               "refusing to report a partial scan of nothing")
        # Changed paths the inventory never held: deleted, or inside a
        # directory the walk does not enter. Neither was read, and before
        # ARB-151 a pull request that only deleted files, or moved its code
        # under dist/, passed the gate with scan_scope saying it was read.
        present = {(f.path, f.repo_id) for f in (inv.whole or inv).files}
        for r in repos:
            for path in sorted(selected.get(r.id, set())):
                if (path, r.id) in present:
                    continue
                if os.path.lexists(os.path.join(r.path, path)):
                    stats["files_changed_not_read"] += 1
                    if len(stats["changed_not_read"]) < 50:
                        stats["changed_not_read"].append({
                            "path": path, "reason": _not_in_inventory_reason(inv, r.id, path)})
                else:
                    stats["files_changed_deleted"] = stats.get("files_changed_deleted", 0) + 1
        stats.setdefault("files_changed_deleted", 0)
        for r in repos:
            gone = {p for p in deleted.get(r.id, set())
                    if (p, r.id) not in present and p not in selected.get(r.id, set())}
            stats["files_changed_deleted"] += len(gone)
        # Remembered so findings landing in a context file -- read so the
        # probes could reason, not because anybody asked about it -- can be
        # told apart from findings in the change itself. Blaming a pull
        # request for a pre-existing issue in an unchanged lockfile is how
        # gates lose the room.
        changed_set = {rid: set(v) for rid, v in selected.items()}
        scan_scope = {"mode": "partial", **stats}
        scan_scope["basis"] = (f"changed since {changed_since}" if changed_since
                               else "an explicit file list")
        scan_scope["changed_since"] = changed_since
        if changed_since and only_files:
            scan_scope["basis"] = f"changed since {changed_since}, plus an explicit file list"

    graph = build_graph(inv, plan_paths=plans)
    # A directory holding only a plan JSON has no .tf files to detect, but it
    # is unambiguously Terraform and the resource probes must still apply.
    if any(r.source in ("plan", "state") for r in graph):
        inv.stacks.add("terraform")

    # Learning is read here and nowhere else: one pinned version per run, with
    # its hash recorded, so the same commit plus the same knowledge version
    # always produces the same bytes.
    from .learn import Knowledge, metrics_from_inventory, resolve_quality_config
    knowledge = Knowledge.load(knowledge_path)
    knowledge_version = knowledge.version_hash()
    if pin_knowledge and pin_knowledge != knowledge_version:
        raise RuntimeError(
            f"knowledge version is {knowledge_version}, pinned to {pin_knowledge}. "
            "Learning changed since this run was pinned; re-pin deliberately."
        )

    profiles = metrics_from_inventory(inv) if (config.get("quality") or {}).get("adaptive") else {}
    run_config = dict(config)
    # Where the config came from is provenance for the report, not a rule
    # any probe reads; keeping it out of the probes' config keeps the result
    # cache key the same whatever path the repository sits at.
    run_config.pop("config_source", None)
    if profiles:
        run_config["quality"] = resolve_quality_config(config, profiles)

    ctx = ProbeContext(repos=repos, inventory=inv, graph=graph, config=run_config, system=manifest,
                       changed=changed_set, changed_since=changed_since, out_dir=out_dir or "")

    disabled = set((config.get("probes") or {}).get("disable") or [])
    cli_skipped = set(skip or [])
    enabled_only = set(only or []) or None
    # Probes the operator chose not to run: --only, --skip, --no-adapters.
    # Their coverage gap is the operator's, and the gate may pass over it;
    # a gap the target's config or the environment caused is not (ARB-152).
    operator_skipped: set[str] = set()

    outcomes: list[ProbeOutcome] = []
    # Findings keyed by the probe's position in the registry, so that the
    # adapters -- which finish in whatever order the pool runs them -- land
    # in the report exactly where a sequential run would have put them.
    findings_by_slot: dict[int, list[Finding]] = {}
    deferred: list[tuple[int, Probe, ProbeOutcome]] = []

    for slot, probe in enumerate(REGISTRY):
        oc = ProbeOutcome(
            name=probe.name, dimensions=list(probe.dimensions),
            checks=probe.checks, version=probe.version,
        )
        outcomes.append(oc)
        if enabled_only is not None and probe.name not in enabled_only:
            oc.status, oc.reason = "skipped", "not selected on the command line"
            operator_skipped.add(probe.name)
            continue
        if probe.name in cli_skipped:
            oc.status, oc.reason = "skipped", "skipped on the command line"
            operator_skipped.add(probe.name)
            continue
        if probe.name in disabled:
            oc.status, oc.reason = "skipped", "disabled in configuration"
            continue
        if scan_scope["mode"] == "partial" and probe.scope not in ("file", "change"):
            # Not run against a subset, because the answer would be wrong
            # rather than merely incomplete. Recorded as not-assessed so it
            # stays in the coverage denominator.
            oc.status = "skipped"
            oc.reason = (f"partial scan ({scan_scope['basis']}): {probe.scope_reason}, "
                         "so it cannot answer from a subset")
            continue
        if probe.external and not use_adapters and enabled_only is None:
            # `use_adapters=False` used to mean only "do not register": the
            # registry is module-global, so once another scan in the same
            # process had registered the analyzers, a scan that asked for none
            # ran all five anyway (FAIL-044; the suite's "fast" tier spent
            # minutes in semgrep). The flag now means what it says. An explicit
            # `only=` that names an analyzer still wins: the caller asked for it.
            # Before the prevented and binary checks: an analyzer the operator
            # switched off is off whether or not it is installed (ARB-152).
            oc.status, oc.reason = "skipped", "external analyzers disabled for this run"
            operator_skipped.add(probe.name)
            continue
        blocked, why = probe.prevented(ctx)
        if blocked:
            # Prevented, not inapplicable: the gap counts against coverage.
            oc.status, oc.reason = "skipped", why
            continue
        ok, why = probe.applicable(ctx)
        if not ok:
            oc.status, oc.reason = "skipped", why
            oc.applicable = False
            continue
        missing = (probe.binary_checker(ctx) if probe.binary_checker is not None
                   else [b for b in probe.binaries if shutil.which(b) is None])
        if missing:
            oc.status, oc.reason = "skipped", f"missing binary: {', '.join(missing)}"
            continue
        if probe.network and not caps["network"]:
            oc.status, oc.reason = "skipped", f"profile '{profile_name}' forbids network access"
            continue
        if probe.model and not caps["model"]:
            oc.status, oc.reason = "skipped", f"profile '{profile_name}' forbids model calls"
            continue
        if probe.external:
            # An analyzer in its own process: run after the native probes,
            # beside the other analyzers, with its own memo (ARB-047).
            deferred.append((slot, probe, oc))
            continue

        t0 = time.time()
        try:
            if cache is not None and probe.cacheable:
                # Hits are assembled from the cache, misses from the probe,
                # and nothing downstream can tell them apart: calibration,
                # overrides, the baseline and suppressions all run on both.
                context = probe.cache_context(ctx) if probe.cache_context else ""
                produced, note = _cache.run_with_cache(
                    probe, ctx, cache, _cache.rules_hash(run_config, probe, context),
                    verify_fraction=verify_sample if verify_cache else 0.0)
                if note["hits"]:
                    oc.reason = (f"{note['hits']} file(s) from cache, "
                                 f"{note['misses']} re-read"
                                 + (f", {note['verified']} verified" if note["verified"] else ""))
            else:
                produced = probe.run(ctx) or []
            oc.status = "ran"
            oc.finding_count = len(produced)
            findings_by_slot[slot] = list(produced)
        except Exception as exc:  # noqa: BLE001 - a probe that raises becomes an error outcome, never a silent pass
            _record_probe_error(oc, exc)
        oc.duration_s = round(time.time() - t0, 3)

    # Source in a language no rule pack reads (Kotlin, Swift, C#, ...) was
    # never assessed by a language probe, and before ARB-144 nothing said so:
    # the `lang_*` probes for the languages present were inapplicable, left
    # the denominator, and a Swift-only repository scored 99/100. One outcome
    # names those languages and sits in the denominator as not assessed.
    from .lang_rules import files_not_read_outcome, not_assessed_outcome
    unassessed = not_assessed_outcome(inv)
    if unassessed is not None:
        outcomes.append(unassessed)
    # Files the walk saw and did not read (a NUL byte, the size cap, UTF-16
    # without a mark, a link out of the tree) sit in the denominator the same
    # way; before ARB-150 a tree of such files scored 100 (FAIL-127).
    not_read = files_not_read_outcome(inv)
    if not_read is not None:
        outcomes.append(not_read)

    if deferred:
        _run_external_probes(deferred, ctx, cache, run_config, verify_cache,
                             adapter_workers(config), findings_by_slot)

    findings: list[Finding] = [f for slot in sorted(findings_by_slot)
                               for f in findings_by_slot[slot]]

    if cache is not None:
        scan_scope["cache"] = {**cache.stats(), "path": str(cache.path)}
        cache.save()
    whole_inv = inv.whole or inv
    scan_scope["skipped"] = whole_inv.skipped_summary()

    assign_occurrences(findings)
    findings = _dedupe(findings)
    if scan_scope["mode"] == "partial":
        for f in findings:
            if f.location.path and f.location.path not in changed_set.get(f.repo_id, set()):
                f.tags.append("outside-this-change")
    # Every finding in the change is attributed to the requirement ids the
    # commits that touched its file cite, so a report can be read per
    # requirement (REQ-038, ARB-052); a `req-scope:` tag says whether that is
    # attribution or context. Findings in context files are not tagged: they
    # were not introduced under any of these ids.
    from .incremental import attribute_requirements
    attribute_requirements(findings, repos, changed_set, changed_since)

    from .learn import apply as apply_knowledge
    calibration = apply_knowledge(findings, knowledge)
    apply_severity_overrides(findings, config)
    apply_baseline(findings, baseline)
    apply_suppressions(findings, config)
    apply_scope_notes(findings, inv)
    from .cwe import apply as apply_cwe
    apply_cwe(findings)

    # The model verification pass (verify.py) runs last among the finding
    # passes, so it sees each finding's final severity and suppression and
    # never spends a call on one policy has already silenced. It annotates;
    # it never removes. Off unless the profile or config asks for it, and
    # never under a profile that forbids model calls.
    from . import verify as _verify
    if _verify.wanted(config, caps, model_verify):
        scan_scope["verification"] = _verify.run(
            findings, inv, config,
            repo_root=(repos[0].path if repos else None))

    report = Report(
        system=system_name,
        arbiter_version=ARBITER_VERSION,
        fingerprint=FINGERPRINT_SCHEME,
        profile=profile_name,
        started_at=_dt.datetime.fromtimestamp(started, _dt.timezone.utc).isoformat(timespec="seconds"),
        repos=repos,
        findings=sorted(
            findings,
            key=lambda f: (
                ["critical", "high", "medium", "low", "info"].index(f.severity)
                if f.severity in ("critical", "high", "medium", "low", "info") else 9,
                f.repo_id, f.location.path, f.location.start_line,
            ),
        ),
        probes=outcomes,
        stacks=sorted(inv.stacks),
        scan_scope=scan_scope,
    )
    for _fi in inv.text_files():
        report.loc_by_language[_fi.language] = (
            report.loc_by_language.get(_fi.language, 0) + _fi.lines)
        report.loc_by_role[_fi.role] = report.loc_by_role.get(_fi.role, 0) + _fi.lines
    report.learning = {
        "knowledge_version": knowledge_version,
        "rules_with_feedback": len(knowledge.rules),
        "adjudicated_findings": len(knowledge.adjudicated),
        "annotated": calibration["annotated"],
        "recalibrated": calibration["recalibrated"],
        "externally_graded": calibration.get("externally_graded", 0),
        "external_checks_measured": len(knowledge.external_severity),
        "adaptive_thresholds": (run_config.get("quality") or {}).get("_adaptive_source", ""),
        "profiles": {k: v for k, v in profiles.items() if v},
    }
    report.scorecard = compute_scorecard(
        report.findings, outcomes,
        # Density denominator: what was read, not what exists. A partial scan
        # measured against whole-repo size would look artificially sparse.
        (scan_scope.get("lines_read") if scan_scope["mode"] == "partial"
         else sum(r.loc for r in repos)),
        config,
    )
    if report.scorecard.withheld_by == "coverage" and operator_skipped:
        # Probes chosen on the command line (--only, --skip, --no-adapters)
        # are the operator's own narrowing, like --changed: the grade is
        # withheld, and the gate -- a question about the findings in front
        # of it -- may still pass (ARB-152). Only when the choice explains
        # the gap, though: with the operator's probes out of the
        # denominator, the rest must reach the bar. Coverage lost to the
        # target's config, a missing analyzer or a language no pack reads
        # is not a choice the operator made, and fails the gate.
        rest = compute_scorecard(
            report.findings, [o for o in outcomes if o.name not in operator_skipped],
            (scan_scope.get("lines_read") if scan_scope["mode"] == "partial"
             else sum(r.loc for r in repos)), config)
        report.scan_scope["probes_selected"] = {"only": sorted(only or []), "skip": sorted(skip or []),
                                                "adapters": bool(use_adapters),
                                                "coverage_without": rest.coverage}
        if not rest.withheld:
            report.scorecard.withheld_by = "probes_selected"
            report.scorecard.withheld_reason += (
                f" (probes were chosen on the command line; coverage of the rest {rest.coverage:.0%})")
    if scan_scope["mode"] == "partial":
        # A partial scan may pass a gate and may not carry a grade. The gate is
        # a question about the findings in front of it ("did anything cross a
        # threshold"), which a subset can answer. A grade is a summary of the
        # repository, and a number that looks like one but describes a diff is
        # precisely the thing this tool exists not to produce. Coverage stays
        # reported, because coverage is what makes the withholding legible.
        _withhold(report, "partial",
                  f"partial scan ({scan_scope['basis']}): "
                  f"{scan_scope['files_read']} of {scan_scope['files_total']} file(s) read. "
                  "A grade would describe the changed files while reading as though "
                  "it described the repository.")
    from .lang_rules import unassessed_languages
    langs = unassessed_languages(inv)
    if langs:
        report.scan_scope["languages_not_assessed"] = langs
    share = sum(v["share"] for v in langs.values())
    assessable = len(whole_inv.assessable_files())
    skipped_share = whole_inv.skipped_source_share()
    if scan_scope["mode"] != "partial" and assessable == 0:
        # Nothing a probe reads was read: an empty directory, a mistyped
        # path, a checkout without its submodules, a tree of docs or of
        # binaries. Before ARB-149 this scored 100 with the gate passing
        # (FAIL-126); a perfect grade for a scan of nothing.
        found = len(whole_inv.files)
        sk = scan_scope["skipped"]
        detail = f"{found} file(s) found, none in a role a probe reads"
        if sk["files"]:
            detail += f" ({sk['files']} not read: {_reason_counts(sk)})"
        _withhold(report, "nothing_read",
                  f"no file this scan could assess was read: {detail}. "
                  "A grade would describe nothing while reading as though it described "
                  "the repository.")
    elif skipped_share > UNASSESSED_SOURCE_LIMIT and report.scorecard.withheld_by in _OVERRIDABLE:
        # Over a coverage withholding, operator-chosen or not: the gate reads
        # the token, and unread source is a gap no --skip explains.
        sk = scan_scope["skipped"]
        _withhold(report, "files_not_read",
                  f"{skipped_share:.0%} of source-like files were not read "
                  f"({sk['source_like_files']} file(s): {_reason_counts(sk)}); a grade would "
                  "describe the files that were read while reading as though it described "
                  "the repository.")
    if share > UNASSESSED_SOURCE_LIMIT and report.scorecard.withheld_by in _OVERRIDABLE:
        # The same withholding a partial scan gets, for the same reason: the
        # number would describe the minority of the source that a rule pack
        # read while reading as though it described the repository.
        names = ", ".join(langs)
        _withhold(report, "unassessed_languages",
                  f"{share:.0%} of source lines are in languages no rule pack reads ({names}); "
                  "a grade would describe the assessed minority while reading as though "
                  "it described the repository.")
    # Control coverage. Summary only; the per-control detail is one command
    # away. Failing to evaluate frameworks must never fail a scan.
    try:
        from .controls import evaluate_all, house_rule_types
        wanted = (config.get("controls") or {}).get("frameworks") or []
        extra = (config.get("controls") or {}).get("packs") or []
        for res in evaluate_all(report.findings, outcomes, only=wanted, extra_dirs=extra,
                                house=house_rule_types(config)):
            summary = {
                "framework": res["framework"]["id"],
                "title": res["framework"]["title"],
                "baseline": res["framework"]["baseline"],
                "counts": res["counts"],
                "declared_total": res["declared_total"],
                "not_enumerated": res["not_enumerated"],
                "assessed_fraction": res["assessed_fraction"],
            }
            if "languages" in res:
                summary["languages"] = res["languages"]
            report.controls.append(summary)
    except Exception:  # noqa: BLE001 - control coverage is a summary; a broken pack must not fail the scan
        pass

    # Precision tiers and rule requirements (precision.py). After every pass
    # that can change a finding -- the model verification pass included --
    # and before the gate, which in tier_mode: tiered reads only the tiers
    # it is told to.
    from .policy import show_mode
    from .precision import annotate as annotate_tiers
    from .precision import rules_block, set_view
    report.scan_scope["tiers"] = annotate_tiers(report.findings, config, profile_name)
    report.rules = rules_block(report.findings)

    report.gate = evaluate_gate(report, config)
    # The view (ARB-100) is recorded after the gate: what the renderings show
    # is the verified tier plus whatever failed the gate.
    set_view(report, show_mode(config))

    # Record every assertion this report makes, then check that none of them
    # outruns its basis. A report that fails its own integrity check is a bug
    # in Arbiter, not a finding about the target.
    from .claims import build_claims, verify
    report.claims = [c.to_dict() for c in build_claims(report)]
    violations = verify(report, config)
    report.integrity = {
        "checked": True,
        "violations": [v.to_dict() for v in violations],
        "ok": not violations,
    }
    report.duration_s = time.time() - started

    if not keep_workspace:
        for d in tempdirs:
            shutil.rmtree(d, ignore_errors=True)
    return report
