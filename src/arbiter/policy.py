"""Configuration, profiles, suppressions, scoring and the gate.

Scoring exists to drive behavior, not to be precise. Two properties matter
more than the formula: findings are normalized by codebase size, and the
grade is withheld when too little of the rubric could actually be evaluated.
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
from pathlib import Path
from typing import Any

from .core import (
    DIMENSIONS,
    SEV_RANK,
    DimensionScore,
    Finding,
    ProbeOutcome,
    Report,
    Scorecard,
    sev_at_least,
)

PROFILES: dict[str, dict] = {
    "offline": {"network": False, "model": False, "description": "air-gapped; vendored rules only"},
    "ci": {"network": False, "model": False, "description": "fast, deterministic, gate-focused"},
    "connected": {"network": True, "model": True, "description": "full depth"},
    "audit": {"network": True, "model": True, "description": "everything, no time budget"},
    # ci plus the model verification pass (verify.py): deterministic probes,
    # then each finding at or above verify.min_severity is checked by a model
    # against a bounded, secret-masked excerpt. The only network traffic is
    # that call; no adapter or probe that fetches is enabled.
    "assisted": {"network": False, "model": True, "verify": True,
                 "description": "deterministic probes, then a model checks each finding"},
}

DEFAULT_WEIGHTS = {
    "security": 0.30,
    "compliance": 0.10,
    "supply_chain": 0.15,
    "quality": 0.20,
    "drift": 0.10,
    "interface": 0.15,
    # Weight zero, deliberately. Assurance findings say how much checking was
    # switched off, not how bad the code is, and folding the two into one grade
    # would be the exact conflation this dimension exists to expose. They are
    # reported, counted, and never scored.
    "assurance": 0.0,
}

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "profile": "offline",
    "probes": {"enable": [], "disable": [], "severity_overrides": {}},
    "gate": {
        # withheld_grade (ARB-152): a withheld grade fails the gate, except
        # the operator's own narrowing (--changed, --only-files), which
        # withholds the grade and may still pass. Only a --config file may
        # set it false; a target's own config may not.
        "fail_on": {"severity": "critical", "new": None, "coverage_below": None,
                    "withheld_grade": True},
        "gate_on_inferred": False,
        # tiered (the default since ARB-100): fail_on reads only findings
        # whose precision tier is in `tiers` (precision.py), so a build fails
        # on what Arbiter has measured to be right at least 99% of the time
        # and on nothing else. legacy: fail_on reads every active finding, as
        # it did before tiers; an explicit opt-in for a repository that wants
        # the louder gate.
        "tier_mode": "tiered",
        "tiers": ["verified"],
    },
    # What the human-facing renderings (console, markdown, pr-comment, SARIF,
    # HTML, annotations) and the MCP tools show (ARB-100, ARB-103).
    # `all` (the default): every tier, verified first, then advisory, then
    # inferred, each section labelled with whether it can block the gate.
    # `verified`: an opt-in for the verified tier only, with one line saying
    # how many advisory and inferred findings were left out;
    # `--verified-only` is that for one run. Showing is not blocking: the
    # gate reads `gate.tier_mode`, whatever this says. report.json always
    # holds every finding.
    "report": {"show": "all"},
    # Precision tiers (precision.py, docs/precision.md). `ledger: null` reads
    # the ledger shipped with Arbiter; `verified_rules` declares more rules
    # verified (globs), which still need the ledger to admit them.
    "precision": {"ledger": None, "verified_rules": [],
                  "deterministic_profiles": ["offline", "ci"]},
    "score": {"weights": DEFAULT_WEIGHTS, "coverage_threshold": 0.6},
    "quality": {"max_file_lines": 800, "max_function_lines": 120, "max_complexity": 20},
    "suppress": [],
    # Rules off by default because the ledger measured them below the
    # advisory bar (precision.py, ARB-174) that this run reports anyway:
    # rule ids or globs, "*" for all; `--all-rules` is "*" for one run.
    # Their findings are tagged `default-off` and never fail the gate.
    "enable_rules": [],
    "rules": [],
    "ignore": [],
    # The persistent per-file result cache (cache.py). `--no-cache` on the
    # command line bypasses it whatever this says; CI runs without it.
    "cache": {"enabled": True},
    # The model verification pass (verify.py). `enabled: null` lets the
    # profile decide (on for `assisted`); offline and ci never call a model,
    # whatever this says.
    "verify": {
        "enabled": None,
        "provider": "anthropic",
        "model": "claude-opus-5-5",
        "effort": "medium",
        "min_severity": "medium",
        "max_findings": 150,
        "max_tokens": 400_000,
        "max_output_tokens": 4000,
        "excerpt_lines": 120,
        "cache": True,
        "skip_rules": ["arbiter/ast.*", "arbiter/quality.*",
                       "arbiter/assurance.suppression-census"],
    },
}


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | None, repo_root: str | None = None) -> dict:
    """Load arbiter.yaml. An explicit path wins; otherwise look in the repo root.

    A file found in the target root is the target's own, and the target is
    what the scan judges: it may make the gate stricter, but it may not
    decide which of its findings count as `verified`, let more of them
    through the gate, hide or downgrade them (`suppress`,
    `probes.severity_overrides`, ARB-148) or lower the coverage bar
    (`restrict_target_config`, ARB-143). Keys it is not allowed to set are
    dropped and listed under `config_source.ignored`, which the renderings
    print, so the drop is never silent. A config the operator names with
    `--config` is trusted in full.
    """
    candidate: Path | None = None
    explicit = bool(path)
    if path:
        candidate = Path(path)
    elif repo_root:
        for name in ("arbiter.yaml", "arbiter.yml", ".arbiter.yaml"):
            p = Path(repo_root) / name
            if p.is_file():
                candidate = p
                break
    if candidate is None or not candidate.is_file():
        return dict(DEFAULTS)
    try:
        import yaml
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise RuntimeError(f"could not read config {candidate}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"config {candidate} must be a mapping")
    ignored: list[str] = []
    if not explicit:
        data, ignored = restrict_target_config(data)
    merged = _merge(DEFAULTS, data)
    check_gate_config(merged, str(candidate))
    check_report_config(merged, str(candidate))
    check_suppress_config(merged, str(candidate))
    resolve_ledger_path(merged, candidate)
    merged["config_source"] = {"path": str(candidate), "explicit": explicit, "ignored": ignored}
    return merged


# What a target's own arbiter.yaml may not set (ARB-143, ARB-148). `precision`
# decides which findings are called verified and `verify` is the pass that
# confirms them; `suppress` hides findings. A repository that could set any
# of them would be grading its own work. `probes.severity_overrides` (a
# downgrade to `info` takes a finding out of every gate) and a lowered
# `score.coverage_threshold` are dropped key by key below.
TARGET_FORBIDDEN_KEYS = ("precision", "verify", "suppress")


def _valid_severity(value: Any) -> bool:
    return isinstance(value, str) and value in SEV_RANK


def normalise_severity(value: Any) -> str | None:
    """The severity name `value` spells, case-insensitively and ignoring
    surrounding space, or None for a name that is not one (ARB-152)."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    return name if name in SEV_RANK else None


def restrict_target_config(data: dict) -> tuple[dict, list[str]]:
    """The subset of a target-root config a scan may honour, and one note
    per key it dropped.

    Tighten versus loosen, key by key against `DEFAULTS["gate"]`:

    * `fail_on.severity` / `fail_on.new`: a known severity is allowed, since
      none ranks above the default `critical` and `new` has no default; the
      name is normalised (`Critical` is `critical`). A null (gate off) is
      dropped. An unknown name is kept so that `check_gate_config` raises
      on it (ARB-152): before that, `sev_at_least` never matched an unknown
      threshold and the gate could never fail.
    * `fail_on.coverage_below`: a fraction adds a check; anything else drops.
    * `fail_on.withheld_grade`: `false` would let a withheld grade pass;
      dropped.
    * `gate_on_inferred`, `fail_on_probe_error`: `true` adds findings or
      probes to the gate; `false` is the default.
    * `tier_mode`: `legacy` gates on more tiers than `tiered`; both allowed.
    * `tiers`: allowed when it keeps every default tier (a superset).
    * A malformed value (`tier_mode: teired`, an unknown tier name) is kept
      so that `check_gate_config` raises on it, as it always has: a typo is
      an error to fix, not a loosening to note.

    `precision`, `verify` and `suppress` are dropped whole (ARB-148: a
    selector-less suppression silenced every finding and the target passed
    its own gate). `probes.severity_overrides` is dropped; a
    `score.coverage_threshold` below the default is dropped, a higher one
    withholds more and is kept. Everything else (`probes.disable`, `rules`,
    `quality`, ...) is left as it was: each is visible in the report, and a
    disabled probe lowers coverage, which the gate now reads (ARB-152).
    """
    out = dict(data)
    notes: list[str] = []
    for key in TARGET_FORBIDDEN_KEYS:
        if key in out:
            out.pop(key)
            notes.append(f"{key}: a target's own config may not set it")
    probes = out.get("probes")
    if isinstance(probes, dict) and "severity_overrides" in probes:
        probes = dict(probes)
        probes.pop("severity_overrides")
        out["probes"] = probes
        notes.append("probes.severity_overrides: a target's own config may not set it")
    score = out.get("score")
    if isinstance(score, dict) and "coverage_threshold" in score:
        floor = DEFAULTS["score"]["coverage_threshold"]
        value = score["coverage_threshold"]
        ok = isinstance(value, (int, float)) and not isinstance(value, bool) and value >= floor
        if not ok:
            score = dict(score)
            score.pop("coverage_threshold")
            out["score"] = score
            notes.append(f"score.coverage_threshold: {value!r} would loosen the grade's "
                         f"coverage bar below {floor}")
    gate = out.get("gate")
    if isinstance(gate, dict):
        kept: dict = {}
        defaults = DEFAULTS["gate"]
        for k, v in gate.items():
            if k == "fail_on" and isinstance(v, dict):
                fo: dict = {}
                for fk, fv in v.items():
                    if fk in ("severity", "new"):
                        name = normalise_severity(fv)
                        if name:
                            fo[fk] = name
                        elif fv is None or not isinstance(fv, str):
                            notes.append(f"gate.fail_on.{fk}: {fv!r} would loosen the gate")
                        else:
                            fo[fk] = fv  # unknown name: check_gate_config raises
                    elif fk == "withheld_grade":
                        if fv is True:
                            fo[fk] = fv
                        else:
                            notes.append(f"gate.fail_on.{fk}: {fv!r} would loosen the gate")
                    elif fk == "coverage_below":
                        if isinstance(fv, (int, float)) and not isinstance(fv, bool) and 0 <= fv <= 1:
                            fo[fk] = fv
                        else:
                            notes.append(f"gate.fail_on.{fk}: {fv!r} would loosen the gate")
                    else:
                        notes.append(f"gate.fail_on.{fk}: unknown key")
                if fo:
                    kept["fail_on"] = fo
            elif k in ("gate_on_inferred", "fail_on_probe_error"):
                if v is True or v == defaults.get(k, False):
                    kept[k] = v
                else:
                    notes.append(f"gate.{k}: {v!r} would loosen the gate")
            elif k == "tier_mode":
                # Both modes are allowed (legacy gates on more); a misspelling
                # is kept so check_gate_config raises on it as it always has.
                kept[k] = v
            elif k == "tiers":
                if not isinstance(v, list) or any(t not in GATE_TIERS for t in v):
                    kept[k] = v  # malformed: check_gate_config raises
                elif set(defaults["tiers"]) <= set(v):
                    kept[k] = v
                else:
                    notes.append(f"gate.{k}: {v!r} would drop a default gating tier")
            else:
                notes.append(f"gate.{k}: unknown key")
        out["gate"] = kept
    elif gate is not None:
        out.pop("gate")
        notes.append("gate: must be a mapping")
    return out, notes


def resolve_ledger_path(config: dict, config_file: Path) -> None:
    """`precision.ledger` is read relative to the config file that names
    it, and must stay inside that file's directory: a config that pointed
    at a ledger elsewhere would be vouching for evidence it does not hold."""
    settings = config.get("precision") or {}
    raw = settings.get("ledger")
    if not raw:
        return
    base = config_file.resolve().parent
    target = Path(str(raw))
    resolved = (target if target.is_absolute() else base / target).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise RuntimeError(
            f"{config_file}: precision.ledger {raw!r} resolves outside the config's "
            f"directory ({base}); keep the ledger beside the config") from None
    config["precision"] = {**settings, "ledger": str(resolved)}


def config_notes(config: dict | None) -> list[str]:
    """The keys a target-root config set and the scan ignored (ARB-143)."""
    return list(((config or {}).get("config_source") or {}).get("ignored") or [])


# Withholding the operator asked for (engine.py), which a gate may pass over.
OPERATOR_WITHHOLDING = ("partial", "probes_selected")

TIER_MODES = ("legacy", "tiered")
GATE_TIERS = ("verified", "advisory", "inferred")
SHOW_MODES = ("verified", "all")
DEFAULT_TIER_MODE = "tiered"


def check_gate_config(config: dict, where: str = "config") -> None:
    """A misspelt gate value must not fall back to some other gate quietly.

    `fail_on.severity` and `fail_on.new` are normalised in place
    (`Critical` becomes `critical`) and an unknown name is an error
    (ARB-152, FAIL-129): `crtical` used to reach `sev_at_least`, which
    matched nothing, so a repository with criticals passed a gate that had
    been configured to fail on them.
    """
    gate = config.get("gate") or {}
    mode = gate.get("tier_mode", DEFAULT_TIER_MODE)
    if mode not in TIER_MODES:
        raise RuntimeError(f"{where}: gate.tier_mode is one of {TIER_MODES}, got {mode!r}")
    tiers = gate.get("tiers", ["verified"])
    if not isinstance(tiers, list) or any(t not in GATE_TIERS for t in tiers):
        raise RuntimeError(f"{where}: gate.tiers is a list drawn from {GATE_TIERS}, got {tiers!r}")
    fail_on = gate.get("fail_on")
    if fail_on is None:
        return
    if not isinstance(fail_on, dict):
        raise RuntimeError(f"{where}: gate.fail_on must be a mapping, got {fail_on!r}")
    from .core import SEVERITIES
    for key in ("severity", "new"):
        value = fail_on.get(key)
        if value is None:
            continue
        name = normalise_severity(value)
        if name is None:
            raise RuntimeError(f"{where}: gate.fail_on.{key} is one of {tuple(SEVERITIES)} "
                               f"or null, got {value!r}")
        fail_on[key] = name
    cov = fail_on.get("coverage_below")
    if cov is not None and (isinstance(cov, bool) or not isinstance(cov, (int, float))
                            or not 0 <= cov <= 1):
        raise RuntimeError(f"{where}: gate.fail_on.coverage_below is a fraction between 0 and 1 "
                           f"or null, got {cov!r}")
    held = fail_on.get("withheld_grade", True)
    if not isinstance(held, bool):
        raise RuntimeError(f"{where}: gate.fail_on.withheld_grade is true or false, got {held!r}")


def check_report_config(config: dict, where: str = "config") -> None:
    """`report.show` is `verified` or `all`; a misspelling must not quietly
    show one or the other."""
    show = show_mode(config)
    if show not in SHOW_MODES:
        raise RuntimeError(f"{where}: report.show is one of {SHOW_MODES}, got {show!r}")


def show_mode(config: dict | None) -> str:
    """Which tiers the renderings show under this configuration (default
    `all`, ARB-103)."""
    return str(((config or {}).get("report") or {}).get("show") or "all")


def load_system(path: str) -> dict:
    import yaml
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or "repos" not in data:
        raise RuntimeError(f"{path} must be a mapping with a `repos` list")
    return data


# ---------------------------------------------------------------------------
# suppressions
# ---------------------------------------------------------------------------

SUPPRESS_SELECTORS = ("rule", "path", "id")


def _parse_expiry(value: Any) -> _dt.date | None:
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def suppression_problems(rules: Any) -> list[str]:
    """What is wrong with each `suppress` entry, one line per problem, or
    [] (ARB-152). An entry needs a `reason`, an `expires` date and at least
    one selector (`rule`, `path`, `id`): the docstring and docs/configuration.md
    had always said `reason` and `expires` were mandatory, but nothing
    checked, and an entry with only a reason matched every finding forever
    (FAIL-129)."""
    if rules is None:
        return []
    if not isinstance(rules, list):
        return ["suppress must be a list of entries"]
    out: list[str] = []
    for i, rule in enumerate(rules):
        where = f"suppress[{i}]"
        if not isinstance(rule, dict):
            out.append(f"{where}: must be a mapping")
            continue
        if not str(rule.get("reason") or "").strip():
            out.append(f"{where}: `reason` is mandatory")
        if "expires" not in rule or rule.get("expires") is None:
            out.append(f"{where}: `expires` (YYYY-MM-DD) is mandatory; a suppression without "
                       "an end is a deletion")
        elif _parse_expiry(rule.get("expires")) is None:
            out.append(f"{where}: `expires` is not a date: {rule.get('expires')!r}")
        if not any(rule.get(k) for k in SUPPRESS_SELECTORS):
            out.append(f"{where}: needs at least one of {SUPPRESS_SELECTORS}; with none it would "
                       "match every finding")
    return out


def check_suppress_config(config: dict, where: str = "config") -> None:
    problems = suppression_problems(config.get("suppress"))
    if problems:
        raise RuntimeError(f"{where}: " + "; ".join(problems))


def apply_suppressions(findings: list[Finding], config: dict) -> int:
    """Mark suppressed findings. Expiry is mandatory and enforced here: an
    entry without a parseable `expires`, without a selector or without a
    reason suppresses nothing (load_config refuses such a file outright;
    this is the backstop for a config built in code)."""
    rules = [r for r in (config.get("suppress") or [])
             if isinstance(r, dict) and not suppression_problems([r])]
    today = _dt.date.today()
    count = 0
    for f in findings:
        for rule in rules:
            rid = rule.get("rule")
            if rid and not (f.rule_id == rid or fnmatch.fnmatch(f.rule_id, rid)):
                continue
            pat = rule.get("path")
            if pat and not fnmatch.fnmatch(f.location.path, pat):
                continue
            fid = rule.get("id")
            # An id names one finding, or the base fingerprint every
            # same-evidence repeat in a file shares (ARB-080): before
            # occurrence ordinals those repeats were one finding, and a
            # suppression written then must keep covering all of them.
            if fid and fid not in (f.id, f.fingerprint_base):
                continue
            exp = _parse_expiry(rule.get("expires"))
            if exp is None or exp < today:
                continue  # expired suppressions stop suppressing, by design
            f.suppressed = True
            f.suppression_reason = rule.get("reason", "")
            count += 1
            break
    return count


def apply_severity_overrides(findings: list[Finding], config: dict) -> None:
    overrides = (config.get("probes") or {}).get("severity_overrides") or {}
    if not overrides:
        return
    for f in findings:
        for pat, sev in overrides.items():
            if f.rule_id == pat or fnmatch.fnmatch(f.rule_id, pat):
                f.severity = sev
                break


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def compute_scorecard(
    findings: list[Finding],
    outcomes: list[ProbeOutcome],
    total_loc: int,
    config: dict,
) -> Scorecard:
    weights = (config.get("score") or {}).get("weights") or DEFAULT_WEIGHTS
    threshold = float((config.get("score") or {}).get("coverage_threshold", 0.6))

    applicable: dict[str, int] = {}
    ran: dict[str, int] = {}
    for o in outcomes:
        # A probe that could never have applied here -- seams on a single
        # repository -- is not an unassessed check; there is nothing it would
        # have assessed. It leaves the denominator. A probe that was prevented
        # (missing binary, profile) stays in it: that gap is real.
        if not getattr(o, "applicable", True):
            continue
        for d in o.dimensions or []:
            if o.status in ("ran", "error", "skipped"):
                applicable[d] = applicable.get(d, 0) + _checks_of(o)
            if o.status == "ran":
                ran[d] = ran.get(d, 0) + _checks_of(o)

    size_factor = max(1.0, (max(total_loc, 1) / 2000.0) ** 0.5)

    card = Scorecard()
    active = [f for f in findings if not f.suppressed]
    for dim in DIMENSIONS:
        app = applicable.get(dim, 0)
        if app == 0:
            continue
        dim_findings = [f for f in active if f.dimension == dim]
        penalty = sum(f.weight() for f in dim_findings) / size_factor
        score = max(0.0, 100.0 - min(100.0, penalty))
        cov = min(1.0, ran.get(dim, 0) / app) if app else 0.0
        card.dimensions[dim] = DimensionScore(
            dimension=dim,
            score=round(score, 1),
            coverage=round(cov, 3),
            findings=len(dim_findings),
            checks_run=ran.get(dim, 0),
            checks_applicable=app,
        )

    total_app = sum(d.checks_applicable for d in card.dimensions.values())
    total_ran = sum(d.checks_run for d in card.dimensions.values())
    card.coverage = round(total_ran / total_app, 3) if total_app else 0.0

    present = {k: weights.get(k, 0.1) for k in card.dimensions}
    wsum = sum(present.values()) or 1.0
    if card.dimensions:
        card.overall = round(
            sum(card.dimensions[k].score * w for k, w in present.items()) / wsum, 1
        )
    if card.coverage < threshold:
        card.withheld = True
        card.overall = None
        card.withheld_by = "coverage"
        card.withheld_reason = (
            f"assessment coverage {card.coverage:.0%} is below the {threshold:.0%} threshold; "
            "an overall grade would overstate what was actually checked"
        )
    return card


def _checks_of(o: ProbeOutcome) -> int:
    return max(1, o.checks)


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------

def evaluate_gate(report: Report, config: dict) -> dict:
    gate_cfg = (config.get("gate") or {})
    fail_on = gate_cfg.get("fail_on") or {}
    gate_inferred = bool(gate_cfg.get("gate_on_inferred", False))
    check_gate_config(config)
    tier_mode = gate_cfg.get("tier_mode", DEFAULT_TIER_MODE)
    gate_tiers = list(gate_cfg.get("tiers") or ["verified"])

    # A rule off by default (ARB-174) is noise by measurement: enabling it
    # shows its findings, never lets them fail the build, in any tier mode.
    considered = [
        f for f in report.findings
        if not f.suppressed and (gate_inferred or f.provenance != "inferred")
        and DEFAULT_OFF_TAG not in (f.tags or [])
    ]
    # Active findings the tier mode kept away from the thresholds, by tier,
    # so a passing tiered gate over a report full of advisory criticals says
    # so in its own block rather than reading as a clean repository.
    excluded: dict[str, int] = {}
    if tier_mode == "tiered":
        # Only the tiers the configuration names can block. An inferred
        # finding is in the inferred tier, so `gate_on_inferred` and
        # `tiers: [..., inferred]` both have to ask for it.
        kept = []
        for f in considered:
            tier = f.tier or "advisory"
            if tier in gate_tiers:
                kept.append(f)
            else:
                excluded[tier] = excluded.get(tier, 0) + 1
        considered = kept

    reasons: list[str] = []
    # The findings behind the severity and new-finding reasons, by id, so a
    # renderer can single out what actually failed the build (the GitHub
    # annotations mark exactly these as errors) instead of every finding at
    # once. Coverage and probe-error reasons have no finding to name.
    failing: set[str] = set()

    sev_threshold = fail_on.get("severity")
    if sev_threshold:
        hits = [f for f in considered if sev_at_least(f.severity, sev_threshold)]
        if hits:
            reasons.append(f"{len(hits)} finding(s) at or above {sev_threshold}")
            failing.update(f.id for f in hits)

    new_threshold = fail_on.get("new")
    if new_threshold:
        hits = [f for f in considered if f.status == "new" and sev_at_least(f.severity, new_threshold)]
        if hits:
            reasons.append(f"{len(hits)} new finding(s) at or above {new_threshold}")
            failing.update(f.id for f in hits)

    cov_below = fail_on.get("coverage_below")
    if cov_below is not None and report.scorecard.coverage < float(cov_below):
        reasons.append(
            f"coverage {report.scorecard.coverage:.0%} below required {float(cov_below):.0%}"
        )

    errored = [p for p in report.probes if p.status == "error"]
    if errored and gate_cfg.get("fail_on_probe_error", False):
        reasons.append(f"{len(errored)} probe(s) errored")

    # A withheld grade is a scan that could not assess enough to say, and a
    # gate that passed over it was a pass on nothing (ARB-152, FAIL-129:
    # probes disabled in the target's config, coverage 3%, grade withheld,
    # gate PASS). The operator's own narrowing is the exception: a partial
    # scan, or probes chosen with --only/--skip, withholds the grade by
    # design and may pass -- unless none of the changed files was read
    # (ARB-151).
    sc = report.scorecard
    ss = report.scan_scope or {}
    if fail_on.get("withheld_grade", True) and sc.withheld \
            and sc.withheld_by not in OPERATOR_WITHHOLDING:
        reasons.append(f"grade withheld ({sc.withheld_by or 'coverage'}): {sc.withheld_reason}")
    if ss.get("mode") == "partial" and ss.get("files_changed_not_read") \
            and not ss.get("files_changed_read"):
        why = ss.get("changed_not_read") or []
        reasons.append(
            f"none of the {ss['files_changed_not_read']} changed file(s) was read"
            + (f" ({'; '.join(sorted({w['reason'] for w in why}))})" if why else ""))

    return {
        "passed": not reasons,
        "reasons": reasons,
        "considered": len(considered),
        "gate_on_inferred": gate_inferred,
        "tier_mode": tier_mode,
        **({"tiers": gate_tiers, "excluded_by_tier": excluded} if tier_mode == "tiered" else {}),
        "failing_ids": sorted(failing),
    }
