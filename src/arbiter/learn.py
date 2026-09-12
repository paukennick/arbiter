"""Learning, without breaking reproducibility.

An evaluator that adapts and an evaluator that is reproducible are in direct
tension: if a scan's behaviour depends on history, the same commit can pass on
Monday and fail on Tuesday, and a baseline, a CI gate and an accreditation
artefact all stop meaning anything.

The resolution is to separate the two:

  * LEARNING is offline. Feedback, measured precision and per-repository
    distributions accumulate into a knowledge file.
  * EXECUTION is deterministic. A scan reads one pinned knowledge version and
    records its hash in the report. Two runs against the same commit and the
    same knowledge version produce identical bytes.

So the tool adapts between runs, deliberately and visibly, rather than
drifting underneath you. Three further limits keep the adaptation honest:

  1. Learning adjusts CONFIDENCE, never SEVERITY. How sure we are is
     measurable from feedback; how much a defect matters is a judgement that
     belongs to the policy file.
  2. Learning never changes a gate outcome unless `gate.use_calibration` is
     explicitly set.
  3. A rule with too few observations reports as unproven rather than
     inheriting a flattering estimate from a handful of samples.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import statistics
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .claims import wilson_lower_bound
from .core import Finding

KNOWLEDGE_VERSION = 1
DEFAULT_PATH = ".arbiter/knowledge.json"

# Below this many adjudicated observations a rule's measured precision is not
# evidence, and the declared confidence stands.
MIN_OBSERVATIONS = 20


@dataclass
class RuleStats:
    """Evidence about one rule, kept in two separate ledgers.

    Adjudicated observations come from a human looking at a real finding.
    Synthetic observations come from generated defects and controls: cheap,
    plentiful, and drawn from a distribution we chose rather than one the
    world produced. Mixing them would let a million generated samples drown
    out ten real ones, so they are counted apart and reported apart.
    """

    rule_id: str
    true_positives: int = 0          # adjudicated by a person
    false_positives: int = 0
    synthetic_detected: int = 0      # planted defect, correctly found
    synthetic_missed: int = 0        # planted defect, not found  -> recall
    synthetic_clean_pass: int = 0    # control with no defect, correctly silent
    synthetic_false_alarm: int = 0   # control with no defect, fired anyway
    first_seen: str = ""
    last_seen: str = ""

    # -- adjudicated ------------------------------------------------------
    @property
    def observations(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float | None:
        n = self.observations
        return self.true_positives / n if n else None

    @property
    def precision_lower_bound(self) -> float | None:
        n = self.observations
        return wilson_lower_bound(self.true_positives, n) if n else None

    @property
    def proven(self) -> bool:
        return self.observations >= MIN_OBSERVATIONS

    # -- synthetic --------------------------------------------------------
    @property
    def synthetic_positives(self) -> int:
        return self.synthetic_detected + self.synthetic_missed

    @property
    def synthetic_negatives(self) -> int:
        return self.synthetic_clean_pass + self.synthetic_false_alarm

    @property
    def recall(self) -> float | None:
        n = self.synthetic_positives
        return self.synthetic_detected / n if n else None

    @property
    def recall_lower_bound(self) -> float | None:
        n = self.synthetic_positives
        return wilson_lower_bound(self.synthetic_detected, n) if n else None

    @property
    def specificity(self) -> float | None:
        n = self.synthetic_negatives
        return self.synthetic_clean_pass / n if n else None

    @property
    def specificity_lower_bound(self) -> float | None:
        n = self.synthetic_negatives
        return wilson_lower_bound(self.synthetic_clean_pass, n) if n else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update({
            "observations": self.observations,
            "precision": self.precision,
            "precision_lower_bound": self.precision_lower_bound,
            "proven": self.proven,
            "synthetic_positives": self.synthetic_positives,
            "synthetic_negatives": self.synthetic_negatives,
            "recall": self.recall,
            "recall_lower_bound": self.recall_lower_bound,
            "specificity": self.specificity,
            "specificity_lower_bound": self.specificity_lower_bound,
        })
        return d


@dataclass
class Knowledge:
    schema_version: int = KNOWLEDGE_VERSION
    updated: str = ""
    rules: dict[str, RuleStats] = field(default_factory=dict)
    # Per-repository metric distributions, used for adaptive thresholds.
    profiles: dict[str, dict] = field(default_factory=dict)
    # Fingerprints a human adjudicated, so the same finding is never re-asked.
    adjudicated: dict[str, str] = field(default_factory=dict)

    # -- identity ---------------------------------------------------------
    def version_hash(self) -> str:
        """Content hash. A scan records this so a run is reproducible."""
        payload = json.dumps(self.to_dict(include_hash=False), sort_keys=True)
        return "k:" + hashlib.sha256(payload.encode()).hexdigest()[:12]

    def to_dict(self, include_hash: bool = True) -> dict:
        d = {
            "schema_version": self.schema_version,
            "updated": self.updated,
            "rules": {k: v.to_dict() for k, v in sorted(self.rules.items())},
            "profiles": self.profiles,
            "adjudicated": self.adjudicated,
        }
        if include_hash:
            d["version"] = self.version_hash()
        return d

    @staticmethod
    def from_dict(d: dict) -> "Knowledge":
        k = Knowledge(
            schema_version=d.get("schema_version", KNOWLEDGE_VERSION),
            updated=d.get("updated", ""),
            profiles=d.get("profiles") or {},
            adjudicated=d.get("adjudicated") or {},
        )
        for rule_id, raw in (d.get("rules") or {}).items():
            k.rules[rule_id] = RuleStats(
                rule_id=rule_id,
                true_positives=int(raw.get("true_positives", 0)),
                false_positives=int(raw.get("false_positives", 0)),
                synthetic_detected=int(raw.get("synthetic_detected", 0)),
                synthetic_missed=int(raw.get("synthetic_missed", 0)),
                synthetic_clean_pass=int(raw.get("synthetic_clean_pass", 0)),
                synthetic_false_alarm=int(raw.get("synthetic_false_alarm", 0)),
                first_seen=raw.get("first_seen", ""),
                last_seen=raw.get("last_seen", ""),
            )
        return k

    # -- persistence ------------------------------------------------------
    @staticmethod
    def load(path: str | None = None) -> "Knowledge":
        p = Path(path or DEFAULT_PATH)
        if not p.is_file():
            return Knowledge()
        try:
            return Knowledge.from_dict(json.loads(p.read_text()))
        except Exception:
            return Knowledge()

    def save(self, path: str | None = None) -> str:
        p = Path(path or DEFAULT_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        self.updated = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))
        return self.version_hash()


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------

def record(knowledge: Knowledge, finding: Finding, verdict: str, note: str = "") -> bool:
    """Adjudicate one finding. Returns False if it was already adjudicated.

    Re-adjudicating the same fingerprint would let one disputed finding move
    the statistics as far as someone cares to click.
    """
    if verdict not in ("true_positive", "false_positive"):
        raise ValueError("verdict must be true_positive or false_positive")
    if finding.id in knowledge.adjudicated:
        return False
    now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    stats = knowledge.rules.setdefault(finding.rule_id, RuleStats(rule_id=finding.rule_id))
    if not stats.first_seen:
        stats.first_seen = now
    stats.last_seen = now
    if verdict == "true_positive":
        stats.true_positives += 1
    else:
        stats.false_positives += 1
    knowledge.adjudicated[finding.id] = f"{verdict}:{note}" if note else verdict
    return True


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

CONFIDENCE_BANDS = ((0.90, "high"), (0.65, "medium"), (0.0, "low"))


def record_synthetic(knowledge: Knowledge, rule_id: str, kind: str, n: int = 1) -> None:
    """Record generated evidence. Kept out of the adjudicated ledger."""
    field_name = {
        "detected": "synthetic_detected",
        "missed": "synthetic_missed",
        "clean_pass": "synthetic_clean_pass",
        "false_alarm": "synthetic_false_alarm",
    }[kind]
    stats = knowledge.rules.setdefault(rule_id, RuleStats(rule_id=rule_id))
    setattr(stats, field_name, getattr(stats, field_name) + n)


def calibrated_confidence(stats: RuleStats) -> str | None:
    """Confidence derived from measured precision, or None when unproven.

    Deliberately reads the adjudicated ledger only. Synthetic evidence speaks
    to whether a rule can detect what it was written to detect; it says
    nothing about how often the things it flags in the wild are real.
    """
    if not stats.proven:
        return None
    lb = stats.precision_lower_bound or 0.0
    for floor, label in CONFIDENCE_BANDS:
        if lb >= floor:
            return label
    return "low"


def apply(findings: list[Finding], knowledge: Knowledge) -> dict:
    """Attach measured precision and recalibrate confidence.

    Severity is deliberately untouched: feedback measures how often a rule is
    right, not how much it matters when it is.
    """
    changed = 0
    annotated = 0
    for f in findings:
        stats = knowledge.rules.get(f.rule_id)
        if stats is None or not stats.observations:
            continue
        annotated += 1
        f.tags = list(f.tags) + [
            f"precision:{stats.precision:.2f}",
            f"n={stats.observations}",
        ]
        new_conf = calibrated_confidence(stats)
        if new_conf and new_conf != f.confidence:
            f.tags.append(f"confidence-was:{f.confidence}")
            f.confidence = new_conf
            changed += 1
    return {"annotated": annotated, "recalibrated": changed}


# ---------------------------------------------------------------------------
# Adaptive thresholds
# ---------------------------------------------------------------------------

def build_profile(values: list[float]) -> dict:
    """Summarize a metric's distribution in this repository."""
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "median": statistics.median(ordered),
        "p90": ordered[min(len(ordered) - 1, int(0.90 * len(ordered)))],
        "p95": ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))],
        "p99": ordered[min(len(ordered) - 1, int(0.99 * len(ordered)))],
        "max": ordered[-1],
    }


def adaptive_threshold(profile: dict, fixed: float, percentile: str = "p95",
                       floor: float | None = None) -> float:
    """A threshold that fits the repository it is judging.

    A fixed 120-line function limit is wrong in both directions: noise in a
    codebase whose median function is 80 lines, and useless in one whose median
    is 12. Where a profile exists, flag the tail of the repository's own
    distribution instead — but never below a floor, so a codebase that is
    uniformly bad cannot normalize its way to a clean report.
    """
    if not profile or profile.get("n", 0) < 30:
        return fixed
    value = float(profile.get(percentile, fixed))
    return max(value, floor if floor is not None else fixed * 0.5)


def metrics_from_inventory(inventory, graph=None) -> dict:
    """Collect the distributions adaptive thresholds are drawn from."""
    file_lines = [f.lines for f in inventory.text_files()
                  if f.role in ("source", "iac") and f.lines]
    out = {"file_lines": build_profile([float(x) for x in file_lines])}

    try:
        from . import ast as ts
        if ts.available():
            lengths: list[float] = []
            complexities: list[float] = []
            for f in inventory.text_files():
                if f.role not in ("source",) or not ts.ts_name(f.language):
                    continue
                for fn in ts.functions(f.abspath, f.language):
                    lengths.append(float(fn.lines))
                    complexities.append(float(fn.complexity))
            out["function_lines"] = build_profile(lengths)
            out["complexity"] = build_profile(complexities)
    except Exception:
        pass
    return out


def resolve_quality_config(config: dict, profiles: dict) -> dict:
    """Return the quality thresholds a run should use, fixed or adaptive."""
    quality = dict(config.get("quality") or {})
    if not quality.get("adaptive"):
        return quality
    quality["max_file_lines"] = int(adaptive_threshold(
        profiles.get("file_lines") or {}, float(quality.get("max_file_lines", 800)), "p95", 200))
    quality["max_function_lines"] = int(adaptive_threshold(
        profiles.get("function_lines") or {}, float(quality.get("max_function_lines", 120)), "p95", 40))
    quality["max_complexity"] = int(adaptive_threshold(
        profiles.get("complexity") or {}, float(quality.get("max_complexity", 20)), "p95", 10))
    quality["_adaptive_source"] = "repository distribution (p95)"
    return quality
