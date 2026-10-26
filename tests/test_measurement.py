"""Tests for the code that judges the rules, not for the rules.

A wrong rule reports a wrong finding, and somebody notices. A wrong
*measurement* certifies the wrong rule, and nobody does -- the number it
prints is the thing you would have used to check. This project has already
been bitten there: a held-out comparison called Kubernetes findings "2.09x
worse" on held-out code, and all three causes were measurement bugs (it
matched a repository by its label rather than its content, counted findings
instead of weighting them by severity and confidence, and used one repository
per side as though that were a sample). Separately, three dependency-pinning
rules carried a hand-assigned severity until measurement showed two of them
fire *more* on good code than on bad.

So this file tests the arithmetic and the guarantees around it: the
confidence interval, the threshold that decides a rule is proven, and the
separation between what a person judged and what a generator produced.
"""
from __future__ import annotations

import json

import pytest

from arbiter.claims import wilson_lower_bound
from arbiter.core import Finding, Location
from arbiter.learn import (
    MIN_OBSERVATIONS,
    Knowledge,
    RuleStats,
    apply,
    calibrated_confidence,
    record_synthetic,
)

# --------------------------------------------------------------------------
# The confidence interval
# --------------------------------------------------------------------------

def test_a_perfect_run_is_not_certainty():
    """Ten for ten is evidence of a rate above roughly 0.72, not of six nines.

    This is the whole reason a lower bound is used instead of the ratio. A
    rule that has never been wrong in ten tries and one that has never been
    wrong in ten thousand are not the same claim.
    """
    assert wilson_lower_bound(10, 10) < 0.85
    assert wilson_lower_bound(10_000, 10_000) > 0.99
    assert wilson_lower_bound(10, 10) < wilson_lower_bound(10_000, 10_000)


def test_the_bound_never_leaves_the_unit_interval():
    for successes, n in [(0, 0), (0, 1), (1, 1), (0, 100), (50, 100), (100, 100)]:
        lb = wilson_lower_bound(successes, n)
        assert 0.0 <= lb <= 1.0, f"{successes}/{n} produced {lb}"


def test_the_bound_never_exceeds_what_was_observed():
    """A lower bound above the point estimate would be an invented claim."""
    for successes, n in [(1, 2), (3, 4), (9, 10), (99, 100), (1, 1000)]:
        assert wilson_lower_bound(successes, n) <= successes / n


def test_more_evidence_at_the_same_rate_tightens_the_bound():
    prev = -1.0
    for n in (10, 100, 1_000, 10_000):
        lb = wilson_lower_bound(int(n * 0.9), n)
        assert lb > prev, "the bound must rise as the same rate is observed more often"
        prev = lb


def test_no_observations_claims_nothing():
    assert wilson_lower_bound(0, 0) == 0.0


# --------------------------------------------------------------------------
# The threshold that decides a rule is proven
# --------------------------------------------------------------------------

def test_a_rule_is_unproven_one_observation_short():
    """The boundary itself, so a change to it has to be deliberate."""
    stats = RuleStats(rule_id="r", true_positives=MIN_OBSERVATIONS - 1, false_positives=0)
    assert stats.observations == MIN_OBSERVATIONS - 1
    assert not stats.proven
    assert calibrated_confidence(stats) is None


def test_a_rule_becomes_proven_exactly_at_the_threshold():
    stats = RuleStats(rule_id="r", true_positives=MIN_OBSERVATIONS, false_positives=0)
    assert stats.proven
    assert calibrated_confidence(stats) is not None


def test_being_proven_is_not_the_same_as_being_right():
    """Twenty verdicts that mostly went against the rule must not read high."""
    bad = RuleStats(rule_id="r", true_positives=4, false_positives=16)
    assert bad.proven
    assert calibrated_confidence(bad) == "low"


# --------------------------------------------------------------------------
# The separation the whole design rests on
# --------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 10, 1_000, 500_000])
def test_generated_evidence_never_makes_a_rule_proven(n):
    """Injection trials must not move calibration, at any volume.

    The live ledger holds 227,999 synthetic observations and no human
    verdicts, and reports exactly zero proven rules. If generated evidence
    counted, a night of trials would manufacture confidence for every rule in
    the pack, and the number a report prints would describe the generator
    rather than the code.
    """
    k = Knowledge()
    for _ in range(min(n, 1000)):
        record_synthetic(k, "arbiter/demo", "detected", n=max(1, n // 1000))
    stats = k.rules["arbiter/demo"]
    assert stats.observations == 0, "synthetic trials must not count as observations"
    assert not stats.proven
    assert calibrated_confidence(stats) is None


def test_synthetic_volume_does_not_shift_a_calibrated_confidence():
    """Hold the human verdicts fixed, vary the generated ones, expect no move."""
    def confidence_with(synthetic: int) -> str | None:
        k = Knowledge()
        stats = RuleStats(rule_id="arbiter/demo", true_positives=18, false_positives=2)
        k.rules["arbiter/demo"] = stats
        for _ in range(synthetic):
            record_synthetic(k, "arbiter/demo", "detected", n=100)
        return calibrated_confidence(k.rules["arbiter/demo"])

    baseline = confidence_with(0)
    assert baseline is not None
    for volume in (1, 50, 500):
        assert confidence_with(volume) == baseline


def test_learning_never_changes_a_native_rules_severity():
    """Severity is policy. Measurement may say how often a rule is right, not
    how much it matters when it is."""
    k = Knowledge()
    k.rules["arbiter/native"] = RuleStats(rule_id="arbiter/native",
                                          true_positives=40, false_positives=0)
    f = Finding(rule_id="arbiter/native", title="t", severity="high",
                confidence="medium", location=Location(path="a.tf"), evidence="e")
    apply([f], k)
    assert f.severity == "high", "calibration moved a native rule's severity"


# --------------------------------------------------------------------------
# Measured severity for external checks
# --------------------------------------------------------------------------

def test_a_measured_severity_reaches_a_scan(tmp_path):
    """The merge that was missing.

    `tools/calibrate_external.py` wrote its severities to a report file and
    `apply()` read a map inside knowledge.json. Nothing moved a value from one
    to the other, so every nightly measurement of the external tools changed
    nothing at all, and the severities in the live ledger came from a one-off
    step that no longer exists.
    """
    report = tmp_path / "external-severity.json"
    report.write_text(json.dumps({
        "checks": {
            "checkov/CKV_AWS_1": {"severity": "low"},
            "checkov/CKV_AWS_2": {"severity": None},   # too few observations to grade
        }
    }), encoding="utf-8")

    k = Knowledge()
    merged = k.merge_external_severity(str(report))
    assert merged == 1
    assert k.external_severity == {"checkov/CKV_AWS_1": "low"}, (
        "a check the tool declined to grade must not be stored")

    graded = Finding(rule_id="checkov/CKV_AWS_1", title="t", severity="medium",
                     location=Location(path="a.tf"), evidence="e")
    ungraded = Finding(rule_id="checkov/CKV_AWS_2", title="t", severity="medium",
                       location=Location(path="a.tf"), evidence="e")
    apply([graded, ungraded], k)

    assert graded.severity == "low"
    assert "severity:measured" in graded.tags
    assert "severity-was:medium" in graded.tags
    assert ungraded.severity == "medium", "an ungraded check keeps the tool's own severity"


def test_measurement_cannot_promote_a_check_to_high():
    """Discrimination measures signal; severity encodes consequence.

    A check requiring a description on every security-group rule fires 33
    times on deliberately broken Terraform and never on well-maintained
    repositories. The ratio is real and reproducible. It is also not a
    security finding, and grading it `high` would put a missing comment
    beside a public bucket.
    """
    import sys
    sys.path.insert(0, "tools")
    from calibrate_external import band

    for ratio in (3.0, 10.0, 50.0, 1_000.0, float("inf")):
        assert band(ratio) != "high", f"ratio {ratio} was promoted to high"
    assert band(10.0) == "medium"
    assert band(3.0) == "low"
    assert band(1.0) == "info"


# --------------------------------------------------------------------------
# Adaptive thresholds
# --------------------------------------------------------------------------

def test_a_profile_is_ignored_until_there_is_enough_of_it():
    """Under thirty samples the fixed threshold stands.

    Six files are a rumour about a codebase, not its distribution, and a
    threshold drawn from six would swing with every file added.
    """
    from arbiter.learn import adaptive_threshold
    thin = {"n": 6, "p95": 4000.0}
    assert adaptive_threshold(thin, fixed=800.0) == 800.0


def test_a_uniformly_bad_codebase_cannot_normalize_its_way_clean():
    """The configured threshold caps the result, so adaptive only tightens.

    Without the cap the worse a codebase gets the more permissive its own
    threshold becomes, and the report improves as the code degrades. The
    earlier version of this test asserted only `>= floor`, which a threshold of
    50,000 satisfies -- it passed while the property it is named for was
    violated by a factor of sixty.
    """
    from arbiter.learn import adaptive_threshold
    awful = {"n": 500, "p95": 50_000.0}
    assert adaptive_threshold(awful, fixed=800.0, floor=200.0) == 800.0

    tidy = {"n": 500, "p95": 10.0}
    assert adaptive_threshold(tidy, fixed=800.0, floor=200.0) == 200.0


def test_degrading_a_codebase_uniformly_cannot_hide_findings():
    """Scaling every measurement must not leave the flagged set unchanged.

    A threshold drawn from a percentile alone is scale-equivariant: at ten
    times the size it is ten times the number, so exactly the same files sit
    above it and a codebase that got uniformly worse reports identically. The
    cap breaks that equivariance, which is the whole reason it is there.
    """
    from arbiter.learn import adaptive_threshold
    files = [5.0, 100.0, 300.0, 700.0, 954.0, 2032.0]

    def flagged(scale: float) -> int:
        profile = {"n": 60, "p95": 1066.0 * scale}
        threshold = adaptive_threshold(profile, fixed=900.0, floor=200.0)
        return sum(1 for f in files if f * scale > threshold)

    assert flagged(1) == 2
    assert flagged(10) > flagged(1), (
        "ten times worse must report more, not the same findings by rank")


def test_profiles_are_stored_per_repository():
    """One threshold for two codebases is wrong for both."""
    from arbiter.learn import Knowledge, learn_profiles, profile_for
    k = Knowledge()
    learn_profiles(k, "terse", {"file_lines": {"n": 40, "p95": 30.0}})
    learn_profiles(k, "sprawling", {"file_lines": {"n": 40, "p95": 3000.0}})
    assert profile_for(k, "terse")["file_lines"]["p95"] == 30.0
    assert profile_for(k, "sprawling")["file_lines"]["p95"] == 3000.0
    assert profile_for(k, "never-profiled") == {}


def test_learning_a_profile_moves_the_knowledge_version():
    """Profiles decide which findings a scan reports, so they are pinned.

    This is why `arbiter profile` is a separate command and a scan never
    writes one: if scanning stored a profile, every run would move the hash it
    had just written into its own report, and `--pin-knowledge` would fail
    against a ledger the pinned run itself produced.
    """
    from arbiter.learn import Knowledge, learn_profiles
    k = Knowledge()
    before = k.version_hash()
    learn_profiles(k, "demo", {"file_lines": {"n": 40, "p95": 120.0}})
    assert k.version_hash() != before


def test_an_empty_measurement_stores_nothing():
    """A repository with no readable source must not get a profile of zeroes."""
    from arbiter.learn import Knowledge, learn_profiles, profile_for
    k = Knowledge()
    learn_profiles(k, "empty", {"file_lines": {}, "complexity": {}})
    assert profile_for(k, "empty") == {}


def test_the_profile_key_does_not_depend_on_a_scans_display_id(tmp_path):
    """Written and read under the same name, or the store is write-only.

    A single-target scan calls its repository "root" for display. Keying the
    profile on that would give every separately-scanned repository the same
    entry, so the first one profiled would set the thresholds for all of them
    -- and a profile written by `arbiter profile` under the directory name
    would never be found again. That is how this was wrong when first written:
    the scan reported `profile_source: measured` with a learned profile
    sitting in the ledger.
    """
    from arbiter.learn import Knowledge, learn_profiles, profile_for, profile_key
    one = tmp_path / "service-alpha"
    two = tmp_path / "service-beta"
    one.mkdir()
    two.mkdir()

    assert profile_key(str(one)) != profile_key(str(two)), (
        "two repositories must not share a profile key")

    k = Knowledge()
    learn_profiles(k, profile_key(str(one)), {"file_lines": {"n": 40, "p95": 42.0}})
    assert profile_for(k, profile_key(str(one)))["file_lines"]["p95"] == 42.0
    assert profile_for(k, profile_key(str(two))) == {}
