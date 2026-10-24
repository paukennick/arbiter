# Accuracy Roadmap

This is the implementation program for Arbiter's 99% accuracy goal. It
complements [precision.md](precision.md), which defines the current
finding-precision ledger and verified tier, and
[testing-harness.md](testing-harness.md), which describes the existing
evaluation instruments.

## The claim we are trying to earn

"99% accuracy" is not a single useful metric for a scanner. Arbiter will
measure and report:

- **Precision:** of findings reported for an in-scope weakness, the share that
  independent reviewers confirm is a real issue at the reported location.
- **Recall:** of independently labelled, in-scope defects in the benchmark,
  the share Arbiter detects.
- **Assessment coverage:** the share of applicable rules and declared
  language, repository, and execution-platform strata that were actually
  evaluated. Unrun or under-sampled strata are unproven, not passes.

The target is a **95% lower confidence bound of at least 99% for both
precision and recall**, not a point estimate of 99%. Claims are made only for
the measured population and each applicable segment that independently meets
the evidence bar. A combined score cannot hide a weak rule, language,
weakness class, repository population, operating system, or architecture.
No report or product copy may imply a guarantee for arbitrary repositories or
unsupported environments.

The eventual goal is to meet that bar for every rule and every supported,
applicable segment that Arbiter presents as verified. Until then, rules and
segments that miss the bar, lack enough labels, or lack trustworthy labels
remain advisory or not assessed; they do not inherit a claim from a stronger
segment.

`docs/precision.md` currently uses a Wilson 95% lower bound for its
population-weighted precision estimate. The roadmap preserves that discipline
while adding recall and requiring uncertainty estimates to account for
repository-level clustering. Findings from one repository are not treated as
independent evidence merely because there are many of them. For intuition, a
simple independent sample with no errors needs about 381 examples for a
two-sided 95% Wilson lower bound to reach 99%; this is not a universal sample
size, and cluster-aware effective sample size can require substantially more.

## Current evidence

As documented on 2026-10-23:

- The precision ledger contains labels for 120 rules; two rules are admitted,
  none is declared verified, and there is no verified-tier precision claim.
- On the AI-written development corpus, native probes detect 33 of 117
  labelled code defects (28%). The rules were tuned against this corpus, so
  this is development evidence, not a generalization claim.
- On the separately held-out AI-written corpus, native probes detect 6 of
  142 labelled defects (4%).

These figures are not directly interchangeable: they use different
populations and roles. They show why better benchmark coverage and recall are
necessary before a 99% claim is plausible. Model-label calibration or a
synthetic invariant test is not a substitute for scanner precision or recall.

## Evidence rules

1. **Declare applicability first.** Maintain a matrix of rule, weakness class,
   language/framework, repository population, analyzer/version, operating
   system, and architecture. Mark combinations as applicable, not applicable,
   unsupported, or not yet measured, with evidence for the decision.
2. **Use independent ground truth.** A benchmark defect must be confirmed by
   two reviewers who do not see Arbiter's finding or rule rationale. Reviewers
   record scope, location, impact, and evidence; a qualified adjudicator
   resolves disagreements. If human reviewers are unavailable, an
   independently maintained benchmark's machine-readable expected outcomes
   can support **benchmark-conformance** results only, after license and
   holdout approval; it does not replace human-grounded claims about a broader
   repository population. Model labels may prioritize review but cannot
   independently certify a claim.
3. **Protect the holdout.** Split by repository or repository family before
   tuning. Rule authors do not inspect held-out findings, labels, or excerpts.
   Keep a development set for iteration, a validation set for decisions, and
   a sealed final test set for claims. Record provenance, license, snapshot,
   tooling versions, and split in the benchmark manifest.
4. **Sample both sides.** Precision requires adjudicating sampled reported
   findings, including findings initially marked unreviewed. Recall requires
   an independent audit of code and configuration for missed defects, not
   merely matching current findings to known labels. Document sampling frames,
   inclusion probabilities, label coverage, and exclusions.
5. **Respect dependence and weighting.** Estimate precision and recall by
   predeclared strata, weight only to a documented target population, and use
   repository-cluster-aware confidence intervals or a validated hierarchical
   method. Do not treat multiple findings from one repository as independent.
   Publish numerator, denominator, interval, effective sample size, cluster
   count, and unlabelled population.
6. **Keep regression evidence in its lane.** Planted fixtures, mutation
   variants, metamorphic tests, synthetic invariants, and model verification
   are valuable for regression and robustness. None alone establishes
   production-distribution precision or recall.
7. **Freeze the experiment.** Pin Arbiter commit, analyzer binaries and rule
   sets, vulnerability databases where relevant, configuration, benchmark
   snapshot, and host image. An update that can change results starts a
   versioned evaluation; old results remain reproducible.
8. **Do not erase misses.** Every missed in-scope defect and false alarm is
   triaged with a reason and traceable regression evidence. Exclusions must be
   predeclared, justified, and counted in coverage, not added after seeing
   unfavorable results.

## Phased implementation

### Accountable roles

These are responsibilities, not assumptions that a role is already staffed:

- **Evaluation lead:** maintains metric definitions, manifests, and
  reproducibility.
- **Benchmark custodian:** controls private/held-out material and its access
  log; does not author the rules being evaluated.
- **Independent reviewers:** label findings and audit repositories without
  seeing Arbiter output; an adjudicator resolves disagreements.
- **Rule owners:** implement and regression-test rule changes on development
  data only.
- **Release approver:** accepts or withholds public claims based on the frozen
  evaluation report.

### Phase 1 — Lock the evaluation contract

**Owner:** evaluation lead, reviewed by an independent statistician or
evaluator.

- Convert the applicability matrix into a versioned, machine-readable
  benchmark manifest.
- Define canonical matching rules for defect identity, location tolerance,
  CWE/category mapping, duplicate findings, and partial detection.
- Define human-review instructions, blind review sheets, disagreement
  adjudication, label provenance, and appeal/correction history.
- Specify a repository-cluster-aware confidence method and validate its
  behavior on simulated data with known rates, unequal weights, zero-error
  strata, and correlated findings.

**Exit:** the manifest and metric implementation are reviewed; synthetic
validation demonstrates calibrated coverage; an independent evaluator can
reproduce scores without access to private model reasoning.

### Phase 2 — Establish a trustworthy baseline

**Owner:** benchmark custodian and independent reviewers.

- Inventory current rule labels, benchmark source provenance, held-out
  boundaries, language coverage, and adjudication quality.
- Identify gaps by weakness, language/framework, repository population, and
  supported execution platform. Do not unseal current holdouts to fill gaps.
- Run pinned, reproducible scans on approved development and evaluation
  populations; record precision, recall, intervals, coverage, and
  not-assessed reasons separately.
- Obtain independent human adjudication for a stratified sample of findings
  and blind repository audits for recall.

**Exit:** baseline results can be rebuilt from immutable manifests; every
result has a declared population and uncertainty; unsupported segments are
visible rather than imputed.

### Phase 3 — Improve precision without concealing recall loss

**Owner:** rule owners; evaluation lead reviews paired metrics.

- Triage false positives by rule and segment; fix root causes or narrow a
  rule's stated scope.
- Re-run the development and validation sets after each rule change.
- Add false-positive regression cases, including counterexamples that look
  similar but are safe.
- Keep the sealed test set unopened until a release candidate is frozen.

**Exit:** candidate precision reaches the predeclared bar on validation data
without unmeasured loss of recall; false-positive regressions are retained.

### Phase 4 — Improve recall from independent misses

**Owner:** rule owners; benchmark custodian protects evaluation boundaries.

- Prioritize missed defects by impact, prevalence, affected segments, and
  whether deterministic static evidence can support detection.
- Add or improve AST, semantic, data-flow, dependency, IaC, and specialist
  analyzer coverage only where evidence supports the capability.
- Add each confirmed miss to development/regression material only after
  preserving the sealed evaluation boundary; do not tune directly against
  final test examples.
- Measure the effect on both recall and precision, plus coverage and runtime.

**Exit:** every change has paired precision/recall evidence and no claimed
segment regresses below its approved floor.

### Phase 5 — Certify claims and promote rules

**Owner:** independent evaluator prepares the report; release approver
authorizes or withholds claims.

- Evaluate a frozen release candidate once against the sealed test set.
- Require the 95% lower bound for both precision and recall to be at least
  99% in every claimed applicable rule/category/language/repository segment.
- Require sufficient repository clusters and labelled-population coverage;
  if evidence is sparse, report "not enough evidence" instead of pooling it
  into a misleading overall result.
- Promote only supported rules to `verified`. Rules without evidence remain
  advisory; missing binaries, grammars, databases, or unsupported platforms
  remain not assessed.
- Publish the benchmark version, evaluation commit, scope, intervals,
  denominators, exclusions, and unproven segments with every claim.

**Exit:** an external reviewer can reproduce the result and verify that no
unmeasured or failing segment is hidden by aggregation.

### Phase 6 — Maintain the evidence

**Owner:** evaluation lead and benchmark custodian.

- Re-evaluate after rule, analyzer, database, or benchmark changes that can
  affect output.
- Add newly discovered production misses and false alarms to development
  material with provenance; keep final test sets sealed or rotate them using
  a documented process.
- Monitor score drift and label quality. Suspend a claim when a dependency
  changes materially, evidence becomes stale, or a segment falls below its
  confidence threshold.

**Exit:** claims remain tied to current, reproducible evidence and are
withdrawn automatically or explicitly when their evidence expires.

## Platform and language scope

Language recall and operating-system support are different questions. Recall
is measured for each applicable language/framework and weakness segment.
Operating-system and architecture testing verifies installation, execution,
output normalization, and parity for the pinned toolchain. Where tool output
or available checks differ by host, that host is a separate metric stratum;
otherwise it is a compatibility gate, not an artificial duplicate of source
labels.

The benchmark must include only combinations explicitly declared supported.
Adding a language, operating system, architecture, analyzer, or repository
population creates a new applicability row that must pass its own evidence
gates before a claim is made. "Works on all platforms" is not inferred from a
Linux-only run.

## Immediate next milestone

ARB-096 established the initial metadata inventory and historical baseline in
[accuracy-baseline.md](accuracy-baseline.md), with the machine-readable source
inventory and per-run record contract in
[accuracy-benchmark-manifest.json](accuracy-benchmark-manifest.json). It
confirmed that the present evidence is insufficient for certification and
identified gaps in human adjudication, cluster-aware uncertainty, benchmark
representativeness, and platform coverage. No detection rules were changed,
and sealed labels/findings/excerpts were not opened.

The next implementation milestone should create a new, non-sealed
development/validation sample for one narrowly scoped weakness and language
slice, complete blind human adjudication, and validate the cluster-aware
estimator before changing rules. Keep the existing sealed AI and gold sources
closed. Expand rule coverage only after this measurement pilot is reviewed.

This roadmap is a program, not a result: it does not certify Arbiter at 99%.
