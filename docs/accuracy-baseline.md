# Accuracy Baseline and Evidence Gaps

Inventory date: 2026-10-23. This is an inventory of existing evidence, not a
new benchmark run or a 99% certification. Machine-readable source inventory
and the per-run record contract are in
[accuracy-benchmark-manifest.json](accuracy-benchmark-manifest.json), validated
by [accuracy-benchmark-manifest.schema.json](accuracy-benchmark-manifest.schema.json).

No rule was changed and no held-out labels, findings, or excerpts were opened
for this inventory. The sealed AI corpus remains aggregate-only. The
historical figures below are quoted from the dated harness and precision
documentation; where the original run commit or host environment was not
recorded there, that reproducibility gap is stated rather than guessed.

## Existing benchmark inventory

| Source | Role | Coverage | Label evidence | Current use and limitations |
|---|---|---|---|---|
| `fixtures/planted` | Regression only | Five language families: Go, Java, Python, Ruby, TypeScript | Maintainer-authored planted positives and safe twins | Validates known shapes; excluded from population accuracy claims. |
| `fixtures/ai-corpus` | Development and regression | 25 apps: 5 tasks × 5 languages | One independent model reviewer per language; reconciled after Arbiter findings | Rules were tuned against it. Native probes detect 33/117 labelled code defects (28%) in the 2026-10-23 report. Not independent final evidence. |
| `fixtures/ai-corpus-heldout` | Sealed aggregate evaluation | 40 apps: 8 tasks × 5 languages; generated with separate models | Independent model labels committed before Arbiter run; no reconciliation; no completed human audit recorded | 6/142 defects detected (4%) in the documented native-only aggregate. The tree is sealed; only the documented aggregate-only scorer and guard are permitted. |
| Pinned public gold repositories | Development and repository-level holdout | 24 repos across Go, Java, Python, Ruby, TypeScript; 17 development and 7 held out | Arbiter finding labels include model labels; the harness describes a 60-row human sheet from 5 repos/41 strata as not yet labelled | Public projects are not a random sample of all repositories. Four repositories report `NOASSERTION` license metadata; resolve license/provenance before external publication. |
| OWASP Benchmark Java/Python | Sealed ground-truth sources | Java: 2,740 cases/11 CWEs; Python: 1,230 cases/14 CWEs | Benchmark expected results; human audit status not recorded | Java source is GPL-2.0; Python is GPL-3.0. Both are fetched at pins and have restrictions recorded in `tools/gold/benchmarks.json`. Synthetic benchmark scope is not production-repository scope. |
| CVE fix pairs and Juliet Java | Sealed ground-truth sources | CVE language mix and Juliet license status not inventoried here; Juliet is Java | Patch-derived or benchmark-provided labels; independent human audit not recorded | License/provenance and label audit are gaps. These sources are held out; do not inspect them while tuning. |

The existing precision ledger reports labels for 120 rules and two admitted
rules, but no rule is declared verified; therefore there is no verified-tier
precision claim. Existing ledger confidence calculations do not account for
repository-level clustering. Model-label calibration is not equivalent to
human ground truth.

## Verification when human reviewers are unavailable

There is no non-human technique that turns noisy labels into independent
ground truth for arbitrary repositories. The viable alternatives have
different, narrower evidential strength:

1. **Known-answer benchmark oracle:** compare against a benchmark's published
   safe/vulnerable expected results. This can establish conformance on that
   benchmark if the source, license, and holdout policy permit its use. It
   does not establish production-population accuracy. The existing OWASP
   Python source is currently sealed in this repository and marked “never
   redistributed or run” in `tools/gold/benchmarks.json`; it is not approved
   for this pilot.
2. **CVE fix-pair datasets:** [CVEfixes v1.0.8](https://github.com/secureIT-project/CVEfixes)
   is a candidate. Its maintainers describe an automatically collected
   dataset covering 11,873 CVEs, 12,107 fixing commits, 4,249 projects, and
   272 CWE types; the [published dataset record](https://doi.org/10.5281/zenodo.13118970)
   declares CC BY 4.0. That does not settle rights for source code from each
   underlying project, prove Python CWE-89 sample size, or make every patch a
   clean ground-truth label. Its archive is about 12.7 GB and has not been
   downloaded or ingested.
3. **Generated unsafe/safe pairs and mutations:** derive expected outcomes
   from how the test cases are constructed, then run property and regression
   checks. This is useful for rule conformance and regression, but is
   maintainer-authored and cannot certify population accuracy.
4. **Other analyzers and model judges:** use them to find disagreements and
   prioritize cases. Agreement is not a truth oracle; model judges need
   calibration against independent truth and cannot substitute for it.

For the chosen Python SQL-injection slice, the recommended no-human path is
to screen CVEfixes metadata for a sufficiently large CWE-89/Python subset
without opening code or labels; verify selected source licenses; then create
an aggregate-only benchmark evaluator. If those gates fail, stop rather than
quietly switching to synthetic examples and calling that accuracy. Any
result must be named **CVEfixes benchmark conformance** and scoped to its
data and label-generation method. It cannot support a general 99% claim.

## Execution-platform evidence

The pull-request fast CI matrix currently runs on Ubuntu and Windows. The
analyzer installation, self-gate, and slow analyzer-backed tier run on Linux
only. The macOS CI work is tracked by pending ARB-063 and is not present in the
current matrix. Architecture is not explicitly matrixed. This is platform
compatibility evidence, not language-level recall evidence; in particular,
the CI setup does not establish equivalent analyzer coverage on Windows.

## Evidence gaps, in priority order

1. **Independent human truth:** Complete a blinded, two-reviewer finding
   sample and a separate blind repository audit for misses. Record reasons,
   abstentions, disagreement adjudication, reviewer agreement, and sampling
   probabilities. Do not use model labels alone to certify the 99% claim.
2. **Cluster-aware uncertainty:** Implement and validate interval estimates
   that respect repositories as sampling clusters and the declared stratified
   sampling design. Publish repository count and effective sample size, not
   only finding count.
3. **Representative populations:** The current application corpora are
   synthetic, and pinned public repositories are a convenience sample.
   Define and recruit representative repository populations for each
   claimed segment.
4. **False-negative discovery:** A labelled benchmark can measure recall only
   for its labelled defect universe. Add independent, blind code/configuration
   audits that actively search for missed defects.
5. **Language and weakness coverage:** The current recall numbers are
   aggregate across five source languages and a limited AI-generated
   population. Build per-weakness and per-language/framework estimates with
   enough independently reviewed repositories in each claimed stratum.
6. **Platform compatibility:** Add macOS and architecture evidence where
   supported, and separately measure analyzer availability and output parity
   per host. Do not extrapolate Linux-only analyzer results.
7. **Provenance and licensing:** Resolve the four `NOASSERTION` gold-repo
   entries and inventory the license, pin, and redistribution terms of CVE
   and Juliet sources before publishing or redistributing data.
8. **Run reproducibility:** Historical score documentation does not consistently
   retain the Arbiter commit, clean/dirty state, exact configuration,
   evaluator revision, host image, architecture, and all tool/database pins.
   Populate the run record in the benchmark manifest for every new evaluation.

## Baseline decision

The present data is suitable for regression, gap discovery, and planning a
narrow pilot. It is not sufficient for a 99% precision-and-recall claim:
the AI-heldout recall is 4%, the AI development recall is 28%, human
adjudication is incomplete, confidence bounds are not cluster-aware, and
platform/segment coverage is incomplete.

**Next milestone:** create a new, non-sealed development/validation sample for
one narrowly scoped weakness and language slice, obtain blind human
adjudication, and validate the cluster-aware estimator before changing rules.
Keep the existing sealed AI and gold sources closed.
