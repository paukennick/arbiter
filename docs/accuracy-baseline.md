# Accuracy Baseline and Evidence Gaps

Inventory date: 2026-10-24. This records the existing evidence and one narrow
benchmark-conformance run; it is not a 99% certification. Machine-readable
source inventory and run metadata are in
[accuracy-benchmark-manifest.json](accuracy-benchmark-manifest.json), validated
by [accuracy-benchmark-manifest.schema.json](accuracy-benchmark-manifest.schema.json).

No detection rules were changed. The sealed AI and OWASP sources remain
untouched; the approved RealVuln subset was evaluated through the aggregate-only
workflow below, without publishing per-case reports. Historical figures below
are quoted from their dated harness and precision documentation; missing run
metadata is stated rather than guessed.

## Existing benchmark inventory

| Source | Role | Coverage | Label evidence | Current use and limitations |
|---|---|---|---|---|
| `fixtures/planted` | Regression only | Five language families: Go, Java, Python, Ruby, TypeScript | Maintainer-authored planted positives and safe twins | Validates known shapes; excluded from population accuracy claims. |
| `fixtures/ai-corpus` | Development and regression | 25 apps: 5 tasks × 5 languages | One independent model reviewer per language; reconciled after Arbiter findings | Rules were tuned against it. Native probes detect 33/117 labelled code defects (28%) in the 2026-10-23 report. Not independent final evidence. |
| `fixtures/ai-corpus-heldout` | Sealed aggregate evaluation | 40 apps: 8 tasks × 5 languages; generated with separate models | Independent model labels committed before Arbiter run; no reconciliation; no completed human audit recorded | 6/142 defects detected (4%) in the documented native-only aggregate. The tree is sealed; only the documented aggregate-only scorer and guard are permitted. |
| Pinned public gold repositories | Development and repository-level holdout | 24 repos across Go, Java, Python, Ruby, TypeScript; 17 development and 7 held out | Arbiter finding labels include model labels; the harness describes a 60-row human sheet from 5 repos/41 strata as not yet labelled | Public projects are not a random sample of all repositories. Four repositories report `NOASSERTION` license metadata; resolve license/provenance before external publication. |
| OWASP Benchmark Java/Python | Sealed ground-truth sources | Java: 2,740 cases/11 CWEs; Python: 1,230 cases/14 CWEs | Benchmark expected results; human audit status not recorded | Java source is GPL-2.0; Python is GPL-3.0. Both are fetched at pins and have restrictions recorded in `tools/gold/benchmarks.json`. Synthetic benchmark scope is not production-repository scope. |
| CVE fix pairs and Juliet Java | Sealed ground-truth sources | CVE language mix and Juliet license status not inventoried here; Juliet is Java | Patch-derived or benchmark-provided labels; independent human audit not recorded | License/provenance and label audit are gaps. These sources are held out; do not inspect them while tuning. |
| RealVuln 3.1.0 Python CWE-89 subset | Aggregate-only external conformance pilot | 11 pinned repositories; 26 vulnerable labels and 34 safe traps | Benchmark-maintainer `manual_review`; only 5/60 explicitly set `manually_verified` | Completed at pinned source and benchmark commits using MIT/Unlicense sources only. Curated vulnerable applications; not representative production repositories or independently audited ground truth. Aggregate result and run metadata follow. |

The existing precision ledger reports labels for 120 rules and three admitted
rules. One rule, `supply.unpinned-action`, is declared verified (ARB-101: 690
tp, 0 fp, Wilson 95% lower 0.9945, model labels including the held-out r5
set); there is still no verified-tier held-out claim from human labels. Existing ledger confidence calculations do not account for
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

## Completed Python CWE-89 conformance pilot

The owner-approved RealVuln 3.1.0 subset contains 11 pinned Python repositories
whose source licenses are MIT or Unlicense. Only the `lang_python` probe ran,
with the offline profile, adapters disabled, and cache and history disabled.
All 11 Python probes were assessed; all 11 overall scorecards were withheld
because this deliberately narrow run did not assess the other applicable
probes. A withheld scorecard is not a low grade and was not used as a result.
The source code was statically scanned, not executed.

| Measure | Aggregate result |
|---|---:|
| Labelled cases | 60 (26 vulnerable, 34 safe traps) |
| Case-level confusion | TP 21, FN 5, FP 6, TN 28 |
| Labelled-case precision | 21/27 = 77.8% |
| Labelled-case recall | 21/26 = 80.8% |
| Safe-trap false-positive rate | 6/34 = 17.6% |
| Unmatched CWE-89 findings | 1, left unassessed |
| 95% repository-cluster bootstrap interval, precision | 64.3%–90.9% |
| 95% repository-cluster bootstrap interval, recall | 50.0%–100.0% |

The intervals use 10,000 seeded repository-cluster bootstrap replicates and
describe stability only within this curated 11-repository subset. The 60
labels are benchmark-maintainer evidence marked `manual_review`; five
explicitly set `manually_verified=true`, and no independent multi-reviewer
audit is documented. The reported precision is labelled-case conformance,
not Arbiter finding-level precision: the unmatched finding remains
unassessed. These measurements are well below the 99% target and cannot
support a production-population, cross-language, cross-platform, or general
accuracy claim. The machine-readable run record retains the commit, dirty
worktree state, evaluator and configuration digests, runtime, matching
tolerance, denominators, uncertainty method, and scope limits.

A separate maintainer-authored Python planted-corpus regression run scored
73/73, including all 8 planted SQL-injection cases, with no reported misses,
unexpected findings, or safe-twin false positives. It ran on Python 3.14.4
under Linux/WSL2 with `tree-sitter-language-pack` 1.22.1. This is regression
evidence only; it does not contradict or replace the RealVuln conformance
result and is not independent accuracy evidence.

CVEfixes remains an unapproved candidate: its large archive was not
downloaded or ingested, and neither source-code licensing nor label quality
has been resolved. Do not silently substitute synthetic fixtures or another
scanner's output for independent ground truth.

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

The evidence is not sufficient for a 99% precision-and-recall claim. The
AI-heldout recall is 4%, AI-development recall is 28%, and this narrow
RealVuln pilot measured 77.8% labelled-case precision and 80.8% labelled-case
recall with wide, benchmark-specific cluster intervals. Human adjudication,
representative populations, blind miss audits, and platform/segment coverage
remain incomplete.

**Next milestone:** obtain independent reviewers or an explicitly approved,
larger source with defensible labels; conduct blind finding adjudication and
repository miss audits; then validate the sampling design and uncertainty
estimator before any rule tuning. Keep the existing sealed AI and gold sources
closed.
