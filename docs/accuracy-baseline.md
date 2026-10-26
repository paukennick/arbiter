# Accuracy Baseline and Evidence Gaps

Inventory date: 2026-10-25. This records the existing evidence, two
benchmark-conformance runs, and two analyzer-differential scans; it is not a
99% certification. Machine-readable
source inventory and run metadata are in
[accuracy-benchmark-manifest.json](accuracy-benchmark-manifest.json), validated
by [accuracy-benchmark-manifest.schema.json](accuracy-benchmark-manifest.schema.json).
The additive multi-CWE aggregate report is
[accuracy-realvuln-multicwe-run.json](accuracy-realvuln-multicwe-run.json).

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
| RealVuln 3.1.0 Python subset | Aggregate-only external conformance pilots | 11 pinned repositories; 502 available labels across 65 primary CWEs; 408 `manual_review` labels scored across 53 CWEs | 66/408 included labels explicitly set `manually_verified`; labels are not independently multi-reviewer adjudicated | Completed on MIT/Unlicense source pins. Curated vulnerable applications; not representative production repositories. The original CWE-89 run is preserved; the additive multi-CWE run and metadata follow. |

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

## Completed multi-CWE conformance baseline

ARB-106 validated all 502 labels in the 11 previously approved pinned
repositories. The labels span 65 primary CWEs. The score includes only the
408 entries with `evidence.source=manual_review`, covering 53 primary CWEs;
it excludes 75 `our-scanner` labels, 13 `gt_expansion_verification_2026_04_29`
labels, five `snyk` labels, and one `walkthrough` label rather than treating
tool-derived or differently sourced labels as equivalent ground truth. Of the
408 included labels, 66 explicitly set `manually_verified=true`. The source
contains no explicit `non_scoring` entries. None of these labels has a
documented independent multi-reviewer audit.

| Measure | Aggregate result |
|---|---:|
| Included labelled cases | 408 (341 vulnerable, 67 safe traps) |
| Case-level confusion | TP 62, FN 279, FP 7, TN 60 |
| Labelled-case precision | 62/69 = 89.9% |
| Labelled-case recall | 62/341 = 18.2% |
| Safe-trap false-positive rate | 7/67 = 10.4% |
| 95% repository-cluster bootstrap interval, precision | 84.5%–94.7% |
| 95% repository-cluster bootstrap interval, recall | 13.0%–23.8% |
| CWE findings unmatched to included labels | 25, left unassessed |

The largest aggregate miss buckets were CWE-79 (0/37 positive cases detected),
CWE-798 (1/22), CWE-918 (0/18), CWE-400 (1/18), CWE-22 (0/17), and CWE-639
(0/13). These counts are prioritization signals only: no case-level examples
were inspected, and no rules were tuned on this benchmark. The multi-CWE run
used only the offline Python probe on all 11 repositories; all 11 overall
scorecards were withheld because the other probes were not assessed. Source
code was not executed. Results are maintainer-label case conformance, not
independently adjudicated truth, finding-level precision, or a production
population estimate.

The multi-CWE evaluator reproduces the original CWE-89 confusion counts
exactly (TP 21, FN 5, FP 6, TN 28); the historical run record and matcher
remain unchanged. The source, label, and scan-report digests, tool versions,
environment, and aggregate results are recorded in the separate run report
and referenced from the benchmark manifest.

## ARB-107: pinned analyzer differential rehearsal

Arbiter native probes, Semgrep, and CodeQL scanned the same 11 pinned,
license-cleared RealVuln Python snapshots. This is an intentionally vulnerable
benchmark cohort, not an ordinary or representative production-repository
sample. No project build, test, setup, or application command was run; CodeQL
used `--build-mode none`, and target code was not executed. Arbiter ran
offline with adapters, cache, and history disabled so its Semgrep adapter
could not duplicate the separately pinned Semgrep run.

| Analyzer | Python security findings | Python files scanned | Result |
|---|---:|---:|---|
| Arbiter native probes | 102 | File-level denominator not comparable to other tools | 0 scan errors; internal probe coverage ranged from 96.9% to 98.4% |
| Semgrep 1.177.0 | 236 | 360 | 0 scan errors; each source repository's `.semgrepignore` was applied |
| CodeQL 2.27.3 / `codeql/python-queries@1.8.13` | 96 | 459/459 | 11/11 invocations succeeded; 0 error- or warning-level notifications |

The pinned source trees were identical across tools, but their effective file
sets were not: Semgrep scanned 360 Python files while CodeQL extracted all 459
Python files. Counts below use normalized repository-relative Python paths
and intersecting inclusive line spans. A finding can overlap more than one
finding from another analyzer, so pair totals are not deduplicated
vulnerability instances.

| Pair | Findings with a location-overlapping counterpart | Unmatched by location | Overlapping pairs with shared CWE tag / without shared CWE tag |
|---|---:|---:|---:|
| Arbiter / Semgrep | 75/102 and 121/236 | 27 Arbiter; 115 Semgrep | 91 / 133 |
| Arbiter / CodeQL | 30/102 and 40/96 | 72 Arbiter; 56 CodeQL | 25 / 53 |
| Semgrep / CodeQL | 89/236 and 61/96 | 147 Semgrep; 35 CodeQL | 73 / 22 |

These are differential-coverage signals only. Overlap is not a true positive;
an unmatched result is not a false positive or false negative; and differing
CWE tags do not adjudicate the underlying issue. No precision, recall, or
accuracy estimate follows from this run. The aggregate record, tool pins,
configuration digest, source archive hashes, and matching contract are in
`docs/accuracy-benchmark-manifest.json`; source archives, databases, and
case-level analyzer reports remain temporary.

A separate maintainer-authored Python planted-corpus regression run scored
73/73, including all 8 planted SQL-injection cases, with no reported misses,
unexpected findings, or safe-twin false positives. It ran on Python 3.14.4
under Linux/WSL2 with `tree-sitter-language-pack` 1.22.1. This is regression
evidence only; it does not contradict or replace the RealVuln conformance
result and is not independent accuracy evidence.

## ARB-109: ordinary-Python cohort differential scan

The frozen ordinary-Python feasibility cohort contains 11 MIT-licensed pinned
repositories selected from a popularity-sorted GitHub metadata frame. Only
those exact snapshots were acquired. Arbiter's scanner sources matched commit
`82ca64b5fc1c4fc8234daea1e8cd1b75051831b7`; Arbiter ran offline with only the
native `lang_python` probe, and its configuration digest is in the manifest.
Semgrep 1.177.0 used rules commit
`40b8c63f75dc7c22c8a77482d73bfb864b146f7e`. CodeQL 2.27.3 used
`codeql/python-queries@1.8.13` with `--build-mode none`. No project build,
test, setup, or application command ran, and no target code was executed.

| Analyzer | Findings | Relevant file coverage | Execution notes |
|---|---:|---:|---|
| Arbiter native `lang_python` | 105 | Probe ran on 11/11 repositories; overall coverage was 8.1% | All 11 overall scorecards were withheld because only one probe was selected. This is not a low grade. |
| Semgrep 1.177.0 | 2,663 | 2,146/3,662 Python files; 4,040 files total | 8 scan errors: 7 timeouts and 1 syntax error. Repository ignore behavior narrows its file set. |
| CodeQL 2.27.3 | 16 | 3,661/3,662 Python files | 11/11 invocations succeeded; 189 extractor warning lines (187 dynamic-library path warnings and 2 module-context warnings). |

Location-span comparison found 39 Arbiter/Semgrep finding pairs: 31 shared a
CWE tag and 8 did not. No location-overlapping pairs were found for
Arbiter/CodeQL or CodeQL/Semgrep. A location match or CWE-tag intersection is
not adjudication; no overlap does not prove a miss or false positive.
Differences in rules, language coverage, ignore behavior, and extraction also
make raw finding totals non-comparable as correctness scores.

This small, popularity-biased convenience cohort is not probability-sampled or
representative. It contributes no precision, recall, false-positive-rate, or
population estimate. There were no labels, independent human review, or rule
tuning, and this result is not eligible for a general 99% claim. The manifest
records tool and environment provenance, archive hashes, per-repository
aggregates, and limitations; raw archives, reports, databases, and
case-level findings remain temporary.

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

## ARB-110 development-recall progress

Development-corpus only (`fixtures/ai-corpus`, native probes with the `ast`
extra installed), model-labelled conformance. The first rule, Go
`http-server-no-timeout`, moved code recall from 34/117 (29.1%) to 37/117
(31.6%), Go from 14/24 to 17/24, with no new false alarms or unreviewed
findings. The sealed held-out aggregate guard also moved (146 to 151
findings, true positives +3 against +5 in scope); that tree was not opened and
the rule was not tuned to it, so treat that as a precision caution, not a
result. Real-repository precision for the rule is unmeasured. This is not a
99% claim.

Second batch, swallowed-exception (Java, Ruby and TypeScript, five rules):
code recall 37/117 to 41/117 (35.0%), Java 5 to 7, Ruby 5 to 6, TypeScript 4
to 5, no new false alarms or unreviewed findings. The first Ruby draft also
fired on a puma `ipv6_interface_available?` probe; probe methods named `foo?`
are now exempt, and the real-repository guard (python, TypeScript, Ruby, Go)
is unchanged. Java has no real-repository guard, so its precision is
unmeasured. The held-out aggregate did not move. Not a 99% claim.

Third batch, path-confinement and SSRF (seven rules): code recall 41/117 to
48/117 (41.0%), no new false alarms or unreviewed findings. The real-repository
guard (python, TypeScript, Ruby, Go) and the held-out aggregate did not move;
Java precision on real code is unmeasured. The rules are shape- and
name-based, so they will miss renamed variables, and only the "optional root"
and "resolve, then connect" shapes are covered. Not a 99% claim.

Fourth batch, unbounded-memory and unhandled-input-error (four rules): code
recall 48/117 to 55/117 (47.0%), no new false alarms, two more unreviewed
findings. The real-repository guard did not move. The sealed held-out
aggregate did (151 to 154 findings, in scope 137 to 140); that tree was not
opened and the rules were not tuned to it, so this is a precision caution, not
a result. Java precision on real code is unmeasured. The rest of the
unhandled-input-error family is semantic and is not addressed. Not a 99% claim.

## Baseline decision

The evidence is not sufficient for a 99% precision-and-recall claim. The
AI-heldout recall is 4%, AI-development recall is 28%, and the RealVuln
multi-CWE manual-review slice measured 89.9% labelled-case precision and
18.2% labelled-case recall with benchmark-specific cluster intervals. The
narrow CWE-89 slice remains at 77.8% precision and 80.8% recall. The ARB-107
and ARB-109 analyzer differentials do not add accuracy evidence. Human
adjudication, representative populations, blind miss audits, and
platform/segment coverage remain incomplete.

**Next milestone:** rule owners should address the broad missed weakness
families using development data only, with regression tests and paired
precision/recall checks. In parallel, execute the predeclared real-repository
precision sample with blinded labels and prepare independent human review.
Keep this RealVuln evaluation data and the existing sealed AI and gold sources
closed to case-level tuning.

Per the owner's 2026-10-24 decision, interim measurements may use blind model
labels when human reviewers are unavailable. Report those results only as
**model-labelled conformance**, with model and prompt provenance; they are not
independent adjudication, certified precision/recall, or evidence for a 99%
claim. This interim option changes no baseline result or label provenance.

## Java real-repository guard (ARB-111)

The guard now also scans `java-netty`, `java-tomcat` and `java-spring-security`
(pinned development-side gold repositories). First scan: 502, 859 and 238
findings. Hand review of the rules added in ARB-110 found
`java.unbounded-work-queue` firing 25 times, 17 of them on object pools, caches
and example or test handlers, so it now matches only a capacity-less
`LinkedBlockingQueue` or a fixed/single-thread executor field (498 and 846
findings after). `java.swallowed-stack-trace-only` fired 7 times, all genuine
swallowed exceptions, 6 of them in example or test code. This is a manual
review of two rules, not a per-rule precision measurement, and not a 99% claim.
The held-out Java repositories were not used.

## ARB-112: model-labelled precision on the ARB-109 cohort

Preregistered (`docs/accuracy-prereg-b.md`) and run once: 105 `lang_python`
findings on 11 pinned repositories, labelled by an opus prosecutor, defender
and adjudicator after a blind OWASP-Python calibration (120/120). 44 tp, 57 fp,
4 unsure; 43.6% tp/(tp+fp), repository-cluster interval [0.031, 0.838] over 7
contributing repositories. `python.sql-injection` carries it (19 tp, 48 fp, 42
of them in the SQL generator sqlglot). Full table and reading in
`docs/accuracy-prereg-b-results.md`. Model-labelled conformance on a
convenience cohort, no rule changed or promoted, not a 99% claim.

