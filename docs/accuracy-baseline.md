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

## External conformance scorecard (ARB-120)

On 2026-10-24, `tools/ground_truth/external_scorecard.py` ran Arbiter
`f52484f` (clean worktree, offline profile, no adapters, no cache, native
probes only) over the outside benchmarks already wired. It wrote one run
record per benchmark in the `run_record_template` shape (checked against
the manifest schema) to [external-scorecard.json](external-scorecard.json),
with per-CWE and per-rule tables in
[external-scorecard.md](external-scorecard.md). Output is aggregate-only:
counts and rates, with no case names, paths, advisory IDs or excerpts.

| benchmark | units (vuln/safe) | clusters | case precision [Wilson 95%] | recall | in-scope recall | safe-case FPR |
|---|---:|---:|---:|---:|---:|---:|
| OWASP Benchmark Java 1.2 | 2,740 (1,415/1,325) | 1 | 0.808 [0.783, 0.831] | 0.591 [0.565, 0.616] | 0.970 [0.956, 0.979] | 0.149 [0.131, 0.170] |
| OWASP Benchmark Python 0.1 | 1,230 (452/778) | 1 | 0.883 [0.838, 0.918] | 0.487 [0.441, 0.533] | 0.974 [0.943, 0.988] | 0.037 [0.026, 0.053] |
| Juliet Java 1.3 (8 CWE dirs) | 18,310 (9,155/9,155) | 1 | 0.688 [0.673, 0.702] | 0.309 [0.299, 0.318] | 0.342 [0.332, 0.352] | 0.140 [0.133, 0.147] |
| CVE fix pairs (70 GHSA) | 140 (70/70) | 70 | 0.556 [0.267, 0.811] | 0.071 [0.031, 0.157] | 0.079 [0.034, 0.173] | 0.057 [0.022, 0.138] |

The CVE repository-cluster bootstrap (10,000 replicates, seed 0) gives
precision [0.333, 0.800], recall [0.014, 0.143] and safe-case FPR
[0.014, 0.114].

**How to read it.**

- These are **benchmark-conformance** results only. They describe agreement
  with each benchmark's own labels under the matching rules stated in the
  scorecard. They are not finding precision as the precision ledger
  defines it, not production-population accuracy, and not a 99% claim.
  *Case precision* is the share of the units Arbiter flagged that the
  benchmark marks vulnerable.
- OWASP and Juliet are each a single synthetic repository, so each is one
  cluster. Their Wilson intervals are case-level only and do not generalise
  beyond the benchmark.
- The OWASP units are the benchmark's own `expectedresults` rows. The
  Juliet and CVE vulnerable/safe units are **Arbiter-defined**, not lists
  those benchmarks publish:
  - Juliet: one case is all the files sharing a case stem. Its `bad` code
    is the vulnerable unit and its `good*` code the safe unit.
  - CVE: the vulnerable unit is the hunks the fix changed, ±2 lines, on the
    vulnerable side. The safe unit is the same window on the fixed side.
- "In scope" means some Arbiter rule for that language claims the CWE. Out
  of scope:
  - OWASP Java: 7 of 11 CWEs.
  - OWASP Python: 8 of 14.
  - Juliet: CWE-23 and CWE-36.

  These are coverage gaps marked not assessed, not passes.
- **No benchmark, CWE or rule reaches a 0.99 lower bound on both precision
  and recall.** The closest are:
  - OWASP Java CWE-330: 218/218 vulnerable units flagged and 0 of 275
    safe units, lower bound 0.983 on both.
  - OWASP Python CWE-330: 99/99, lower bound 0.963.
  - OWASP Python CWE-328: 71/71, lower bound 0.949.
- **Largest weak spots** (gap to 0.99, from the scorecard's ranking):
  - Rules that claim a CWE but flag nothing:
    - Juliet CWE-190: 4,257 vulnerable units; `java.parsed-count-overflow`
      and `java.parsed-number-narrowed` never fire.
    - Juliet CWE-81: 335 units.
    - `java.argument-injection` on Juliet CWE-78 and OWASP Java CWE-78.
    - `python.argument-injection` on OWASP Python.
    - Most CVE strata (CWE-22, 79, 200, 287, 798, 918: 0 detected each).
  - Rules that fire but are far from the bar:
    - Juliet XSS recall 0.16 at precision 1.0 (CWE-80 and CWE-83).
    - Safe-case false positives on the injection rules: Juliet CWE-89 FPR
      0.486 and CWE-78 FPR 0.457 at about 0.99 recall; OWASP Java CWE-78
      FPR 0.688; OWASP Python CWE-78 FPR 0.857, CWE-94 0.333, CWE-502
      0.333.
    - CVE overall: 5 of 70 fixes detected.
- **Development exposure.** OWASP Java/Python and Juliet have already been
  used to measure earlier rule changes (for example ARB-065's
  before-and-after false-positive rates, recorded in the CHANGELOG). The
  CWEs that were worked on, such as OWASP injection recall near 1.0, are
  therefore not untouched-holdout evidence. The large difference between
  in-scope recall on OWASP (0.97) and on Juliet (0.34) and the CVE pairs
  (0.08) is consistent with that.
- **Holdout status.** Once rules are tuned on this scorecard's weak spots,
  OWASP Benchmark, Juliet and the 70 CVE pairs are **spent as sealed sets**
  for those rules. From then on, their results for those rules are
  development evidence. ARB-121's frozen GHSA split becomes the fresh
  holdout for any claim about them.

Reproduce (about 8 minutes on the recorded host; needs
`tools/fetch_corpus.sh` and `tools/ground_truth/fetch_gt.sh` first):

```bash
python tools/ground_truth/external_scorecard.py --aggregate-only \
    --corpus ~/wt/corpus-gold --gt ~/wt/corpus-gt \
    --out docs/external-scorecard.json --markdown docs/external-scorecard.md
```

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
