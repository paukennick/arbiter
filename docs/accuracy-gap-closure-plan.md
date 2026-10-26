# Accuracy Gap-Closure Plan (no human reviewers)

Status: plan, ARB-110. It is not a result and not a 99% claim. Human
reviewers are unavailable for the foreseeable future, so every number
produced under this plan is **model-labelled conformance**: evidence about
agreement with frozen model labels and known-answer benchmarks, never
audited truth. The sealed AI held-out set, the sealed gold and OWASP sources,
RealVuln, and the ARB-109 cohort are evaluation data and stay closed to
tuning and training.

## What the numbers say the work is

| Half of the goal | Measured | Gap driver |
|---|---|---|
| Recall | 4% (AI held-out), 28% (AI development, native), 18.2% (RealVuln multi-CWE) | Whole weakness families have no rule: unbounded memory, missing authentication, ignored errors, SSRF guard gaps, path traversal when a root is unset, retry without backoff (`docs/testing-harness.md`, "Where the misses are"). |
| Precision | 89.9% (RealVuln multi-CWE labelled cases); one rule verified at Wilson lower bound 0.9945 | Most rules stay advisory; too few adjudicated labels per rule. |

Recall is the dominant gap and is rule coverage, not triage. A learned model
cannot find a defect no analyzer reports. Learning is therefore applied to
the two places it helps without leaking evaluation data.

## Workstreams

### A. Recall: development-only rule work

1. Rank missed categories from the **development** corpus
   (`fixtures/ai-corpus`) by defect count and by CWE, per language.
2. For each family, write rules with planted-defect and safe-twin fixtures in
   `fixtures/planted` first, with regression and precision-guard checks.
3. Re-score the development corpus only. Never score or inspect the held-out
   tree, RealVuln, or ARB-109 findings to decide what to write. The sealed
   scorer stays aggregate-only.
4. Record per-family recall before and after with denominators.

### B. Precision: preregistered, blinded, model-labelled sample (ARB-109 cohort)

Preregistration, frozen before any label is produced:

- **Population:** findings from Arbiter's `lang_python` probe on the 11
  frozen ARB-109 snapshots (105 findings at scan time). Because that count is
  small, review all of them rather than sampling.
- **Semgrep/CodeQL findings** are sampled only to estimate disagreement:
  stratified by repository and by whether Arbiter overlaps, with a fixed seed
  recorded in the manifest before labelling and inclusion probabilities kept.
- **Packets:** the existing `tools/label_models.py` path: bounded code
  excerpt, file path, and a neutral claim. Analyzer identity, rule id,
  severity, confidence and agreement status are removed. One frozen rubric
  and the same packet shape for every analyzer.
- **Labellers:** prosecutor and defender with an adjudicator, as already
  implemented, plus the existing blind calibration against known-truth
  items. The labeller's own agreement with truth on calibration items is
  reported next to every result.
- **Outputs:** per-rule counts, Wilson intervals, repository-clustered
  uncertainty, and the unresolved/`unsure` rate. Labelled **model-labelled
  conformance**. No rule is promoted to verified on ARB-109 labels alone.
- **Re-scan:** the raw ARB-109 reports were deleted after aggregation; the
  stage re-acquires only the 11 pinned archives and verifies their recorded
  SHA-256 before scanning.

The frozen preregistration for this stage is `docs/accuracy-prereg-b.md` (ARB-112).

### C. Learned triage on GPU (precision/ranking only)

The frozen split and CPU baseline for this stage are now in `docs/accuracy-triage-cpu-baseline.md` (ARB-113) with artifacts under `tools/gold/labels/triage/`.

Goal: rank advisory findings so the likely true positives surface first and
estimate per-finding probability, to raise advisory-tier precision. It does
not create findings.

- **Hardware:** the local RTX 5070 Laptop (8 GB) runs the CPU/small-model
  baseline and inference. Training beyond that rents a RunPod GPU (owner
  decision, 2026-10-25). Needs `torch` and a code model; neither is installed
  yet, so dependency changes go through their own requirement.
- **Cloud rules:** only public or repo-owned development code is uploaded
  (owner-approved); sealed gold, held-out, RealVuln and ARB-109 data never
  leave the machine. No secrets or API keys on the pod. Pin model id,
  revision, seed and package versions; weights and pod artifacts stay out of
  git, with only metrics, split lists and hashes committed.
- **Budget (owner: no hard cap, keep it modest):** interim ceiling of USD 25
  per experiment and USD 75 in total, using a single on-demand or spot
  24-48 GB card (LoRA on a 7B code model, or a smaller encoder), with a
  hard run-time limit and the pod stopped on completion. Raising a ceiling
  needs the owner. The CPU baseline must come first; spend is justified
  only if the baseline leaves headroom.
- **Training data (development only):** existing model labels on the tuned
  gold repositories and the AI development corpus, and ground-truth items
  (OWASP, CVE fixes) when their license and holdout policy permit. About
  3,000 model-labelled findings and 1,300 ground-truth items exist today.
- **Never trained on or tuned against:** the AI held-out sets (including r5),
  sealed gold repositories, RealVuln, the ARB-109 cohort.
- **Split:** by repository (and by family where forks exist), never by
  finding. A repository appears on exactly one side. Fixed seed and split
  list committed before training.
- **Label noise:** targets are model labels with known labeller error, so
  report model-vs-truth calibration and train with `unsure` excluded. Do not
  present predicted probability as truth.
- **Deployment rule:** a learned score may reorder or annotate advisory
  findings with provenance `inferred`. It never relabels a deterministic
  finding as verified and never blends into the deterministic tier.
- **Evaluation:** frozen repository-disjoint development split first, then
  one-shot evaluation on ARB-109 labels, reported as model-labelled
  conformance with the training lineage recorded.

## Claim ladder

| Claim | Allowed when |
|---|---|
| "Rule X has precision at or above 0.99 (Wilson lower bound) on stratum Y, model-labelled" | Enough labels on held-out repositories; already true for one rule. |
| "Family F recall on the development corpus rose from a to b" | Workstream A, development data only. |
| "Triage model lifts advisory precision from p to q, model-labelled, repository-disjoint" | Workstream C evaluated once on frozen data. |
| Any 99% precision/recall claim for the scanner overall | Not supportable without independent truth and a representative population. |

## Order of work

1. Workstream A on the largest development-corpus miss families, with
   fixtures first.
2. Workstream B re-scan and labelling after the preregistration is committed.
3. Workstream C feasibility only after A and B exist: dependency approval,
   split list, baseline ranker (no GPU) for comparison, then GPU model.
