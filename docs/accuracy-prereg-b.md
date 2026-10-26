# Preregistration: model-labelled precision of `lang_python` on the ARB-109 cohort (ARB-112)

Status: **approved by the owner 2026-10-25 and frozen by the commit that
introduces this file** (choices: Arbiter at the freeze parent, calibration
threshold 0.80, budget cap USD 15, labels never used to tune rules). Nothing
below has been scanned, labelled or looked at. After the
freeze commit this file is append-only: a change is a dated `Amendment`
section at the end, never an edit, and an amendment made after any label
exists is reported next to the results as a deviation.

Parent plan: `docs/accuracy-gap-closure-plan.md`, Workstream B.
Claim made by this study: **model-labelled conformance** of Arbiter's native
Python probe on 11 convenience-sampled repositories. It is not a precision
estimate for Python code in general, and it is no step towards a 99% claim by
itself (`docs/accuracy-roadmap.md` requires independent human truth).

## Question

Of the findings Arbiter's `lang_python` probe reports on the frozen ARB-109
cohort, what share does an independent model-labelling pipeline judge to be
real, per rule, and how reliable is that pipeline on items whose truth is
known?

## Population

- The 11 repositories in `docs/accuracy-benchmark-manifest.json`
  (`ordinary_repository_precision_pilot.repositories`), at the recorded
  `source_commit`, from archives whose SHA-256 equals the recorded
  `source_archive_sha256`. A hash mismatch stops the study.
- Arbiter at the **parent of the freeze commit** (the commit that introduces
  this file; `git rev-parse <freeze>^`, recorded in the results), checked out
  in a separate worktree, offline profile, `lang_python` probe only, no cache,
  no history, no adapters. Its configuration digest is recorded at run time.
  This version includes the four Python rules added under ARB-110
  (`path-confinement-optional`, `ssrf-check-then-connect`, `unbounded-queue`,
  `compare-digest-unnormalised`), all written from the development corpus
  only. The ARB-109 scan used commit
  `82ca64b5fc1c4fc8234daea1e8cd1b75051831b7` (105 findings, configuration
  digest `e001cd6a3677c208d28c85a4cd6364b25a467e23405e59d0f7de7b9ab95d34ea`),
  so the population here is not the ARB-109 aggregate.
- Gate before any model call: scanning the same 11 repositories at
  `82ca64b` in a second worktree must give exactly **105** findings with the
  manifest's per-repository counts (this proves the archives and procedure
  match ARB-109), and the scan at the freeze parent must contain all 105 of
  them (same rule, path and line) plus only findings from rules that did not
  exist at `82ca64b`, listed by rule. Any other difference stops the study and
  is reported. The population is the freeze-parent scan; the 105 and the new
  findings are reported separately as well as together.
- Every finding is reviewed (a census). There is no sampling and no
  stratification. Semgrep and CodeQL findings are out of scope for this study.
- Nothing is executed: archives are extracted and read, never built or run.

## Packets (blinding)

Built by the existing `tools/label_models.py` path at PROMPT_VERSION `v3`:
bounded code excerpt from `arbiter.context`, repository-relative path, and a
neutral claim from `CLAIMS`. Arbiter's title, description, remediation,
rule id, severity, confidence, tier and the verifier's verdict are not in the
packet. One packet shape for every finding. The prompts and `CLAIMS` table are
frozen at the git blob of `tools/label_models.py` current at the freeze
commit; a later change to either voids the registration (amendment, then a
fresh start).

## Labellers

- Prosecutor and defender (different prompts, neither sees the other), then
  an adjudicator when they differ, exactly as implemented.
- Model: the logged-in Claude CLI, model alias `opus`
  (`tools/label_models.py` default), headless, no tools, no settings, skills or
  MCP servers. The resolved model id is recorded in every label.
- Verdicts are `tp`, `fp` or `unsure`. `unsure` is kept and reported; it is
  never relabelled, dropped or counted as `tp` or `fp`.

## Calibration

The same labellers, blind, on 120 items from
`tools/gold/labels/owasp-python.jsonl` (comments and test-case names scrubbed,
truth attached after they answer), seed `20261022`, drawn before the cohort
is labelled. Reported next to every result: labeller-vs-truth agreement,
sensitivity on true items, false-positive rate on safe items, and Cohen's
kappa between prosecutor and defender.

Reliability rule: if labeller-vs-truth agreement on calibration is below
**0.80**, the cohort results are labelled *low reliability* and shown only as
counts, never as a rate headline.

## Outputs (all computed by one script, written and committed before the run)

`tools/prereg_b_analysis.py`, committed before any label exists, reads the
label file and produces:

1. Per rule: findings, `tp`, `fp`, `unsure`, and `tp / (tp + fp)` with a
   Wilson 95% interval. Rules with fewer than 10 findings show counts only.
2. All rules together, the same way.
3. Repository-clustered uncertainty: percentile cluster bootstrap over the 11
   repositories (10,000 resamples, seed `109`), reported with the number of
   repositories that contributed at least one finding and the finding-level
   interval beside it.
4. The `unsure` rate, overall and per rule.
5. The calibration block above.

Headline wording is fixed: "model-labelled conformance on an 11-repository
convenience cohort", with the repository count and the calibration agreement
in the same sentence.

## What may and may not be done with the results

- No rule is promoted to `verified` on these labels.
- **These labels are not used to write, tune or exempt any rule.** The cohort
  is the evaluation set for Workstream C's one-shot test, so a rule change
  driven by it would burn it. A false positive found here is recorded and only
  acted on if the same defect reproduces on development data; if the owner
  chooses to act on the cohort directly, the cohort is declared development
  data from that point and Workstream C needs a new evaluation set.
- Sealed sets (`fixtures/ai-corpus-heldout`, gold held-out, RealVuln) are not
  opened.
- No 99% statement is made. Unreported outcomes are not possible: every run's
  label file is committed, including a run that is stopped early.

## Cost and stop rules

- Roughly 105 to 140 findings (the count is known only after the re-scan)
  plus 120 calibration items, two labellers each, adjudicator on
  disagreement. Earlier runs cost about USD 0.03 per item
  (`tools/gold/labels/ai-corpus-model.jsonl`: 114 items, USD 3.08), so the
  expected total is about USD 7.
- `--budget-usd 15` on the run; it stops before a call that could pass the
  cap. A usage-limit stop leaves a partial label file, which is committed and
  reported as partial.
- Only bounded excerpts of the pinned public MIT repositories leave the
  machine, the same as earlier labelling runs.

## Limits stated up front

- Eleven repositories, popularity-biased, seeded convenience sample; the
  cohort was chosen from a GitHub metadata frame, not from a population of
  production code.
- The labeller is a model in the same family as the assistant that wrote
  many of the rules. Agreement with truth on the calibration set is the only
  evidence of its independence; it is not human truth.
- The manifest asks for a coordinator independent of rule authors. The
  pipeline blinds packets mechanically, but the same person and assistant set
  it up; this is disclosed, not resolved.
- Precision only. Recall needs the separate blind repository miss audit.

## Execution order

1. Owner approves this file; commit it (the freeze).
2. Commit `tools/prereg_b_analysis.py` with a unit test on synthetic labels.
3. Re-acquire the 11 archives, verify SHA-256, extract to a temporary
   directory outside the repository.
4. Re-scan at `82ca64b` and at the freeze parent; check the subset gate.
5. Run calibration, then the cohort, with `--budget-usd 15`.
6. Run the analysis script; commit the label file and the result tables.
7. Delete the extracted archives and scan outputs; `CHANGELOG.md`,
   `.ai/project-context.md` and `docs/accuracy-baseline.md` record the result
   with the wording above.
