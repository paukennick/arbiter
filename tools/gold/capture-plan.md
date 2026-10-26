# Capture-recapture plan (ARB-172, D6) -- pre-registered 2026-10-26

Written and committed before any labelling call and before any development
estimate was computed. Changes after this commit are listed at the end with
their reason.

## Detectors

| Detector | What runs | Languages |
| --- | --- | --- |
| `arbiter` | every native probe (findings without the `external-tool` tag) | all |
| `semgrep` | the pinned semgrep-rules checkout (`tooling.json` `semgrep_rules_ref`) through `semgrep.adapter.toml` | all |
| `bandit` | `bandit.adapter.toml` | Python |

Not detectors here: **ruff** (default E/F rules, no security checks, no CWE);
**gitleaks** (secrets only; included in the `hardcoded-secret` family when it
reports anything); **trivy, checkov** (dependencies and IaC, outside these
families); **CodeQL** -- not installed on this machine, and the only CodeQL
results in the repository's history (ARB-107) are on RealVuln, which is
held-out and aggregate-only. It joins as a fourth detector when an adapter
exists.

A detector is in a stratum when it has at least one rule mapped to that
family for that language -- decided from the rule packs, not from whether it
happened to report anything. A repository-detector pair whose run did not
finish (`status != "ran"`) is dropped from the stratum, never read as zero.

## Matching

Same repository, same file, same CWE family (`arbiter.capture.family_of`:
rule override, then the lowest-numbered CWE with a family), and line within
3 of the site's anchor line (the first finding's line). Anchored, not
chained; one capture per detector per site.

## Truth

A site enters the capture histories only if it is a confirmed defect:

* Benchmarks: OWASP Benchmark Python/Java -- the site's file is a test case
  marked real whose CWE is in the site's family (`benchmarks.json` aliases);
  Juliet Java -- the site is inside a `bad` method (`benchmarks_gt.juliet_side`)
  of a case in the family. One case = one defect: Juliet's multi-file cases
  (`_51a`/`_51b`) collapse to one, OWASP's one file per case already does.
  A case found by several sites counts once per detector.
* Development data: tp from the model labeller v3 (existing labels reused by
  repository, path, line and rule; new labels from `tools/label_models.py`,
  prompts unchanged) -- `unsure` and `fp` sites are dropped.

## Estimators (primary first)

* Two detectors: Lincoln-Petersen with Chapman's correction, log-normal
  interval on the unseen part.
* Three detectors: AIC-best log-linear Poisson model among independence up to
  all-but-one pairwise interactions (models with at least one residual degree
  of freedom), profile-likelihood 95% interval. Chao's lower bound (incidence
  form, f1/f2) reported beside it. Pairwise Chapman reported for every pair.
* Benchmarks additionally get a repository-free check: estimate vs true total.
* Development strata pooled across repositories; repository bootstrap (400
  resamples, seed `capture|<language>|<family>`) for the interval where there
  are at least 5 repositories with a capture.
* Catch rate = found / N-hat, interval from N-hat's interval.

A stratum with fewer than 10 confirmed sites or no site caught by two
detectors is reported as "not estimable", not as a number.

## Labelling (development data only, at most $20)

Data: gold dev repositories (`~/wt/corpus-gold-dev`, `held_out: false`) and the
45 `slice: "dev"` repositories of `tools/gold/breadth-r7-python-repos.json`
(`~/wt/corpus-r7py-dev`). Nothing held-out is scanned or labelled.

1. Scan with every adapter (`tools/capture_recapture.py scan`).
2. Cluster all detectors' findings into family sites; reuse existing labels.
3. Unlabelled sites, in strata with at least two detectors present and at
   least one multi-detector site: label every site if the dry run costs
   <= $18; otherwise sample within each capture-history pattern (seed
   20261026, equal share per pattern, the rest by size) and weight each
   pattern's labelled tp count by its sampling fraction.
4. `python tools/label_models.py label ... --budget-usd 20 --jobs 2`, own cache
   (`arbiter-out/capture/label-cache.jsonl`), own output
   (`tools/gold/labels/capture-dev-model.jsonl`). The site is labelled through
   ONE member finding (Arbiter's when present, else the first by detector
   name); the label applies to the site.
5. Adapter rule ids without a `CLAIMS` pattern get the existing claim text
   of the family's Arbiter rule, word for word (no new prompt text). Sites
   whose family has no Arbiter claim text are not labelled and not used.

Stop rule: stop labelling at $20 spent or when every eligible site is labelled.

## Held-out data later

`capture_recapture.py` reads only the scan directory and label files it is
given. Running it on a held-out set later: scan that set into its own
directory, label with the held-out labeller run, and publish only per-family
totals (N-hat, found per detector), never per-repository or per-site rows.

## Changes after registration

All made before any labelling call and before any development estimate.

1. **Cross-language strata.** `hardcoded-secret` and `unpinned-action` are
   about a file, not a language: one stratum `any` over every file.
   Detectors: secrets = arbiter, semgrep, gitleaks (gitleaks was named above
   but missing from the code); unpinned actions = arbiter, semgrep. Bandit is
   not in `any` (it reads Python only).
2. **Rule overrides found missing:** semgrep `python.requests.best-practice.use-timeout`
   -> `missing-timeout` (it carries no CWE, so Semgrep had silently dropped out
   of the timeout stratum); semgrep `github-actions-mutable-action-tag` ->
   `unpinned-action`.
3. **Labelling order (replaces step 3).** Two runs, one per development set
   (the `--corpus` differs). Run 1 (gold-dev) `--budget-usd 20`; run 2
   (r7py-dev) `--budget-usd` = 20 minus run 1's reported spend. Within each,
   label multi-detector sites first; then single-detector sites only in
   strata where at least one multi-detector site came back tp (a stratum
   with no tp overlap is not estimable, so its single-detector labels buy
   nothing). If a stratum's single-detector sites would exceed what is left,
   sample them per capture-history pattern (seed 20261026) and weight.
4. **Validation reporting.** Benchmarks report "truth inside the 95%
   interval in X of Y strata" and flag zero-width intervals as degenerate.
5. **Juliet extraction.** `unzip` left `CWE89_SQL_Injection`, `CWE80_XSS` and
   `CWE190_Integer_Overflow` empty on this machine; they were extracted with
   Python's `zipfile` from the same SHA-256-checked archive (3,682 / 1,090 /
   7,047 files) and Juliet rescanned.
