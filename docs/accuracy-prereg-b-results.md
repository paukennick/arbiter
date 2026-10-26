# ARB-112 results: model-labelled precision of `lang_python` on the ARB-109 cohort

Run under `docs/accuracy-prereg-b.md` (frozen in `a9a0610`, analysis script in
`e720959`). One run, no re-runs, no deviations from the preregistration.
Label files: `tools/gold/labels/arb109/` (kept in a subdirectory so the
`labels/*.jsonl` globs used by the precision ledger do not pick up evaluation
data). **These labels are evaluation data: they must not be used to write,
tune or exempt rules, and Workstream C may not train on them.**

**Model-labelled conformance on an 11-repository convenience cohort;
calibration agreement with truth 1.0 (n=120).** Not a precision estimate for
Python code in general, and not a 99% claim.

## Run record

| item | value |
|---|---|
| Arbiter | `1e9020c` (freeze parent), `lang_python` only, offline, no cache or adapters |
| Gate | `82ca64b` gives 105 findings matching the ARB-109 manifest per repository; the freeze-parent scan is identical by rule, path and line (the four ARB-110 Python rules fire on none of the 11 repositories) |
| Archives | 11 pinned, all SHA-256 equal to the manifest |
| Labeller | `claude-opus-5-5` prosecutor + defender, adjudicator on disagreement; prompt `v3` |
| Calibration | 120 blind OWASP-Python items, seed `20261022`: 93 tp and 27 fp all called correctly, 0 `unsure`, kappa 1.0 |
| Cohort | 105 findings (census); 2 needed adjudication |
| Cost | USD 3.84 calibration + USD 4.88 cohort = USD 8.72 of the USD 15 cap |

## Result

| rule | findings | tp | fp | unsure | tp/(tp+fp) | Wilson 95% |
|---|---:|---:|---:|---:|---:|---|
| `python.sql-injection` | 67 | 19 | 48 | 0 | 0.284 | [0.19, 0.401] |
| `python.code-injection` | 17 | 14 | 2 | 1 | 0.875 | [0.64, 0.965] |
| `python.request-body-unbounded` | 5 | 0 | 4 | 1 | 0.0 | counts only |
| `python.http-no-timeout` | 5 | 5 | 0 | 0 | 1.0 | counts only |
| `python.command-injection` | 4 | 1 | 1 | 2 | 0.5 | counts only |
| `python.insecure-random-for-secret` | 2 | 2 | 0 | 0 | 1.0 | counts only |
| `python.unsafe-deserialization` | 2 | 2 | 0 | 0 | 1.0 | counts only |
| `python.swallowed-error-in-worker-loop` | 2 | 0 | 2 | 0 | 0.0 | counts only |
| `python.retry-loop-no-backoff` | 1 | 1 | 0 | 0 | 1.0 | counts only |
| **all** | 105 | 44 | 57 | 4 | 0.436 | [0.343, 0.533] |

`unsure` rate 3.8% overall. Repository-cluster bootstrap: 7 of the 11
repositories had any finding; 95% interval **[0.031, 0.838]**. The
finding-level interval is far too narrow to trust, because the findings are
concentrated: conan 42, sqlglot 43, InvenTree 9, litestar 6, bottle 3,
helium 1, apscheduler 1.

## Reading it

- Every rate here is dominated by `python.sql-injection` (67 of 105), and 42 of
  its 48 false-positive labels are in one repository, sqlglot, a SQL
  *generator* whose purpose is to build SQL text from an AST. The pattern
  fires on code whose job is assembling SQL. In conan the same rule was 19
  tp / 4 fp.
- So the headline 43.6% is a statement about this cohort, mostly about one
  repository, not about the rule across Python code. The point estimate for a
  typical repository could be far higher or lower; the cluster interval says
  so.
- Small rules (under 10 findings) are counts only, as preregistered. Two
  rules show 0 tp (`request-body-unbounded` 0/4 decided,
  `swallowed-error-in-worker-loop` 0/2); that is too few to conclude, and
  too few repositories, but it is a reason to look at them on development
  data.
- Calibration agreement of 1.0 is on OWASP Benchmark, which is synthetic and
  has an easy true/false structure; it shows the labeller is not broken, not
  that it is right on real code. The labeller is also in the same model
  family as the assistant that wrote many of the rules.

## What follows (and does not)

- No rule is promoted to verified.
- No rule was changed. Per the preregistration, a false-positive pattern seen
  here is only acted on if it reproduces on development data. The
  `sql-injection` generator pattern is a candidate to check against the
  development corpus and the pinned real repositories, not to fix from this
  cohort.
- Human adjudication of the 105 (especially the sqlglot 42 and the conan 4)
  would convert this from model-labelled conformance into evidence; none has
  been done.
