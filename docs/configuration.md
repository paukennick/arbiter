# Configuration

`arbiter.yaml` at the repository root is the whole configuration surface. There
is no second config file, no environment-variable override matrix, and no
implicit user-level defaults. Arbiter looks for `arbiter.yaml`, then
`arbiter.yml`, then `.arbiter.yaml` in the first target; `--config FILE`
overrides that. Every key is optional: anything you leave out takes the default
in `DEFAULTS` in `src/arbiter/policy.py`. The only environment variables a scan
reads are credentials and cache locations (`ANTHROPIC_API_KEY` for the model
passes, `ARBITER_CACHE_DIR`, `ARBITER_NO_VERSION_MEMO`), never policy.

This repository's own [`arbiter.yaml`](../arbiter.yaml) is a working example.

## Which config is trusted

A file found in the target root is the target's own, and the target is what
the scan judges (ARB-143, ARB-148). It may use the features that add to the
scan -- `probes.disable`, `rules`, `quality`, `score.weights`, `report`,
`cache` -- and it may make the gate **stricter**. It may not:

- set `precision` (`ledger`, `verified_rules`, `deterministic_profiles`) or
  `verify`, which decide which of its findings are called `verified`;
- **hide or downgrade** its findings: `suppress` and
  `probes.severity_overrides` are dropped whole (a selector-less `suppress`
  entry set every finding aside and the repository graded 100), and a
  `score.coverage_threshold` below the default 0.6 is dropped (a higher one
  withholds more and is kept);
- **loosen** the gate: `fail_on.severity: null`, `fail_on.coverage_below:
  null`, `fail_on.withheld_grade: false`, `gate_on_inferred: false` or
  `fail_on_probe_error: false` where the file would otherwise have set them
  true, or a `tiers` list that drops a default gating tier. Tightening is
  honoured: a lower `fail_on.severity`, a `fail_on.new`, a `coverage_below`,
  `tier_mode: legacy` (gates on more tiers), `tiers` that add to the default.

Dropped keys are not silent: `report.json` records them under
`scan_scope.config.ignored`, and the console, markdown and pull-request
renderings print one line naming them. A misspelt gate value (`tier_mode:
teired`, `fail_on.severity: crtical`) is an error (exit 2), never a quiet
fallback; `Critical` is read as `critical`.

**A repository that keeps its suppressions in its own `arbiter.yaml` passes
the file explicitly**: `arbiter gate . --config arbiter.yaml`. That is the
operator saying the file is theirs. Arbiter's own CI and `omni gate` do so.

`--config FILE` is the operator's choice and is trusted in full. A
`precision.ledger` path is resolved relative to the config file that names it
and must stay inside that file's directory; a path that escapes is an error.
Whatever the ledger declares, its `bar` is never read below Arbiter's
`DEFAULT_BAR`.

## Contents

- [The file](#the-file)
- [Profiles](#profiles)
- [Model verification](#model-verification)
- [Gating](#gating)
- [Precision tiers](#precision-tiers)
- [Pull-request review comments](#pull-request-review-comments)
- [Scoring](#scoring)
- [Choosing probes](#choosing-probes)
- [Suppressions](#suppressions)
- [House rules](#house-rules)
- [Adaptive thresholds](#adaptive-thresholds)
- [External analyzers](#external-analyzers)
- [Other keys](#other-keys)
- [Where state lives](#where-state-lives)

---

## The file

```yaml
version: 1
profile: offline          # offline | ci | assisted | connected | audit

gate:
  fail_on:
    severity: critical    # any critical fails the build
    new: high             # new highs fail; pre-existing ones don't
    coverage_below: 0.60  # refuse to certify a thin scan
  gate_on_inferred: false

suppress:
  - rule: "arbiter/quality.no-tests"
    reason: "tests live in a sibling repository"
    expires: 2027-01-31   # expiry is mandatory

rules:
  - id: code-note-anchors
    type: reference_integrity
    refs:    { files: "**/*.py", pattern: "#\\s*note:\\s*(?P<ref>[\\w./#-]+)" }
    anchors: { files: ".ai/code-notes/**/*.md", pattern: "^#+\\s*(?P<anchor>.+)$" }
    severity: high
```

## Profiles

A profile is a capability budget, not a severity setting.

| Profile | Network | Model | For |
|---|---|---|---|
| `offline` (default) | no | no | air-gapped and high-side environments |
| `ci` | no | no | fast, deterministic gating |
| `assisted` | only the model call | verification only | `ci` plus the model verification pass ([precision.md](precision.md#model-verification)) |
| `connected` | yes | yes | full depth: registry lookups, the judgement pass |
| `audit` | yes | yes | everything, no time budget |

A probe that needs a capability the profile forbids is skipped with that reason
recorded, so the report says what the profile cost you. Coverage falls by
exactly the amount that was not checked — the grade never quietly absorbs it.

Override per run with `arbiter scan . --profile connected`.

## Model verification

The `verify:` block configures the optional model verification pass, which
asks a model to confirm or reject each finding and records the verdict on it
(how it works: [precision.md](precision.md#model-verification)). It needs
`ANTHROPIC_API_KEY`; without one, every candidate is recorded as
`not_verified` and the report says so. Defaults:

```yaml
verify:
  enabled: null            # null: the profile decides (on for assisted)
  provider: anthropic
  model: claude-opus-5-5
  effort: medium
  min_severity: medium
  max_findings: 150        # model calls per scan
  max_tokens: 400000       # input + output tokens per scan
  max_output_tokens: 4000  # per call
  excerpt_lines: 120
  cache: true              # .arbiter/verify-cache.json; cache_path overrides
  skip_rules: ["arbiter/ast.*", "arbiter/quality.*", "arbiter/assurance.suppression-census"]
  # fp_notes_path: FILE    # known false-positive notes; default: the shipped ledger
```

| Profile | Verification runs |
|---|---|
| `offline`, `ci` | never, whatever `verify.enabled` or `--model-verify` say |
| `assisted` | yes, unless `verify.enabled: false` or `--no-model-verify` |
| `connected`, `audit` | only with `verify.enabled: true` or `--model-verify` |

Do not confuse this with `arbiter verify REPORT`, which checks a report's
claim ledger and calls no model ([cli.md](cli.md#integrity-and-compliance)).

## Gating

```yaml
gate:
  fail_on:
    severity: critical
    new: high
    coverage_below: 0.60
  gate_on_inferred: false
  fail_on_probe_error: false
  tier_mode: tiered
  tiers: [verified]
```

| Key | Default | Effect |
|---|---|---|
| `fail_on.severity` | `critical` | any finding at or above this severity fails |
| `fail_on.new` | none | findings at or above this severity that are absent from the baseline (`--baseline`) fail |
| `fail_on.coverage_below` | none | the run fails if rubric coverage falls below this fraction |
| `fail_on.withheld_grade` | `true` | a withheld grade fails the gate (coverage below `score.coverage_threshold`, most of the source in languages no pack reads or in files the walk did not read, or nothing assessable read), unless the withholding is the operator's own narrowing: `--changed`, `--only-files`, `--only`, `--skip`, `--no-adapters`. Only a `--config` file may set it `false` (ARB-152) |
| `gate_on_inferred` | `false` | when false, findings with `provenance: inferred` (from a model) never fail a build |
| `fail_on_probe_error` | `false` | when true, a probe that errored fails the build |
| `tier_mode` | `tiered` | `tiered`: `fail_on` reads only findings whose precision tier is in `tiers` ([below](#precision-tiers)), and the gate block records what it set aside as `excluded_by_tier`. `legacy`: `fail_on` reads every active finding, as before tiers. Any other value is an error |
| `tiers` | `[verified]` | under `tier_mode: tiered`, the tiers that can fail the gate: any of `verified`, `advisory`, `inferred` |

Suppressed findings never fail the gate. The gate reads severity, never
confidence, so calibration ([calibration.md](calibration.md)) cannot change a
gate outcome. (Older docs mention a `use_calibration` key; nothing reads it.)

`coverage_below` is the guard against a reassuring result from a scan that
barely ran. Without it, uninstalling an analyzer looks identical to fixing every
finding it produced. Since ARB-152 the grade's own bar backs it: a scan whose
grade is withheld fails the gate (`withheld_grade`), so a machine without the
analyzers installed reports `grade withheld (coverage)` rather than PASS --
install them (`arbiter tools install`), or say `--no-adapters` and own the
narrowing. `scorecard.withheld_by` names the cause (`coverage`,
`unassessed_languages`, `files_not_read`, `nothing_read`, or the operator's
`partial` / `probes_selected`).

Source in a language no rule pack reads (Kotlin, Swift, Scala, C#, Rust, PHP,
...) counts against coverage too: one `lang_unsupported` outcome, skipped and
sized like the packs that are missing, names the languages and their share of
the source lines (`scan_scope.languages_not_assessed`), and when more than
half the source lines are in such languages the grade is withheld
(ARB-144). The language-neutral probes (secrets, IaC, supply chain, drift)
still run over the whole tree.

Files the walk saw and did not read count the same way (ARB-150): a file with
a NUL byte in its first 4KB, one over 2,000,000 bytes, UTF-16 saved without a
byte-order mark, a symbolic link to a file outside the tree. Each is listed
with its reason under `scan_scope.skipped` (`by_reason`, `entries` for the
source-like ones, `dirs` for every directory the walk did not enter --
`vendor/`, `node_modules/`, a symlinked directory -- with a bounded file
count), one `files_not_read` outcome sits in the coverage denominator, the
console and markdown print a `NOT READ` line, and when more than half the
source-like files were skipped the grade is withheld. A scan that read
nothing a probe assesses -- an empty directory, docs only, binaries only --
withholds the grade outright (ARB-149). Under `--changed`, a changed file
no probe read (moved under `dist/`, binary, in a skipped directory) is
listed in `scan_scope.changed_not_read`; when none of the changed files was
read the gate fails, and a delete-only change is named as such (ARB-151).

## Precision tiers

Every finding in every report carries a precision tier, `verified`,
`advisory` or `inferred`, and a one-line `tier_reason`. The tier says whether
the finding is precise enough to block a `tiered` gate; it never hides or
re-grades a finding. The rules for assigning tiers are in
[precision.md](precision.md#tiers).

```yaml
precision:
  ledger: null            # null = the ledger shipped with Arbiter (src/arbiter/packs/precision.json)
  verified_rules: []      # rule ids or globs declared verified; the ledger must still admit them
  deterministic_profiles: [offline, ci]   # profiles that cannot ask a model
```

Only a config passed with `--config` can set this block; a target's own
`arbiter.yaml` cannot ([above](#which-config-is-trusted)). `ledger` is
relative to the config file and must stay beside it.

Today one rule is declared verified, `supply.unpinned-action` (ARB-101), so
every other deterministic finding is `advisory`: the default `tiered` gate
reads only unpinned-Action findings, while the default view still lists
every finding, each labelled with whether it can block the gate. A
repository that wants the severity gate over every finding meanwhile sets
`gate.tier_mode: legacy`
([precision.md](precision.md#current-numbers) has the current state).

## What the report shows

```yaml
report:
  show: all               # all (default) | verified
```

| Key | Default | Effect |
|---|---|---|
| `show` | `all` | `all`: the console, markdown, pull-request comment, SARIF, HTML and GitHub annotations list every active finding, verified first, then advisory, then inferred, each section labelled with what the tier means and whether it can block the gate, under one line such as `2 verified (can block the gate) · 71 advisory (shown, not gating) · 0 inferred`. `verified`: an opt-in that lists verified findings only (plus any finding that failed the gate), with one line saying how many advisory and inferred findings were left out (`no verified findings; N advisory findings not shown` when there are none). `--verified-only` on the command line is `verified` for one run; `--advisory` is `all` for one run, which changes nothing unless this file says `verified`. Any other value is an error |

Showing is not blocking: `report.show` never changes what can fail the gate
(`gate.tier_mode`, `gate.tiers`), and the gate never changes what is shown.
ARB-100 briefly made `verified` the default; with one verified rule that
hid nearly every finding, so ARB-103 made `all` the default again
([precision.md](precision.md#tiers)).

`report.json` always holds every finding with its `tier` and `tier_reason`,
plus a top-level `tiers` block (`shown`, `counts`, `shown_count`,
`not_shown`) recording which view was in force. Baselines and `new` /
`existing` status are computed over the full set
([precision.md](precision.md#tiers)).

## Pull-request review comments

```yaml
review:
  min_tier: advisory      # advisory (default) | verified
  max_comments: 20        # 0-100
  suggestions: true
```

| Key | Default | Effect |
|---|---|---|
| `min_tier` | `advisory` | which findings `arbiter gate --post-review` may post. `verified`: rules the precision ledger admits. `advisory`: also rules at the ledger's advisory bar, or, while the ledger has none, high-severity high-confidence findings whose rule the ledger has not measured below 0.85 |
| `max_comments` | `20` | inline comments per run; the rest are listed in the summary comment |
| `suggestions` | `true` | post mechanical fixes as ```` ```suggestion ```` blocks |

Any other value is an error. Only findings on lines the pull request changed
are ever posted, whatever these say ([pr-review.md](pr-review.md)).

## Scoring

```yaml
score:
  coverage_threshold: 0.6     # below this rubric coverage the overall grade is withheld
  weights:                    # per dimension; the defaults are below
    security: 0.30
    quality: 0.20
    supply_chain: 0.15
    interface: 0.15
    compliance: 0.10
    drift: 0.10
    assurance: 0.0            # deliberately zero: it measures the checking, not the code
```

`coverage_threshold` decides when the grade is withheld; `gate.fail_on.coverage_below`
decides when the gate fails. They are separate keys.

## Choosing probes

```yaml
probes:
  disable: [judgement]                 # same as --skip on every run
  severity_overrides:
    "arbiter/quality.todo-density": info   # rule id or glob -> severity
  adapters_parallel: 2                 # see External analyzers
```

`--only` and `--skip` on the command line choose probes for one run; `arbiter
probes .` lists the probe names. A disabled probe is reported as skipped, so
coverage shows what it cost.

## Suppressions

```yaml
suppress:
  - rule: "arbiter/*"
    path: "fixtures/**"
    reason: "planted defects — this is the golden-fixture test corpus"
    expires: 2099-01-01
```

Three properties, each deliberate:

- **`reason`, `expires` and a selector (`rule`, `path` or `id`) are
  mandatory**, and checked when the config loads: an entry missing any of
  them is a config error (exit 2), and `apply_suppressions` ignores such an
  entry even in a config built in code (ARB-152; before, an entry with only
  a `reason` matched every finding forever). An expired suppression stops
  suppressing rather than failing the run, so the finding returns and is
  re-decided instead of quietly persisting forever.
- **Suppressed findings stay in the report**, marked and attributed. They are
  not deleted; a reader can always see what was set aside and on whose say-so.
- **Patterns match rule and path**, including external rules
  (`checkov/*`), so a third-party analyzer can be quieted in one place.

## House rules

Five rule types cover repository-specific policy without writing code:

| Type | Asserts |
|---|---|
| `file_exists` | a required file is present |
| `file_absent` | a forbidden file is not present |
| `content_match` | a pattern is present, or forbidden, in matching files |
| `reference_integrity` | every reference resolves to a declared anchor |
| `metric_threshold` | a measured metric stays within a limit |

Plus `ast_query`, which runs a tree-sitter query and reports the captures —
structural, so it catches the construct however it is formatted:

```yaml
rules:
  - id: no-bare-except
    type: ast_query
    languages: [python]
    files: "src/**/*.py"
    # The predicate is the rule: `(except_clause) @hit` alone matches every handler.
    query: '(except_clause (identifier) @t (#match? @t "^(Exception|BaseException)$")) @hit'
    capture: hit
    title: "Broad except clause"
    remediation: "Catch the specific exception, or re-raise after handling."
    severity: low
```

`ast_query` requires the `ast` extra (tree-sitter). Without it the rule reports
as not assessed, naming the missing dependency.

`files:` and `paths:` are globstar patterns matched against the whole
repo-relative path, case-sensitively on every OS (ARB-147): `*` stays inside
one path segment, `**` spans any number of segments, so `**/*.py` is every
Python file at any depth (the root included), `src/**/*.py` includes
`src/a.py`, and `*.py` is the root's Python files only. Before ARB-147 these
went through `fnmatch`, where `**/*` missed every root file and `src/**/*.py`
missed `src/a.py`.

## Adaptive thresholds

Thresholds can adapt to the repository rather than to history, which needs no
knowledge file and preserves reproducibility:

```yaml
quality:
  adaptive: true
  max_file_lines: 900       # the ceiling: adaptive may tighten, never loosen
  max_function_lines: 140
```

File length, function length and complexity limits are drawn from that
codebase's own p95, bounded above by the configured value so adaptive can only
tighten, and below by a floor so a very terse codebase is not held to a
threshold too strict to mean anything:

```text
file_lines      n=30   median=143  p95=795
function_lines  n=210  median=12   p95=75     # the fixed 120 limit was too lax here
complexity      n=210  median=5.5  p95=27
```

A distribution with fewer than 30 samples is ignored and the fixed threshold
stands.

## External analyzers

The adapters (ruff, bandit, semgrep, checkov, gitleaks) run after the native
probes, concurrently, in a thread pool of `probes.adapters_parallel` workers
(default: the smaller of 4 and the CPU count; `1` runs them one after
another). Their outcomes and findings are written into the report in
registry order whatever order they finished in, so the report's bytes do not
depend on the scheduler.

```yaml
probes:
  adapters_parallel: 2
```

With the result cache on, each adapter is also memoised whole in
`.arbiter/cache.json`: one entry per adapter, keyed on its name, the tool's
version, the configuration, Arbiter's own source, a digest of every inventory
file and of the analyzer configuration at the repository root
(`pyproject.toml`, `ruff.toml`, `.ruff.toml`, `setup.cfg`, `.bandit`,
`bandit.yaml`, `.semgrep.yml`, `.semgrep.yaml`, `.semgrep/`, `.checkov.yaml`,
`.checkov.yml`, `.gitleaks.toml`). A hit replays the stored findings and the
probe's outcome says `replayed from cache (nothing the tool reads changed)`.
It is all-or-nothing by design: none of these tools has been measured to be
file-local, so one changed byte in one file re-runs the whole adapter rather
than guessing which of its findings survive. `--verify-cache` re-runs one
memoised adapter per scan and reports a divergence as
`arbiter/assurance.cache-divergence`; `--no-cache` disables the memo along
with the rest of the cache.

## Other keys

| Key | Effect |
|---|---|
| `quality.max_file_lines`, `quality.max_function_lines`, `quality.max_complexity` | fixed thresholds (defaults 800, 120, 20); see [Adaptive thresholds](#adaptive-thresholds) |
| `cache.enabled` | `false` turns the result cache off, like `--no-cache` ([cli.md](cli.md#the-result-cache)) |
| `controls.frameworks`, `controls.packs` | limit the control-coverage summary to these framework ids; extra pack directories ([compliance.md](compliance.md)) |
| `terraform.plans` | Terraform plan JSON files to read, as `--tfplan` ([probes.md](probes.md#terraform-supply-a-plan)) |
| `judgement.provider`, `judgement.model`, `judgement.timeout`, `judgement.api_key_env` | the judgement pass ([probes.md](probes.md#the-judgement-pass)) |
| `out` | tells the doc-drift probe where generated output lives ([below](#where-state-lives)) |

## Where state lives

| Path | Contents | Commit it? |
|---|---|---|
| `arbiter.yaml` | configuration | yes |
| `.arbiter/baseline.json` | accepted current state | yes |
| `.arbiter/knowledge.json` | calibration ledgers and learned confidence | yes |
| `.arbiter/external-severity.json` | measured severities for external checks | yes |
| `.arbiter/cache.json` | per-file results of the file-local probes, and one whole-tree entry per external analyzer | no — git-ignored |
| `.arbiter/verify-cache.json` | model verification verdicts, keyed on the excerpt, model and prompt version | optional — not git-ignored; committing it lets another machine reproduce the verdicts without model calls |
| `~/.cache/arbiter/tool-versions.json` (`ARBITER_CACHE_DIR`) | the external analyzers' version strings, keyed on each binary's path, mtime and size, so registration does not run every `--version` on every invocation; `--no-cache` leaves it alone, `ARBITER_NO_VERSION_MEMO=1` bypasses it, and a tool replaced in place with the same size and mtime keeps its old string until the file is deleted | no — machine-local |
| `arbiter-out/` | reports from the last run | no — git-ignored |
| `arbiter-ab/` | A/B harness output | no — git-ignored |

Where a run writes is decided by `--out` on the command line. An optional
`out:` key in `arbiter.yaml` tells the doc-drift probe which directory holds
generated output, so a document that names `REPORT.md` under it is not
reported as describing a missing file; it does not move the output itself. The
probe treats any `arbiter-out` segment and the run's own `--out` the same way —
see [What doc_drift leaves alone](probes.md#what-doc_drift-leaves-alone).
