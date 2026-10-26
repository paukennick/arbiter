# Arbiter

**A repository and system evaluator that refuses to grade what it did not
actually inspect.**

| | |
|---|---|
| **Version** | 0.1.0 — pre-release, no tagged releases, not on PyPI |
| **Python** | 3.10 or later |
| **Runtime dependencies** | PyYAML (and `tomli` on Python 3.10) |
| **License** | Apache-2.0 — see [Licensing](#licensing) |

Arbiter scans one repository, or a **system** of several, and reports findings
in seven dimensions: security, compliance, quality, drift, interface, supply
chain and assurance. Next to the findings it reports how much of its own
rubric it could run, names every check that did not run and why, and withholds
the overall grade when that coverage is too low.

It never executes the code it scans. It runs 21 native probes (276 rules,
189 of them in tree-sitter packs for Python, TypeScript/JavaScript, Go, Java
and Ruby), wraps six external analyzers (ruff, bandit, semgrep, checkov,
gitleaks, Trivy) when they are installed, and maps findings to ten control
frameworks, including the 2024 CWE Top 25 per language.

## Contents

- [What to expect](#what-to-expect)
- [Install](#install)
- [First scan](#first-scan)
- [Reading the report](#reading-the-report)
- [Gating in CI](#gating-in-ci)
- [Configuring](#configuring)
- [Where to go next](#where-to-go-next)
- [Principles](#principles)
- [Developing Arbiter](#developing-arbiter)
- [Licensing](#licensing)

## What to expect

Arbiter is honest about what it measures, and the measurements are modest:

- **Precision.** Every finding carries a precision tier. A rule becomes
  `verified` only when it is declared verified and the precision ledger has
  enough labels to admit it. As of 2026-10-24, 3 rules meet the admission bar
  and one, `supply.unpinned-action`, is declared verified, so **nearly every
  finding is `advisory`**: shown, labelled, and unable to block the gate.
  There is no human-labelled verified-tier precision figure yet. Details:
  [docs/precision.md](docs/precision.md#current-numbers).
- **Recall is low.** On 25 AI-written services, after rules were written for
  their defect classes, the native probes catch 33 of 117 labelled code
  defects (28%). On a held-out set of 40 such apps, scored once before those
  rules, they caught 6 of 142 (4%). Details:
  [docs/testing-harness.md](docs/testing-harness.md#what-the-numbers-say).
  A clean report means the checks that ran found nothing, not that the code
  is safe.
- **The 99% goal is not achieved.** Arbiter is working toward separate,
  benchmark-scoped precision and recall claims with confidence bounds; it
  will not infer accuracy for unmeasured languages, repositories, or
  platforms. See the [accuracy roadmap](docs/accuracy-roadmap.md) and the
  [current benchmark baseline](docs/accuracy-baseline.md).

## Install

```bash
git clone https://github.com/paukennick/arbiter && cd arbiter
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[ast]"                            # the ast extra runs the language packs
./tools/install_tools.sh                           # optional: the six analyzers and the grammars (bash)
```

Without the `ast` extra, or without the analyzers, Arbiter still runs; what
it could not run is reported as not assessed. Other extras (`mcp`, `api`,
`dev`) and Windows notes: [SETUP.md](SETUP.md).

## First scan

The repository ships a small fixture with fourteen planted defects:

```bash
arbiter scan fixtures/legacy-platform --no-open
```

```text
  3 critical  3 high  4 medium  8 low  5 info
  2 verified (can block the gate) · 21 advisory (shown, not gating) · 0 inferred
  tiers: 2 verified · 21 advisory · 0 inferred (tier_mode tiered: gate reads verified)
  overall 61.0/100   coverage 98%
  ...
  FINDINGS (verified) — measured at least 99% precise; can block the gate
  low      root:.github/workflows/ci.yml:9  Action `actions/checkout` pinned to a mutable ref (`v4`)
  ...
  FINDINGS (advisory) — not confirmed; shown, cannot block the gate
  critical root:app/config.py:4  AWS access key ID committed
           arbiter/secrets.aws-access-key  f:cf802335c8f2  [advisory] rule on probation: not declared verified
  ...
  gate PASS
```

Arbiter shows everything it finds, and blocks only on what it has measured.
Findings come in three tiers, listed in this order, each in its own labelled
section:

- **verified**: rules the precision ledger has measured to be right at least
  99% of the time. Only these can fail the gate (`gate.tier_mode: tiered`).
  One rule has reached that bar so far, `supply.unpinned-action`.
- **advisory**: everything else a rule found. Not confirmed, shown, and
  unable to block the gate. Most real defects are here today, which is why
  they are shown.
- **inferred**: found by a model. Not confirmed, shown, not gating.

The gate above passes because the two verified findings are low and the
default gate fails on criticals; the three advisory criticals are listed but
do not block. `--verified-only` (or `report.show: verified`) narrows the
listing to the verified tier for one run, and then says how many findings it
left out instead of reading as clean:

```text
  2 verified findings shown; 21 advisory findings not shown (run with --advisory to include them)
```

`arbiter-out/report.json` holds every finding either way, each with its
`tier`. Then:

```bash
arbiter explain f:cf802335c8f2      # one finding in full
arbiter probes fixtures/legacy-platform   # which probes can run here, and why not
arbiter scan . --format json,html,console # your own repository, with an HTML page
```

To point it at your own code, with a baseline and your first adjudications,
follow [RUNNING-ON-YOUR-OWN-CODE.md](RUNNING-ON-YOUR-OWN-CODE.md).

## Reading the report

Read these, in order:

1. **Coverage.** Checks that ran divided by checks that applied. Below 60%
   the overall grade is withheld, not estimated.
2. **NOT ASSESSED.** Every probe that did not run, with the reason: a
   missing analyzer, a missing grammar, a profile that forbids the network.
   A check that could not run is not a check that passed.
3. **Findings**, worst first. Each has a severity, a confidence, a
   `provenance` (`deterministic` or `inferred`, from a model), a precision
   tier, and a remediation labelled with where it came from.
4. **The assurance dimension.** Suppression comments, excluded paths and
   tests that assert nothing. It has weight zero: it measures how much of
   the checking is switched off, not the code.

Every field, explained: [docs/reading-a-report.md](docs/reading-a-report.md).

## Gating in CI

`arbiter gate` is `scan` plus an exit code: 0 pass, 1 gate failure, 2 error.

```bash
arbiter baseline arbiter-out/report.json             # accept today's findings into .arbiter/baseline.json
arbiter gate . --profile ci --baseline .arbiter/baseline.json
```

With the default policy the gate fails on any **verified** critical finding
(`gate.tier_mode: tiered`): a build fails on what Arbiter has measured to be
right, and on nothing else, while the report still lists every finding.
Blocking (`gate.tier_mode`) and showing (`report.show`) are separate
settings. `gate.tier_mode: legacy` fails on every critical
finding whatever its tier. Add `new: high` (below) so the gate also fails on
new high findings while the baseline absorbs existing ones. A ready-made GitHub workflow (a fast check on pull
requests, a full scan nightly) is in `examples/pull-request-gate/`; the
composite action, SARIF upload, annotations and GitLab are in
[docs/ci.md](docs/ci.md). `arbiter gate . --changed origin/main` reads only
what a branch changed and records whole-tree checks as not assessed.
`arbiter gate . --post-review` posts the trusted findings on the lines a pull
request changed as one GitHub review, updated in place on each push, with
mechanical fixes as suggestion blocks; `arbiter review-feedback collect`
reads the 👍/👎 reactions back as labels ([docs/pr-review.md](docs/pr-review.md)).

## Configuring

`arbiter.yaml` at the repository root is the only configuration. Every key is
optional:

```yaml
version: 1
profile: ci                 # offline (default) | ci | assisted | connected | audit
gate:
  fail_on:
    severity: critical      # any verified critical fails
    new: high               # new verified highs fail; ones in the baseline don't
    coverage_below: 0.60    # refuse to pass a thin scan
  tier_mode: tiered         # tiered (default): only verified findings fail | legacy: every finding
report:
  show: all                 # all (default): every tier, labelled | verified: verified findings only
suppress:
  - rule: "arbiter/secrets.*"
    path: "tests/fixtures/**"
    reason: "test vectors, committed on purpose"
    expires: 2027-01-01     # reason and expiry are mandatory
```

A profile is a capability budget. `offline` and `ci` never touch the network
or a model. `assisted` is `ci` plus an optional model check of each finding
(needs `ANTHROPIC_API_KEY`). Every key, including precision tiers
(`gate.tier_mode`), house rules and scoring:
[docs/configuration.md](docs/configuration.md). This repository's own
[`arbiter.yaml`](arbiter.yaml) is a working example.

## Where to go next

[docs/README.md](docs/README.md) indexes every document. The most used:

| Document | For |
|---|---|
| [docs/cli.md](docs/cli.md) | every command and flag |
| [docs/configuration.md](docs/configuration.md) | every `arbiter.yaml` key, profiles, gating, suppressions |
| [docs/probes.md](docs/probes.md) | every check, what it needs and what it catches |
| [docs/precision.md](docs/precision.md) | precision tiers, the ledger, the model verification pass, current numbers |
| [docs/ci.md](docs/ci.md) | GitHub Actions, GitLab, partial scans |
| [docs/pr-review.md](docs/pr-review.md) | review comments on pull requests, suggested fixes, reaction feedback |

## Principles

1. **Coverage is reported, never assumed.** A probe that could not run is
   recorded as *not assessed*, with a reason. It is never silently a pass.
2. **Deterministic and inferred findings never blend.** Every finding carries
   `provenance`. Inferred findings do not gate unless you ask them to.
3. **The tool never executes the target.** No `npm install`, no
   `terraform init`, no importing the target's Python.
4. **One core, many languages.** Language support arrives as probes, rule
   packs and adapters, not core changes.
5. **No claim outruns its basis.** Every report carries a claim ledger, and
   twelve invariants are machine-checked before the report is written
   (`arbiter verify` re-checks it; [docs/evidence.md](docs/evidence.md#claim-integrity)).
6. **Adaptation is deliberate, never ambient.** Calibration accumulates
   offline in `.arbiter/knowledge.json`; it moves confidence, never severity,
   and a scan records the knowledge version it read.

## Developing Arbiter

```bash
pip install -e ".[dev,ast]"
python -m pytest -q -m "not slow"   # the fast tier, what every pull request runs
python -m pytest -q -m slow         # real analyzers; run ./tools/install_tools.sh first
python tools/precision_guard.py check
arbiter gate .                      # Arbiter gates itself under its own arbiter.yaml
```

The golden-fixture tests matter most: `fixtures/legacy-platform` holds
fourteen planted defects that `.arbiter-expected.yaml` enumerates, and
`fixtures/planted/<lang>/` holds planted defects beside correct twins for the pack rules.
How Arbiter is built: [docs/architecture.md](docs/architecture.md). Changes
are recorded in [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]`, by date
and requirement. Outside contributions are not accepted yet; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licensing

Arbiter is licensed under the **Apache License, Version 2.0** — see
[LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright © 2026 Nicholas J Pauken.
[docs/licensing.md](docs/licensing.md) records the decision and its history.

**Scan output belongs to you.** Reports, findings, baselines and knowledge
files Arbiter generates from your material are yours. Apache-2.0 grants no
trademark rights (§6); see [TRADEMARKS.md](TRADEMARKS.md).

The external analyzers are neither vendored nor redistributed; each is
installed separately and governed by its own license ([NOTICE.md](NOTICE.md)).
One review is open: redistributing them in the air-gapped bundle (L-6,
ARB-005), so `arbiter bundle build` ships Arbiter without them
([docs/bundle.md](docs/bundle.md)).
