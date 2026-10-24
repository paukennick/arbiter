# README accuracy audit

A line-by-line check of [README.md](../README.md), and of the top of
[RUNNING-ON-YOUR-OWN-CODE.md](../RUNNING-ON-YOUR-OWN-CODE.md), against the
code on branch `legal-docs` (from `main` at `33e7e5a`), done on 2026-10-23.
This page reports; it changes neither file. `README.md` is being edited on
another branch, so the suggested fixes are for whoever merges that work.

## How it was checked

- Commands were run from a source checkout with `python -m arbiter.cli`
  (`PYTHONPATH=src`), Python 3.14, tree-sitter-language-pack 1.22.1 with
  grammars cached, and the five analyzers installed (semgrep 1.177.0,
  checkov 3.3.17). "Without analyzers" runs removed `~/.local/bin` from
  `PATH`.
- Numbers were compared with `src/arbiter/packs/precision.json`,
  `tools/precision_guard.py check`, `docs/precision.md`,
  `docs/testing-harness.md`, `tools/gold/results/` and a fresh
  `tools/ai_corpus_score.py` run on the development corpus. The held-out
  corpus was not re-scored, because it is scored once by design.
- Relative links and anchors are already checked by `tests/test_docs.py`,
  which passes. External links were not fetched (no network access was used).

**Status key.** *accurate*: matches the code; *wrong*: does not match now;
*stale*: was true and has drifted; *unverifiable*: cannot be checked offline
from this repository. **r5** marks a claim that becomes wrong when branch
`r5-verified-output` merges: it makes `report.show: verified` and
`gate.tier_mode: tiered` the defaults and adds `--advisory` to show the rest
(`git diff 33e7e5a...r5-verified-output -- src/arbiter/policy.py`).

## Counts

| | Claims checked | Accurate | Wrong | Stale | Unverifiable | r5 |
|---|---:|---:|---:|---:|---:|---:|
| README.md | 60 | 52 | 4 | 2 | 2 | 6 |
| RUNNING-ON-YOUR-OWN-CODE.md (lines 1–45) | 7 | 4 | 2 | 0 | 1 | 0 |

The r5 column overlaps the others: an r5 claim is accurate today. One more
README claim ("Outside contributions are not accepted yet", line 203)
becomes wrong when this branch merges.

## The worst errors

1. **The first-scan output matches neither real install** (README lines
   74–83). The shown counts (23 findings, coverage 98%, overall 61.0) appear
   only with `--no-adapters`. The command as written gives 73 findings
   (3 critical, 3 high, 41 medium, 12 low, 14 info) at 100% coverage when the
   analyzers are installed, and **withholds the grade at 23% coverage** when
   they are not, which is the state right after the install steps above it
   that skip the optional `install_tools.sh`.
2. **"reason and expiry are mandatory" for suppressions is not enforced**
   (line 149). A suppression with neither `reason` nor `expires` was accepted
   and suppressed its finding without warning (`policy.apply_suppressions`
   applies any matching entry; only an expired date is checked).
   `docs/configuration.md` makes the same claim.
3. **"`offline` and `ci` never touch the network"** (line 152) is too strong.
   Arbiter's own code makes no model or registry call under them, but a URL
   target is cloned under any profile, a missing tree-sitter grammar is
   downloaded by the grammar library, and semgrep and checkov contact their
   vendors at start-up unless told not to
   ([data-handling.md](data-handling.md#known-gaps)).
4. **Admitted-rule count is stale** (line 44): the shipped ledger admits 3
   rules, not 2 (`tools/precision_guard.py check`: "0 rule(s) declared
   verified, 120 in the ledger, 3 admitted"). `docs/precision.md`
   "Current numbers" has the same stale figure.

## README.md

| Claim | Line | Status | Evidence | Suggested fix |
|---|---:|---|---|---|
| Version 0.1.0 | 8 | accurate | `pyproject.toml` `version = "0.1.0"`; `arbiter --version` | |
| "no tagged releases" | 8 | accurate | no release tags; the one tag, `Arbiter`, marks a 2026-09-14 commit and is not a release | |
| "not on PyPI" | 8 | unverifiable | needs a network lookup | |
| Python 3.10 or later | 9 | accurate | `requires-python = ">=3.10"` (note: `.ai/project-configuration.md` says `>=3.11`, which is the inconsistent one) | |
| Runtime deps PyYAML, `tomli` on 3.10 | 10 | accurate | `pyproject.toml` `dependencies` (`tomli` for `python_version < '3.11'`) | |
| Licence Apache-2.0 | 11 | accurate | `LICENSE` | |
| Seven dimensions, named | 13–15 | accurate | `core.DIMENSIONS` has exactly those seven | |
| Reports coverage, names checks not run, withholds the grade when coverage is low | 15–17 | accurate | observed: "grade withheld — assessment coverage 23% is below the 60% threshold" | |
| Never executes the code it scans | 19 | accurate | no build, install or import of target code found; probes read files | |
| 21 native probes | 19 | accurate | 21 registered non-external probes (`probes` registry; `arbiter probes`) | |
| 263 rules, 176 in tree-sitter packs for five languages | 19–21 | accurate | `packs/rules/*.yaml`: 263; `ast/*.yaml`: 26+42+34+39+35 = 176 | |
| Wraps five analyzers when installed | 21–22 | accurate | `packs/adapters/*.adapter.toml`: ruff, bandit, semgrep, checkov, gitleaks | |
| Ten control frameworks incl. 2024 CWE Top 25 | 22–23 | accurate | `packs/controls/`: 10 files incl. `cwe-top25-2024.yaml` | |
| A rule is `verified` only when declared and admitted | 42–44 | accurate | `precision.py`; [precision.md](precision.md#tiers) | |
| "2 of the 120 labelled rules meet the admission bar" | 44–45 | **stale** | ledger: 120 rules, **3 admitted** (`supply.unpinned-action` 196 labels, lower 0.981, added in round 4) | "3 of the 120"; update `docs/precision.md` too |
| None is declared verified; every finding is `advisory` | 45–46 | accurate; **r5** | `precision_guard`: 0 declared; scan shows "0 verified · 23 advisory". After r5 the default output shows verified findings only, so a default scan lists no findings at all | say how to see advisory findings (`--advisory`) |
| No verified-tier precision figure; 99% target not reached | 46–47 | accurate | `docs/precision.md` "Current numbers" | |
| 25 AI-written services; 33 of 117 defects (28%) | 48–50 | **stale** | 25 apps in `fixtures/ai-corpus/`; re-run of `tools/ai_corpus_score.py` at `33e7e5a`: **34 of 117 (29%)** | "34 of 117 (29%)", with the date |
| Held-out 40 apps, 6 of 142 (4%), scored once | 50–51 | accurate | 40 apps in `fixtures/ai-corpus-heldout/`; `tools/gold/results/2026-10-22-ai-corpus-heldout.md`: "6/142 (4%)" | |
| "A clean report means the checks that ran found nothing" | 53–54 | accurate | design rule 1; DISCLAIMER says the same | |
| `git clone https://github.com/paukennick/arbiter` | 59 | unverifiable | no network; the repository is stated to be public | |
| `pip install -e ".[ast]"` runs the language packs | 61 | accurate | `ast` extra = tree-sitter + language pack | |
| `./tools/install_tools.sh` installs the five analyzers and grammars | 62 | accurate | default `WANT=(checkov semgrep bandit ruff gitleaks)`, plus `fetch_grammars` | |
| Without `ast` or analyzers it still runs; what it could not run is not assessed | 65–66 | accurate | observed with analyzers off `PATH`: probes "skip — missing binary" | add that the grade is then withheld (coverage 23% on the fixture) |
| Other extras `mcp`, `api`, `dev` | 66–67 | accurate | `pyproject.toml` (there is also `tools`) | |
| Fixture has fourteen planted defects | 71 | accurate | `.arbiter-expected.yaml`: 14 `expected` | |
| Sample output for `arbiter scan fixtures/legacy-platform --no-open` | 74–83 | **wrong**; **r5** | matches only `--no-adapters`. With analyzers: 73 findings, coverage 100%. Without: grade withheld at 23%. The `f:cf802335c8f2` finding id is right. After r5, the tiers line and the advisory findings are not shown by default | show the command that produces this output (`--no-adapters`), or replace the output with a real one and say which install it came from |
| "That writes `arbiter-out/report.json`" | 86 | accurate (incomplete) | also writes `arbiter-out/history.jsonl` and `fixtures/legacy-platform/.arbiter/cache.json` inside the target (git-ignored) | mention the cache, so a user is not surprised by `.arbiter/` appearing |
| `arbiter explain f:cf802335c8f2` | 89 | accurate; **r5** | prints the finding from `arbiter-out/report.json`. After r5 the id is not in the default console output | |
| `arbiter probes fixtures/legacy-platform` | 90 | accurate | runs; lists each probe with ready/skip and reason | |
| `arbiter scan . --format json,html,console` | 91 | accurate | `--format` accepts those | |
| Grade withheld below 60% coverage | 101–102 | accurate | `score.coverage_threshold: 0.6` in `policy.DEFAULTS` | |
| NOT ASSESSED lists reasons (missing analyzer, grammar, network profile) | 103–105 | accurate | observed reasons: "missing binary", "missing tree-sitter grammar", "profile ... forbids network access" | |
| Each finding has severity, confidence, provenance, tier, labelled remediation | 106–108 | accurate | `core.Finding` fields incl. `remediation_source` | |
| Assurance dimension has weight zero | 109–111 | accurate | `policy.DEFAULT_WEIGHTS["assurance"] = 0.0` | |
| `arbiter gate` exit codes 0 / 1 / 2 | 117 | accurate | observed 1 on the fixture, 2 on a missing directory, 0 on a passing partial gate | |
| `arbiter baseline arbiter-out/report.json` writes `.arbiter/baseline.json` | 120 | accurate | `--out` default `.arbiter/baseline.json` | |
| `arbiter gate . --profile ci --baseline ...` | 121 | accurate | flags exist; ran | |
| Default policy fails on any critical finding | 124 | accurate; **r5** | `DEFAULTS["gate"]["fail_on"]["severity"] = "critical"`, `tier_mode: legacy`. After r5 (`tier_mode: tiered`) only `verified` findings block, and no rule is verified, so the default gate blocks nothing | state the tiered default and what it blocks |
| `new: high` fails on new highs while the baseline absorbs old ones | 124–126 | accurate; **r5** | `gate.fail_on.new`; same tier caveat after r5 | |
| Ready-made workflow in `examples/pull-request-gate/`: fast PR check, nightly full scan | 126–128 | accurate | `arbiter-pr.yml`: `pull_request` job and `schedule: cron "0 9 * * *"` job | |
| Composite action, SARIF, annotations and GitLab in `docs/ci.md` | 128–129 | accurate | `docs/ci.md` has each; action at `ci/github-action/action.yml` | |
| `--changed origin/main` reads only the branch's changes and records whole-tree checks not assessed | 129–130 | accurate | observed `scan_scope.mode: partial`; `quality`, `doc_drift` skipped "partial scan ... reads relationships" | |
| `arbiter.yaml` at the root is the only configuration | 134 | accurate (loose) | `--config` overrides the path; a system manifest is a separate file | |
| Profile list `offline` (default), `ci`, `assisted`, `connected`, `audit` | 139 | accurate | `policy.PROFILES`; `DEFAULTS["profile"] = "offline"` | |
| Suppression "reason and expiry are mandatory" | 149 | **wrong** | a suppression with neither was applied without warning (`policy.apply_suppressions`) | enforce it in code, or say "should carry"; fix `docs/configuration.md` line 208 too |
| "`offline` and `ci` never touch the network or a model" | 152–153 | **wrong** | true of Arbiter's model and registry calls; not of URL clones (`inventory.acquire_one`), grammar downloads (`ast._parser`), or semgrep/checkov start-up requests | "never call a model or a package registry, and send none of your code anywhere"; link [PRIVACY.md](../PRIVACY.md) |
| `assisted` = `ci` plus an optional model check of each finding, needs `ANTHROPIC_API_KEY` | 153–154 | **wrong** (detail) | under `assisted` the check is on by default (`verify.wanted`: `caps["verify"]`), and covers findings at or above `verify.min_severity` (medium), up to 150, not each finding. It sends code excerpts to Anthropic | "plus a model check of each medium-or-worse finding, which sends masked excerpts to Anthropic's API (needs `ANTHROPIC_API_KEY`)" |
| `gate.tier_mode` key | 155 | accurate; **r5** | exists; its default changes under r5 | |
| `docs/README.md` indexes every document | 161 | accurate once this branch's index entries land | before this branch every `docs/*.md` was indexed | |
| Table of most-used documents | 163–169 | accurate | all five files exist; `tests/test_docs.py` passes | |
| Twelve machine-checked invariants; `arbiter verify` | 181–183 | accurate | `claims.INVARIANTS`: CI-1 … CI-12; `verify` subcommand exists; `docs/evidence.md#claim-integrity` resolves | |
| Calibration in `.arbiter/knowledge.json`, moves confidence never severity, scan records the version | 184–186 | accurate | `learn.DEFAULT_PATH`; `learn.py` "Learning never changes a gate outcome"; report `learning.knowledge_version` | |
| Developer commands (`.[dev,ast]`, both pytest tiers, `precision_guard.py check`, `arbiter gate .`) | 190–196 | accurate | extras and markers exist; `precision_guard.py check` exits 0 | |
| `.arbiter-expected.yaml` enumerates fourteen; `fixtures/planted/<lang>/` has bad and good twins | 198–200 | accurate | 14 entries; `bad/` and `good/` under five languages | |
| "Outside contributions are not accepted yet" | 203–204 | accurate today; **wrong when `legal-docs` merges** | this branch's `CONTRIBUTING.md` accepts contributions under Apache-2.0 with a DCO sign-off | "Contributions are welcome under the DCO; see CONTRIBUTING.md" |
| Apache-2.0; Copyright © 2026 Nicholas J Pauken | 208–209 | accurate | `LICENSE`, `NOTICE` | |
| Scan output belongs to you; §6 grants no trademark rights | 212–214 | accurate | `NOTICE`; Apache-2.0 §6; `TRADEMARKS.md` (now also holds the Arbiter policy) | |
| Analyzers neither vendored nor redistributed; L-6 open; bundle ships without them | 216–220 | accurate | `NOTICE.md`; `docs/licensing.md` L-6 open; `arbiter bundle --help`: "no analyzers" | |
| Relative links and anchors throughout | all | accurate | `tests/test_docs.py::test_every_relative_link_and_anchor_resolves` passes | |

## RUNNING-ON-YOUR-OWN-CODE.md, lines 1–45

| Claim | Line | Status | Evidence | Suggested fix |
|---|---:|---|---|---|
| "Nothing here needs my sandbox" | 6 | wrong (voice) | first-person aside from an earlier session; there is no sandbox | delete the sentence |
| Repositories "never leave" the machine under `offline` and `ci` | 6–7 | accurate | no source code is sent under those profiles; the vendor and grammar requests send none | add "see PRIVACY.md" |
| `connected`, `audit` and `assisted` send masked excerpts to a model API when `ANTHROPIC_API_KEY` is set | 7–9 | **wrong** (incomplete) | true, but `connected` and `audit` also send package names to PyPI and npm (`authored.package_exists`), and masking is partial ([data-handling.md](data-handling.md#redaction-and-its-limits)) | add the registry lookups and "partly masked" |
| Link `docs/configuration.md#profiles` | 10 | accurate | heading "Profiles" exists | |
| Apache-2.0 lets you run it on your code; output is yours | 12–15 | accurate | `LICENSE`, `NOTICE` | |
| CLI is pure Python and works the same on Windows; `.sh` helpers need bash | 17–22 | accurate | CLI is Python; `tools/*.sh` are bash; Windows CI runs the suite (`pr-check.yml`) | |
| `git clone https://github.com/paukennick/arbiter` | 45 | unverifiable | no network | |

## Links the README should gain

A "Legal and policy" section, next to "Licensing", listing:

- [LICENSE](../LICENSE) and [NOTICE](../NOTICE) (already linked)
- [DISCLAIMER.md](../DISCLAIMER.md): what results do and do not mean
- [PRIVACY.md](../PRIVACY.md) and [docs/data-handling.md](data-handling.md):
  what leaves the machine
- [SECURITY.md](../SECURITY.md): reporting vulnerabilities
- [TRADEMARKS.md](../TRADEMARKS.md): the Arbiter name (already linked)
- [CONTRIBUTING.md](../CONTRIBUTING.md), [DCO](../DCO) and
  [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)
- [docs/ai-assisted-development.md](ai-assisted-development.md)
- [docs/third-party-content.md](third-party-content.md)

The "Configuring" paragraph on profiles (line 152) should link
[PRIVACY.md](../PRIVACY.md).
