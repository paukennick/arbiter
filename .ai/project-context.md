# Project Context: arbiter

Decision history for this repository. `CLAUDE.md` routes here. Where this
file and `.ai/core-context.md` (generic operating principles) overlap, this
file wins for anything project-specific. Append dated sections; do not
rewrite earlier ones.

## What this is

Arbiter (`arbiter-eval`) is a polyglot repository and system evaluator. It
scans one repository or a system of several and reports findings across
security, compliance, quality, drift and cross-repo interface dimensions,
together with how much of its own rubric it was actually able to run.

Pipeline and module ownership are in `README.md` "Layout". Native probes
need nothing installed; external analyzers (ruff, bandit, checkov, semgrep,
gitleaks) are wrapped through declarative adapter manifests in
`src/arbiter/packs/`. An A/B harness (`arbiter ab`) compares configurations,
tools and builds of Arbiter itself, and an offline learning loop
(`tools/train_cycle.sh`, `.github/workflows/train.yml`) calibrates rules
against a corpus of public repositories with a held-out set.

Design rules that constrain every change (from `README.md`):

1. Coverage is reported, never assumed — a probe that could not run is
   *not assessed*, never a silent pass.
2. Deterministic and inferred findings never blend; every finding carries
   `provenance`.
3. The tool never executes the target.
4. Language support arrives as probes and adapters, not core changes.
5. No claim outruns its basis; report invariants are machine-checked.
6. Adaptation is deliberate — a scan reads one pinned knowledge version.

## 2026-09-12 — OmniEngineering and Headroom adopted (REQ-001)

**What changed.** Added the OmniEngineering workspace (`.ai/`, `./omni`,
`make_ai.py`, `CLAUDE.md`, `CHANGELOG.md`) and installed Headroom's Claude
Code integration at local scope.

**Why it was done by hand rather than `omni adopt`.** The only OmniEngineering
source on this machine is the STEP-Migration repo, and `omni adopt` copies its
whole `.ai/` directory — including that project's 80-entry requirements
registry, code-notes, archives and CUI-marked project history. Instead:

- `make_ai.py`, `omni`, `.ai/rules/`, `.ai/schemas/`, `.ai/.ignore` and
  `.ai/core-context.md` came from `~/dev/STEP-Migration` (newest CLI), with
  STEP values removed from the ruleset `configuration` block, the
  requirements schema description and `core-context.md` section 5.
- `.ai/playbooks/`, `.ai/checklists/` and `.ai/knowledge/swebok/` came from
  the `Documents/GitHub/STEP-Migration` copy, which predates STEP's REQ-080
  deletion of those generic files. They were checked for STEP-specific text
  and contain none.
- Context brief, manifest, configuration, this file and the requirements
  registry were written fresh for arbiter.

**Known gaps.** `.ai/adapters/*`, `.ai/checklists/public-release.md`,
`.ai/rules/fallback-llm-rules.json` and `.ai/rules/hci-ui-rules.json` are
required by `make_ai.py` but exist in no local copy, so `omni doctor` reports
them and `omni sync` stops before writing root shims. Pull them from the
OmniEngineering upstream when it is available rather than inventing them.

**Headroom.** `headroom init claude` (headroom-ai 0.37.0, installed in the
STEP-Migration venv and exposed on PATH via `WindowsApps\headroom.cmd`) wrote
`.claude/settings.local.json`: it routes Claude Code through the proxy at
`127.0.0.1:8787` and adds SessionStart and PreToolUse (Bash|PowerShell) hooks
that keep the proxy running. That file holds machine-specific paths, so it is
git-ignored. It takes effect after Claude Code restarts. Because Headroom
lives in another project's venv, recreating that venv would break these hooks.
