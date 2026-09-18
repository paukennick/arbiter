# Project Configuration

These settings correspond to the `configuration` block in
`.ai/rules/universal-engineering-ruleset.json`. Keep the two in step.

## Required Project Values

- `project_name`: `arbiter`
- `repository_type`: `application` (Python CLI and library, package `arbiter-eval`)
- `primary_language_or_stack`: `Python >=3.11`, setuptools with a `src/` layout; the only runtime dependency is `PyYAML`; optional `ast` extra adds tree-sitter
- `package_manager`: `pip` (`pip install -e .[dev]`; external analyzers via `./tools/install_tools.sh`)
- `build_command`: `pip install -e .`
- `test_command`: `python -m pytest tests/ -q` — the golden-fixture tests over `fixtures/legacy-platform` are the ones that matter; a rule or adapter change that misses a planted defect fails the suite
- `lint_command`: none gating; `ruff` is available through the `tools` extra
- `typecheck_command`: none configured
- `changelog_location`: `CHANGELOG.md`, grouped by date under `[Unreleased]`, each entry citing its `REQ-###`
- `documentation_locations`: `.ai/project-context.md` (decision history), `CHANGELOG.md`, `README.md` (overview: capabilities, administration, versioning, licensing), `docs/` (granular reference, one file per category), `SETUP.md` (installation), `NOTICE.md` (third-party components), `docs/licensing.md` (licensing requirements)
- `branching_or_pr_standard`: main branch `main`; remote `github.com/paukennick/arbiter`; no PR template in-repo
- `comment_style`: minimal — comments only for non-obvious WHY, matching the existing `src/arbiter/` style
- `requirement_id_prefix`: `REQ` — active registry at
  `.ai/requirements/requirements.json`, retired entries at
  `.ai/requirements/archive.json`; assign the next free ID with
  `python omni requirement add`, which allocates across both files

## Project-Specific Notes (arbiter)

- `CLAUDE.md` is a thin routing shim to `.ai/entrypoints/claude.md`. Only
  Claude Code is used here, so the other assistant shims (`AGENTS.md`,
  `.cursorrules`, `LLM_CONTEXT.md`, Copilot, Kiro) are not installed.
- The OmniEngineering CLI is at the repo root: run `python omni doctor`,
  `python omni map` (regenerates `.ai/project-map.md`; safe here because the
  map is not hand-curated) and `python omni sync`.
- **`.mcp.json` registers Arbiter's own MCP server** (`arbiter mcp`, stdio,
  tools `arbiter_scan`, `arbiter_gate`, `arbiter_review_queue` — see
  `docs/mcp.md`). When those tools are available, call Arbiter through them
  instead of shelling out to the `arbiter` CLI — same `src/arbiter/service.py`
  underneath, no `Bash` permission prompt, and the result comes back as
  structured JSON rather than text to reparse. The CLI is still the right
  choice for anything the tool surface deliberately omits, chiefly
  `arbiter review --apply`: no MCP tool records a verdict (see `mcp.py`'s
  module docstring). `omni doctor` checks this registration by actually
  building the server (`validate_mcp_server`), not just reading `.mcp.json`,
  because the `mcp` SDK's own shape has moved under this project before.
- **Resolved `omni doctor` gap (REQ-028).** The scaffold was assembled from
  local STEP-Migration copies because no pristine OmniEngineering upstream is
  on this machine, and `.ai/adapters/*` (7 files), `.ai/checklists/public-
  release.md`, `.ai/rules/fallback-llm-rules.json` and
  `.ai/rules/hci-ui-rules.json` did not exist in any local copy — see
  `.ai/project-context.md` for the REQ-001 history. Rather than continuing to
  wait on an upstream that was never available, these were authored directly
  for arbiter on 2026-09-17 and wired into `.ai/context-manifest.json`'s
  `indexes`/`adapter_prompts`/`checklists` keys; they are arbiter-specific
  content, not upstream material, and should be reviewed as such rather than
  assumed to match whatever OmniEngineering upstream eventually ships.
  Doctor also FAILs on things deliberately not installed: the non-Claude
  pointer files (`LLM_CONTEXT.md`, `AGENTS.md`, `.cursorrules`,
  `.cursorignore`, `.github/copilot-instructions.md`,
  `.kiro/steering/omnicontext.md`) and the OmniEngineering legal files
  (`LICENSE`, `NOTICE`, `TRADEMARKS.md` — arbiter is proprietary and has its
  own `NOTICE.md`). Its root-placement WARNs about `src/`, `tests/` etc. are
  expected for an adopter repo. Any FAIL outside these lists is real drift.
- **CI.** Two workflows. `.github/workflows/pr-check.yml` runs on every pull
  request over a matrix of `ubuntu-latest` and `windows-latest` — the test
  suite with `-rs`, then `tools/integrity.py` — and finishes in about a
  minute. `.github/workflows/train.yml` runs the two-hour measurement cycle
  nightly on ubuntu only and commits its results back. The matrix is on the
  fast workflow deliberately (REQ-024); `fail-fast: false` so a Linux failure
  cannot cancel the Windows job. Neither is a *required* check: this repository
  has no rulesets and `main` is unprotected, so both are informative until that
  changes.
- **Headroom** is installed at local scope in `.claude/settings.local.json`
  (git-ignored): `ANTHROPIC_BASE_URL=http://127.0.0.1:8787` plus
  SessionStart/PreToolUse hooks that run `headroom init hook ensure` to keep
  the proxy up. The `headroom` MCP server (`headroom_retrieve`,
  `headroom_compress`, `headroom_stats`) is registered at user scope. To
  remove the integration: `headroom unwrap claude` or delete that file.
- Arbiter's own rules apply to work on it: coverage is reported, never
  assumed; the tool never executes the target; deterministic and inferred
  findings never blend. See `README.md` "Principles" (six, not four — the
  count grew when knowledge pinning and machine-checked invariants landed).
