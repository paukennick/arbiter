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
- **Known `omni doctor` gaps.** The scaffold was assembled from local
  STEP-Migration copies because no pristine OmniEngineering upstream is on
  this machine. These required files do not exist in any local copy and are
  expected to be reported missing until pulled from upstream:
  `.ai/adapters/*` (6 files), `.ai/checklists/public-release.md`,
  `.ai/rules/fallback-llm-rules.json`, `.ai/rules/hci-ui-rules.json`.
  Because `omni sync` verifies required files before writing root shims, it
  stops after regenerating `.ai/entrypoints/`; `CLAUDE.md` was written from
  `make_ai.ASSISTANT_POINTERS` so it matches the generated content.
  Doctor also FAILs on things deliberately not installed: the non-Claude
  pointer files (`LLM_CONTEXT.md`, `AGENTS.md`, `.cursorrules`,
  `.cursorignore`, `.github/copilot-instructions.md`,
  `.kiro/steering/omnicontext.md`) and the OmniEngineering legal files
  (`LICENSE`, `NOTICE`, `TRADEMARKS.md` — arbiter is proprietary and has its
  own `NOTICE.md`). Its root-placement WARNs about `src/`, `tests/` etc. are
  expected for an adopter repo. Any FAIL outside these lists is real drift.
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
