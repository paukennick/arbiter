# Changelog

All notable changes to Arbiter are recorded here. Entries are grouped by date
under `[Unreleased]` (there are no release tags yet) and reference the
`REQ-###` they serve. Rationale belongs in `.ai/project-context.md`.

## [Unreleased]

### 2026-09-12

- Adopted the OmniEngineering workspace: `.ai/` source-of-truth scaffold
  (rules, schemas, playbooks, checklists, SWEBOK knowledge pack), the
  repo-local `./omni` CLI (`make_ai.py`), a `CLAUDE.md` routing shim, and a
  requirements registry. (REQ-001)
- Installed Headroom for Claude Code at local scope: `.claude/settings.local.json`
  routes traffic through the Headroom proxy (`127.0.0.1:8787`) and registers
  its session hooks. The file is machine-specific and git-ignored. (REQ-001)
