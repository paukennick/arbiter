# OmniEngineering Context Brief

Use this file as the first low-token orientation layer. Do not read the entire
workspace by default.

## Default Loading Rule

For most tasks, load only:

1. `.ai/context-brief.md`
2. `.ai/project-context.md` — arbiter's decision history and open gaps
3. `.ai/project-configuration.md`
4. `.ai/project-map.md`
5. `.ai/requirements/requirements.json`

Then inspect only the project files named by the active requirement or prompt.
`README.md` "Layout" names the module responsible for each pipeline stage.

## Escalation Rule

Read more context only when the task needs it:

| Need | Read |
| --- | --- |
| Implementation scope and traceability | `.ai/rules/controlled-implementation.json` |
| Completion gate | `.ai/rules/completion-workflow.json` |
| Data contracts, validation, persistence | `.ai/rules/data-governance.json` |
| Module boundaries and interfaces | `.ai/rules/oop-design.json` |
| Full policy uncertainty | `.ai/rules/universal-engineering-ruleset.json` |
| A task-shaped procedure (debugging, review, release...) | `.ai/playbooks/` |
| Pre-implementation / pre-completion gates | `.ai/checklists/` |
| Engineering-discipline depth | `.ai/knowledge/swebok/README.md` |
| Probe, adapter or pack behavior | `README.md`, `src/arbiter/packs/` |
| Training and calibration workflow | `SETUP.md`, `tools/` |

## Token Rules

- Prefer `.ai/project-map.md` over broad directory traversal.
- Prefer the one relevant rulepack over all rulepacks.
- Never load `training/`, `arbiter-out/` or `fixtures/` wholesale; open the
  specific fixture a test names.
- Respect `.ai/.ignore`.
