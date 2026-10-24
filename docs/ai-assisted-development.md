# AI-assisted development

Arbiter is developed with substantial help from AI coding assistants, mainly
Anthropic's Claude models running in Claude Code. This page says what that
means in practice, how the work is checked, and what the project asks of
contributors who use AI tools.

## How Arbiter is built

- **Much of the code and documentation was written with AI assistance.** The
  owner, Nicholas J Pauken, sets the direction, decides what is built,
  reviews the result and commits it. Claude drafts most of the code, tests
  and prose.
- **The record shows it.** Of the 389 commits on `main` at `33e7e5a`
  (2026-10-23), 266 carry a `Co-Authored-By: Claude ...` trailer and 61 more
  are authored by Claude directly; 41 are written by the nightly training job
  (`arbiter-training`). The practice since 2026-09 has been for commits to be
  authored by the owner with the model named as co-author
  ([.ai/project-context.md](../.ai/project-context.md), 2026-09-12).
- **AI-generated test material is labelled.** The services under
  `fixtures/ai-corpus/` and `fixtures/ai-corpus-heldout/` were written by
  Claude models on purpose, as a corpus of AI-written code to measure Arbiter
  against; each app's model, prompt and date are recorded in that directory's
  `manifest.json`. The model labels under `tools/gold/labels/` were produced
  by Claude models acting as labellers and are marked with the labeller and
  prompt version in every record ([docs/precision.md](precision.md)).

## How the work is checked

AI-written changes go through the same checks as any other, and the checks
are designed not to take the model's word for anything:

- **Human review.** The owner reviews each change before committing or
  merging it; that is the project's stated practice, not something a tool
  enforces.
- **Tests.** The test suite (`python -m pytest -q`; the fast tier runs on
  every pull request) includes golden-fixture tests that fail when a rule
  stops catching a planted defect, property-based tests and mutation checks
  (`tools/mutate_tests.py`).
- **The completion gate.** `./omni gate` (OmniEngineering) checks that a
  change touching code has a requirement, a changelog entry and passing
  tests, and runs `arbiter gate --changed` so Arbiter scans its own change.
  Continuous integration (`.github/workflows/pr-check.yml`) runs it on every
  pull request, and `.githooks/pre-commit` runs it before each commit for
  anyone who enables the hooks.
- **Recorded defects.** Defects that reached `main` are recorded with root
  cause and regression test in `.ai/failures/failure-ledger.json`.
- **Independent measurement.** Precision figures are measured against
  labelled corpora with held-out sets, and model labellers are calibrated
  blind against ground truth before their labels are counted
  ([docs/precision.md](precision.md)).

None of this makes AI-written code correct by construction. It is the same
standard of evidence the project would ask of any author.

## If you contribute with AI tools

You may. The rules are the ones in [CONTRIBUTING.md](../CONTRIBUTING.md),
applied plainly:

1. **You are responsible for the contribution.** Signing off under the
   [Developer Certificate of Origin](../DCO) means you certify you have the
   right to submit it under Apache-2.0. That applies to AI-generated output
   too: check that the tool's terms let you contribute its output under an
   open-source licence, and do not submit output that reproduces code you
   cannot license (for example from a GPL project).
2. **Read, understand and test it.** Do not submit code you have not reviewed
   yourself. A pull request should pass the tests and `./omni gate` before you
   open it.
3. **Say so.** Name the tools you used in the pull request, and add a
   `Co-Authored-By:` trailer for the assistant if you like; it is the
   project's own practice.
4. **Do not let an assistant adjudicate.** Calibration verdicts
   (`arbiter feedback`, `arbiter review --apply`) must come from a person who
   looked at the finding. `arbiter feedback` and `arbiter review --interactive`
   refuse to record a verdict when stdin is not a terminal, and the batch paths
   record that they were batch imports
   ([docs/calibration.md](calibration.md#adjudicating-needs-a-terminal)).

## Open question for counsel

Whether, and how far, AI-assisted material is protected by copyright varies
by jurisdiction and is unsettled. The project's position is that the owner
directs, selects, reviews and arranges the work and is its author; that
position has not been reviewed by counsel ([licensing.md](licensing.md)).
