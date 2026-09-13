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

## 2026-09-12 — Documentation, corpus figures, REQ lifecycle, licensing (REQ-002…005)

**Documentation (REQ-002).** `README.md` was 900 lines and was the only product
document. It is now an overview; granular material lives in `docs/`, one file
per category. Claims were re-verified against source rather than copied forward:
the dimension weights, severity and confidence factors, probe skip precedence,
fingerprint construction and CLI surface in the new docs all came from reading
`core.py`, `policy.py`, `engine.py` and `cli.py`. `SETUP.md` became an
installation guide — its previous first-person narrative, including a paragraph
retracting an earlier mistaken claim, was not repository documentation.

**Corpus figures (REQ-003).** The docs quoted three different corpus sizes. The
tooling is authoritative and self-consistent: `tools/corpus.py` and
`tools/fetch_corpus.sh` both describe 41 repositories — 16 vulnerable, 20 clean,
5 examples — with 5 held out (2/2/1), leaving 36 tuned. The old "39" was
14 tuned-vulnerable plus 20 and 5 *untuned* counts, which is why it never
reconciled. `--counts` now derives this offline so documentation cites a command
instead of a memory. The measured lines/findings table predates the two Go
repositories and is labelled rather than silently updated, because it cannot be
recomputed without cloning the corpus.

**Requirement lifecycle (REQ-004).** The registry appears in every context
profile in `.ai/context-manifest.json`, so every entry is a permanent
per-session cost — the STEP-Migration workspace this scaffold came from carries
80. Terminal requirements now sweep into `.ai/requirements/archive.json`, which
no profile loads. The subtle part is ID allocation: `next_requirement_id` read
only the active registry, so archiving alone would have silently reused retired
IDs and broken CHANGELOG references. It now scans both files, `omni doctor`
errors on collision, and archiving a non-terminal requirement is refused. The
three-digit ID format caps the project at 999, so reuse would corrupt history
rather than conserve anything.

Policy: a requirement is archived once it is `completed` or `withdrawn` **and**
its outcome is recorded in `CHANGELOG.md` and this file. Rationale lives here
permanently; the registry holds only live work. Not every change earns a REQ —
routine maintenance rides an existing one or is a CHANGELOG line.

**Licensing (REQ-005).** `pyproject.toml` declares `Proprietary` but there is no
`LICENSE` file and no copyright notice, so no terms are granted in writing;
`omni doctor` independently flags this. `docs/licensing.md` states eight
requirements (L-1…L-8) and the open questions that block drafting. Two points
are load-bearing: scan output must belong to the user, since reports are meant
for accreditation packages and PR comments; and `semgrep` is LGPL-2.1, so the
air-gapped bundle cannot ship until the redistribution review in L-6 is done.
Engineering cannot close this one — it needs counsel.

## 2026-09-12 — Adapter timeouts on Windows (REQ-006)

**What changed.** `Adapter._kill_group` delegates to a new `Adapter._kill_tree`
when `os.killpg` is absent; there it runs `taskkill /T /F /PID`, falling back to
`proc.kill()` if `taskkill` is unavailable or fails. The POSIX path keeps its
SIGTERM-then-SIGKILL group signalling unchanged, minus a branch that had become
unreachable.

**Why not the one-line fix.** The obvious repair is
`getattr(_signal, "SIGKILL", _signal.SIGTERM)`, and it is wrong. It clears the
`AttributeError` without delivering what the function promises: Windows has no
`os.setsid` or `os.killpg` either, so there is no group, and signalling the
direct child leaves its descendants running. Measured on this machine with the
same shape as the test — a shell that backgrounds a grandchild and sleeps —
`proc.kill()` let the grandchild run to completion and write its marker;
`taskkill /T /F` did not. The one-line version would have converted a crash
into a passing-looking kill that still orphaned the workers, which is the
original checkov failure wearing a different hat.

**Residual risk.** `taskkill /T` resolves the tree from the parent PID at kill
time, so a grandchild already orphaned by an intermediate process that exited
first is not reachable; a Windows Job object would close that, at the cost of
`ctypes` plumbing or a new dependency. Not worth it until something demonstrates
the gap. CI is `ubuntu-latest` only (`.github/workflows/train.yml`, single job,
no matrix), so this branch is exercised only by developers on Windows — which is
why a crash on every adapter timeout survived to be found by hand.

## 2026-09-12 — The bundle commits, recorded after the fact (REQ-007)

**What this is.** Six commits (`8775017`…`54f9a13`) were authored in a session
that could not push, travelled here as a git bundle, and were fast-forwarded
onto `main` and pushed. They changed probes, packs, gates, scoring and the CLI
surface, and none of them had a CHANGELOG entry or a section here. REQ-007 is
the recording, not the work; the work itself was unticketed.

**Written from the diffs, not the commit messages.** Those messages are long and
persuasive and were written by a session holding context this one does not, which
is the same reason REQ-002 re-verified its claims against source. Verified here
before being restated: the seven file-scoped probes and the conservative `repo`
default (`probes.py`, `authored.py`); CI-11's presence in `claims.INVARIANTS`
and its two reasoned exemptions; that `withheld`/`withheld_reason` are declared
fields on `Scorecard`, serialized, round-tripped and guarded by CI-3, so a
withheld grade is machine-checked rather than a rendering convention; the nine
token patterns and their severities; `exclude_native` handling in
`probe_resource_policy`; and the `(path, mtime_ns, size)` cache key.

**Relayed, not verified.** The performance and training figures those commits
cite — Traefik 59s → 6s, 158 findings against 158 on the files both scans read,
4401/4401 injection recall, 1653/1653 after the cache fix — cannot be reproduced
on this machine: the corpus is not cloned and there is no Traefik checkout. They
are recorded as that session's measurements and are not restated as fact in
`CHANGELOG.md`.

**Gap found while reading, not fixed.** `adapters.py:342` registers every
adapter-backed probe without a `scope`, so all five external analyzers (ruff,
bandit, checkov, semgrep, gitleaks) inherit the `repo` default and are recorded
as not-assessed in any partial scan. That is the right default — nothing has
established that those tools give subset-exact answers — but it means the
pull-request gate runs native probes only, and neither `docs/ci.md` nor
`RUNNING-ON-YOUR-OWN-CODE.md` says so. Worth either declaring the scope
deliberately per adapter or documenting the limitation; it should not stay
implicit in a default.

**Also outstanding.** `HANDOFF.md` tells a fresh session to expect `310 passed`.
That has never matched this machine, where the suite is 307 passed and 3 skipped
after REQ-006.

## 2026-09-12 — Two defects the first calibration queue exposed (REQ-008, REQ-009)

**How they were found.** Preparing the first adjudication queue meant scanning
Arbiter with itself. One rule, `drift.doc-references-missing-file`, produced 187
of the 230 unsuppressed findings — 81%. A rule that dominates a self-scan that
heavily is either the most important rule in the system or broken, and reading
the evidence settled it before any verdict was marked.

**Why it was worth stopping for (REQ-008).** `docs/calibration.md` states that
one finding moves the statistics once and re-adjudicating a fingerprint is
refused. Observations are therefore the one input in this system that cannot be
bought twice. Measured by scanning Arbiter with itself before and after the
change, with the output directory removed so that neither run could read the
other's: 187 findings before, 28 after, and **all 20** findings already queued
were in the vanishing set. Adjudicating that queue would
have spent a fifth of the rule's lifetime evidence recording, permanently, the
behaviour of a bug — and recorded it flatteringly, since a corrected rule would
never have emitted them. The fix is one line; the reason to make it first is
that the alternative is not reversible.

**The defect.** `lstrip("./")` strips a character set, not a prefix. Every path
beginning with a dot lost it, so `.ai/context-brief.md` was tested as
`ai/context-brief.md` and neither the exact nor the suffix membership test could
match. The sibling rule twenty lines above already used `_normalize_relative()`,
which resolves `.` and `..` segments properly and returns empty for a path that
escapes the repository root; the two rules now agree. Of the 28 survivors, 20
are real drift — including the `.ai/rules/fallback-llm-rules.json` and
`.ai/rules/hci-ui-rules.json` gap recorded under REQ-001, which the noise had
been burying. The remaining 8 name files under `.arbiter/` that exist on disk,
and are a different defect; see below.

**No margin.** 20 genuine findings against a `MIN_OBSERVATIONS` of 20 is exactly
the threshold and not one finding more. Repairing any of the drift the rule now
correctly reports removes queue material with it. If this rule is to be proven,
it must be adjudicated before its findings are fixed, or adjudicated against a
second repository.

**Two defects the verification turned up, neither fixed here.** Both were found
because the before/after numbers refused to reconcile, which is the argument for
insisting that they do.

*Arbiter scans its own output directory.* `arbiter-out/` is in `.gitignore`, but
nothing excludes it from a scan, and a scan reads the working tree rather than
the index. So the run read the previous run's `report.json` and `review-queue.md`:
40 of 109 unsuppressed findings — 37% — came from its own output. Two distinct
loops. `assurance.blanket-suppression` matched `# noqa` and `checkov:skip`
inside the evidence strings of the earlier report, inventing 23 findings. And
`drift.doc-references-missing-file` read the *old rule's mangled paths* out of
the old review queue and reported them as missing files, so the defect's output
became the next scan's input. Any tool that writes its output beneath the
directory it scans has this problem; the output directory is known at scan time
and should be excluded from the walk.

*`.arbiter/` is invisible to the inventory.* `.arbiter` is in `inventory.SKIP_DIRS`,
so `.arbiter/knowledge.json` and `.arbiter/external-severity.json` — both tracked
in git and present on disk — are not in `ctx.inventory.files`. Documentation that
names them is therefore reported as referring to missing files: 8 of the 28
surviving findings, and 6 of the 20 in the queue. The skip is defensible for
probes that would otherwise scan a 322 KB severity table as source, but
`doc_drift` resolves references against that same inventory and cannot tell
"absent" from "deliberately not walked". A file the tool wrote itself should not
read as documentation drift.

**A caution about measuring rules out of band.** The before/after figures above
were first estimated with a standalone script that applied the rule's predicate
to `git ls-files`. It disagreed with the real scan in both directions and its
numbers were wrong. Two reasons, both instructive: findings are deduplicated on
`Finding.id`, whose fingerprint includes `evidence` but deliberately not the line
number, so one path named eleven times in a file is one finding, not eleven; and
the scan resolves against the walked inventory, which `SKIP_DIRS` and
`MAX_FILE_BYTES` make narrower than the git index in some places and the
untracked working tree makes wider in others. Measure a rule by running the
scanner.

**Encoding (REQ-009).** Reading the generated queue back failed on byte `0x97`,
an em dash written as cp1252. Thirteen `write_text()` calls omitted `encoding=`,
so every text artifact took the console codepage. Precisely: the JSON writers
were never corrupt, because `json.dumps` escapes non-ASCII by default — the
damage was confined to the HTML, markdown, PR-comment and review-queue
renderings, which emit em dashes directly. The JSON calls were made explicit
anyway, so correctness stops depending on a default that could be changed by
passing `ensure_ascii=False` for readability. The matching reads are explicit
too, since an artifact that cannot be read back on another machine is not
evidence. Deliberately out of scope: `graph.py` and `review_ui.py` read files
belonging to the *scanned* repository with `errors="replace"`, which is a
different question — what to do about a target file that is not UTF-8 — and
should not be answered by a change aimed at Arbiter's own output. Also left
alone: the YAML and TOML configuration readers in `policy.py`, `controls.py`,
`ab.py` and `adapters.py`. TOML is specified as UTF-8, so `adapters.py:291`
reading a pack manifest through the platform default is a latent defect of the
same family, worth a separate look.

**Why this class of bug survives.** Both are Windows-only, and CI is
`ubuntu-latest` with no matrix — the same reason the REQ-006 timeout crash lived
as long as it did. Three platform defects have now been found by hand on this
machine. A Windows job in CI would have caught all three.

## 2026-09-12 — Licensing taken as far as engineering can take it (REQ-005)

**What changed.** `LICENSE`, `CONTRIBUTING.md`, a `license = { file = "LICENSE" }`
reference and an `authors` entry in `pyproject.toml`, and a README section that
cites the licence instead of apologising for its absence. L-2 and L-8 are closed;
L-1 is closed provisionally.

**Why an interim notice rather than waiting for the real one.** L-3 — the grant
itself — follows from two decisions counsel cannot make: who owns the copyright,
and whether the model is per-seat, per-repository or site. Until those are
answered, the best available instrument is one that asserts ownership and refuses
permission. That is a worse licence than none only if someone mistakes it for a
grant, which is why the file says three times that it is not one.

**The one clause drafted in full.** L-4, ownership of scan output, is stated
now rather than deferred, because it only gives rights away: it can be written
without knowing the commercial model, it cannot become more generous later, and
the product is unusable for its stated purpose — accreditation packages,
pull-request comments — if ownership of the output is ambiguous. It is marked as
intended to survive into the operative licence unchanged.

**A problem the git history creates.** All 33 commits are authored
`Claude Opus 5 <noreply@anthropic.com>`; no human appears anywhere in the record,
and `pyproject.toml` had no `authors` field. L-2 asks the owner to assert
copyright while the repository's own evidence attests that a model wrote it. The
ordinary position is that the person directing the work is the author and that
purely machine-generated material is not copyrightable at all, but the record
points the wrong way and should be raised with counsel alongside questions 1 and
2. Future commits should carry the owner as author with the model as
co-author, which is the accurate description of both.

## 2026-09-12 — MCP before a Python API (REQ-010)

**The decision.** Expose Arbiter as an MCP server that shells out to the
`arbiter` console script, ahead of stabilising a Python API.

**Why this order, having first argued the opposite.** The initial reasoning was
that an MCP server would import the package, so a designed API had to come first.
That dependency does not exist: the console script at `pyproject.toml:22` is
already a published surface documented in `docs/cli.md`, and shelling out to it
keeps the process isolation the scanner relies on. Meanwhile
`src/arbiter/__init__.py` exports only `__version__` and `run_scan` takes twelve
parameters, so stabilising the API first means freezing a surface before anything
has used it. Better to let observed MCP traffic shape it.

**Why not a hosted API.** Hosting requires customer source to leave the customer's
machine, which contradicts the `offline` and `ci` profiles that declare
`network: False`, and it is the one distribution scenario `docs/licensing.md`
marks as needing counsel — LGPL obligations differ again for network use. MCP
relocates the installation rather than removing it, which is worth saying out
loud, because "no local install" is what was asked for and MCP does not strictly
deliver it.

**The constraint that matters most.** No MCP tool may record an adjudication.
`arbiter review --apply` is deliberately outside the surface. The ledger's value
is that it is the one signal the system did not generate; an automated caller
marking verdicts would convert measured precision into the tool's opinion of
itself, at machine speed.
