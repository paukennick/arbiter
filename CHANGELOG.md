# Changelog

All notable changes to Arbiter are recorded here. Entries are grouped by date
under `[Unreleased]` (there are no release tags yet) and reference the
`REQ-###` they serve. Rationale belongs in `.ai/project-context.md`.

## [Unreleased]

### 2026-09-12

- Restructured the documentation. `README.md` is now an overview — what Arbiter
  is, its capabilities, administration, versioning and licensing — and the
  granular material moved into `docs/` split by category: `architecture.md`,
  `cli.md`, `configuration.md`, `probes.md`, `systems.md`, `compliance.md`,
  `evidence.md`, `calibration.md`, `ab-testing.md` and `ci.md`. `SETUP.md` is
  now an installation guide; its training-operations content moved to
  `docs/ci.md`. (REQ-002)
- Settled the corpus composition figures. The docs quoted 42 repositories in one
  place and 39 in another, and the population table mixed a tuned-only count for
  the vulnerable population with full counts for the other two. `tools/corpus.py`
  is authoritative — 41 repositories, 5 held out, 36 tuned — and a new
  `--counts` flag recomputes that without the corpus cloned, so the numbers stop
  drifting. Stack gaps are now reported in both directions. (REQ-003)
- Bounded requirement registry growth. Completed and withdrawn requirements are
  swept into `.ai/requirements/archive.json`, which no context profile loads, by
  `python omni requirement archive`. IDs are allocated across both files and are
  never reused; `omni doctor` errors if they ever collide. The active registry is
  read into every session, so it is a working set, not a history. (REQ-004)
- Wrote up the licensing requirements in `docs/licensing.md`: eight requirements
  covering the operative grant, copyright ownership, ownership of scan output and
  the redistribution review that blocks the air-gapped bundle. `NOTICE.md` now
  records every third-party component and whether it is redistributed. The
  `LICENSE` file itself remains outstanding and needs counsel. (REQ-005)
- Made adapter timeouts stop the analyzer on Windows. `Adapter._kill_group`
  named `signal.SIGKILL`, which does not exist there, so every timeout raised
  `AttributeError` out of the cleanup path. Windows also has no `os.killpg`, so
  signalling the direct child alone left the fanned-out workers running — the
  exact failure the process-group path exists to prevent. Timeouts now fall back
  to `taskkill /T /F`, which walks the child tree from the parent PID. POSIX
  behaviour is unchanged. (REQ-006)

Six commits (`8775017`…`54f9a13`) landed from an offline bundle without
changelog entries. Recorded here after the fact, written from their diffs.
(REQ-007)

- Added incremental scanning. `arbiter scan|gate --changed REF` reads only the
  files that differ from a ref plus uncommitted work, and `--only-files` takes
  an explicit list; both run through the new `src/arbiter/incremental.py`.
  Every probe now declares a `scope`. Seven are file-scoped — `secrets`,
  `resource_policy`, `ast_metrics`, `supply_chain`, `house_rules`,
  `house_rules_ast` and `authored` — and everything else keeps the conservative
  `repo` default and is recorded as not-assessed, with the partial scan named
  as the reason, rather than being run against a subset it cannot answer from.
  Selection always retains dependency manifests, lockfiles, CI workflows and
  Terraform, because those are the files a probe reasons about but does not
  report on. (REQ-007)
- Made a partial scan unable to describe the repository. Reports carry
  `scan_scope`; a partial one contributes an abstention naming the unread
  files, which flows into the gate claim, the grade and every dimension. The
  overall grade is withheld outright, "probe ran and found nothing" narrows to
  "found nothing in the files it was given", and finding density is measured
  against lines read rather than repository size. Invariant **CI-11** — a
  partial scan may make no complete-scope claim about the repository — is
  machine-checked alongside the other ten, with the coverage measurement and a
  failing gate as the two reasoned exceptions. A ref that does not resolve
  refuses the scan instead of quietly reading nothing. (REQ-007)
- Added nine provider-issued token rules: Stripe, OpenAI, Anthropic, Google,
  GitLab, npm, SendGrid and PyPI at critical, Slack incoming webhooks at high.
  The issuer assigns these prefixes, so the value is its own evidence and the
  symbol name is irrelevant — which is why `STRIPE_KEY = "sk_live_…"` passed
  the name-based heuristic untouched. Six patterns terminate in an explicit
  lookahead rather than `\b`, because the charset is base64url and a token
  ending in `-` has no word boundary after it. The injection harness gained
  matching positive and control generators, the controls covering test-mode
  keys, wrong lengths, placeholders, interpolations and `sk-` used as a slug.
  (REQ-007)
- Shipped the pull-request gate as a worked example: `examples/pull-request-gate/`
  holds a two-job workflow and its config, `RUNNING-ON-YOUR-OWN-CODE.md` walks
  through a first scan, a baseline, adjudication and then the gate, and
  `docs/ci.md` gained "Scanning only what changed" and "A ready-made workflow".
  Only the nightly full-scan job may refresh the baseline; refreshing it from a
  partial scan would forgive every finding in the files that scan did not read.
  (REQ-007)
- Tagged findings a change did not cause. In a partial scan, findings landing
  in a context file the diff never touched are tagged `outside-this-change` and
  counted on the console. They stay in the report — the baseline, not deletion,
  is what keeps them out of the gate. (REQ-007)
- Added three provider-neutral TLS rules: `database-allows-plaintext-connections`,
  `weak-tls-version` and `no-https-redirect`. Resource rules also gained
  `exclude_native` beside `exclude_providers`, because a control can be
  expressible on one resource of a provider and absent on another — Azure SQL
  enforces TLS with no property saying so, and a provider-wide exclusion is too
  coarse to express that. `aws_elb`/`aws_alb`, Azure app services and GCP HTTP
  proxies and App Engine versions are normalized into the resource graph so the
  new rules have something to match. (REQ-007)
- Fixed a read cache that could serve one file's bytes for another. `_READ_CACHE`
  keyed on path alone and depended on every caller clearing it between scans;
  the injection harness invokes probes directly and writes every generated case
  to the same path, so it was served stale text. The key is now
  `(path, st_mtime_ns, st_size)` with a bounded size, so the cache cannot be
  wrong regardless of who calls it. (REQ-007)
- Taught `tools/corpus.py` to weight what it counts. Per-repository output now
  carries severity-and-confidence weighted totals, weight by language and lines
  by language, and the held-out comparison is made per KLOC of the language the
  rules actually fire on rather than per repository line counted flat. (REQ-007)
- Restored the shebang and executable bits on the four `tools/*.sh` scripts; an
  earlier commit had indented `#!/usr/bin/env bash` by two spaces, which stops
  the kernel recognising the file as a script whatever the mode bit says.
  Added `HANDOFF.md`, a cold-read briefing for a session arriving without the
  history. (REQ-007)

- Adopted the OmniEngineering workspace: `.ai/` source-of-truth scaffold
  (rules, schemas, playbooks, checklists, SWEBOK knowledge pack), the
  repo-local `./omni` CLI (`make_ai.py`), a `CLAUDE.md` routing shim, and a
  requirements registry. (REQ-001)
- Installed Headroom for Claude Code at local scope: `.claude/settings.local.json`
  routes traffic through the Headroom proxy (`127.0.0.1:8787`) and registers
  its session hooks. The file is machine-specific and git-ignored. (REQ-001)
