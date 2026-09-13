# Changelog

All notable changes to Arbiter are recorded here. Entries are grouped by date
under `[Unreleased]` (there are no release tags yet) and reference the
`REQ-###` they serve. Rationale belongs in `.ai/project-context.md`.

## [Unreleased]

### 2026-09-13

- Fixed the nightly training job, which had never once written its results back.
  `git add -A .arbiter training` matched `.gitignore`'s `training/`, git exited 1,
  and the step's `bash -e` failed the job two seconds after a 55-minute cycle
  finished successfully — so run 1 measured everything and committed nothing.
  `training/` now ignores its contents rather than itself, and the three files
  that accumulate (`WORKLIST.md`, `fix-pairs.json`, `disagreements.json`) are
  tracked while the per-run stamped logs stay out. (No requirement covers the
  nightly training job — the four entries below are unplanned repair, and the
  gap is itself worth a requirement.)
- Fixed the same job silently degrading the handoff it exists to produce. Its
  final step read `/tmp/corpus-out/summary.json` and `/tmp/discriminate.json`,
  which nothing writes, so every night it overwrote the complete `WORKLIST.md`
  that `train_cycle.sh` had just written with one headed "Incomplete: no results
  found for corpus, discrimination". It now reads the newest stamped files under
  `training/`, and still runs on failure so a cycle that dies early leaves a
  handoff from what did finish.
- Clone the practice repositories 300 commits deep instead of 1, and deepen the
  ones already on disk. `fixpairs.py` skips a shallow clone, so fix-pair mining
  had been reporting "0 candidate fix pairs from 41 repositories in 0s" — every
  repository skipped, every night. Those pairs are the only ground truth in the
  system Arbiter did not generate itself, so the cost in clone size is worth
  paying. `train_cycle.sh` now runs `fetch_corpus.sh` every cycle rather than
  only when the corpus is missing, because that is what catches up a cached
  clone; the script is idempotent and records the depth it reached.
- Restored `.arbiter/knowledge.json` from the artifact of the failed run: 27
  rules with measurements where the committed copy had 15, 55,075 planted faults
  against 44,000, and the 12 additional rules all previously unmeasured. Human
  adjudications are 0 in both copies, so nothing a person decided was touched.
  `training/disagreements.json` came back with it — 317 contested findings where
  exactly one of two analyzers is wrong.

### 2026-09-12

- Built the hosted API over that service layer, in `src/arbiter/api.py`. Access
  is distributed by hand: `arbiter api key add --user "..."` mints one key for
  one user, prints it once and stores only its SHA-256 hash, so the key file is
  not a credential store; `key list` and `key revoke` complete the set. A key is
  scoped to a user and nothing else, and one user holds at most one live key —
  minting over a live key is refused unless `--replace` is passed, which revokes
  the old one in the same command, so a shared or half-rotated key cannot arise
  quietly. `POST /v1/scan`, `/v1/gate` and `/v1/review-queue` take an uploaded
  archive — never a repository credential — and `GET /v1/health` needs no key.
  Nothing is retained: the workspace is deleted when the request ends and server
  paths are withheld from responses. Uploads are capped at 100 MB and refused
  before extraction. FastAPI and uvicorn are an optional extra imported only
  inside `create_app`, so a plain install still depends on PyYAML alone.
  `arbiter mcp` now runs the MCP server. (REQ-018)
- Raised the per-key request limit from 30 an hour to 120, and published every
  limit on `GET /v1/health` alongside `"free": true`. Nobody is charged and the
  service is for people testing it, so a limit anybody can feel during normal
  use is a restriction dressed up as capacity. The concurrency caps are
  unchanged, because those are what decide whether the machine stays up.
  Reworded the access and terms documents to say plainly that it is free, that
  there is nothing to apply for, and that nobody is asked what they intend to
  scan; issuing keys by hand is how access works in the absence of an identity
  system, not a vetting step. (REQ-018)
- Added the pilot deployment in `deploy/`: a Dockerfile that installs Arbiter
  with the `api` and `tools` extras into a virtualenv and copies it into a clean
  image running as uid 10001, a `compose.yaml` pairing it with Caddy, and a
  `Caddyfile` carrying the hostname, the ACME contact and a 110 MB body limit.
  Arbiter shares Caddy's network namespace so that "bound to loopback" is
  literally true rather than approximately true, which is what makes believing
  `X-Forwarded-Proto` safe and is also the only way uvicorn accepts forwarded
  headers. The container is read-only, capability-free, `no-new-privileges`, and
  capped at 3 GB, 2 CPUs and 512 processes, because the analyzers parse
  attacker-chosen files even though nothing from an upload is executed. The
  image must stay private: running semgrep conveys no copy, but publishing the
  image would. (REQ-018, REQ-005)
- Capped concurrent scans for the whole server at 4, not just 2 per key, since
  the per-key limit multiplies by the number of testers and five of them at once
  would be ten analyzer runs on one machine. A caller over their own share is
  told that rather than told the service is busy. (REQ-018)
- Added a request log: one JSON line per request to `~/.arbiter/audit.log`
  (`--audit`, `ARBITER_AUDIT`, or `--no-audit` to keep nothing), holding the key
  id, the user, the operation, the status, the bytes uploaded and the elapsed
  time — and nothing about the code, because a log that quoted findings would
  rebuild on disk what the request path deletes. Failures and refused keys are
  logged too, the latter without writing the rejected key down. A log write that
  fails complains on stderr rather than failing the scan. (REQ-018)
- Documented how to run the pilot in `docs/pilot-runbook.md` — container with a
  memory limit, TLS-terminating proxy with a body limit, one key per tester,
  what to read in the log — and what to tell a tester about their code in
  `docs/pilot-terms.md`, which is a draft pending counsel. (REQ-018, REQ-005)
- Made TLS mandatory on the hosted API, with no plaintext mode. Requests carry
  an API key and a copy of somebody's source, so `serve` refuses to start
  without either `--cert`/`--key` or `--behind-proxy`, and refuses individual
  plaintext requests with `426 Upgrade Required`. `--behind-proxy` binds to
  loopback only, because `X-Forwarded-Proto` is a header any client can invent
  and believing it on a public interface would let anyone call their own
  plaintext request secure; without the flag the header is ignored. Direct TLS
  offers forward-secret AEAD ciphers only, which leaves nothing a TLS 1.0 or 1.1
  client can negotiate — a hard version floor is not assertable from here,
  because uvicorn builds its own SSL context, so it comes from the platform
  policy or from a terminating proxy. Every response carries a two-year
  `Strict-Transport-Security` header, and the default port is now 8443.
  (REQ-018)
- Made an API key a limited grant rather than a permanent one, before any key is
  handed out. Keys now expire after 90 days by default (`--expires-days`, or
  `--no-expiry` for a deliberate permanent one), a single key is capped at 30
  requests an hour and 2 concurrent scans, and exceeding either returns `429`
  with `Retry-After`. Limits are per key, so one recipient cannot exhaust
  another's. Expired, revoked and unknown keys share one `401` message, because
  distinguishing them would confirm that a guessed key had once existed. The
  counts live in one process's memory, which bounds this to a single-machine
  deployment — recorded in `docs/hosted-api.md` rather than implied. (REQ-018)
- Began the move to a hosted API, reversing the decision to expose Arbiter only
  over MCP. MCP relocates the installation rather than removing it, and "no
  local install" was the requirement. Both surfaces now call one
  transport-neutral service layer, `src/arbiter/service.py`, which owns the
  containment: workspaces created outside the server tree with `source/` and
  `output/` as siblings and removed when the scan ends; uploaded archives
  refused whole if any member is absolute, traverses upward, is a link or a
  device node, or breaches the size and count bounds; `connected` and `audit`
  refused unless an operator explicitly allows the network; and no operation
  that records an adjudication verdict, asserted by test rather than convention.
  `docs/hosted-api.md` holds the design; the HTTP surface is not built and the
  framework is deliberately unchosen. The licensing objection recorded against
  hosting was wrong and is corrected in `docs/licensing.md` — LGPL-2.1
  obligations attach to conveying a copy, so L-6 does not gate a hosted service.
  (REQ-018, REQ-010)
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
- Fixed the drift rule that reports a file named in prose as missing. It
  normalized the path with `lstrip("./")`, which strips a character set rather
  than a prefix, so `` `.ai/context-brief.md` `` collapsed to
  `ai/context-brief.md` and matched nothing on disk — every dotted path in the
  repository read as missing. It now uses `_normalize_relative()`, the helper
  the sibling link rule already used, and skips paths that escape the
  repository root. Measured by scanning Arbiter with itself before and after,
  the rule goes from 187 findings to 28. (REQ-008)
- Made Arbiter write and read its own artifacts as UTF-8 rather than the
  platform default. Thirteen `write_text()` calls omitted `encoding=`, so on
  Windows the HTML, markdown, PR-comment and review-queue renderings were
  written in the console codepage; a generated `review-queue.md` here was
  undecodable as UTF-8. Reports are meant to travel into accreditation packages
  and pull requests, so they cross machines. Files belonging to the scanned
  repository are untouched — those are decoded with `errors="replace"` by
  design. (REQ-009)
- Put the licensing position in writing as far as it can go without counsel.
  `LICENSE` now exists, asserting copyright to Nicholas J Pauken, reserving all
  rights, assigning ownership of scan output to the user, and disclaiming any
  grant over the adapted third-party analyzers. It says plainly that it is an
  interim notice and not the operative grant. `pyproject.toml` references it by
  file rather than declaring the bare string `Proprietary`, and names the
  author. `CONTRIBUTING.md` states that external contributions are not
  accepted, which L-8 requires be settled before a patch is taken rather than
  after. This closes L-2 and L-8, and L-1 provisionally; REQ-005 stays open
  because L-3 follows from decisions only the owner can make and the L-6
  redistribution review is untouched. (REQ-005)
- Stopped a scan from reading its own output. `--out` defaults to
  `arbiter-out`, a relative path inside the tree being scanned, and the walk
  knew nothing about it, so every run after the first reported on the previous
  run's rendering. Measured here: 28 of 101 unsuppressed findings were located
  inside `arbiter-out` — 27.7% — and 24 of those were
  `assurance.blanket-suppression`, the rule that was about to be adjudicated,
  inflated by a report that is naturally full of the term it searches for.
  `run_scan` now takes `out_dir` and `walk_repo` skips it. Two consecutive
  scans into the default path produce identical findings, none of them inside
  the output directory. (REQ-011)
- Read files belonging to the scanned repository as UTF-8. Nine call sites used
  `read_text(errors="replace")` with no encoding, so the codec was the platform
  default — cp1252 on Windows. `errors=` governs what happens on failure, and
  cp1252 decodes almost every byte without failing, so it never errored, it
  silently produced wrong characters: an em dash in a scanned file reached a
  generated review queue as `â€”`. REQ-009 fixed Arbiter's own artifacts and
  deliberately excluded these sites, reasoning that `errors="replace"` was the
  design intent. That reasoning was wrong — the intent is never crashing on a
  target file, which `encoding="utf-8"` preserves. (REQ-012)
- Checked documented paths against disk rather than only against the walked
  inventory. Directories in `SKIP_DIRS` never enter the inventory, so tracked
  files under `.arbiter` read as missing: 8 of 31 doc-drift findings here.
  Whether a documented file exists is a question about disk, not about what the
  probes were shown. The sibling broken-link rule had the identical defect
  fifteen lines away and got the same fix. `.arbiter/baseline.json` still
  reports, correctly — it is documented but genuinely absent. The other 22
  findings are untouched, and `omni doctor` independently confirms them.
  (REQ-013)
- Gave doc-drift findings a repository in their `Location`. `Location.short()`
  builds its `repo:path` prefix from the Location rather than the Finding, and
  `doc_drift` set the id on the Finding only, so all 330 drift findings in a
  36-repository corpus scan rendered as bare paths. Two of those repositories
  each contain a python/ tree, so a line naming a README under it identified no
  repository a reader could open. (Those paths are deliberately not backticked:
  they belong to another repository, and backticking them here manufactures the
  very drift finding this entry is about.)
  (REQ-014)
- Made the review queue name the repository for every probe, not just for
  doc-drift. The same defect ran wider than one probe: 3,227 of 3,564 findings
  in that scan carried a blank `Location.repo_id` — `supply_chain` 0 of 1,817,
  `secrets` 0 of 377, `resource_policy` 7 of 1,040 — while `assurance` sets it
  at every construction site. The `Finding` carries the id in all 3,564 cases,
  so `review.where()` qualifies the path from there and both the markdown and
  HTML front ends use it, rather than adjudication waiting on some twenty
  construction sites across eight probes, several of them repo-level or
  cross-repo and needing judgement rather than a mechanical pass. Those sites
  are still wrong, so SARIF, HTML and console output remain unqualified.
  (REQ-015)
- Named the repository at every probe construction site, closing the residual
  risk REQ-015 recorded rather than fixed. Eighteen of the twenty sites took the
  id already in scope on the enclosing finding. Two did not, and they are why
  the renderer went first. The `interface` rule for unused IAM grants collected
  service names into a set and discarded where each grant was written, so it
  could cite only a synthetic `iam:` string and attributed the finding to the
  alphabetically first infrastructure repository — the wrong one whenever the
  grant was not in it; it now keeps the grant's location the way the
  neighbouring collections already did. The two `house_rules` path rules matched
  against every path in the scan flattened into one set, which left them the
  only sites in the tree setting no repository on the finding at all, and let
  one repository's LICENSE answer the rule for every repository; both now ask
  per repository. Re-measured on the same 36-repository corpus: 3,564 findings
  before and after, of which 3,227 were unattributed before and none after, and
  no finding changed repository. (REQ-016)
- Made the review sampler spread across repositories, not only across files.
  Within a rule it ordered findings so that distinct files came first, which one
  repository satisfies on its own: of six queues drawn from the 36-repository
  corpus, `resource.k8s-no-security-context` took 19 of 20 from a single
  repository and all 20 from teaching material, which the corpus tooling states
  is useless as a false-positive measure. Twenty findings from one repository
  are largely one author, one generator and one set of conventions, so they
  answer whether the rule is right about that repository while the ledger
  records the answer as though it were about the rule. Selection now
  round-robins across repositories and keeps file spread as the secondary axis
  inside each. Re-measured on the same corpus: average distinct repositories per
  queue 6.0 to 12.2, largest single-repository share 64.2% to 30.0%, and the
  k8s-no-security-context queue from one population to all three. Population is
  deliberately not an input — that label lives in the corpus tooling, and a
  library that ranks findings must not import the test harness — so repository
  spread is the proxy. Spread also cannot exceed the pool:
  `resource.unencrypted-database` still draws 18 of 20 from terragoat, because
  only three repositories in the corpus produce that finding at all. (REQ-017)

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
