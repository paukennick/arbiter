# Data handling

What Arbiter reads, what it sends anywhere, what it writes to disk, and what
it keeps. Every statement here was checked against the code on 2026-10-23
(the module or function is named so you can check it again); where something
depends on a third-party tool rather than on Arbiter, that is said too.

The short version is in [PRIVACY.md](../PRIVACY.md). This file is the long
one.

## Contents

- [Summary](#summary)
- [What runs locally](#what-runs-locally)
- [What can leave your machine](#what-can-leave-your-machine)
- [Profiles and what each allows](#profiles-and-what-each-allows)
- [Exactly what is sent to a model](#exactly-what-is-sent-to-a-model)
- [Redaction, and its limits](#redaction-and-its-limits)
- [Telemetry](#telemetry)
- [Third-party analyzers](#third-party-analyzers)
- [What is written to disk](#what-is-written-to-disk)
- [Personal data](#personal-data)
- [The hosted API and HTTPS MCP server](#the-hosted-api-and-https-mcp-server)
- [Retention and deletion](#retention-and-deletion)
- [Known gaps](#known-gaps)

## Summary

- Arbiter is a command-line tool and library that runs on your machine. It
  reads files; it never executes the code it scans.
- Arbiter's own code has **no telemetry**. It sends nothing to the Arbiter
  project or its copyright holder.
- Under the default `offline` profile, and under `ci`, Arbiter's own code makes
  no model call and no registry lookup. Three things can still reach the
  network under those profiles, and none of them sends your source code:
  cloning a target you gave as a URL, a tree-sitter grammar download, and
  start-up requests made by two of the third-party analyzers (semgrep and
  checkov). See [Known gaps](#known-gaps).
- `assisted`, `connected` and `audit` can send **masked excerpts of your code
  to Anthropic's API** (`api.anthropic.com`), and only when an Anthropic API key
  is in the environment. `connected` and `audit` also send **package names**
  to PyPI and the npm registry.
- Reports, caches, baselines and calibration ledgers are written to your disk,
  in the places listed below. Arbiter deletes none of them; they are yours to
  keep or remove.

## What runs locally

Everything a scan does runs as local processes on your machine:

- **Inventory.** `inventory.walk_repo` walks the target, skipping the
  directory names in `inventory.SKIP_DIRS` (`.git`, `node_modules`, `.venv`,
  `.arbiter` and others) and files git reports as ignored
  (`inventory._gitignored`, which runs `git ls-files --others --ignored`).
- **Native probes** (`probes.py`, `lang_rules.py`, `dataflow.py`,
  `authored.py`, `assurance.py` and the rest) read file contents in memory.
- **Git.** Arbiter runs local `git` commands (`rev-parse`, `ls-files`, `log`,
  `config --get`) through `subprocess`. None of them contacts a remote.
- **External analyzers** (ruff, bandit, semgrep, checkov, gitleaks), when
  installed, run as separate local processes (`adapters.Adapter`). Their own
  network behaviour is covered under
  [Third-party analyzers](#third-party-analyzers).

The scanned code is never built, installed, imported or run (design rule 3 in
the [README](../README.md#principles)).

## What can leave your machine

This is the complete list of network paths in Arbiter's own package
(`src/arbiter/`), found by searching it for every HTTP client and subprocess
call. Paths in `tools/` are developer tooling for this repository and are not
part of the installed package; they are listed separately at the end.

| Path | Destination | What is sent | When | Code |
|---|---|---|---|---|
| Model verification pass | `https://api.anthropic.com/v1/messages` | one finding at a time: rule text and a bounded, masked excerpt (details below) | profile allows a model, the pass is on, and the API key is set | `verify.VerifyProvider.ask`, gated by `verify.wanted` |
| Judgement probe | `https://api.anthropic.com/v1/messages` | the first 6,000 characters of up to 24 files, masked, each labelled with its path | `connected` or `audit`, and the API key is set | `judgement.probe_judgement`, `AnthropicProvider.complete` |
| Package existence check | `https://pypi.org/pypi/<name>/json`, `https://registry.npmjs.org/<name>` | the name of an imported package no manifest declares (a `GET` with `User-Agent: arbiter`) | `connected` or `audit` only | `authored.package_exists`, gated in `authored.probe_authored` |
| Remote target | the git host in the URL | a normal `git clone --depth 1` | whenever a scan target, or a `source` in a system manifest, is an `http(s)://`, `ssh://` or `git@` URL, **under any profile** | `inventory.acquire_one` |
| `arbiter remote` | the server you name | a gzip tar of the target directory (see [Known gaps](#known-gaps)) and your Arbiter API key | only when you run `arbiter remote ...` | `client.build_archive`, `client._upload` |
| `arbiter bundle build` | your Python package index | `pip download` / `pip wheel` requests for Arbiter's dependencies | only when you build a bundle | `bundle.py` |

`arbiter api serve` and `arbiter mcp serve` open listening sockets; they
accept requests and do not originate any beyond the paths above.

Developer tooling in this repository (not installed with the package):
`tools/fetch_corpus.sh` and `tools/ground_truth/fetch_gt.sh` clone or download
public corpora; `tools/install_tools.sh` downloads the analyzers, a pinned
semgrep ruleset and tree-sitter grammars; `tools/label_models.py` and
`tools/verify_eval.py` send masked excerpts of corpus code to Claude.

## Profiles and what each allows

A profile is a capability budget (`policy.PROFILES`). The engine refuses to
run a probe that needs a capability the profile does not grant and records it
as *not assessed* (`engine.py`, the `probe.network` and `probe.model` checks).

| Profile | `network` | `model` | Model verification by default | Judgement probe | Registry lookups |
|---|:-:|:-:|---|:-:|:-:|
| `offline` (default) | no | no | never | no | no |
| `ci` | no | no | never | no | no |
| `assisted` | no | **yes** | **on** | no | no |
| `connected` | yes | yes | off unless `verify.enabled: true` or `--model-verify` | yes | yes |
| `audit` | yes | yes | off unless `verify.enabled: true` or `--model-verify` | yes | yes |

Two details matter:

- `assisted` declares `network: False`, but its model call does travel over
  the network to Anthropic. `network: False` there means "no probe or adapter
  fetches"; it does not mean nothing leaves the machine.
- A profile that forbids a model wins over everything:
  `verify.wanted` returns `False` for `offline` and `ci` even when
  `--model-verify` is passed.

**Credentials.** Both model paths read the API key from the environment
variable `ANTHROPIC_API_KEY`; `verify.api_key_env` or `judgement.api_key_env`
in `arbiter.yaml` names a different variable. The key is sent only to
`api.anthropic.com`, in the `x-api-key` header. Without it the pass records
every candidate as `not_verified` and the judgement probe is recorded as not
assessed (`judgement.Unavailable`); neither is silently skipped.

## Exactly what is sent to a model

### Model verification (`verify.py`)

**Which findings.** `verify.candidates` selects findings that are not
suppressed, not `inferred`, at or above `verify.min_severity` (default
`medium`) and whose rule is not in `verify.skip_rules`. At most
`verify.max_findings` (default 150) are sent, within an estimated
`verify.max_tokens` budget (default 400,000).

**One request per finding**, containing (`verify.build_prompt`,
`verify.rule_text`):

- the rule id, title, severity, CWE, description and remediation;
- "known false-positive patterns" for the rule, read from
  `tools/gold/precision.json` when it exists next to the package (a source
  checkout), otherwise "(none recorded)";
- the finding's repository-relative path and line number;
- an excerpt built by `context.build`: the enclosing function (at most
  `verify.excerpt_lines`, default 120 lines, or a 30-line window each side of
  the line when no function encloses it), up to 30 import lines, the class
  header (4 lines), up to 3 same-file helper functions (40 lines each), up to
  3 definitions from other files in the same repository (30 lines each, each
  labelled with its repository-relative path), and up to 2 same-file callers
  (25 lines each). The whole excerpt is capped at
  max(220, `excerpt_lines` + 100) lines, and every line is cut at 240
  characters.

**What comes back** is a verdict (`confirmed`, `rejected` or `unsure`), a
reason of at most 400 characters and an optional line number. It is recorded
on the finding as `verification` in the report, and the verdict is cached in
`<target>/.arbiter/verify-cache.json` (keyed by a SHA-256 of the
finding id, excerpt, model, prompt version and rule text; the excerpt itself
is not cached).

**Model and settings.** `verify.model` (default `claude-opus-5-5`),
`verify.effort` (default `medium`), `verify.max_output_tokens` (default 4,000).

### Judgement probe (`judgement.py`)

Runs only under `connected` and `audit`. `judgement._select_files` picks up to
12 documentation files and up to 12 code, configuration or IaC files (24 in
all), takes the **first 6,000 characters** of each, masks them, and stops at
90,000 characters in total. One request per repository sends them all,
each preceded by `=== <repository-relative path> ===`. The default model is
`claude-sonnet-4-5` (`judgement.DEFAULT_MODEL`; `judgement.model` overrides
it). Findings it returns are marked `provenance: inferred` and do not gate
unless `gate.gate_inferred` is set.

### Who receives it

Anthropic, PBC, through its public API, under the terms of the account whose
key you supplied. Arbiter does not set any data-retention or training option
on the request; what Anthropic does with API inputs is governed by your
agreement with Anthropic, not by Arbiter. Read those terms before enabling a
model-backed profile on code you are not free to share.

## Redaction, and its limits

Before anything is sent to a model, `judgement._mask_secrets` replaces:

- complete PEM private-key blocks (header through footer);
- AWS access key IDs (the `AKIA` and `ASIA` prefixes);
- GitHub tokens (`gh` + one of `p o u s r` + `_`) and Slack tokens (`xox`
  prefixes);
- the value in any `name = value` or `name: value` assignment whose name
  contains `password`, `secret`, `token` or `api_key`/`api-key`, when the value
  is six or more characters.

Masked values appear to the model as `[redacted ...]`.

**Limits, measured on 2026-10-23** by calling `_mask_secrets` and
`verify.build_excerpt` directly:

- **Only those shapes are masked.** A bare Anthropic, Stripe or Google API key,
  a JWT, a credential inside a database URL (`scheme://user:pass@host`), a
  password shorter than six characters, and personal data such as names or
  email addresses all pass through unchanged when they are not in a
  `password=`/`token=`-style assignment.
- **A private key cut by the excerpt window is not masked.** The PEM rule
  needs both the header and the footer. When an excerpt shows only part of a
  key (a long function, or a key block longer than the window), the
  base64 body lines are sent. Reproduced with a 40-line key in a 170-line
  function and `excerpt_lines: 40`.
- **The judgement probe truncates before it masks.** `_select_files` cuts each
  file at 6,000 characters and then masks, so a private key that straddles
  the cut loses its footer and is sent unmasked.
- `tools/label_models.py` additionally masks database-URL credentials; the
  verification pass does not.

Redaction reduces exposure; it is not a guarantee. Treat an excerpt sent to
a model as disclosed.

**In reports**, `probes._mask` prints a secret's value with all but its first
four and last four characters replaced by `*` (values of eight characters or
fewer are fully starred). Findings from external analyzers carry the rule,
path and line, not the matched text, in the fields Arbiter maps. A report is
still sensitive: it says where credentials are, and what kind.

## Telemetry

None in Arbiter's code. Searching `src/arbiter/` for HTTP clients finds
`urllib` in exactly four modules: `judgement.py` and `verify.py`
(Anthropic), `authored.py` (PyPI/npm) and `client.py` (the server you name
with `arbiter remote`). No module reports usage, errors, crashes or version
checks anywhere. Words that look related are not: the "telemetry" hits in
`inventory.py` and `assurance.py` are comments about the `opentelemetry-js`
project, and the "analytics" hit in `graph.py` is the Terraform resource type
`azurerm_log_analytics_workspace`.

## Third-party analyzers

Arbiter invokes these only when they are installed, as separate processes
with your environment passed through (`adapters.Adapter.run` copies
`os.environ`). Each is governed by its own licence and its own data practices.
Arbiter does not vendor or redistribute any of them ([NOTICE.md](../NOTICE.md)).

| Tool | What we checked | Network behaviour as invoked by Arbiter |
|---|---|---|
| **semgrep** (`semgrep.adapter.toml`; 1.177.0 pinned by `tools/install_tools.sh`) | semgrep's installed Python source (its scan command, version check and metrics modules) | Rules come from a local pinned checkout, so no rules are fetched. Arbiter passes neither `--disable-version-check` nor `--metrics=off`. **The version check is on by default** and contacts `semgrep.dev` (at most about once a day; semgrep caches the answer). Usage metrics default to `auto`, which sends them only when rules come from the Semgrep registry **or you are logged in** (`semgrep login`, or `SEMGREP_APP_TOKEN` in the environment). |
| **checkov** (`checkov.adapter.toml`; 3.3.17 observed) | checkov's installed Python source (its entry point and Bridgecrew/Prisma platform integration) | Arbiter does not pass `--skip-download`. Without an API key, checkov **fetches policy guidelines from Prisma Cloud** (`api0.prismacloud.io`) when it starts, unless `BC_SKIP_MAPPING=TRUE` is set. With `BC_API_KEY` in the environment checkov enters its platform-integration mode; Arbiter has not tested that path. |
| **gitleaks** (`gitleaks.adapter.toml`) | the command line Arbiter passes (`detect --no-git`) | Not inspected in depth; no network endpoint was found in the binary's strings. |
| **bandit** (`bandit.adapter.toml`) | bandit's installed source | No HTTP client found outside its check definitions. |
| **ruff** (`ruff.adapter.toml`) | not inspected (a compiled binary) | Unverified. |

To keep semgrep and checkov from contacting their vendors, set
`SEMGREP_ENABLE_VERSION_CHECK=0`, `SEMGREP_SEND_METRICS=off` and
`BC_SKIP_MAPPING=TRUE` in the environment that runs Arbiter. Those are the
tools' own settings, not Arbiter's. Consult each tool's documentation for its
current behaviour; versions change.

## What is written to disk

| What | Where | Written by | Contains |
|---|---|---|---|
| Report | `<out>/report.json` (`--out`, default `arbiter-out/`), plus `<out>/report.html`, `<out>/report.sarif`, `<out>/REPORT.md`, `<out>/pr-comment.md` and `<out>/annotations.txt` for the formats you ask for | `report.write_all` | findings with paths, lines, titles and masked evidence; model verdicts and reasons when the pass ran; the **absolute local path** and short commit of each scanned repository; timestamps |
| Run history | `<out>/history.jsonl` (off with `--no-history`) | `history.append` | one line per run: commit, counts, coverage, grade, profile, time |
| Result cache | `<target>/.arbiter/cache.json` (`--cache-path`; off with `--no-cache`) | `cache.ResultCache` | per-file cached probe results keyed by content hashes |
| Verification cache | `<target>/.arbiter/verify-cache.json` | `verify.run` | model verdicts and reasons, keyed by hash |
| Baseline | `.arbiter/baseline.json` by default | `arbiter baseline` | finding ids accepted as existing |
| Calibration ledger | `.arbiter/knowledge.json` by default (`--knowledge`) | `arbiter feedback`, `arbiter review --apply` (`learn.Knowledge.save`) | adjudications, each with a **reviewer identity** (see below), time and entry point |
| Tool cache | `~/.cache/arbiter/` (`ARBITER_CACHE_DIR` overrides) | `adapters.cache_dir`, `lang_rules` | the analyzer version memo, compiled-pack stamps, and what `install_tools.sh` put there |
| Grammar cache | the tree-sitter-language-pack cache under `~/.cache/` | that library | parser binaries |
| Other commands | JSON and HTML written by `arbiter ab`, `arbiter diff`, `arbiter dashboard` and `arbiter review` under the output path you give | `cli.py` | derived from reports |
| Hosted server only | `~/.arbiter/keys.json` (`ARBITER_KEYS`), `~/.arbiter/audit.log` (`ARBITER_AUDIT`) | `api.mint_key`, `api.AuditLog` | see [below](#the-hosted-api-and-https-mcp-server) |

`arbiter remote` reads `~/.arbiter/client.json` (server address and key) when
it exists; Arbiter never writes that file. Temporary clones of URL targets are
deleted when the scan ends (`engine.py`, the `tempdirs` cleanup).

## Personal data

Arbiter does not collect personal data for itself and sends nothing to its
authors. It does handle personal data in four ways you should know about:

1. **Whatever is in the code you scan** may appear in excerpts sent to a model
   under a model-backed profile (redaction does not look for personal data),
   and in reports.
2. **Reviewer identity.** `arbiter feedback` and `arbiter review --apply`
   record who made each verdict: `--reviewer`, or else your git
   `user.email`, or else `user.name` (`cli._resolve_reviewer`). The ledger is
   designed to be committed, so that identity becomes part of the repository's
   history.
3. **Local paths.** Reports record the absolute path of each scanned
   repository, which often contains an operating-system user name. Anyone you
   share a report with sees it.
4. **Hosted operators** hold a user label for each API key and a per-request
   log line naming it (next section).

## The hosted API and HTTPS MCP server

These are for an operator running Arbiter for other people
([hosted-api.md](hosted-api.md), [mcp.md](mcp.md)). As the code stands:

- Each request's upload is extracted into a fresh temporary workspace and the
  workspace is deleted when the request ends (`service.Workspace`,
  `api.handle_scan`).
- `api.AuditLog` writes one JSON line per request: time, operation, key id,
  the key's user label, HTTP status, bytes uploaded and duration. It records
  no file names, findings or code.
- `service.check_profile` refuses `connected` and `audit`. It **accepts
  `assisted`**, which would send excerpts of uploaded code to Anthropic if the
  server's environment held an API key; the shipped `deploy/` files set none
  ([hosted-api.md](hosted-api.md)).
- The semgrep and checkov start-up requests described above happen on the
  server too, whenever the server's container can reach the internet.

What an operator does with uploads, logs and keys beyond that is a matter for
the operator's own terms (for the pilot, [pilot-terms.md](pilot-terms.md)).

## Retention and deletion

Arbiter keeps nothing on anyone's behalf and has no deletion schedule. Every
file in the table above is yours: delete `arbiter-out/`, the `.arbiter/` files
and `~/.cache/arbiter/` whenever you like. A committed calibration ledger stays
in git history after you delete it. Data sent to Anthropic, PyPI, npm, a git
host or an `arbiter remote` server is held under that party's terms.

## Known gaps

Found while writing this page. They contradict a simple "offline means
nothing leaves" story, and are recorded rather than smoothed over.

1. **Grammar downloads under `offline`.** `ast.cached_grammars` promises not to
   download, but `probe_ast_metrics` (through `ast.functions` and
   `ast.parse_file`) and `context.parse` call `ast._parser`, and
   tree-sitter-language-pack 1.22.1's `get_parser` downloads a grammar from
   `github.com` when it is not cached. `ast_metrics` declares no `grammars`
   requirement, so it does not check the cache first. Reproduced with an empty
   grammar cache and the network blocked: `ast.functions` on a Python file
   called `get_parser("python")`, which attempted the download. With
   `tools/install_tools.sh` run, the default prefetch covers Python,
   JavaScript, TypeScript, TSX, Go, Java and Ruby; a repository with C, C++,
   PHP, Rust or shell files can still trigger a download. No code is sent; the
   request fetches a parser.
2. **semgrep and checkov contact their vendors** at start-up under every
   profile, as described [above](#third-party-analyzers).
3. **URL targets are cloned under every profile**, including `offline`.
4. **`arbiter remote` uploads more than a scan reads.** `client.build_archive`
   skips `SKIP_DIRS` names but does not consult `.gitignore`, so git-ignored
   files such as `.env` are uploaded, although `client.py`'s docstring says the
   archive "will not send what the scanner would not have read".
5. **Redaction gaps**, listed under
   [Redaction, and its limits](#redaction-and-its-limits).
6. **Hosted `assisted`**, listed in the previous section.

None of these is fixed by the change that added this page; it is
documentation only. They are recorded on requirement ARB-102 for follow-up.
