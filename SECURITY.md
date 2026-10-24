# Security policy

## Supported versions

Arbiter has not had a release yet. The package version is `0.1.0`, there are
no version tags, and it is installed from the git repository.

| Version | Supported |
|---|---|
| `main` branch (latest commit) | yes |
| any older commit | no; update to the latest `main` |

When releases begin, this table will name the release lines that receive
security fixes.

## Reporting a vulnerability

**Please do not report security vulnerabilities in public issues, pull
requests or discussions.**

Report privately through GitHub:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub private vulnerability
   reporting). This opens a draft security advisory that only you and the
   maintainers can see.

If that option is not available, use
[PRIVATE SECURITY CONTACT: to be provided by the owner], or open a public
issue that says only that you have a security report and asks for a private
channel, without any details.

### What to include

- the affected commit (output of `git rev-parse HEAD`) and how you installed
  Arbiter;
- the command, profile and configuration (`arbiter.yaml`) involved;
- what an attacker controls (for example a repository being scanned, an
  upload to the hosted API, an MCP request) and what they gain;
- step-by-step reproduction, ideally a minimal repository or archive;
- any logs or output, with secrets removed;
- whether you believe the issue is already public or being exploited.

## What to expect

These are goals, not guarantees. Arbiter is maintained by one person.

| Step | Goal |
|---|---|
| Acknowledge your report | within 7 days |
| Initial assessment (confirmed or not, and severity) | within 14 days |
| Fix or mitigation for a confirmed high or critical issue | within 90 days of the report |

You will be kept informed of progress, and told before anything is
published.

## Coordinated disclosure

Please give the maintainers a reasonable chance to fix an issue before you
disclose it publicly. The default embargo is **90 days** from the report, or
until a fix is published if that is sooner; it can be shortened or extended
by agreement, for example if the issue is being exploited.

When a fix ships, a GitHub security advisory will describe the issue and the
fixed commit and, with your permission, credit you. A CVE will be requested
through GitHub when the issue warrants one.

## Scope

**In scope:** the code in this repository that is part of Arbiter, including:

- the scanner and its probes, rule packs and adapters (`src/arbiter/`);
- the command-line interface, the MCP server and the hosted API
  (`arbiter mcp serve`, `arbiter api serve`) and their authentication, rate
  limits and upload handling;
- the `deploy/` files, `ci/github-action/` and `examples/`;
- problems such as: a scanned repository causing code execution or file
  access outside its tree, a secret leaking into a report, a log or a model
  request in a way the documentation says it should not
  ([docs/data-handling.md](docs/data-handling.md)), a report claiming a check
  passed when it did not run, or a bypass of the hosted API's key, profile or
  archive checks.

**Out of scope:**

- **Deliberately vulnerable test material.** `fixtures/` (including
  `fixtures/legacy-platform/`, `fixtures/planted/`, `fixtures/ai-corpus/` and
  `fixtures/ai-corpus-heldout/`) contains planted defects, insecure
  configuration and AI-written code with known flaws on purpose: it is what
  Arbiter is tested against. These are not vulnerabilities in Arbiter.
- **Synthetic credentials.** Key- and token-shaped strings in `tests/` and
  `fixtures/` are fake values written to exercise the secret checks, and the
  AWS key in `fixtures/legacy-platform/app/config.py` is the example key from
  AWS's own documentation ([NOTICE.md](NOTICE.md#planted-credentials)). They
  grant access to nothing.
- **Missed findings and false positives** on your code. Arbiter's detection
  limits are documented and measured ([DISCLAIMER.md](DISCLAIMER.md),
  [docs/precision.md](docs/precision.md)); please report them as ordinary
  issues. A missed finding is a security report only if Arbiter claims to
  have run a check that it did not run.
- Vulnerabilities in third-party analyzers Arbiter invokes (semgrep, checkov,
  gitleaks, bandit, ruff), in Python, or in dependencies; report those to
  their maintainers. Tell us too if Arbiter's use of them makes the problem
  worse.
- The OmniEngineering workspace tooling (`.ai/`, `omni`, `make_ai.py`,
  `omni_graph.py`, `omni_mcp.py`), unless the issue is specific to how
  Arbiter uses it; report upstream otherwise.
- Someone else's deployment of the hosted API. Report those to the operator.

## Safe harbour

If you make a good-faith effort to follow this policy (you test only against
your own installation, avoid privacy violations and data destruction, and
give us time to respond), the copyright holder will not pursue or support
legal action against you for that research.
