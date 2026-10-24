# Privacy

Arbiter is software you run yourself. It is not a service, and the Arbiter
project receives nothing from your use of it: there is no telemetry, no usage
reporting and no account.

What it does with your code, in brief:

- **By default nothing goes to a model.** The `offline` (default) and `ci`
  profiles never call a model or a package registry.
- **Model-backed profiles send excerpts to Anthropic.** `assisted`,
  `connected` and `audit` can send bounded, partly redacted excerpts of your
  code to Anthropic's API, using your own `ANTHROPIC_API_KEY`, and only when
  that key is set. `connected` and `audit` also look up package names on PyPI
  and npm.
- **Some network traffic does not depend on the profile.** Scanning a URL
  clones it; a missing tree-sitter grammar may be downloaded; and semgrep and
  checkov, if installed, contact their vendors when they start. None of these
  sends your source code.
- **Output stays on your disk.** Reports, caches, baselines and calibration
  ledgers are written locally. They can contain file paths, local directory
  names and, in the calibration ledger, the reviewer's git email or name.
- **Redaction is partial.** Credential-shaped values are masked before
  anything is sent, but only some shapes are recognised.

The full account, with what is sent, to whom, when, what is written where,
the limits of redaction and the known gaps, is in
[docs/data-handling.md](docs/data-handling.md).

If you run Arbiter as a hosted service for other people, you are the one
handling their data; [docs/hosted-api.md](docs/hosted-api.md) describes what
the server keeps.

Third-party analyzers Arbiter invokes (semgrep, checkov, gitleaks, bandit,
ruff) and the model provider you configure have their own privacy terms.
