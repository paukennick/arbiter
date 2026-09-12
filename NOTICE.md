# Third-party components

Arbiter itself depends only on PyYAML at runtime.

The adapters in `src/arbiter/packs/adapters/` invoke external analyzers but do
not vendor or redistribute them. Each is installed separately by the operator.
Their licenses apply to those tools, not to Arbiter:

| Tool | License |
|---|---|
| ruff | MIT |
| bandit | Apache-2.0 |
| checkov | Apache-2.0 |
| semgrep | LGPL-2.1 (CLI) |
| gitleaks | MIT |

Before building a distributable air-gapped bundle that *does* include these
binaries, review each license for redistribution terms. That review has not
been done yet.

The AWS access key in `fixtures/legacy-platform/app/config.py` is the example
key published in AWS documentation. It is not a live credential.
