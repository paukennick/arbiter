# Arbiter

**A polyglot repository and system evaluator that refuses to grade what it did
not actually inspect.**

| | |
|---|---|
| **Version** | 0.1.0 — pre-release, no tagged releases yet |
| **Python** | 3.11 or later |
| **Runtime dependencies** | PyYAML |
| **License** | Proprietary — see [Licensing](#licensing) |

Arbiter scans one repository, or a **system** of several, and produces findings
across seven dimensions: security, compliance, quality, drift, interface, supply
chain and assurance. Alongside the findings it reports how much of its own
rubric it was able to run, and withholds the overall grade when that coverage
falls below threshold.

It ships with native probes that require nothing installed, wraps external
analyzers through declarative adapters, maps findings to five government control
frameworks, and includes an A/B harness for comparing configurations, tools, and
builds of Arbiter itself. Every report carries a machine-checked claim ledger
recording which checks support each assertion and which abstained.

---

## Principles

1. **Coverage is reported, never assumed.** A probe that could not run is
   recorded as *not assessed*, with a reason. It is never silently a pass.
2. **Deterministic and inferred findings never blend.** Every finding carries
   `provenance`. Inferred findings are advisory and do not gate by default.
3. **The tool never executes the target.** No `npm install`, no
   `terraform init`, no importing the target's Python.
4. **One core, many languages.** Language support arrives as probes and
   adapters, not core changes.
5. **No claim outruns its basis.** Every assertion carries the checks that
   support it and the checks that abstained, and ten invariants are
   machine-checked before the report is written.
6. **Adaptation is deliberate, never ambient.** Learning accumulates offline; a
   scan reads one pinned knowledge version and records its hash.

## Capabilities

### Dimensions and scoring

Findings are weighted by severity times confidence, then rolled up per dimension:

| Dimension | Weight | Covers |
|---|---|---|
| `security` | 0.30 | Secrets, insecure resources, disabled protections |
| `quality` | 0.20 | Complexity, file and function size, test presence |
| `supply_chain` | 0.15 | Unpinned dependencies and actions, invented imports |
| `interface` | 0.15 | Seams between repositories in a system |
| `compliance` | 0.10 | Control-mapped resource policy |
| `drift` | 0.10 | Documentation, contracts and code disagreeing |
| `assurance` | **0.00** | Whether the checking itself is switched on |

`assurance` scores zero deliberately. A repository with four hundred `# noqa`
comments is not insecure, it is *unmeasured* — a fact about the evidence, not
about the code, and folding the two into one grade would be the exact
conflation the dimension exists to expose.

### What it detects

Thirteen native probes covering secrets, a provider-neutral resource policy over
Terraform, CloudFormation, CDK and Kubernetes, AST metrics in 11 languages,
supply-chain pinning, documentation drift, cross-repo interface seams, defects
characteristic of machine-drafted code, contract mismatches between artifacts,
and assurance. Plus adapters for `ruff`, `bandit`, `checkov`, `semgrep` and
`gitleaks`.

Full table, requirements and rationale: **[docs/probes.md](docs/probes.md)**.

### Beyond single-repository scanning

| Capability | Summary |
|---|---|
| **Multi-repo systems** | Six seam checks across repositories — constant disagreement, unprovided environment variables, ungranted IAM permissions, unexposed ports. Every finding cites spans in both repos. → [docs/systems.md](docs/systems.md) |
| **Terraform plan reading** | Resolved variables, expanded `for_each`, flattened modules. Unknown values report as *not assessed*, never as a pass. → [docs/probes.md](docs/probes.md#infrastructure-as-code) |
| **Control coverage** | NIST 800-53r5, NIST 800-171r2, SSDF 800-218, FedRAMP Moderate r5, CMMC L2 — independent packs, five resolution states, honest denominators. → [docs/compliance.md](docs/compliance.md) |
| **Claim integrity** | A claim ledger per report, ten invariants, verified before the report is written. → [docs/evidence.md](docs/evidence.md#claim-integrity) |
| **Calibration** | Offline learning from adjudicated findings; confidence moves, severity never does. → [docs/calibration.md](docs/calibration.md) |
| **A/B harness** | Compare profiles, analyzers, or two builds of Arbiter over one target. → [docs/ab-testing.md](docs/ab-testing.md) |

## Quick start

```bash
pip install -e .
arbiter scan ./my-repo
```

```bash
./tools/install_tools.sh     # optional: the five external analyzers, pinned
```

Full installation, optional extras and training setup: **[SETUP.md](SETUP.md)**.

## Commands

```bash
arbiter scan ./repo                            # analyze and report
arbiter scan --system arbiter-system.yaml      # several repos, one verdict
arbiter gate ./repo --baseline .arbiter/baseline.json   # exit 1 on policy failure
arbiter probes ./repo                          # what can run here, and why not
arbiter explain f:8c41d2ae9b07                 # one finding in full
arbiter baseline arbiter-out/report.json       # snapshot current state
arbiter diff before.json after.json            # new / fixed / unchanged
arbiter verify arbiter-out/report.json         # does any claim outrun its basis?
arbiter controls arbiter-out/report.json       # control coverage, including gaps
arbiter review arbiter-out/report.json         # adjudicate a batch in one pass
arbiter feedback f:8c41 --false-positive       # adjudicate one finding
arbiter learn                                  # what has been learned
arbiter ab --spec examples/ab-native-vs-checkov.yaml    # compare two arms
```

Full reference: **[docs/cli.md](docs/cli.md)**.

## Administration

### Configuration

`arbiter.yaml` at the repository root is the whole configuration surface —
profile, gate thresholds, suppressions and house rules. There is no second
config file and no implicit user-level defaults. The repository's own
`arbiter.yaml` is a working example.

→ **[docs/configuration.md](docs/configuration.md)**

### Profiles

A profile is a capability budget. A probe needing a capability the profile
forbids is skipped with that reason recorded, so the report says what the
profile cost you.

| Profile | Network | Model | For |
|---|---|---|---|
| `offline` | no | no | air-gapped and high-side environments |
| `ci` | no | no | fast, deterministic gating |
| `connected` | yes | yes | full depth |
| `audit` | yes | yes | everything, no time budget |

### Output and exit codes

`--format json,sarif,html,markdown,console`. JSON is canonical and written
first; every other format is a rendering of it.

| Code | Meaning |
|---|---|
| `0` | pass |
| `1` | gate failure |
| `2` | error |

### State

| Path | Contents | Commit it? |
|---|---|---|
| `arbiter.yaml` | configuration | yes |
| `.arbiter/baseline.json` | accepted current state | yes |
| `.arbiter/knowledge.json` | calibration ledgers | yes |
| `.arbiter/external-severity.json` | measured severities for external checks | yes |
| `arbiter-out/`, `arbiter-ab/` | run output | no — git-ignored |

### Continuous integration

```yaml
- uses: ./ci/github-action
  with:
    target: .
    profile: ci
    baseline: .arbiter/baseline.json
```

The action uploads SARIF so findings render inline on pull requests. A GitLab
template is in `ci/gitlab/`. → **[docs/ci.md](docs/ci.md)**

### Testing

```bash
python -m pytest tests/ -q
```

The golden-fixture tests are the ones that matter: `fixtures/legacy-platform`
holds fourteen deliberately planted defects that `.arbiter-expected.yaml`
enumerates, and any change that regresses on one of them fails the suite.

## Documentation

| Document | Contents |
|---|---|
| [SETUP.md](SETUP.md) | Installation, optional extras, enabling the training loop |
| [docs/architecture.md](docs/architecture.md) | Pipeline, module layout, fingerprinting, scoring |
| [docs/cli.md](docs/cli.md) | Full command reference, formats, exit codes |
| [docs/configuration.md](docs/configuration.md) | `arbiter.yaml`, profiles, gating, suppressions, house rules |
| [docs/probes.md](docs/probes.md) | Every check, what it requires, what it catches |
| [docs/systems.md](docs/systems.md) | Multi-repository systems and seam checks |
| [docs/compliance.md](docs/compliance.md) | Control packs and coverage states |
| [docs/evidence.md](docs/evidence.md) | Claim integrity, injection training, corpus tuning |
| [docs/calibration.md](docs/calibration.md) | Learning, adjudication, external severity |
| [docs/ab-testing.md](docs/ab-testing.md) | The A/B harness |
| [docs/ci.md](docs/ci.md) | CI integration and continuous training |
| [CHANGELOG.md](CHANGELOG.md) | Dated entries, referenced to requirements |
| [NOTICE.md](NOTICE.md) | Third-party components and their licenses |

## Project status

Implemented through P2 plus claim integrity and calibration: the engine, policy,
resource graph, cross-repo seam checks, Terraform plan reading, a
machine-checked claim ledger and an offline learning loop. Everything documented
here works today.

Tuned against a corpus of **41 public repositories** in three populations —
deliberately vulnerable (16), well-maintained production (20) and teaching
material (5) — of which **5 are held out** and never tuned against, leaving a
tuning set of 36. On the severities that gate a build the separation is total:
zero criticals and zero highs across 2.3 million lines of well-maintained
production code. Method and limits: [docs/evidence.md](docs/evidence.md).

**Not yet built:** the Claude skill, air-gapped bundles, and the dashboard.
Commercial control packs (PCI-DSS, HIPAA, SOC 2, CIS) are a data file each in
the format the five government packs already use — the interfaces exist, the
implementations do not.

## Versioning

The project is at `0.1.0` and has no tagged releases. All changes are recorded
in [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]`, grouped by date and
referenced to the requirement they serve.

Reproducibility is versioned separately from the package: a scan is reproducible
given `(commit, config, knowledge version)`, and `--pin-knowledge` fails the run
if calibration has moved since a release gate was pinned.

## Licensing

Arbiter is **proprietary**. `pyproject.toml` declares
`license = { text = "Proprietary" }`.

> **Administrative note:** no `LICENSE` file has been added to the repository
> yet, so no terms are currently granted in writing. Add one before any
> distribution.

The licensing position is specified in **[docs/licensing.md](docs/licensing.md)**
— eight requirements covering the operative grant, copyright ownership,
ownership of scan output, and the redistribution review that blocks the
air-gapped bundle. Tracked as REQ-005.

Arbiter depends only on PyYAML at runtime. The external analyzers it adapts are
neither vendored nor redistributed — each is installed separately by the
operator and governed by its own license. Those licenses, and the review still
required before shipping an air-gapped bundle that includes them, are recorded
in [NOTICE.md](NOTICE.md).
