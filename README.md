# Arbiter

A repository evaluator that refuses to grade what it did not actually inspect.

Arbiter scans one repository or a **system** of several, produces findings
across six dimensions, and reports how much of its own rubric it was able to
run. It ships with native probes that need nothing installed, wraps external
analyzers through declarative adapters, and includes an A/B harness for
comparing configurations, tools, and builds of Arbiter itself.

Status: **P0–P2 + claim integrity + calibration** — engine, policy, resource graph,
cross-repo seam checks, Terraform plan reading, a machine-checked claim ledger and
an offline learning loop.
Tuned against a corpus of twenty-seven public repositories. Everything below
works today.

```
pip install -e .
arbiter scan ./my-repo
```

---

## The four rules

1. **Coverage is reported, never assumed.** A probe that could not run is
   recorded as *not assessed*, with a reason. It is never silently a pass, and
   the overall grade is withheld when coverage falls below threshold.
2. **Deterministic and inferred findings never blend.** Every finding carries
   `provenance`. Inferred findings are advisory and do not gate by default.
3. **The tool never executes the target.** No `npm install`, no
   `terraform init`, no importing the target's Python.
4. **One core, many languages.** Language support arrives as probes and
   adapters, not core changes.
5. **No claim outruns its basis.** Every assertion the report makes carries the
   checks that support it and the checks that abstained, and ten invariants are
   machine-checked before the report is written.
6. **Adaptation is deliberate, never ambient.** Learning accumulates offline;
   a scan reads one pinned knowledge version and records its hash.

---

## Commands

```bash
arbiter scan ./repo                            # analyze and report
arbiter scan --system arbiter-system.yaml      # several repos, one verdict
arbiter gate ./repo --baseline .arbiter/baseline.json   # exit 1 on policy failure
arbiter probes ./repo                          # what can run here, and why not
arbiter explain f:8c41d2ae9b07                 # one finding in full
arbiter baseline arbiter-out/report.json       # snapshot current state
arbiter ab --spec examples/ab-native-vs-checkov.yaml    # compare two arms
arbiter verify arbiter-out/report.json         # does any claim outrun its basis?
arbiter feedback f:8c41 --false-positive       # adjudicate, so the tool calibrates
arbiter learn                                  # what has been learned, and what it supports
arbiter diff before.json after.json            # new / fixed / unchanged
```

Output formats: `--format json,sarif,html,markdown,console`. JSON is canonical
and written first; every other format is a rendering of it.

Exit codes: `0` pass, `1` gate failure, `2` error.

---

## What it finds

| Probe | Dimension | Needs | Catches |
|---|---|---|---|
| `secrets` | security | nothing | AWS keys, private keys, GitHub/Slack tokens, credentialed URLs, high-entropy literals assigned to credential-named symbols |
| `resource_policy` | security, compliance | nothing | 13 provider-neutral rules over the normalized resource graph — unencrypted storage, public buckets, open ingress, plaintext listeners, missing retention |
| `quality` | quality | nothing | Oversized files, TODO clusters, repositories with no tests |
| `ast_metrics` | quality | tree-sitter | Function length, cyclomatic complexity and nesting depth measured from a real parse tree, in 11 languages |
| `house_rules_ast` | quality, security | tree-sitter | Your own tree-sitter queries from `arbiter.yaml` |
| `supply_chain` | supply chain | nothing | Unpinned Python/npm dependencies, GitHub Actions on mutable refs, `pull_request_target` |
| `doc_drift` | drift | nothing | Broken documentation links, files described in prose that do not exist, documented environment variables nothing reads |
| `interface` | interface | 2+ repos | Six seam checks — see below |
| `house_rules` | quality, drift | nothing | Your own rules from `arbiter.yaml` |

Plus adapters for `ruff`, `bandit`, `checkov`, `semgrep` and `gitleaks`. Any
that are not installed report as skipped with the binary named.

### Terraform: give it a plan

Reading `.tf` source is a fallback. A plan has resolved variables, expanded
`for_each` and `count`, and flattened modules — source has none of that.

```bash
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > tfplan.json
arbiter scan . --tfplan tfplan.json          # or just drop tfplan.json in the repo
```

Arbiter never generates the plan itself: `terraform init` downloads and
executes provider code, and the tool does not execute what it scans.

On the bundled `fixtures/tfplan`, where one of two `for_each` bucket instances
gets a public ACL from a conditional expression:

| | Source only | With the plan |
|---|---|---|
| Public bucket | **missed** — the conditional is unparseable literally | found, cited at `modules/storage/main.tf:5` |
| Unencrypted volume (`encrypted = var.encrypt_volumes`) | **false high** — reads the variable name as a value | *not assessed*, unknown until apply |
| Destroyed security group with open ingress | flagged | ignored, the plan destroys it |
| Bucket instances seen | 1 | 2 |

Three details make this work:

- **Findings still cite source.** Plan JSON has no file or line, so each plan
  resource is joined back to the HCL block that declared it by address, and the
  finding points at code you can open.
- **Unknown is not absent.** A value in `after_unknown` cannot be judged.
  Treating it as missing is exactly how a scanner reports an encrypted bucket as
  unencrypted, so the check returns *unknown* and is reported as not assessed —
  never as a pass, never as a finding.
- **Siblings link through `configuration`.** By the time
  `bucket = aws_s3_bucket.data.id` reaches `after`, it is a resolved string or
  an unknown; the reference only survives in the plan's configuration section.

A repository read from source alone gets an `info` finding saying so.

### The resource graph

Terraform, CloudFormation, CDK-synthesized templates and Kubernetes manifests
normalize into one `Resource` shape with a provider-neutral `kind`, so a rule
is written once:

```yaml
- id: unencrypted-database
  match_kinds: [database]
  assert: property_truthy
  any_of: [storage_encrypted, StorageEncrypted, encrypted, KmsKeyId]
  severity: high
  controls: [NIST-800-53r5:SC-28]
```

That fires on an RDS instance, an Azure PostgreSQL server and a Cloud SQL
instance without a line of provider-specific code.

---

## Multi-repo systems

A single repository is a system of one. Point Arbiter at a manifest to
evaluate several together and get findings on the seams between them:

```yaml
system: platform
repos:
  - id: infra
    path: ./infra
    role: infrastructure
  - id: app
    path: ./app
    role: application

shared_constants:
  - name: VECTOR_DIMENSION       # a stated contract: disagreement is high, not medium
```

Six checks run on the seams, and every cross-repo finding cites spans in both
repositories:

| Check | Catches |
|---|---|
| `constant-disagreement` | The same named constant with different values in two repos. High when the system manifest declares it a shared contract, medium otherwise. |
| `env-var-never-provided` | The application reads a variable that nothing in the system sets. |
| `env-var-provided-but-unused` | Infrastructure provisions a variable no code reads — usually a removed feature. |
| `permission-not-granted` | The application calls an AWS service that no IAM policy in the system grants. |
| `permission-unused` | A granted service with no call site: unused privilege. |
| `port-not-exposed` | The application targets a port no infrastructure resource exposes. |

```
high  app:src/embeddings.py:5   `VECTOR_DIMENSION` has different values in different repositories
                                infra=512, app=1024
high  app:src/embeddings.py:9   `OPENSEARCH_ENDPOINT` is read at runtime but nothing provides it
high  app:src/embeddings.py:11  Application calls `bedrock` but no IAM policy in the system grants it
med   app:src/embeddings.py:14  Application targets port 9200, which no infrastructure resource exposes
low   infra:iam:dynamodb        IAM grants `dynamodb` but no application code calls it
low   infra:stack.py:12         `LEGACY_FEATURE_FLAG` is provisioned but nothing reads it
```

The permission checks see SDK call sites, so an application that reaches a
service over raw HTTP reads as an unused grant. That limitation is why those
findings carry low confidence.

---

## Configuration

`arbiter.yaml` at the repository root is the whole configuration surface.

```yaml
version: 1
profile: offline          # offline | ci | connected | audit

gate:
  fail_on:
    severity: critical    # any critical fails the build
    new: high             # new highs fail; pre-existing ones don't
    coverage_below: 0.60  # refuse to certify a thin scan
  gate_on_inferred: false

suppress:
  - rule: "arbiter/quality.no-tests"
    reason: "tests live in a sibling repository"
    expires: 2027-01-31   # expiry is mandatory; an expired suppression stops suppressing

rules:
  - id: code-note-anchors
    type: reference_integrity
    refs:    { files: "**/*.py", pattern: "#\\s*note:\\s*(?P<ref>[\\w./#-]+)" }
    anchors: { files: ".ai/code-notes/**/*.md", pattern: "^#+\\s*(?P<anchor>.+)$" }
    severity: high
```

House-rule types: `file_exists`, `file_absent`, `content_match`,
`reference_integrity`, `metric_threshold`.

### Profiles

| Profile | Network | Model | For |
|---|---|---|---|
| `offline` | no | no | air-gapped and high-side environments |
| `ci` | no | no | fast, deterministic gating |
| `connected` | yes | yes | full depth |
| `audit` | yes | yes | everything, no time budget |

A probe that needs a capability the profile forbids is skipped with that
reason recorded, so the report says what the profile cost you.

---

## A/B testing

An **arm** is any named way of producing findings for the same target. One
abstraction covers all three comparisons worth making.

```yaml
# examples/ab-native-vs-checkov.yaml
ab: native suite vs checkov
targets: [../fixtures/legacy-platform]
arms:
  - name: native-all
    skip: [checkov, semgrep, bandit, ruff, gitleaks]
  - name: checkov
    kind: tool
    tool: checkov
```

```
arbiter ab --spec examples/ab-native-vs-checkov.yaml --out ab-out
```

| Arm kind | Meaning |
|---|---|
| `arbiter` | the pipeline with a given profile / probe selection / config |
| `tool` | one external analyzer on its own, normalized through its adapter |
| `command` | any command that writes a `report.json` — use it to compare two builds of Arbiter |

Matching runs in three passes and every match records which pass found it,
because a comparison that hides how it matched is not evidence:

1. identical fingerprint
2. same repository, file and line (±2)
3. same file, overlapping title wording (Jaccard ≥ 0.5)

Where a target carries `.arbiter-expected.yaml`, each arm is also scored
against that ground truth. Recall is always reported. **Precision is reported
only when the fixture declares `exhaustive: true`** — against a partial list of
planted defects, a real analyzer's extra findings are not false positives, and
reporting them as such would be a lie in Arbiter's favor.

Sample result against the bundled fixture:

```
A  native-all   23 findings in 0.02s · recall 100% (14/14 planted)
B  checkov      32 findings in 5.50s · recall  36% (5/14 planted)

agreement 17% — 8 matched, 15 only in A, 24 only in B
8 severity disagreements: Arbiter rates a public bucket critical, Checkov CE rates it medium
```

Read that honestly: Checkov goes far deeper on Terraform than Arbiter's 13
native rules, and the 24 findings only it produced are real. What the
comparison shows is that the two are complementary, that severity calibration
differs sharply, and that nothing Arbiter found was invented.

---

## Fingerprinting

A finding's ID is `sha256(rule_id ‖ repo_id ‖ path ‖ logical_address ‖
normalized_evidence)` — deliberately **excluding the line number**. Reformat a
file and the baseline survives; change a port number and it does not. Without
this the "new findings only" gate turns into noise and people switch it off.

---

## CI

```yaml
# .github/workflows/arbiter.yml
- uses: ./ci/github-action
  with:
    target: .
    profile: ci
    baseline: .arbiter/baseline.json
```

The action uploads SARIF so findings render inline on the pull request and
posts the Markdown report as a comment. A GitLab template is in
`ci/gitlab/`.

---

## Layout

```
src/arbiter/
  core.py        Finding, Location, Report, fingerprinting
  inventory.py   acquire + classify + stack detection
  graph.py       TF / CFN / K8s → normalized Resource
  probes.py      native probes + the probe contract
  adapters.py    declarative external-tool adapters
  policy.py      config, profiles, suppressions, scoring, gate
  engine.py      the eight-stage pipeline
  report.py      json · sarif · console · markdown · html
  ab.py          the A/B harness
  cli.py         commands
  packs/         rule packs and adapter manifests (data, not code)
fixtures/        synthetic repos with known planted defects
tests/           unit + golden-fixture regression tests
```

## Testing

```
python -m pytest tests/ -q
```

The golden-fixture tests are the ones that matter. `fixtures/legacy-platform`
contains fourteen deliberately planted defects and
`fixtures/legacy-platform/.arbiter-expected.yaml` enumerates them; a rule edit
or adapter upgrade that regresses on any of them fails the suite.

## Confidence, honestly bounded

Six nines of *verdict correctness on arbitrary code* is not achievable, and a
tool that claims it is choosing a flattering denominator. By Rice's theorem no
static analyzer is both sound and complete on arbitrary programs, and
separately, a claim needs evidence: ~3,000,000 clean observations per rule to
assert an error rate below 10⁻⁶ at 95% confidence.

What *is* achievable is claim integrity — **the tool never asserts something it
did not verify.** That is a property of Arbiter's own execution rather than of
the code under analysis, so it is decidable and enumerable.

```
arbiter verify arbiter-out/report.json --show-claims
python tools/integrity.py --probes 6
```

Every report carries a claim ledger: each assertion with the checks that
support it and the checks that abstained. Ten invariants forbid a claim from
outrunning its basis, and the engine verifies its own report before writing it.

| Evidence | Result |
|---|---|
| Reports enumerated exhaustively over the bounded state space | **3,188,646** |
| Integrity failures | **0** |
| Invariants declared / proven enforced by mutation | **10 / 10** |

Exhaustive over that space is a stronger statement than six nines within it —
and says nothing outside it, which is why the bound is stated rather than
extrapolated. For verdict correctness, `arbiter learn` reports measured
per-rule precision with a Wilson lower bound, and a rule under 20 adjudicated
observations reports as **unproven** rather than inheriting a flattering
estimate from a handful of samples.

## Learning without losing reproducibility

Adapting and being reproducible pull against each other: if behaviour depends
on history, the same commit passes on Monday and fails on Tuesday, and
baselines, gates and accreditation artefacts stop meaning anything. Arbiter
separates the two.

```
arbiter feedback f:8c41d2ae9b07 --false-positive --note "vendored fixture"
arbiter learn                                  # what has been learned, and what it supports
arbiter scan . --pin-knowledge k:4cf3d3fa2f02  # freeze it for a release gate
```

Learning is offline and accumulates in `.arbiter/knowledge.json`. Execution
reads **one pinned knowledge version** and records its hash, so
`(commit, config, knowledge version)` always produces identical bytes. Three
limits keep it honest:

- **Confidence moves, severity never does.** How often a rule is right is
  measurable; how much it matters when it is right is a policy judgement.
- **Learning never changes a gate outcome** unless `gate.use_calibration` is set.
- **One finding moves the statistics once.** Re-adjudicating a fingerprint is
  refused.

Thresholds adapt to the repository rather than to history, which needs no
knowledge file at all — set `quality.adaptive: true` and file length, function
length and complexity limits are drawn from that codebase's own p95, with a
floor so a uniformly bad codebase cannot normalize its way to a clean report.

```
file_lines      n=30   median=143  p95=795
function_lines  n=210  median=12   p95=75     # the fixed 120 limit was too lax here
complexity      n=210  median=5.5  p95=27
```

A distribution with fewer than 30 samples is ignored, and the fixed threshold
stands.

## Training evidence

Rules are trained by planting known defects into real files from the corpus
and measuring what is found, alongside controls that look like defects and are
not. Seeds come from the corpus rather than from templates, because effective
sample size is bounded by generator diversity, not by trial count.

```
python tools/inject.py --trials 40000 --knowledge .arbiter/knowledge.json
```

| | Result |
|---|---|
| Trials | 30,000 across 15 rules |
| Recall | **15,000 / 15,000** |
| Specificity | **15,000 / 15,000** |
| Rules with controls | **15 / 15** |
| Per-rule Wilson lower bound | 0.995 – 0.999 |

Every rule has controls. That row matters more than the other two: a rule with
measured recall and no controls could be firing on everything and the numbers
would still look perfect. Six rules were in exactly that state until controls
were written for them.

Read that honestly. It measures whether a rule detects defects drawn from a
generator, against controls drawn from the same generator. It is evidence
about rule mechanics, not about code in the wild — which is why synthetic
observations are kept in a separate ledger from human adjudication and
`arbiter learn` reports them apart. Calibration reads only the adjudicated
ledger.

Its real value is what it found. Training exposed six defects that breadth
alone had not:

| Defect | Consequence |
|---|---|
| `:=` did not match | Every Go short variable declaration was invisible to the secret detector. Recall on that rule was **0.48**. |
| Backticks were not strings | A secret in a JavaScript template literal was invisible. |
| `Job`, `CronJob`, `Pod` were not `compute` | A third of injected Kubernetes workload defects matched no rule at all. |
| Hyphenated placeholders | `your-api-key-here` was reported as a credential, because `\w` does not match a hyphen. |
| Kubernetes PVCs scored by AWS properties | `unencrypted-volume` fired on every PersistentVolumeClaim in Kubernetes' own examples — 20 false positives. |
| No rules for absent hardening | Kubernetes defaults are the insecure ones. A deliberately vulnerable Kubernetes repository produced **two** findings; it now produces twelve. |
| Unquoted values were invisible | `.env` files, Kubernetes Secrets, `docker-compose`, `export VAR=`, Dockerfile `ENV` and `.properties` — the formats where secrets most commonly leak — were **all** unreadable, because the pattern required quotes. |
| Six rules had no controls | Recall was measured; false-alarm rate was not measured at all. |

## Tuning evidence

Rules are tuned against twenty-seven public repositories across thirteen
languages and five infrastructure formats, split into **three** populations.
A rule that fires on `flask` is telling you about the rule, not about the code.

| Population | Repos | Lines | Findings | Per KLOC | Critical | High |
|---|---|---|---|---|---|---|
| **Deliberately vulnerable** | 5 | 101,069 | 241 | 2.38 | 7 | 20 |
| **Well-maintained production** | 17 | 839,751 | 693 | **0.83** | **0** | **0** |
| **Teaching material** | 5 | 596,206 | 2,211 | 3.71 | 0 | 14 |

On the severities that gate a build, the separation is total: seven criticals
and twenty highs across the vulnerable repositories, and **not one of either**
across 839,751 lines of well-maintained production code.

### Why teaching material is its own population

Reference CloudFormation stacks, CDK samples, Helm charts, `docker-compose`
collections and Kubernetes examples are written to be short and readable, not
production-ready. They genuinely do lack resource limits, security contexts
and pinned versions — so the findings are *correct about the file* and useless
as a measure of false-positive rate.

Counting them as well-maintained code made the noise rate look roughly four
times worse than it is. 2,211 of what were reported as 2,904 "clean" findings
came from five example repositories. Separating them moved the real number
from 2.02 to **0.83 per KLOC**, and the rules did not change.

The lesson generalizes: a corpus label is a claim about what the code is
*for*. Getting it wrong corrupts every rate computed from it.

### Severity is earned by measurement

A rule's severity is set by how much more it fires on bad code than on good
code, measured stack-for-stack — never by how serious the underlying idea
sounds. Comparing a Kubernetes rule against the whole corpus is invalid when
only one vulnerable repository is Kubernetes and it is 359 lines long.

| Rule | Good | Bad | Ratio | Severity |
|---|---|---|---|---|
| `k8s-no-resource-limits` | 0.38/kloc | 5.57/kloc | **14.5×** | medium |
| `k8s-no-security-context` | 0.42/kloc | 5.57/kloc | **13.2×** | medium |
| four more k8s hardening rules | — | — | **11.7×** | medium |
| `supply.unpinned-action` (CloudFormation) | 0.00/kloc | 0.27/kloc | **219×** | low |
| `supply.unpinned-action` (Node) | 0.06/kloc | 0.27/kloc | **4.3×** | low |
| `supply.unpinned-npm-dep` | 0.68/kloc | 0.73/kloc | **1.1×** | **info** |
| `supply.unpinned-python-dep` | — | 0.00/kloc | **0.0×** | **info** |

The last two were demoted on this evidence. A floating `^4.17.0` is still worth
knowing about, so they still report — but `info` carries zero score weight, so
a project is no longer graded down for something that turned out to be just as
common in good code as in bad. `unpinned-action` stayed, because it separates.

The Kubernetes hardening rules stayed at medium for the same reason in
reverse: they looked like noise (724 findings on "clean" code) only because
the teaching repositories were mislabelled and the comparison was unmatched.
Stack-matched, they are among the most discriminating rules in the tool.

```
python tools/corpus.py --root /tmp/corpus --out /tmp/corpus-out
```

Each false positive that tuning removed has a regression test in
`tests/test_arbiter.py` naming the repository it came from.

## Not yet built

Per the design spec, these are later phases: control-framework packs and the
coverage matrix, the model-backed claim extraction behind docs-vs-code drift,
the Claude skill, air-gapped bundles, and the dashboard. The interfaces they
plug into exist; the implementations do not.
