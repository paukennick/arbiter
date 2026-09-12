# Arbiter

A repository evaluator that refuses to grade what it did not actually inspect.

Arbiter scans one repository or a **system** of several, produces findings
across seven dimensions, and reports how much of its own rubric it was able to
run. It ships with native probes that need nothing installed, wraps external
analyzers through declarative adapters, and includes an A/B harness for
comparing configurations, tools, and builds of Arbiter itself.

Status: **P0–P2 + claim integrity + calibration** — engine, policy, resource graph,
cross-repo seam checks, Terraform plan reading, a machine-checked claim ledger and
an offline learning loop.
Tuned against a corpus of forty-two public repositories in three populations,
five of them held out and never tuned against. Everything below works today.

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
arbiter controls arbiter-out/report.json       # control coverage, including the gaps
arbiter review arbiter-out/report.json         # adjudicate a batch in one pass
arbiter review report.json --html              # ...as a page you can tap through
arbiter review report.json --interactive       # ...or one keypress each, in the terminal
arbiter review --apply arbiter-out/review.md   # record the verdicts
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
| `assurance` | assurance | nothing | Whether the *checking* is switched on: silenced findings across fifteen tools' ignore syntaxes, configuration that excludes code from analysis, tests that cannot fail |
| `authored` | supply chain, security | nothing | Defects characteristic of machine-drafted code: imports of packages nothing declares (and, connected, packages that do not exist), stubs on production paths, disabled security checks |
| `judgement` | drift | a model | Claims in prose that the code contradicts. Inferred, never gates |

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

Its real value is what it found. Training exposed defects that breadth alone
had not:

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

The two methods find different things, and neither substitutes for the other.
Injection finds rules that fail *mechanically* — a pattern that cannot match
what it claims to match. Breadth finds rules that work mechanically and are
still wrong about real code, which is the harder failure to see: a critical
finding on three literal dots passes every injection trial ever written,
because the generator never thinks to plant a placeholder.

## Tuning evidence

Rules are tuned against **thirty-nine public repositories** across thirteen
languages and five infrastructure formats, split into three populations.
A rule that fires on `flask` is telling you about the rule, not about the code.

| Population | Repos | Lines | Findings | Per KLOC | Critical | High |
|---|---|---|---|---|---|---|
| **Deliberately vulnerable** | 14 | 661,814 | 1,091 | 1.65 | 16 | 71 |
| **Well-maintained production** | 20 | 2,309,276 | 3,630 | 1.57 | **0** | **0** |
| **Teaching material** | 5 | 596,206 | 2,211 | 3.71 | 0 | 14 |

On the severities that gate a build, the separation is total: sixteen
criticals and seventy-one highs across the broken repositories, and **not one
of either** across 2.3 million lines of well-maintained production code in
twenty projects.

The overall per-KLOC rates are almost identical between the first two
populations, and that is not a failure — it is the point of the next section.
Most findings are low-severity style and hygiene notes that any large codebase
accumulates. What matters is not how often a rule speaks but how hard it
pushes, and on that measure the populations are cleanly separated.

### Every stack needs a broken counterpart

The vulnerable population started at five repositories covering Terraform,
CloudFormation, Node and Kubernetes. Eight of the thirteen languages had
nothing broken to compare against at all, so any rule covering them could not
be measured — it could only be asserted. Java, Ruby, PHP, Python, TypeScript,
Docker, CDK and a second, larger Kubernetes project were added for that reason.

Widening found defects that repetition could not. Running the old set a
hundred more times would have found none of them:

| Defect | Consequence |
|---|---|
| A PEM header with a placeholder body counted as a key | Argo CD's operator manual shows how to register a credential; the key body in the example is **three literal dots**. Arbiter reported it as a critical, high-confidence leaked private key — the worst finding it can produce, on nothing. |
| `integration/`, `e2e/` and `hack/` were not recognised as test paths | Traefik commits real TLS keys under `integration/resources/tls` so its integration suite has something to serve. Identical in kind to the keys under `psf/requests`' `tests/certs/`, which were already handled — a different word for the directory changed the verdict from medium to **critical**. |
| A credential inside documentation counted as production | A key in a manual illustrates where the key goes. `role == "docs"` now downgrades the same way a test path does. |

All three were criticals on well-maintained code. All three are now regression
tests naming the repository they came from.

### Severity is earned by measurement, not by intuition

`tools/discriminate.py` measures every rule against both populations and
reports whether its severity is supported. Three things about that measurement
were wrong before the tool existed, and each one produced confident nonsense.

**The denominator.** A Kubernetes rule can only fire on Kubernetes manifests.
Measured against whole-repository size it looks immaculate inside a
400,000-line Go project containing forty lines of YAML — not because the rule
is good, but because 399,960 lines were never eligible to fail. The denominator
is now the lines written in the languages that rule actually fires on, counted
separately in each population. Reports carry `loc_by_language` so this is
computable from any saved scan.

**The numerator.** Arbiter already knows a manifest under `testdata/` is not a
deployment: it reports the finding, labels it, and drops its severity and
confidence so it barely moves the grade. Counting that at full weight measures
the rule against a claim the tool never made. In Argo CD, **195 of 203**
findings for one rule were exactly this. Findings are now counted by what they
are worth — severity weight times confidence factor, the same arithmetic the
scorecard uses.

**The comparison itself.** The broken repositories are broken in the *security*
sense. Nobody publishes a repository that is deliberately badly documented, so
for quality and drift rules there is no broken population and the ratio
measures nothing. `ast.function-too-long` fires five times more per line on
well-maintained code than on the goats — but the goats are small teaching apps
and the well-maintained repositories are mature production codebases. That
ratio is a statement about codebase age. Only security and compliance rules get
a verdict; everything else gets its number printed and no conclusion drawn.

With all three corrected, every scoring security rule separates the
populations — the tool's own verdict line reads *"none — every scoring
security rule with enough data separates the populations"*:

| Rule | Weighted ratio | Severity |
|---|---|---|
| `secrets.aws-access-key` | 2457× | critical |
| `resource.k8s-host-path-volume` | 704× | medium |
| `resource.unencrypted-database` | 473× | high |
| `secrets.private-key` | 14.2× | critical |
| `secrets.jwt` | 10.7× | medium |
| `secrets.assigned-credential` | 10.7× | high |
| `supply.unpinned-action` | 10.5× | low |
| `resource.k8s-no-security-context` | 7.6× | medium |
| `resource.k8s-not-run-as-non-root` | 6.6× | medium |
| `resource.k8s-privilege-escalation-not-disabled` | 6.5× | medium |
| twelve rules that never fire on good code | ∞ | — |

Three rules were demoted to `info` on this evidence, which reports them at zero
score weight rather than deleting them:

| Rule | Ratio | Why |
|---|---|---|
| `supply.unpinned-npm-dep` | 1.1× raw | Caret ranges are just as common in good Node as in bad. Libraries are *supposed* to declare ranges. |
| `supply.unpinned-python-dep` | 0.0× | Fired only on well-maintained code. |
| `supply.pull-request-target` (safe form) | 1.5× | The rule already separates the dangerous form — a workflow that checks out the PR head — and scores that `high`. The benign form appeared twelve times on good repositories and once on broken ones. Scoring it was the only reason this rule failed its own test. |

The Kubernetes hardening rules were nearly demoted on the *raw* count, at
1.5×. Weighted, they run 6.5× to 7.6×: almost every clean-code hit was a
`testdata/` manifest the tool had already discounted. They stayed at medium,
and the reason is now on record so the question is not reopened from the raw
counts.

```
python tools/corpus.py         --root /tmp/corpus   # population summary
python tools/discriminate.py   --root /tmp/corpus   # per-rule discrimination
python tools/worklist.py       --out training/WORKLIST.md   # what to fix next
```

### Training has two halves, and only one needs a person

`.github/workflows/train.yml` runs the whole cycle nightly on GitHub's
machines — corpus scan, discrimination, injection, claim integrity, tests —
and commits the results back. It never edits a rule. It only measures.

Deciding what a result *means* is the other half, and it is where every real
defect has come from: whether a finding on a well-maintained repository is the
rule's fault or the code's, whether a ratio is real or an artefact of how it
was measured. `tools/worklist.py` is the handoff between the two. It reads
what the cycle measured and writes a ranked queue, so the next session starts
from a question rather than a pile of tables.

Its six checks, in the order they have actually paid off:

| Check | Why it is there |
|---|---|
| Critical or high on well-maintained code | The strongest signal available. Three real defects in one afternoon, including a critical on three literal dots. |
| A severity the measurement does not support | A rule that fires no harder on broken code is describing a style, not detecting a defect. |
| A rule with no controls | The dangerous state, because it looks perfect: recall reads 1.0000 whether the rule is precise or fires on everything. |
| A rule nothing has ever exercised | An assertion wearing the costume of a measurement. |
| A stack with no broken counterpart | Its rules cannot be measured at all. Closing eight of these is what found the three criticals above. |
| No finding reviewed by a person | Calibration reads **only** the adjudicated ledger. No schedule can fill it, because it is a judgement about what you would act on. |

An empty queue is itself a finding: it means the corpus has stopped teaching
us anything, and the next useful move is to widen it, not to run it again.

Each false positive that tuning removed has a regression test in
`tests/test_arbiter.py` naming the repository it came from.

## Control coverage

Five government framework packs ship: NIST 800-53r5, NIST 800-171r2, NIST
SSDF 800-218, FedRAMP Moderate Rev 5 and CMMC Level 2. Each is an
**independent** pack — controls map straight to checks, never routed through a
hub framework, because chaining two approximate crosswalks produces a
compliance claim two translations removed from anything that ran.

Every control resolves to one of five states, and the split between the last
three is the entire point:

| State | Meaning |
|---|---|
| `satisfied` | A covering check ran, applied, and found nothing. |
| `violated` | A covering check fired. |
| `not_assessed` | A check covers this on paper but did not run here — tool absent, value unknown until apply. **Not a pass.** |
| `no_coverage` | Assessable in principle; Arbiter has no check for it. |
| `not_automatable` | No static analyzer can ever assess this — personnel screening, physical access, incident-response exercises. A person must. |

Plus `not_enumerated`: controls the pack does not list at all, counted against
the framework's real published size so a pack covering twenty controls cannot
report full coverage.

```
$ arbiter controls arbiter-out/report.json --framework FedRAMP-Moderate-r5

       8  violated         a check fired
       0  not_assessed     a check covers this but did not run — not a pass
       0  no_coverage      assessable in principle; Arbiter has no check for it
       5  satisfied        a check ran, applied, and found nothing
       5  not_automatable  no static analyzer can assess this; a person must
     305  not_enumerated   not in this pack; assess by other means
     323  controls in this baseline

    4.0% of the baseline carries evidence from this scan (13 of 323).
```

Four percent. No compliance product would print that number, which is why it
is the right one: the other 96% is unevidenced by this scan, and a reader of
an accreditation package needs to know which 96%.

Every automatable control also carries a `residual` note saying what a person
must still check even when the automated part passes — because encryption
being switched on says nothing about who holds the key, and FedRAMP AU-11
fixes a retention period a check confirming "some period is set" cannot see.

## The judgement pass

A model is worth adding only for questions with no definite shape: does the
README describe behaviour the code no longer has, does a comment contradict
the function under it. It is not here to re-find secrets — those have
decidable answers, and swapping a decidable check for a probabilistic one is a
downgrade dressed as an upgrade.

```yaml
profile: connected          # offline and ci forbid model calls outright
judgement:
  provider: anthropic       # reads ANTHROPIC_API_KEY from the environment
  model: claude-sonnet-4-5
```

Three rules it obeys:

- **Inferred findings never blend with deterministic ones.** Everything from
  this pass is `provenance: inferred`, and the gate ignores inferred findings
  unless `gate.gate_inferred` is set. A model's opinion should not turn a build
  red on its own.
- **No provider configured is *not assessed*, never a pass.** The easy
  implementation returns an empty list when there is no key — and an empty list
  is indistinguishable from "looked, found nothing". So the probe reports
  skipped with the reason, and coverage drops by exactly what was not checked.
- **A finding citing a file the model was not shown is discarded**, not
  reported with a caveat. Secrets are masked before anything leaves the
  machine, and model-stated confidence never reaches `high` — confidence
  asserted by a model is a different quantity from confidence measured from
  adjudicated outcomes, and sharing a scale would be a category error.

## Calibrating somebody else's tool

Checkov's open build reports `"severity": null` on every finding. Arbiter's
adapter invented `medium` for all of them, so one Terraform repository
produced 477 findings of identical weight and no way to tell the two that
matter from the 475 that do not.

`tools/calibrate_external.py` measures every individual external check —
every `CKV_AWS_*`, every bandit `B*` — against the same three-population
corpus used for native rules, and assigns severity from the measured ratio:

| Measured ratio | Assigned |
|---|---|
| ≥ 10× | medium |
| ≥ 3× | low |
| < 3× | info — reported, zero weight |
| fewer than 5 observations | nothing assigned; no claim made |
| seen in only one repository | capped at low |

Note the ceiling: **measurement cannot promote a check to `high`.**
Discrimination measures *signal* — how much more often a check fires on broken
code. Severity encodes *consequence* — how much it matters when the check is
right. Those correlate and are not the same quantity.

The example that forced the rule: "Ensure every security group and rule has a
description" fires 33 times on deliberately broken Terraform and zero times on
the well-maintained `terraform-aws-modules` repositories, which are meticulous
about descriptions. The ratio is real, reproducible and stack-matched. It is
also not a security finding, and grading it `high` would put a missing comment
on the same footing as a public S3 bucket. So measurement may say "this
carries signal" and may say "this carries none"; it may not manufacture a
claim about consequence.

On Terragoat, 477 findings of identical `medium` became 296 medium, 151 low
and 30 info — 181 regraded from measurement.

This does not breach the standing rule that learning never touches severity.
For a native rule, severity is a deliberate policy statement and nothing may
move it. For an external check the tool supplied *no* severity — replacing an
invented constant with a measured one is not drift. The table lives in the
knowledge file, is part of its version hash, and `--pin-knowledge` still fails
a run if it moved.

## Adjudication, made cheap enough to happen

Calibration reads one ledger: findings a person judged right or wrong. Not the
injection trials, not the corpus discrimination — those measure whether a rule
works mechanically and whether it separates populations, and neither answers
whether the things it flags are things you would act on.

That ledger sat at zero, because adjudicating meant copying fingerprints one
at a time. `arbiter review` writes a file of findings chosen to move the most
rules past the twenty-observation line — rules already close to the threshold
first, spread across files so twenty instances of one mistake are not counted
as twenty observations, never re-asking an adjudicated finding. Mark `[y]` or
`[n]`, then `arbiter review --apply`.

## Is the checking switched on?

A clean report has two possible causes that look identical from the outside:
the analyzers ran over everything and found nothing, or large parts of the
tree were excluded, hundreds of findings were silenced by inline comments, and
the tests that would have caught a regression assert nothing.

Every scanner hands you the same green tick for both. They have to — they
honour the suppression comments that hide findings from them, and a test that
asserts nothing still passes. The silencing is invisible to the thing being
silenced.

Measured across ten corpus repositories: **445 suppression comments**, 169 in
one project, and not one of them appears in any tool's output.

The `assurance` dimension reports three things: inline suppressions across
fifteen tools' ignore syntaxes (with the blanket ones — an ignore naming no
rule — separated out), configuration that excludes parts of the tree from
analysis, and tests that cannot fail. It carries **weight zero**. A repository
with four hundred `# noqa` comments is not insecure, it is *unmeasured*, and
scoring those the same way is the conflation the dimension exists to expose.

## Machine-authored code

A growing share of new code is drafted by a model, and model-drafted code
fails in ways human-drafted code mostly does not: confident, fluent,
plausible-looking code that refers to things which do not exist. A model is
the worst available reviewer for this — asked to check its own hallucinated
import, it reads the import, finds it plausible (it generated it precisely
because it was plausible) and passes.

These failures are decidable, so they are a deterministic probe rather than
part of the judgement pass:

| Check | What it catches |
|---|---|
| `undeclared-import` / `import-of-nonexistent-package` | A module nothing declares. See below. |
| `stub-on-production-path` | `return True  # TODO`, `raise NotImplementedError`, a `pass` body. Severity keyed to whether the function name says it decides something: a stub in `verify_signature` is not an unfinished feature, it is an always-yes. |
| `security-check-disabled` | `verify=False`, `InsecureSkipVerify: true`, `StrictHostKeyChecking=no`. Written to make an example work, then never removed. |
| `docstring-promises-absent-behaviour` | A docstring saying the function validates or retries, in a body that does neither. |

The import check ships in **two modes**, and the split is the honest part:

- **Offline** it knows only that a manifest does not declare something. That
  is mostly a stale manifest, so it reports at zero weight and says the
  distinction needs a registry.
- **Connected** it asks the registry whether the package exists at all. A name
  that resolves to nothing is **critical** — the import cannot ever have
  worked, so the name was invented, and an unclaimed package name sitting in a
  shipped import is an invitation to whoever registers it first.

```
$ arbiter scan ./app --profile connected
  critical  import-of-nonexistent-package  fastapi_auth_middleware_helper
  critical  import-of-nonexistent-package  secure_token_validator
```

Zero false criticals across the 42-repo corpus.

## Adjudicating

```bash
arbiter review report.json --html          # one self-contained page
arbiter review report.json --interactive   # one keypress per finding
arbiter review report.json --apply review.md
```

The page has no server, no network and no build step, so it works from a phone
with the wifi off — which matters, because the reports worth adjudicating are
often the ones you cannot send anywhere. One finding at a time with the code
around it: adjudicating from a list encourages skimming, and a skimmed verdict
is worse than none, because this ledger is the only thing calibration reads.

Which twenty findings you see is the whole question, and they are chosen to
move the most rules past the twenty-observation line — rules closest to the
threshold first, spread across files, never re-asking an adjudicated finding.

## Evidence the tool did not generate for itself

Everything else Arbiter measures against, it made. Injection plants faults
from patterns somebody chose. Corpus discrimination compares two populations
that were also chosen. Both share a blind spot: a rule can pass all of it and
still be wrong about real code.

**Real fix pairs** (`tools/fixpairs.py`) close that. Walk a repository's
history, scan each commit and its parent, and find a finding present in the
parent and gone in the child at the same site. Somebody who knew the system
decided something needed changing; nobody wrote that commit to be found by a
scanner. A rule that fires on both sides of a commit that plainly fixed the
thing is wrong, and nothing else in the pipeline would have said so.

Commit messages are deliberately *not* the filter — libraries are full of
feature commits mentioning encryption that fix nothing, and real remediations
get committed as "update manifests". The finding appearing and then
disappearing is the signal.

**Disagreement mining** (`tools/disagree.py`) decides which findings are worth
a person's attention. Where two independent analyzers looked at the same line
and reached different conclusions, exactly one is wrong, so a verdict there
resolves real uncertainty instead of confirming a settled one. Four buckets —
contested, severity disagreement, corroborated (agreed, deliberately *not*
queued) and coverage gap (an external tool checks something Arbiter has no
rule for, which is a list of rules worth writing rather than a disagreement).

**Held-out repositories.** Five repos, one of each population, never used to
tune a rule. Every figure in this project was previously measured on
repositories the rules were tuned against, which is how a tool ends up fitted
to its own practice set. The corpus tool now reports both rates — and prints
its own caveat, because a per-KLOC rate over two repositories is as much about
what those repositories contain as about whether the rules generalize. The
figure that survives a small sample is the count of build-breaking findings,
and that one is zero.

## Not yet built

Per the design spec: the Claude skill, air-gapped bundles, and the dashboard.
Commercial control packs (PCI-DSS, HIPAA, SOC 2, CIS) are a data file each in
the format the five government packs already use. The interfaces exist; the
implementations do not.
