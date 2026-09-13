# CI and Automation

## Contents

- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Any other runner](#any-other-runner)
- [Scanning only what changed](#scanning-only-what-changed)
- [A ready-made workflow](#a-ready-made-workflow)
- [Choosing a gate](#choosing-a-gate)
- [Continuous training](#continuous-training)

---

## GitHub Actions

```yaml
# .github/workflows/arbiter.yml
- uses: ./ci/github-action
  with:
    target: .
    profile: ci
    baseline: .arbiter/baseline.json
```

The action uploads SARIF so findings render inline on the pull request, and
posts the Markdown report as a comment.

## GitLab CI

A template is in `ci/gitlab/arbiter.gitlab-ci.yml`.

## Any other runner

Arbiter is a Python package with one runtime dependency, and the gate is an exit
code:

```bash
pip install -e .
arbiter gate . --profile ci --baseline .arbiter/baseline.json --format json,sarif
```

| Code | Meaning |
|---|---|
| `0` | pass |
| `1` | gate failure |
| `2` | error |

## Scanning only what changed

A full scan costs about a minute per half-million lines. That is fine nightly
and too slow to sit in front of a merge. Caching file reads bought 20%, which
was the measurement that mattered: reading was never the bottleneck, the
analysis is.

So `--changed` reads less.

```bash
arbiter gate . --changed origin/main --baseline .arbiter/baseline.json
```

Every probe declares a scope. **file** means every finding depends only on the
file it is in — a hardcoded secret is a secret whether or not the rest of the
tree was read. **repo** means the answer depends on relationships between
files, and a subset-based answer is not weaker, it is false.

In a partial scan the file-scoped probes run, and the repo-scoped ones are
recorded as skipped with the partial scan named as the reason — so they stay in
the coverage denominator as not-assessed rather than vanishing. The files read
are the changed ones plus dependency manifests, lockfiles, CI workflows and
Terraform, which is where a rule genuinely reasons about a file it is not
reporting on.

Traefik, 171 changed files of 2,293: **59s → 6s**. The file-scoped findings are
identical to the full scan's on the files both read — 158 and 158, nothing
missing, nothing extra. `scope="file"` is a claim of exactness, so it is tested
rather than assumed.

### What a partial scan may not say

- The overall grade is **withheld outright**. The gate is a question a subset
  can answer ("did anything cross a threshold"); a grade is a summary of the
  repository, and a number that looks like one but describes a diff is the
  thing this tool exists not to produce.
- "Probe ran and found nothing" becomes "found nothing in the files it was
  given".
- No claim in the report is scoped complete except the coverage measurement
  itself, which is a statement *about* the incompleteness.

That last one is invariant **CI-11**, and it caught a real bug while this was
being built: a dimension can reach 100% check coverage in a partial scan,
because every probe carrying it is file-scoped and ran — having read a third of
the files. Fixed at the source rather than exempted.

A ref that does not exist refuses rather than scanning nothing. An empty diff
and a failed diff look identical downstream, and the second would produce a
green gate that read no files at all.

Findings that land in a context file the branch did not touch are tagged
`outside-this-change`, so a pull request is not blamed for a lockfile it never
opened. The baseline is what keeps them out of the gate.

## A ready-made workflow

`examples/pull-request-gate/` holds a two-job workflow and the config that goes
with it:

| | pull request | nightly / main |
|---|---|---|
| what it reads | the changed files, plus manifests, lockfiles, CI and Terraform | everything |
| how long | seconds | a minute per half-million lines |
| what it blocks on | anything critical, anything new at high | nothing; it reports |
| grade | withheld | reported |
| refreshes the baseline | no | yes, from the default branch only |

The nightly job is the only one allowed to refresh the baseline. Refreshing it
from a partial scan would quietly forgive every finding in the files that scan
did not read.

## Choosing a gate

The `ci` profile forbids network and model calls, which makes a run fast and
deterministic — the same commit produces the same bytes.

Three settings matter more than the rest:

```yaml
gate:
  fail_on:
    severity: critical    # consequence
    new: high             # direction of travel
    coverage_below: 0.60  # refuse to certify a thin scan
```

`new: high` is what makes adoption survivable on an existing codebase: the
baseline absorbs what is already there, and the build fails on what you add.
Because fingerprints exclude line numbers, reformatting does not invalidate the
baseline.

`coverage_below` is the guard against a reassuring result from a scan that
barely ran. Without it, an analyzer that failed to install looks identical to an
analyzer that found nothing.

Refresh the baseline deliberately, never automatically:

```bash
arbiter baseline arbiter-out/report.json
```

## Continuous training

`.github/workflows/train.yml` runs the measurement cycle nightly on GitHub's
runners and commits the results back. **It never edits a rule. It only
measures.** A run takes about ten minutes.

Each run:

1. downloads the practice repositories, if they are not already present
2. runs every rule against them and records what it found
3. measures each rule's ability to tell good code from broken code
4. plants known faults and checks the rules catch them
5. checks the tool never claims to have checked something it skipped
6. runs the test suite
7. commits the results back to the repository

Because step 7 writes to the repository, the next run starts from everything the
previous runs learned.

Run a cycle by hand at any time:

```bash
./tools/train_cycle.sh           # about fifteen minutes
PUSH=1 ./tools/train_cycle.sh    # and save the results
```

### The half that needs a person

Deciding what a result *means* is the part a schedule cannot do: whether a
finding on a well-maintained repository is the rule's fault or the code's,
whether a ratio is real or an artefact of how it was measured. Every real defect
found so far came from that half.

`training/WORKLIST.md`, regenerated by every nightly run, is the handoff. It
ranks what to look at and says why, so a session starts from a question rather
than a pile of tables.

Its six checks, in the order they have actually paid off:

| Check | Why it is there |
|---|---|
| Critical or high on well-maintained code | The strongest signal available. Three real defects in one afternoon, including a critical on three literal dots. |
| A severity the measurement does not support | A rule that fires no harder on broken code is describing a style, not detecting a defect. |
| A rule with no controls | The dangerous state, because it looks perfect: recall reads 1.0000 whether the rule is precise or fires on everything. |
| A rule nothing has ever exercised | An assertion wearing the costume of a measurement. |
| A stack with no broken counterpart | Its rules cannot be measured at all. Closing eight of these found three criticals on good code. |
| No finding reviewed by a person | Calibration reads **only** the adjudicated ledger. No schedule can fill it, because it is a judgement about what you would act on. |

An empty queue is itself a finding: the corpus has stopped teaching anything,
and the next useful move is to widen it, not to run it again.

Once a fortnight is enough. The nightly job keeps the evidence current in the
meantime.

### Two things to know about the numbers

**Running more trials does not make the tool more trustworthy past a point.**
Twenty thousand faults generated from fifteen patterns is closer to fifteen
independent tests than to twenty thousand. What improves the evidence is more
kinds of fault and more kinds of code, not more repetitions. That is why the
practice set spans thirteen languages and five infrastructure formats, and why
every fault is planted into a real file rather than a made-up one.

**Most real defects have come from widening, not from repeating.** Every time the
practice set grew, it found something the previous set could not. See
[evidence.md](evidence.md#every-stack-needs-a-broken-counterpart).
