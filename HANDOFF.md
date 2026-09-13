# Arbiter — context for a Claude Code session

Drop this file into a session that has this repository connected. It is written
to be read cold, by someone with no history of how the tool got here.

---

## Task zero: land the pending commits

There is a git bundle, `arbiter-update.bundle`, carrying commits that were built
in a Cowork session which cannot push (the git proxy refuses to issue a
credential for a repo that is not in that session's authorized set — a known
open bug, and there is no setting that fixes it). The bundle is how they travel.

```bash
git fetch /path/to/arbiter-update.bundle main:incoming
git merge --ff-only incoming
python -m pytest -q          # expect: 310 passed
git push origin main
git branch -d incoming
```

`--ff-only` is deliberate. If it refuses, something moved on `main` since the
bundle was cut — stop and rebase rather than forcing anything.

If the bundle is not to hand, everything below still applies; skip to "Where
things stand".

---

## What Arbiter is

A repository evaluator that refuses to grade what it did not actually inspect.
It scans one repository or a **system** of several, produces findings across
seven dimensions, and reports how much of its own rubric it was able to run.

The premise is not "find more bugs than the other scanner". Every scanner finds
things. The premise is that a report should never assert something the tool did
not verify, and that the gap between "checked and clean" and "could not check"
should be visible in every output. That sounds like a small distinction and it
is the entire product.

Python 3.11, PyYAML the only runtime dependency, `pip install -e .`.

---

## The rules that are not up for negotiation

A fresh session will break these by accident, because each one looks like a bug
worth fixing until you know why it is there.

**1. A check that could not run is `not assessed`, never a pass.** If a probe is
missing its binary, forbidden by the profile, or unconfigured, it is recorded
with a reason and it stays in the coverage denominator. Returning an empty list
instead would make every unconfigured scan report clean forever.

**2. Coverage is reported, and below the threshold the grade is withheld.** Not
estimated, not extrapolated. Withheld, with the reason printed.

**3. The tool never executes the target repository.** No `npm install`, no
`terraform init`, no importing the target's Python. For Terraform the operator
generates the plan and Arbiter reads the JSON. This is not a performance
decision and there is no flag to turn it off.

**4. Deterministic and model-inferred findings never blend.** Every finding
carries `provenance`. Inferred findings are advisory and do not gate by default,
and a model's stated confidence never reaches `high`.

**5. No claim outruns its basis.** Every assertion a report makes is recorded as
a Claim with the checks that support it and the checks that abstained. Eleven
invariants (CI-1 … CI-11) forbid a claim that overreaches, and the engine
verifies its own report before writing it. `tools/integrity.py` enumerates the
bounded state space — 354,294 reports, zero failures — and separately proves
each invariant is enforced by deliberately breaking it.

If a change makes an invariant fail, the invariant is almost certainly right.
Three real bugs were found that way. Exempting one to make a test pass is the
single worst thing you can do to this codebase.

**6. Measurement may cap a severity, never manufacture one.** Discrimination
measures *signal*; severity encodes *consequence*. "Ensure every security group
has a description" separates broken code from good code perfectly and is still
not a security finding. A check reaches `high` only when its own tool says so.

**7. Suppressed findings stay in the report,** marked, attributed, with a reason
and a mandatory expiry. Suppression may hide a finding and may never raise
coverage — that is invariant CI-6.

---

## How anything gets verified here

Four independent methods, and they catch different things. Run the ones that
bear on what you changed.

```bash
python -m pytest -q                     # 310 tests
python tools/integrity.py               # claim invariants, exhaustive
python tools/inject.py --trials 8000    # plant known faults, measure recall + specificity
python tools/corpus.py                  # 42 real repos in three populations
python tools/discriminate.py            # does each rule separate broken from good code
```

The division of labour is worth knowing:

- **Injection** finds rules that fail *mechanically* — a pattern that cannot
  match what it claims to. It found that `:=` was unmatched, so every Go short
  declaration was invisible to the secret detector (recall 0.48).
- **The corpus** finds rules that work mechanically and are still wrong about
  real code. It found a critical "leaked private key" that was three literal
  dots in Argo CD's manual — a case that passes every injection trial ever
  written, because a generator never thinks to plant a placeholder.
- Neither replaces reading the output.

**Every new rule needs a control, not just a positive case.** A rule that fires
on everything scores perfect recall. Six rules once had measured recall and zero
controls, which is the dangerous state.

**Fixture correctness matters more than fixture breakage.** `fixtures/multicloud`
has a correct half as well as a broken one, and writing the correct half is what
exposed a bug where a volume encrypted with a customer-managed KMS key was
reported `high` as unencrypted on every provider.

---

## Measurement traps this project has already fallen into

Four times, each the same shape, each recorded in the source where it happened.
If you are about to compute a ratio, read this first.

1. **Denominator.** A Kubernetes rule judged against whole-repo size looks
   spotless inside a 400,000-line Go project containing forty lines of YAML.
   Reports carry `loc_by_language` and `loc_by_role`; judge a rule against the
   lines it could actually have fired on.
2. **Numerator.** Arbiter already discounts `testdata/` manifests, so counting
   them at full weight measures the rule against a claim the tool never made —
   195 of 203 findings for one rule in Argo CD. Weight by severity × confidence.
3. **The comparison itself.** The broken corpus is broken in the *security*
   sense. For quality and drift rules there is no broken population, so the
   ratio is a statement about codebase age. Only security and compliance rules
   get a verdict.
4. **The label.** Teaching repositories are not clean code and not broken code;
   they are a third population. Splitting them out moved the well-maintained
   false-positive rate from 2.02 to 0.83 per KLOC with no rule change at all.

And one about samples: `MIN_REPOS_TO_PROMOTE = 2`. One repository is not a
population.

---

## Held-out repositories

Five repos are never tuned against: `argo-cd`, `php-guzzle`, `dvwa`, `cdkgoat`,
`compose-awesome`. A fix driven by evidence from one of them **spends** that
rule's holdout, and that is recorded in the source beside the change rather than
quietly skipped. It has happened once, deliberately, for
`authored.security-check-disabled`.

---

## Where things stand

- 42-repo corpus in three populations. 0 critical and 0 high across 2.3M lines
  of well-maintained production code; 17 critical / 79 high across 695K lines of
  deliberately broken code.
- Adapters proven end to end (checkov, semgrep, bandit, ruff, gitleaks, pinned
  versions in `tools/install_tools.sh`). Bumping any of them means re-running
  `tools/calibrate_external.py` — measured severities are keyed to check ids.
- Five US government control packs, each independent, each reporting the real
  published baseline as its denominator.
- Incremental scanning: `--changed REF` reads the diff and records the checks
  that need the whole tree as not assessed. Traefik 59s → 6s, with the
  file-scoped findings identical to a full scan on the files both read.
- Nightly training runs on GitHub's runners (`.github/workflows/train.yml`) and
  regenerates `training/WORKLIST.md`. It measures and never edits a rule.

**The one thing blocking further progress is adjudication.** Calibration reads
only the adjudicated ledger and the ledger is empty, so all of that machinery is
currently inert. About twenty verdicts on one rule is where `arbiter learn`
stops calling it unproven.

```bash
arbiter review arbiter-out/report.json --html review.html   # self-contained page
arbiter review arbiter-out/report.json --apply review.md
```

`RUNNING-ON-YOUR-OWN-CODE.md` is the walkthrough for pointing it at a real
repository.

---

## Opening move for a working session

```bash
cat training/WORKLIST.md
```

It is a ranked queue with the evidence for each item and the question that item
raises. It decides nothing. An **empty** queue is itself a finding: the corpus
has stopped teaching us anything, and the move then is to widen it — carefully.
Two candidates have already been rejected rather than mislabelled (a gigabyte of
vendored fuzzing engine, and an advisory database, which is metadata *about*
vulnerabilities rather than vulnerable code). A gap left open and reported beats
a gap papered over.
