# Proposal: learning from use

**Status: proposal. Nothing here is built.**

## The problem

Arbiter has a designed memory and it is nearly empty. `.arbiter/knowledge.json`
carries four stores; two of them work and two do not:

| Store | State | Fed by |
|---|---|---|
| `rules` | 27 rules, generated evidence only | `tools/inject.py` |
| `external_severity` | 288 checks graded | `tools/calibrate_external.py`, nightly |
| `profiles` | one repository | `arbiter profile`, by hand |
| `adjudicated` | **empty** | a person, and nothing else |

`calibrated_confidence()` reads only the last one. With zero verdicts, no rule
is proven, and every confidence number in every report is still the rule
author's original guess. 227,999 generated observations have not moved it and
never will, by design: a fault the tool planted for itself says whether a rule
*can* detect what it was written to detect, not whether the things it flags are
things anyone would act on.

The gap is not storage. The ledger is 28 KB. It is that the only input which
counts requires somebody to sit down and judge findings, and that has never
happened — so the calibration machinery has run for the tool's entire life
without changing a single verdict.

## What this proposes

**Learn from the signal ordinary use already produces, without asking anyone to
adjudicate anything.**

Every time a person suppresses a rule, narrows it to a path, or lets a finding
sit unactioned across many scans, they have made a judgement. Today that
judgement is written into `arbiter.yaml` as a config entry and then forgotten —
nothing counts it, nothing notices that the same rule has been suppressed in
nine repositories, and nothing tells the rule's author that their rule is being
switched off rather than fixed.

That is a weaker signal than an adjudication, and it must never be confused for
one. But it is continuous, and it arrives for free.

### The shape

A fifth store, `usage`, keyed by `(repo_id, rule_id)`:

| Field | Meaning |
|---|---|
| `scans` | times this rule was applicable and the repository was scanned |
| `fired` | times it produced at least one finding |
| `suppressed_at` | paths it has been suppressed under, with the stated reason |
| `suppression_age` | how long the suppression has stood |
| `persisted` | findings present in a baseline and still present N scans later |
| `fixed` | findings that disappeared at a site where the code changed |

The last row is the valuable one and already has machinery:
`tools/fixpairs.py` mines exactly this from git history, and its output sits in
`training/fix-pairs.json` with 162 candidates awaiting confirmation. A finding
somebody actually fixed is the strongest non-adjudicated evidence that exists,
because nobody wrote that commit to satisfy a scanner.

### What it may and may not do

It must obey the same three constraints as the rest of the ledger, which are
what make this project's evidence worth anything:

1. **It may move confidence, never severity.** Severity is a policy statement.
   The single existing carve-out is external checks, where the tool supplied no
   severity at all and Arbiter was inventing one.
2. **It must be a separate ledger from adjudication**, the way synthetic
   evidence already is. A suppression means "not here, not now"; it does not
   mean "wrong". Somebody silencing a correct finding to ship on a Friday must
   not teach the tool that the finding was false. Mixing them would let a busy
   quarter erase a rule that works.
3. **It must be offline and pinned.** Learning accumulates between runs; a scan
   reads one version and records its hash. Nothing may update the ledger during
   a scan, or a run moves the hash it just wrote into its own report — the
   reason `arbiter profile` is a separate command.

### What it would be worth

Concretely, it would let the tool say things it currently cannot:

- "This rule has fired in 14 repositories and been suppressed in 11 of them.
  Nobody is fixing what it reports." That is a rule to demote or delete, and
  no amount of injection testing would ever reveal it.
- "This rule's findings get fixed within a week in every repository that has
  one." That is a rule to raise confidence on, and it is the closest thing to
  a true positive that does not require an adjudication.
- "Every suppression of this rule cites the same reason." That is a missing
  exemption in the rule, not a user problem.

## Why not a graph or a relational database

The instinct to reach for one is reasonable and I think it is wrong here, for
three reasons:

1. **Capacity is not the constraint.** 27 rules and a few hundred external
   checks is kilobytes. The bottleneck is input.
2. **The pinning guarantee is harder to keep.** The ledger's value comes from
   being content-hashed, so `(commit, config, knowledge version)` reproduces
   byte for byte and `--pin-knowledge` fails loudly when the table moves. A
   file hashes trivially. A live database has to be snapshotted and hashed to
   make the same promise, and that promise is the product.
3. **It adds a dependency to a tool with one.** Arbiter's only runtime
   dependency is PyYAML, which is what lets it run in an air-gapped pipeline
   next to the code it is judging.

The `usage` store above is relational in *shape* — repo × rule × outcome over
time — and that shape fits a nested dict at this size. If it ever outgrows a
file, the thing to reach for is SQLite: one file, no server, hashable, in the
standard library. I would not reach for it before the store exists and is
demonstrably too big.

## Sequencing

The first step is not this proposal. It is that **the adjudicated ledger is
empty and 508 items are already queued** — 162 fix-pairs and 346 contested
findings, drawn and waiting. Twenty verdicts on one rule is the point where
`arbiter learn` stops calling it unproven. A dozen on the noisiest rules is
worth more than another million generated trials.

Usage learning is the right thing to build *after* there is enough adjudicated
evidence to check it against. Built first, it would have nothing to be
validated against, and a weak signal nobody can calibrate is how a tool starts
quietly grading itself on a curve.
