# What to work on next

Generated 2026-09-12T23:40:41+00:00 by `tools/worklist.py` from the last training cycle.

Nothing here is a decision. Each entry says what the measurement shows and what question it raises.

No criticals or highs on well-maintained code. That is the check that has found the most, so it being quiet is the single best sign available.

### 1. [MEDIUM] Stacks with no deliberately-broken counterpart

A language that appears only in well-maintained repositories cannot be measured. There is nothing to compare its rules against, so they can be asserted but never tested.

- **go** — 811,194 lines of good code, 15,256 broken
- **cpp** — 147,949 lines of good code, 0 broken
- **rust** — 56,386 lines of good code, 0 broken
- **rst** — 23,251 lines of good code, 0 broken
- **c** — 8,660 lines of good code, 7 broken
- **r** — 5,616 lines of good code, 0 broken

Add a deliberately-vulnerable repository for each, to `tools/fetch_corpus.sh` and `tools/corpus.py`. Closing eight of these gaps is what surfaced three false criticals that had survived every injection trial ever run.

### 2. [HIGH] No real finding has ever been reviewed by a person

Calibration reads **only** the adjudicated ledger — the one a person fills in — and it is empty, so the calibration machinery is currently doing nothing at all.

That separation is deliberate. Faults the injector generates come from a pattern somebody chose, so they measure whether a rule works mechanically. Only a person looking at a real finding on real code says whether the things it flags are worth flagging. Mixing them would let a hundred thousand generated cases drown out ten real ones — which is why no amount of nightly running will ever fill this in.

It is also the one gap that no schedule and no session can close, because it is a judgement about what you would actually act on.

```
arbiter scan ./some-repo
arbiter feedback f:8c41 --false-positive
arbiter feedback f:9d02 --true-positive
arbiter learn
```

Twenty adjudications on one rule is the point where `arbiter learn` stops calling it unproven. A dozen on the noisiest rules is worth more than another million trials.

### 3. [HIGH] 14 real-world fix pairs waiting for a verdict

A commit where a maintainer changed code a rule fired on, after which it stopped firing. This is the only evidence in the whole system that the tool did not generate for itself — nobody wrote these commits to be found by a scanner.

- `arbiter/secrets.pg-url` — 3 candidate pair(s)
- `arbiter/resource.k8s-no-security-context` — 2 candidate pair(s)
- `arbiter/resource.k8s-privilege-escalation-not-disabled` — 2 candidate pair(s)
- `arbiter/resource.k8s-not-run-as-non-root` — 2 candidate pair(s)
- `arbiter/resource.k8s-writable-root-filesystem` — 2 candidate pair(s)
- `arbiter/resource.k8s-capabilities-not-dropped` — 2 candidate pair(s)
- `arbiter/supply.unpinned-action` — 1 candidate pair(s)

Each one is a CANDIDATE: a finding also disappears when the code around it is rewritten for unrelated reasons. Confirm that the change addressed the finding, then it becomes a permanent regression case — this rule must fire on the parent commit and must not fire on the child, forever. A rule that fires on both sides of a commit that plainly fixed the thing is wrong, and nothing else in the pipeline would have told you.

### 4. [LOW] Rules with too little evidence to judge

Not a defect — a gap. Fewer than five findings in total, so the ratio beside each is arithmetic rather than evidence.

- `arbiter/resource.database-publicly-accessible` — 0 good, 2 broken
- `arbiter/resource.host-network` — 1 good, 1 broken
- `arbiter/resource.k8s-host-namespace` — 0 good, 4 broken
- `arbiter/resource.k8s-privilege-escalation` — 0 good, 1 broken
- `arbiter/resource.k8s-runs-as-root` — 0 good, 1 broken
- `arbiter/resource.no-log-retention` — 2 good, 1 broken
- `arbiter/resource.privileged-container` — 0 good, 4 broken
- `arbiter/resource.public-object-store` — 0 good, 1 broken
- `arbiter/resource.unencrypted-queue` — 1 good, 1 broken

More repetitions will not help. Effective sample size is bounded by how many different kinds of code and fault exist, not by trial count. These need more varied code.


---

## Where things stand

- **vulnerable**: 16 repos, 694,772 lines, 1294 findings, 17 critical, 89 high
- **clean**: 20 repos, 2,309,276 lines, 4252 findings, 0 critical, 0 high
- **examples**: 5 repos, 596,206 lines, 2433 findings, 0 critical, 15 high
- **15** rules have injection results; **0** findings have been reviewed by a person

The measurement traps that have produced a wrong answer here before, all three worth re-reading before acting on any number above:

1. Counting teaching repositories as production code — it made the noise rate look four times worse than it was.
2. Dividing by whole-repository size — it makes a Kubernetes rule look spotless inside a large Go project.
3. Counting findings the tool already discounted as test fixtures — 195 of 203 findings for one rule were exactly that.
