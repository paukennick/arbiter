# What to work on next

Generated 2026-10-27T14:06:39+00:00 by `tools/worklist.py` from the last training cycle.

Nothing here is a decision. Each entry says what the measurement shows and what question it raises.

> Incomplete: no results found for corpus, discrimination. Run `./tools/train_cycle.sh` first.

### 1. [HIGH] No real finding has ever been reviewed by a person

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

### 2. [HIGH] 169 real-world fix pairs waiting for a verdict

A commit where a maintainer changed code a rule fired on, after which it stopped firing. This is the only evidence in the whole system that the tool did not generate for itself — nobody wrote these commits to be found by a scanner.

- `arbiter/supply.unpinned-npm-dep` — 146 candidate pair(s)
- `arbiter/authored.undeclared-import` — 5 candidate pair(s)
- `arbiter/secrets.pg-url` — 3 candidate pair(s)
- `arbiter/supply.unpinned-action` — 2 candidate pair(s)
- `arbiter/secrets.private-key` — 2 candidate pair(s)
- `arbiter/resource.public-object-store` — 2 candidate pair(s)
- `arbiter/resource.host-network` — 1 candidate pair(s)
- `arbiter/secrets.assigned-credential` — 1 candidate pair(s)

Each one is a CANDIDATE: a finding also disappears when the code around it is rewritten for unrelated reasons. Confirm that the change addressed the finding, then it becomes a permanent regression case — this rule must fire on the parent commit and must not fire on the child, forever. A rule that fires on both sides of a commit that plainly fixed the thing is wrong, and nothing else in the pipeline would have told you.

### 3. [HIGH] Contested findings, ready to adjudicate

217 findings where both Arbiter and an external analyzer cover the kind of defect, and only one of them fired. Exactly one is wrong about that line, so a verdict there resolves a real uncertainty instead of confirming a settled one.

- 98 where only **arbiter** fired
- 67 where only **checkov** fired
- 49 where only **semgrep** fired
- 3 where only **gitleaks** fired

A batch is already prepared. Twenty of these are worth more than twenty random findings, because a finding two independent tools agree on is the least informative thing a person can spend a verdict on.


---

## Where things stand

- **27** rules have injection results; **0** findings have been reviewed by a person

The measurement traps that have produced a wrong answer here before, all three worth re-reading before acting on any number above:

1. Counting teaching repositories as production code — it made the noise rate look four times worse than it was.
2. Dividing by whole-repository size — it makes a Kubernetes rule look spotless inside a large Go project.
3. Counting findings the tool already discounted as test fixtures — 195 of 203 findings for one rule were exactly that.
