# Review comments on pull requests

`arbiter gate --post-review` puts Arbiter's findings into the pull request as
GitHub review comments, on the lines the author just changed (ARB-173). A
finding in a batch report is rarely acted on; the same finding in code review
usually is. Meta reported fix rates going from near zero for batch reports to
above 70% once the findings appeared in review.

## Contents

- [What a developer sees](#what-a-developer-sees)
- [What gets posted](#what-gets-posted)
- [Configuration](#configuration)
- [Running it](#running-it)
- [Updates on each push](#updates-on-each-push)
- [Suggested fixes](#suggested-fixes)
- [Feedback: reactions become labels](#feedback-reactions-become-labels)
- [What it does not do](#what-it-does-not-do)

## What a developer sees

The developer sees one inline comment on each changed line that has a trusted
finding, and one summary comment on the conversation tab. The example below
was rendered from a test fixture. It assumes a ledger with an advisory bar of
0.85, because the ledger shipped today does not admit
`python.http-no-timeout` (see [What gets posted](#what-gets-posted)).

Inline, on `client.py` line 5:

> **Arbiter** · medium · `arbiter/python.http-no-timeout`
>
> **`requests.get(url, headers={"Authorization": token})` has no timeout: a stalled upstream stalls this call forever**
>
> `requests` and `urllib` block indefinitely by default. One upstream that accepts the connection and never answers pins a worker thread (or the whole request handler) until the process is restarted.
>
> Suggested fix:
> ```suggestion
>     r = requests.get(url, headers={"Authorization": token}, timeout=30)
> ```
> `timeout=30` is a starting point; pick the bound this call can afford.
>
> <sub>Posted because: advisory bar: lower bound 0.925 on 357 labels. Useful? React 👍 or 👎 on this comment; Arbiter reads the reactions back as labels (`arbiter review-feedback collect`).</sub>

The suggestion block gives the author a **Commit suggestion** button. Each
comment ends with a hidden marker,
`<!-- arbiter-finding id=f:… rule=… -->`. That marker is how later runs find
the comment again, and how reactions are traced back to their rule.

The summary comment starts with the hidden marker `<!-- arbiter-review -->`.
It holds the gate verdict (the same text `--format pr-comment` renders) and
any findings that went over the comment cap, listed under "N more findings in
the summary".

## What gets posted

A finding is posted only if it passes all three of these checks:

1. **It is on a changed line.** The finding's line must be one this pull
   request added or modified. Untouched code gets no comment, even inside a
   changed file. The finding's line in the checked-out code must also read
   exactly as the diff added it. On a `pull_request` event, the checkout is
   GitHub's merge commit, and its line numbers can differ from the head commit
   that review comments attach to. A finding whose line has moved is skipped
   rather than posted on the wrong line.
2. **Its rule is trusted.** The trust check reads the precision ledger
   ([precision.md](precision.md#ledger)) at run time:
   - A rule the ledger **admits** is always trusted. Admission means a lower
     bound of at least 0.97 on at least 30 labels.
   - Under `review.min_tier: advisory` (the default), a rule at the ledger's
     **advisory bar** is also trusted, once the ledger has one. That bar is
     either a per-rule `advisory` admission or a `bar.advisory_lower`
     threshold. A rule the ledger marks `default_off` is never posted.
   - **While the ledger has no advisory bar**, which is true of the ledger
     shipped today, a finding qualifies on its own when it is high or
     critical severity, high confidence and deterministic. There is one
     exception: if the ledger has measured the rule on 30 or more labels with
     a lower bound below 0.85, the rule's own track record wins. That
     currently keeps 13 measured rules off pull requests, including
     `python.sql-injection` at 0.078.
   - Model-found findings are never posted, and neither are findings the
     model pass rejected or was unsure of, or suppressed findings.
3. **It is within the cap.** At most `review.max_comments` inline comments
   are posted (default 20). The rest are listed in the summary.

With the ledger shipped on 2026-10-26, three rules are admitted:
`supply.unpinned-action`, `assurance.blanket-suppression` and
`java.weak-random-for-secret`. `python.http-no-timeout` sits just below the
bar, at a lower bound of 0.968, and is medium severity, so its suggestion
does not appear on real pull requests yet. It will appear once the advisory
bar lands in the ledger, or if a repository opts in with
`precision.verified_rules` and the ledger later admits the rule.

## Configuration

```yaml
review:
  min_tier: advisory      # advisory (default) | verified
  max_comments: 20        # 0-100; the rest go in the summary
  suggestions: true       # mechanical ```suggestion blocks
```

| Key | Default | Effect |
|---|---|---|
| `min_tier` | `advisory` | `verified`: only ledger-admitted rules. `advisory`: also rules at the advisory bar, or the high-severity fallback described above |
| `max_comments` | `20` | inline comments per run; anything over the cap is listed in the summary |
| `suggestions` | `true` | `false` turns off suggestion blocks; the remediation text is shown instead |

A value outside these choices is a config error, not silently ignored.

## Running it

```bash
arbiter gate . --post-review                      # in a pull_request workflow
arbiter gate . --post-review --review-base main   # locally: prints what it would post
```

From the composite action:

```yaml
permissions:
  contents: read
  pull-requests: write        # for the review comments
  security-events: write      # for the SARIF upload
steps:
  - uses: actions/checkout@<sha>
    with:
      fetch-depth: 0          # only needed when the API is unavailable
  - uses: OWNER/arbiter/ci/github-action@<ref>
    with:
      post-review: "true"
```

What happens in each situation:

| Situation | Result |
|---|---|
| `GITHUB_TOKEN` with `pull-requests: write`, a `pull_request` event | changed lines read from `GET /pulls/{n}/files`; review posted or updated |
| no token | dry run: the comments it would post are printed to the log. The changed lines come from `git diff <base>...HEAD`, where the base is `--review-base`, else `--changed`, else `origin/$GITHUB_BASE_REF` |
| a pull request from a fork | the token cannot write, so nothing is posted; the summary goes to the job summary |
| GitHub refuses the write (401, 403 or 404) | the summary goes to the job summary |
| any other API error, including rate limits | one log line, `review: not posted (...); the gate result is unaffected` |
| one comment GitHub rejects as outside the diff (HTTP 422) | the comments are retried one at a time, and the refused ones are dropped and counted |
| a shallow checkout with no merge base (dry run only) | posting is skipped with a note to set `fetch-depth: 0` |

**The gate's exit code is fixed before posting starts.** Nothing the review
step does, including an exception, changes it.

The review is anchored to the head commit, read from the event payload's
`pull_request.head.sha` and never from `GITHUB_SHA`, which on a
`pull_request` event is the merge commit. When the scan target is a
subdirectory of the repository, finding paths are prefixed with that
directory before they are matched against the diff. In a multi-repository
`--system` scan, only findings in the first repository are posted.

## Updates on each push

- **Summary:** one comment, found by its `<!-- arbiter-review -->` marker and
  edited in place. It is edited only when its text changed.
- **Inline comments:** matched to findings by fingerprint. Fingerprints leave
  out line numbers, so a finding that moved keeps its comment. A finding that
  already has a comment is never posted again; its comment is edited only if
  the text changed.
- **Findings that went away:** the comment is edited to begin "Arbiter no
  longer reports `<rule>` here as of `<sha>`", with the original folded
  underneath. This only happens when the finding's file was scanned in this
  run. A partial scan that did not read the file proves nothing about it.
  The REST API cannot resolve a review thread (that needs GraphQL's
  `resolveReviewThread`), so the thread stays open for the author to resolve.

## Suggested fixes

Fixes come from a registry in `src/arbiter/pr_review.py`. A rule provides one
with `@register_fix("arbiter/<rule>")`, as a function that takes the finding
and the file's text and returns a one-line replacement, or `None`. **A fix
must return `None` unless the edit is mechanical and certain.** Arbiter
would rather show no suggestion than a suggestion that changes behaviour
beyond the rule's scope.

The first fix is for `python.http-no-timeout`. It appends `timeout=30` to a
`requests.<method>(...)` call. It refuses to suggest anything for:

- `urlopen`, whose third positional argument is already the timeout
- a call that spans lines
- a line holding two `requests` calls
- a call with `**kwargs`, which may already carry a timeout
- a call with a comment inside its parentheses
- anything that is not the module-level `requests` function

After making the edit, it parses the file again and requires the new syntax
tree to equal the old one plus exactly one `timeout` keyword. That re-parse
is the proof that the fix changes nothing else.

## Feedback: reactions become labels

Every inline comment invites a 👍 or 👎. To read the reactions back:

```bash
GITHUB_TOKEN=... arbiter review-feedback collect --repo owner/name --pr 123
```

This writes one label per person per finding to
`.arbiter/labels/human-pr.jsonl`, or wherever `--out` points. It merges with
what is already there: collecting twice adds nothing, and a changed reaction
replaces the earlier label. The record follows the
[label format](precision.md#label-format):

```json
{"finding_id": "pr:owner/name#123:f:144a635222ba", "rule_id": "arbiter/python.http-no-timeout",
 "label": "tp", "question": "useful", "labeller": "human:pr-reaction",
 "provenance": "human:pr-reaction", "reactor": "sha256:1f0e…", "source": "pr-reaction",
 "held_out": false, "role": "labeller", "date": "2026-10-26", "repo": "owner/name",
 "pr": 123, "path": "client.py", "line": 5, "comment_id": 101}
```

- 👍 is recorded as `tp` and 👎 as `fp`. The question the person answered is
  "was this useful", which is close to "is this a true positive" but not the
  same; `question` records which one it was.
- The reactor's login is lower-cased and hashed with SHA-256, keeping 16 hex
  characters. That is enough to de-duplicate and count distinct people, but
  the file does not name anyone.
- Bots are ignored, and so is the comment's own author (the token's account).
- A person who left both 👍 and 👎 has not decided, and gets no label.

**These labels stay out of admission until Nick decides how they may count.**
`tools/precision_ledger.py build` drops every record whose `labeller` or
`provenance` is `human:pr-reaction`, wherever the file sits, and says how
many it dropped. A test builds the ledger with and without 200 such labels
and requires identical counts. They are the human spot-check evidence that
[the precision research](precision.md) asks for. The intended route to the
ledger, once agreed, is:

1. Compare them with the model labels on the same rules.
2. Report the agreement rate, and the reactor count behind it.
3. Only then decide whether they may count toward admission, or only veto
   it.

Reactions are not a random sample: people react to what they notice, on
findings already filtered to trusted rules. Any use of them has to say so.

These labels are separate from `arbiter feedback` and `arbiter review`
verdicts, which calibrate confidence in one repository's knowledge file
([calibration.md](calibration.md)).

## What it does not do

- It does not resolve review threads. That needs the GraphQL API; a finding
  that went away is noted in the comment instead.
- It does not post findings from repositories other than the pull request's
  own in a `--system` scan.
- It does not run on the hosted API or MCP surfaces; it is a `gate` flag
  only.
