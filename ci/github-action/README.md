# Arbiter GitHub Action

This is a composite action. It installs Arbiter, runs `arbiter gate --github`,
and uploads `report.sarif` to code scanning. With `post-review: "true"` it
also posts the trusted findings on the lines a pull request changed as one
GitHub review, updated in place on each push ([../../docs/pr-review.md](../../docs/pr-review.md)).

```yaml
on: pull_request
permissions:
  contents: read
  security-events: write    # SARIF upload
  pull-requests: write      # only with post-review
jobs:
  arbiter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: OWNER/arbiter/ci/github-action@<ref>
        with:
          post-review: "true"
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `target` | `.` | path to scan |
| `system` | `""` | an `arbiter-system.yaml`; overrides `target` |
| `profile` | `ci` | capability profile |
| `baseline` | `""` | baseline JSON for new/existing labelling |
| `fail` | `"true"` | `"false"` makes the step exit 0 whatever the gate returned |
| `config` | `arbiter.yaml` | the config to trust in full; a missing file means the defaults |
| `post-review` | `"false"` | `"true"` posts review comments. It never changes the gate's result: API errors, rate limits and a missing permission are log lines, not failures |
| `token` | `${{ github.token }}` | the token the review is written with. It is passed to Arbiter only when `post-review` is `"true"` |

## Outputs

| Output | Meaning |
|---|---|
| `report` | path to `report.json` |

## Forks

A pull request from a fork gets a read-only token, so the action cannot
comment on it. In that case the review goes into the job summary instead,
and the gate result is unchanged. Do not switch to `pull_request_target` to
get a write token: that event runs with the base repository's permissions
while checking out the fork's code.

The rest of the action's behaviour is in [../../docs/ci.md](../../docs/ci.md#github-actions).
