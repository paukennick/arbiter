# Contributing

Defect reports, reproductions, documentation corrections and pull requests
are welcome, on the terms below.

- Security problems: do not open a public issue; see [SECURITY.md](SECURITY.md).
- Everyone taking part is expected to follow the
  [Code of Conduct](CODE_OF_CONDUCT.md).

## The terms: Apache-2.0 in, Apache-2.0 out

Arbiter is licensed under the Apache License, Version 2.0
([LICENSE](LICENSE)). Contributions are accepted under the same licence:
section 5 of the licence says that, unless you explicitly state otherwise,
any contribution you intentionally submit for inclusion is offered under its
terms. There is no contributor licence agreement and no copyright assignment;
you keep the copyright in your contribution.

## Sign your commits: the Developer Certificate of Origin

Every commit in a pull request must carry a `Signed-off-by` line. By adding
it you certify the [Developer Certificate of Origin](DCO) (version 1.1):
in short, that you wrote the change or otherwise have the right to submit it
under the project's licence, and that you understand the contribution and
your sign-off are public and kept permanently.

Git adds the line for you:

```bash
git commit -s -m "Describe the change"
```

which appends

```text
Signed-off-by: Your Name <you@example.com>
```

using your `user.name` and `user.email`. Use your real name, or the name you
are publicly known by, and an address you can be reached at. Anonymous and
pseudonymous sign-offs cannot be accepted, because the point of the
certificate is that someone is answerable for it.

Forgot? Amend the last commit with `git commit --amend -s --no-edit`, or sign
every commit on your branch with `git rebase --signoff origin/main`, then
force-push the branch.

A pull request whose commits are not all signed off cannot be merged.

## AI-assisted contributions

You may use AI tools to help write a contribution. You are still its author
for the purposes of the DCO: you must have the right to submit it, and you
must have read, understood and tested it. Say in the pull request which
tools you used. The project's own practice and the rules for contributors are
in [docs/ai-assisted-development.md](docs/ai-assisted-development.md).

## Third-party code

Do not paste code, tests or data from other projects into a contribution
unless their licence allows it and is compatible with Apache-2.0. Name the
source and its licence in the pull request. Code from GPL, AGPL or unknown
sources cannot be accepted into `src/`. See
[docs/third-party-content.md](docs/third-party-content.md) for how the
repository's existing third-party test material is inventoried.

## Before you open a pull request

- Follow the workflow in [AGENTS.md](AGENTS.md) and `.ai/`: tie the change to
  a requirement id, record it in [CHANGELOG.md](CHANGELOG.md), and run
  `python -m pytest -q -m "not slow"` and `python omni gate`.
- Keep a change to one concern. A rule change needs tests that show the
  defect it catches and the correct code it leaves alone.
- Do not change files under `fixtures/` to make a test pass; they are the
  measurement.

## Forks and names

Forks need no permission: keep `LICENSE` and `NOTICE`, and mark files you
change (licence §4). If you distribute a modified version, see
[TRADEMARKS.md](TRADEMARKS.md) on naming it.
